"""Mocked IPinfo transport; fixture intelligence never enters production storage."""
import copy
import os
import unittest
from unittest.mock import patch
import httpx
from backend.intelligence import providers as ti
from backend.core.origin_confidence import compute_origin_confidence
from backend.core.pipeline import select_indicators, geolocation_summary
from backend.parsers.email_parser import parse

IP='8.8.8.8'
CORE={'ip':IP,'geo':{'country':'United States','country_code':'US','city':'Fixture city','region':'Fixture region','latitude':0,'longitude':0},
      'as':{'asn':'AS15169','name':'Google LLC','type':'hosting'},'is_hosting':True}

def parsed():
    return parse(b'Received: from source [8.8.8.8] by receiver; Wed, 30 Sep 2026 10:00:00 +0000\nFrom: a@example.com\nTo: b@example.com\nSubject: Test\n\nHello')

def row(provider,result,status='Available'):
    return {'provider':provider,'query':IP,'type':'ip','status':status,'result':result}

class IPinfoOriginTests(unittest.TestCase):
    def setUp(self):
        for p in (patch.object(ti,'db'),patch.object(ti,'statuses',return_value={'ipinfo':'Configured'}),
                  patch.object(ti,'secret',return_value='fixture-token'),patch.dict(os.environ,{'IPINFO_API_MODE':'lookup'})):
            p.start();self.addCleanup(p.stop)
        ti.db.threat_intelligence.find_one.return_value=None
        ti.db.provider_cooldowns.find_one.return_value=None

    def request(self,payload=CORE,code=200):
        client=httpx.Client
        def handle(req):
            self.assertEqual(req.headers['Authorization'],'Bearer fixture-token')
            self.assertNotIn('fixture-token',str(req.url))
            self.assertEqual(req.url.host,'api.ipinfo.io')
            return httpx.Response(code,json=payload)
        with patch.object(ti.httpx,'Client',side_effect=lambda **kw:client(transport=httpx.MockTransport(handle),**kw)):
            return ti.lookup_provider('ipinfo','ip',IP)

    def test_core_plan_unknown_privacy_and_valid_zero_coordinates(self):
        result=self.request()
        self.assertEqual(result['status'],'Available')
        self.assertEqual(result['result']['asn'],15169)
        self.assertTrue(ti.coordinates_available(result['result']))
        self.assertIsNone(result['result']['is_vpn'])
        self.assertNotIn('fixture-token',str(result))

    def test_plus_legacy_and_lite_schemas(self):
        plus={**CORE,'anonymous':{'is_vpn':True,'is_proxy':False,'is_tor':False}}
        self.assertTrue(ti.normalize_ipinfo(plus,IP)['is_vpn'])
        self.assertIs(ti.normalize_ipinfo(plus,IP)['is_proxy'],False)
        legacy={'ip':IP,'loc':'12.3,45.6','country':'US','org':'AS15169 Google LLC','privacy':{'vpn':False,'tor':True}}
        result=ti.normalize_ipinfo(legacy,IP)
        self.assertEqual(result['latitude'],12.3);self.assertTrue(result['is_tor']);self.assertEqual(result['asn'],15169)
        lite={'ip':IP,'asn':'AS15169','as_name':'Google LLC','country':'United States','country_code':'US'}
        self.assertIsNone(ti.normalize_ipinfo(lite,IP)['latitude'])

    def test_failures_are_bounded_sanitized_results(self):
        for code,status in [(401,'Invalid Credentials'),(403,'Access Denied'),(429,'Rate Limited'),(500,'Unavailable')]:
            with self.subTest(code=code):self.assertEqual(self.request(code=code)['status'],status)
        for payload in ([],{}, {'ip':'1.1.1.1','org':'wrong'}, {'ip':IP,'geo':'bad'}, {'ip':IP}):
            with self.subTest(payload=payload):self.assertEqual(self.request(payload)['status'],'Unavailable')
        with patch.object(ti.httpx,'Client') as client:
            client.return_value.__enter__.return_value.get.side_effect=httpx.ReadTimeout('fixture-token')
            result=ti.lookup_provider('ipinfo','ip',IP)
        self.assertEqual(result['status'],'Unavailable');self.assertNotIn('fixture-token',str(result))

    def test_nonpublic_never_contacts_ipinfo(self):
        with patch.object(ti.httpx,'Client') as client:
            for ip in ('127.0.0.1','192.168.1.1','203.0.113.3','::1','::ffff:10.1.1.1','invalid'):
                self.assertEqual(ti.lookup_provider('ipinfo','ip',ip)['status'],'Not Applicable')
            client.assert_not_called()

    def lookup(self,primary,allow=True):
        calls=[]
        def mock(provider,kind,ip):
            calls.append(provider)
            return primary if provider=='ipinfo' else row(provider,{'latitude':10,'longitude':20,'country':'Fallback country','city':'Fallback city','asn':42} if provider=='geoip' else {})
        config={'enabled_providers':['ipinfo','geoip'],'rdap_enabled':False}
        with patch.object(ti,'settings',return_value=config),patch.object(ti,'lookup_provider',side_effect=mock),patch.object(ti,'reverse_dns',return_value=None):
            result=ti.lookup('ip',IP,allow_external=allow)
        return result,calls

    def test_priority_partial_fallback_and_provenance(self):
        primary=row('ipinfo',ti.normalize_ipinfo(CORE,IP))
        item,calls=self.lookup(primary)
        self.assertNotIn('geoip',calls)
        self.assertEqual(ti.network_geo(item)['data_source'],'IPinfo')
        partial=row('ipinfo',{'asn':15169,'organization':'Google LLC','country':'IPinfo country'})
        item,calls=self.lookup(partial)
        self.assertLess(calls.index('ipinfo'),calls.index('geoip'))
        result=ti.network_geo(item)
        self.assertEqual(result['country'],'Fallback country');self.assertEqual(result['asn'],15169)
        self.assertEqual(result['field_sources']['latitude'],'MaxMind');self.assertEqual(result['field_sources']['asn'],'IPinfo')
        rows=ti.enrich_mail_path(parsed(),[item])
        self.assertEqual(rows[0]['city'],'Fallback city')
        self.assertEqual(geolocation_summary(parsed(),[item])['locations'][0]['asn'],15169)

    def test_failures_and_privacy_setting_preserve_local_fallback(self):
        for status in ('Unavailable','Rate Limited','Invalid Credentials','Disabled','Not Configured'):
            item,calls=self.lookup(row('ipinfo',None,status))
            self.assertIn('geoip',calls);self.assertEqual(ti.network_geo(item)['data_source'],'MaxMind')
        item,calls=self.lookup(row('ipinfo',None),allow=False)
        self.assertNotIn('ipinfo',calls);self.assertIn('geoip',calls)

    def test_rdap_network_only_not_registration_country_location(self):
        item={'type':'ip','query':IP,'providers':[],'rdap':{'status':'Available','result':{'asn':'42','organization':'Example ISP','asn_country':'US','network_cidr':'8.8.8.0/24'}}}
        result=ti.network_geo(item)
        self.assertEqual(result['data_source'],'RDAP');self.assertNotIn('country',result)
        self.assertFalse(ti.coordinates_available(result))

    def test_cloud_and_privacy_reduce_confidence_without_false_flags(self):
        plain={**ti.normalize_ipinfo(CORE,IP),'organization':'Example ISP','is_hosting':False,'network_type':'isp'}
        enrich=lambda data:[{'type':'ip','query':IP,'providers':[row('ipinfo',data)]}]
        base=compute_origin_confidence(parsed(),enrich(plain))
        cloud=compute_origin_confidence(parsed(),enrich(ti.normalize_ipinfo(CORE,IP)))
        vpn=compute_origin_confidence(parsed(),enrich({**plain,'is_vpn':True}))
        self.assertLess(cloud['score'],base['score']);self.assertLess(vpn['score'],base['score'])
        self.assertEqual(cloud['probable_origin']['mail_cloud_provider'],'Google / Gmail')
        self.assertIsNone(cloud['probable_origin']['is_tor']);self.assertLess(base['score'],60)
        self.assertIn(base['level'],('HIGH','MEDIUM','LOW'))
        self.assertEqual(base['disclaimer'],ti.ORIGIN_DISCLAIMER)

    def test_rdap_crosscheck_and_header_anomalies(self):
        item={'type':'ip','query':IP,'providers':[row('ipinfo',ti.normalize_ipinfo(CORE,IP))],
              'rdap':{'status':'Available','result':{'asn':'AS15169','organization':'Google LLC','network_cidr':'8.8.8.0/24'}}}
        good=compute_origin_confidence(parsed(),[item])
        self.assertEqual(good['probable_origin']['rdap_cross_check']['status'],'Consistent')
        item['rdap']['result']['asn']='99'
        bad=compute_origin_confidence(parsed(),[item])
        self.assertEqual(bad['probable_origin']['rdap_cross_check']['status'],'Mismatch')
        p=parsed();p['anomalies']=[{'finding':'timestamp order'}]
        self.assertLess(compute_origin_confidence(p,[item])['score'],good['score'])

    def test_candidate_always_in_budget_and_destination_never_selected(self):
        p=parsed();p['iocs']=[{'type':'ip','value':f'1.1.1.{i}'} for i in range(1,30)]+p['iocs']
        selected,_=select_indicators(p)
        self.assertEqual(selected[0]['value'],IP)
        p=parse(b'Received: by server [8.8.8.8]\n\nHello')
        self.assertIsNone(compute_origin_confidence(p,[])['candidate_ip'])

if __name__=='__main__':unittest.main()
