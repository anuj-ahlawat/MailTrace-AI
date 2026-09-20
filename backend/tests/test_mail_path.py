"""IP provenance and failure isolation; mocked provider values stay in tests."""
import copy
import os
import unittest
from unittest.mock import patch,MagicMock
from types import SimpleNamespace
import httpx

from app.platform.forensics import parse,classify_ip,ip_kind
from app.platform.intelligence import enrich_mail_path,local_geoip,coordinates_available
from app.platform import intelligence as ti

def message(headers='',body='Planning meeting tomorrow.'):
    return (headers+'From: sender@example.com\nTo: reader@example.com\nSubject: Planning\n\n'+body).encode()

def provider(ip):
    return {'provider':'geoip','query':ip,'status':'Available','result':{'country':'Fixture country','latitude':10,'longitude':20,'asn':64500},'source':'Isolated test fixture'}

class MailPath(unittest.TestCase):
    def test_all_required_address_classes(self):
        cases={'8.8.8.8':'Public','2606:4700:4700::1111':'Public','10.0.0.1':'Private','172.16.0.1':'Private',
            '192.168.1.1':'Private','127.0.0.1':'Loopback','169.254.1.1':'Link-local','::1':'Loopback',
            'fe80::1':'Link-local','fd00::1':'Private','203.0.113.10':'Reserved','2001:db8::1':'Reserved',
            '224.0.0.1':'Multicast','ff02::1':'Multicast','0.0.0.0':'Reserved','100.64.0.1':'Reserved',
            '999.8.8.8':'Invalid','2001:db8:::1':'Invalid','not-an-ip':'Invalid'}
        for ip,expected in cases.items():
            with self.subTest(ip=ip):
                info=classify_ip(ip);self.assertEqual(info['classification'],expected)
                self.assertEqual(info['public'],expected=='Public')

    def test_ipv4_mapped_ipv6_and_scope(self):
        for ip,kind,lookup in [('::ffff:8.8.8.8','Public','8.8.8.8'),('::ffff:10.0.0.1','Private','10.0.0.1'),
            ('::ffff:127.0.0.1','Loopback','127.0.0.1'),('::ffff:203.0.113.10','Reserved','203.0.113.10'),('fe80::1%eth0','Link-local','fe80::1')]:
            info=classify_ip(ip);self.assertEqual(info['classification'],kind);self.assertEqual(info['lookup_ip'],lookup)
        self.assertEqual(ip_kind('::ffff:8.8.8.8'),'Public')

    def test_all_received_headers_source_and_destination(self):
        parsed=parse(message('Received: from middle ([IPv6:2606:4700:4700::1111]) by final [1.1.1.1]; Fri, 18 Sep 2026 10:01:00 +0000\nReceived: from local [10.0.0.1] by middle [8.8.8.8]; Fri, 18 Sep 2026 10:00:00 +0000\n'))
        self.assertEqual(len(parsed['received_chain']),2)
        self.assertEqual(parsed['received_chain'][0]['source_server'],'local')
        self.assertEqual(parsed['received_chain'][1]['destination_server'],'final')
        self.assertEqual({i['value'] for i in parsed['iocs'] if i['type']=='ip'},{'10.0.0.1','8.8.8.8','1.1.1.1','2606:4700:4700::1111'})
        self.assertEqual(parsed['origin']['candidate_ip'],'2606:4700:4700::1111')
        self.assertIsNone(parsed['origin']['ip'])
        self.assertTrue(all(h['raw'] and h['timestamp'] for h in parsed['mail_path']))

    def test_common_header_formats_and_invalid_literals(self):
        headers='Received: from mail.example.com (mail.example.com [8.8.8.8])\nReceived: from [203.0.113.10] by server\nReceived: from server ([2001:db8::1])\nReceived: by server with SMTP; Fri, 18 Sep 2026 10:00:00 +0000\nReceived: from bad [999.0.0.1] ([IPv6:not-valid])\n'
        parsed=parse(message(headers))
        with patch.object(ti,'lookup_provider',side_effect=lambda p,k,ip:provider(ip)):rows=enrich_mail_path(parsed,[])
        self.assertEqual(len(parsed['mail_path']),5)
        invalid=[r for r in rows if r['type']=='invalid']
        self.assertEqual(len(invalid),2)
        self.assertTrue(all(r['location_reason']=='Invalid IP address' for r in invalid))
        self.assertNotIn('10:00:00',{r['ip'] for r in rows})

    def test_body_and_hostname_fragments_are_not_ip_headers(self):
        parsed=parse(message('Received: from mail8.8.8.8.example by server\n','8.8.8.8 and 2606:4700:4700::1111 are examples.'))
        self.assertFalse(parsed['ip_observations']);self.assertFalse(enrich_mail_path(parsed,[]))
        self.assertIsNone(parsed['origin']['candidate_ip'])

    def test_no_received_and_ip_bearing_headers(self):
        parsed=parse(message());self.assertEqual(parsed['mail_path'],[]);self.assertEqual(enrich_mail_path(parsed,[]),[])
        parsed=parse(message('X-Originating-IP: [10.0.0.5]\nX-Sender-IP: [::1]\nReceived-SPF: pass; client-ip=192.168.1.1; envelope-from=test@example.com\n'))
        self.assertEqual(len(parsed['ip_observations']),3);self.assertIsNone(parsed['origin']['candidate_ip'])
        with patch.object(ti,'lookup_provider') as call:
            rows=enrich_mail_path(parsed,[]);call.assert_not_called()
        self.assertTrue(all(not r['location_available'] for r in rows))

    def test_repeated_and_mapped_ips_are_queried_once(self):
        parsed=parse(message('Received: from a [8.8.8.8] by b [8.8.8.8]\nReceived: from b [::ffff:8.8.8.8] by c\n'))
        with patch.object(ti,'lookup_provider',side_effect=lambda p,k,ip:provider(ip)) as call:
            rows=enrich_mail_path(parsed,[])
        self.assertEqual(call.call_count,1);self.assertEqual(len(rows),3)
        self.assertEqual({r['role'] for r in rows},{'source','destination'})

    def test_every_public_ip_is_queried_beyond_reputation_budget(self):
        parsed=parse(message(''.join(f'Received: from host [8.8.8.{i}] by server\n' for i in range(1,31))))
        enrichment=[]
        with patch.object(ti,'lookup_provider',side_effect=lambda p,k,ip:provider(ip)) as call:
            rows=enrich_mail_path(parsed,enrichment)
        self.assertEqual(call.call_count,30);self.assertEqual(len(rows),30);self.assertEqual(len(enrichment),30)
        self.assertTrue(all(c.args[0]=='geoip' for c in call.call_args_list))

    def test_existing_lookup_reused_and_failure_isolated(self):
        parsed=parse(message('Received: from a [8.8.8.8] by b [1.1.1.1]\nReceived: from c [9.9.9.9] by b\n'))
        enrichment=[{'type':'ip','query':'8.8.8.8','providers':[provider('8.8.8.8')]}]
        def answer(p,k,ip):
            if ip=='1.1.1.1':raise TimeoutError('fixture timeout')
            return provider(ip)
        with patch.object(ti,'lookup_provider',side_effect=answer) as call:rows=enrich_mail_path(parsed,enrichment)
        self.assertEqual(call.call_count,2)
        failed=next(r for r in rows if r['ip']=='1.1.1.1')
        self.assertFalse(failed['location_available']);self.assertEqual(failed['location_reason'],'GeoIP data unavailable')
        self.assertEqual(sum(r['location_available'] for r in rows),2)

    def test_empty_missing_rate_limit_and_credential_failures(self):
        for state,result in [('Available',{}),('Not Found',None),('Rate Limited',None),('Invalid Credentials',None),('Unavailable',None),('Disabled',None)]:
            parsed=parse(message('Received: from a [8.8.8.8] by b\n'))
            with patch.object(ti,'lookup_provider',return_value={'provider':'geoip','status':state,'result':result}):row=enrich_mail_path(parsed,[])[0]
            self.assertFalse(row['location_available']);self.assertTrue(row['location_reason'])
        self.assertFalse(coordinates_available({'latitude':float('nan'),'longitude':20}))
        self.assertFalse(coordinates_available({'latitude':91,'longitude':20}))
        self.assertTrue(coordinates_available({'latitude':0,'longitude':0}))

    def test_non_public_never_opens_database_or_http(self):
        with patch('geoip2.database.Reader') as reader,patch.object(ti.httpx,'Client') as http:
            for ip in ['10.0.0.1','127.0.0.1','fe80::1','::1','ff02::1','2001:db8::1','::ffff:10.0.0.1','invalid']:
                self.assertIsNone(local_geoip(ip)['result'])
            reader.assert_not_called();http.assert_not_called()

    def test_existing_persistent_cache_is_used(self):
        cached=provider('8.8.8.8')
        with patch.object(ti,'statuses',return_value={'geoip':'Configured'}),patch.object(ti,'db') as db,patch.object(ti,'local_geoip') as reader:
            db.threat_intelligence.find_one.return_value={'data':cached}
            result=ti.lookup_provider('geoip','ip','8.8.8.8')
            self.assertTrue(result['cached']);reader.assert_not_called()
            ti.lookup_provider('geoip','ip','::ffff:8.8.8.8')
            keys=[c.args[0]['_id'] for c in db.threat_intelligence.find_one.call_args_list]
            self.assertEqual(keys[0],keys[1])

    def test_destination_only_ip_is_not_origin(self):
        parsed=parse(message('Received: by receiving.example [8.8.8.8] with SMTP; Fri, 18 Sep 2026 10:00:00 +0000\n'))
        self.assertIsNone(parsed['origin']['candidate_ip']);self.assertEqual(parsed['origin']['candidate_ips'],[])
        self.assertEqual(parsed['ip_observations'][0]['role'],'destination')

    def test_existing_reputation_adapters_and_error_statuses(self):
        client=httpx.Client
        payloads={'virustotal':{'data':{'attributes':{'last_analysis_stats':{'malicious':0}}}},'abuseipdb':{'data':{'abuseConfidenceScore':0}},'urlscan':{'results':[]},'greynoise':{'ip':'8.8.8.8','noise':False,'riot':True}}
        with patch.object(ti,'db') as db,patch.object(ti,'statuses',return_value={p:'Configured' for p in payloads}),patch.object(ti,'secret',return_value='test-only-key'):
            db.threat_intelligence.find_one.return_value=None
            for name,payload in payloads.items():
                for code in [200,401,429,500]:
                    with self.subTest(provider=name,code=code),patch.object(ti.httpx,'Client',side_effect=lambda **kw:client(transport=httpx.MockTransport(lambda req:httpx.Response(code,json=payload)),**kw)):
                        result=ti.lookup_provider(name,'ip','8.8.8.8')
                        self.assertEqual(result['status'],{200:'Available',401:'Invalid Credentials',429:'Rate Limited',500:'Unavailable'}[code])
                        self.assertNotIn('test-only-key',str(result))

if __name__=='__main__':unittest.main()
