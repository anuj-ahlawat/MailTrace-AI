import copy
import unittest
from unittest.mock import patch

import httpx
from app.platform import intelligence as ti
from app.platform.store import DEFAULTS,now


class IntelligenceConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.config={**copy.deepcopy(DEFAULTS),'dns_enabled':True,'automatic_enrichment':True,'enabled_providers':list(ti.KEYS)}
        for p in (patch.object(ti,'db'),patch.object(ti,'settings',return_value=self.config),patch.object(ti,'secret',return_value='test-key')):
            p.start();self.addCleanup(p.stop)
        ti.db.threat_intelligence.find_one.return_value=None
        ti.db.provider_cooldowns.find_one.return_value=None

    def test_enabled_missing_optional_keys_are_visible(self):
        with patch.object(ti,'secret',return_value=''),patch.object(ti,'reverse_dns',return_value={'status':'Available'}):
            result=ti.lookup('ip','8.8.8.8')
        providers={p['provider']:p for p in result['providers']}
        self.assertIn('urlscan',providers);self.assertIn('greynoise',providers)
        self.assertEqual(providers['urlscan']['status'],'Not Configured')
        self.assertIn('API key',providers['greynoise']['reason'])

    def test_429_creates_shared_cooldown_honoring_retry_after(self):
        client=httpx.Client
        response=httpx.MockTransport(lambda req:httpx.Response(429,headers={'Retry-After':'120'}))
        with patch.object(ti,'statuses',return_value={'virustotal':'Configured'}),patch.object(ti.httpx,'Client',side_effect=lambda **kw:client(transport=response,**kw)):
            result=ti.lookup_provider('virustotal','ip','8.8.8.8')
        self.assertEqual(result['status'],'Rate Limited')
        until=ti.db.provider_cooldowns.update_one.call_args.args[1]['$set']['until']
        self.assertGreater((until-now()).total_seconds(),115)
        self.assertEqual(ti.db.threat_intelligence.update_one.call_args.args[1]['$set']['expires_at'],until)
        ti.db.provider_cooldowns.find_one.return_value={'until':until}
        with patch.object(ti,'statuses',return_value={'virustotal':'Configured'}),patch.object(ti.httpx,'Client') as network:
            blocked=ti.lookup_provider('virustotal','domain','example.com')
            network.assert_not_called()
        self.assertEqual(blocked['status'],'Rate Limited')

    def test_rotated_key_uses_a_different_cache_and_cooldown(self):
        with patch.object(ti,'statuses',return_value={'virustotal':'Configured'}),patch.object(ti.httpx,'Client') as network:
            network.return_value.__enter__.return_value.get.side_effect=httpx.ReadTimeout('test')
            ti.lookup_provider('virustotal','ip','8.8.8.8')
            first=ti.db.threat_intelligence.find_one.call_args.args[0]['_id']
            with patch.object(ti,'secret',return_value='rotated-key'):
                ti.lookup_provider('virustotal','ip','8.8.8.8')
            second=ti.db.threat_intelligence.find_one.call_args.args[0]['_id']
        self.assertNotEqual(first,second)
        self.assertNotIn('rotated-key',second)

    def test_health_distinguishes_configuration_from_last_outcome(self):
        ti.db.threat_intelligence.find_one.return_value={'data':{'status':'Rate Limited','timestamp':'2026-09-20T00:00:00Z','reason':'Quota reached','query':'private-indicator','result':{'private':'report'}}}
        with patch.object(ti,'statuses',return_value={'virustotal':'Configured','urlscan':'Not Configured'}):
            health=ti.provider_health()
        self.assertTrue(health['automatic_enrichment']);self.assertTrue(health['dns_enabled'])
        self.assertEqual(health['providers']['virustotal']['last_lookup_status'],'Rate Limited')
        self.assertEqual(health['providers']['urlscan']['configuration'],'Not Configured')
        self.assertNotIn('private-indicator',str(health));self.assertNotIn('report',str(health))

    def test_timeout_has_an_actionable_reason_and_is_cached(self):
        with patch.object(ti,'statuses',return_value={'virustotal':'Configured'}),patch.object(ti.httpx,'Client') as network:
            network.return_value.__enter__.return_value.get.side_effect=httpx.ReadTimeout('test')
            result=ti.lookup_provider('virustotal','domain','example.com')
        self.assertEqual(result['status'],'Unavailable');self.assertIn('timed out',result['reason'])
        ti.db.threat_intelligence.update_one.assert_called_once()

    def test_reserved_test_domains_never_query_public_providers(self):
        with patch.object(ti.httpx,'Client') as network:
            for kind,value in [('domain','micr0soft-support.example'),('url','https://login.invalid/path'),('domain','host.local'),('domain','HOST.EXAMPLE.')]:
                result=ti.lookup_provider('virustotal',kind,value)
                self.assertEqual(result['status'],'Not Applicable')
                self.assertIn('Reserved',result['reason'])
            network.assert_not_called()

    def test_http_400_is_an_indicator_error_not_provider_outage(self):
        client=httpx.Client
        with patch.object(ti,'statuses',return_value={'virustotal':'Configured'}),patch.object(ti.httpx,'Client',side_effect=lambda **kw:client(transport=httpx.MockTransport(lambda req:httpx.Response(400)),**kw)):
            result=ti.lookup_provider('virustotal','domain','example.com')
        self.assertEqual(result['status'],'Invalid Indicator');self.assertEqual(result['http_status'],400)
