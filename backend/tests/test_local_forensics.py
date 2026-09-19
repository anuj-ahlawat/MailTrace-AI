"""Regression checks use synthetic fixtures and isolated provider transports only."""
import base64
import copy
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import dkim
import dns.resolver
import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.platform import intelligence as ti
from app.platform.authentication import enrich_authentication, verify_dkim
from app.platform.forensics import parse, analyze_url, classify_ip
from app.platform.pipeline import risk
from app.platform.store import DEFAULTS

FIXTURES = Path(__file__).parent / 'fixtures'
UNAVAILABLE_ML = {'status': 'Model unavailable', 'label': None, 'confidence': None}


class LocalForensics(unittest.TestCase):
    def test_all_requested_email_scenarios(self):
        for name in ('benign', 'phishing', 'bec', 'impersonation', 'suspicious_urls'):
            with self.subTest(name=name):
                original = (FIXTURES / (name + '.eml')).read_bytes()
                digest = hashlib.sha256(original).hexdigest()
                parsed = parse(original)
                self.assertTrue(parsed['sender'])
                self.assertEqual(parsed['origin']['candidate_ip'], '8.8.8.8')
                self.assertIsNone(parsed['origin']['ip'])
                self.assertEqual(parsed['authentication']['spf']['reported_result'], 'NEUTRAL')
                self.assertTrue(parsed['mime']['parts'])
                self.assertEqual(digest, hashlib.sha256(original).hexdigest())
                score = risk(parsed, UNAVAILABLE_ML, [], copy.deepcopy(DEFAULTS))
                self.assertIn(score['verdict'], ('Unknown','PHISHING','BEC'))
                self.assertLessEqual(score['risk_score'], 100)
        phishing = parse((FIXTURES / 'phishing.eml').read_bytes())
        self.assertIn('display_href_mismatch', {s['type'] for u in phishing['urls'] for s in u['signals']})
        self.assertTrue(phishing['html_body'])
        self.assertTrue(parse((FIXTURES / 'impersonation.eml').read_bytes())['sender_identity']['display_name_mismatch'])
        attachment = parse((FIXTURES / 'benign.eml').read_bytes())['attachments'][0]
        self.assertEqual(attachment['sha256'], hashlib.sha256(b'Planning agenda\n').hexdigest())

    def test_url_indicators_are_evidence_not_verdicts(self):
        url = analyze_url('http://xn--pple-43d.a.b.c.example.xyz/login?next=https%3A%2F%2Fevil.example&x=' + 'a'*260, 'https://apple.com', 'example.com')
        types = {s['type'] for s in url['signals']}
        self.assertTrue({'unencrypted_http', 'internationalized_domain', 'long_url', 'subdomains', 'review_tld', 'credential_keywords', 'redirect_parameter', 'encoding', 'display_href_mismatch'} <= types)
        self.assertFalse(url['visited'])
        self.assertFalse(url['redirect_parameters'][0]['followed'])
        self.assertNotIn('verdict', url)
        self.assertIn('display_href_mismatch', {s['type'] for s in analyze_url('https://bad.example', 'example.com')['signals']})

    def test_ip_classification(self):
        for value, expected in [('8.8.8.8','Public'), ('10.0.0.1','Private'), ('127.0.0.1','Loopback'), ('240.0.0.1','Reserved'), ('no-ip','Invalid'), ('::1','Loopback')]:
            self.assertEqual(classify_ip(value)['classification'], expected)

    def test_invalid_email_rejected(self):
        with self.assertRaises(ValueError): parse(b'This is not an RFC email')

    def test_one_provider_does_not_dominate_risk(self):
        parsed = parse((FIXTURES/'benign.eml').read_bytes())
        provider = {'provider':'virustotal','status':'Available','result':{'data':{'attributes':{'last_analysis_stats':{'malicious':1,'harmless':89}}}}}
        data = [{'query':'example.com','providers':[provider]} for _ in range(25)]
        scored = risk(parsed, UNAVAILABLE_ML, data, copy.deepcopy(DEFAULTS))
        intel = next(c for c in scored['contributions'] if c['category']=='intelligence')
        self.assertLess(intel['points'], 1)
        self.assertEqual(scored['verdict'], 'Unknown')
        provider['result']['data']['attributes']['last_analysis_stats']['malicious'] = 80
        stronger = risk(parsed, UNAVAILABLE_ML, data, copy.deepcopy(DEFAULTS))
        self.assertLessEqual(next(c for c in stronger['contributions'] if c['category']=='intelligence')['points'],7)
        self.assertEqual(ti.malicious_signals([{'query':'8.8.8.8','providers':[{'provider':'abuseipdb','status':'Available','result':{'data':{'abuseConfidenceScore':99,'totalReports':1}}}]}]), [])


class Authentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        private = key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
        public = key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.public_record = 'v=DKIM1; k=rsa; p=' + base64.b64encode(public).decode()
        raw = (FIXTURES/'benign.eml').read_bytes()
        cls.signed = dkim.sign(raw,b'local',b'example.com',private,include_headers=[b'from',b'to',b'subject',b'date']) + raw

    def answer(self, name, kind):
        values = [self.public_record] if '._domainkey.' in name else ['v=DMARC1; p=reject; adkim=s'] if name.startswith('_dmarc.') else ['v=spf1 -all']
        return {'query':name,'record_type':kind,'status':'Available','values':values,'source':'Isolated DNS fixture'}

    def test_genuine_dkim_signature_and_tamper(self):
        with patch('app.platform.authentication.dns_query', side_effect=self.answer):
            parsed = parse(self.signed)
            result = enrich_authentication(self.signed, parsed, {'dns_enabled':True})
            self.assertEqual(result['dkim']['local_verification']['status'], 'PASS')
            self.assertEqual(result['dmarc']['local_assessment']['status'], 'PASS')
            self.assertEqual(result['spf']['dns_policy']['verification_status'], 'Unknown')
            tampered = self.signed.replace(b'Weekly planning',b'Changed subject')
            self.assertEqual(verify_dkim(tampered,parse(tampered),True)['status'],'FAIL')

    def test_dkim_dns_failure_not_fabricated_fail(self):
        with patch('app.platform.authentication.dns_query', return_value={'status':'Unavailable','values':[]}):
            result = verify_dkim(self.signed, parse(self.signed), True)
            self.assertEqual(result['status'],'Unavailable')
        self.assertEqual(verify_dkim(self.signed, parse(self.signed), False)['status'],'Not Configured')

    def test_unverified_headers_cannot_pass_dmarc(self):
        raw = b'Authentication-Results: untrusted; spf=pass; dkim=pass; dmarc=pass\r\n' + (FIXTURES/'benign.eml').read_bytes()
        with patch('app.platform.authentication.dns_query', side_effect=self.answer):
            result = enrich_authentication(raw,parse(raw),{'dns_enabled':True})
        self.assertEqual(result['dmarc']['reported_result'],'PASS')
        self.assertEqual(result['dmarc']['local_assessment']['status'],'Unknown')

    def test_dns_txt_chunks_spf_and_timeout(self):
        class Answer(list):
            rrset=SimpleNamespace(ttl=300)
        resolver=MagicMock();resolver.resolve.return_value=Answer([SimpleNamespace(strings=(b'v=spf1 ',b'-all'))])
        self.assertEqual(ti.dns_query('example.com','TXT',resolver)['values'],['v=spf1 -all'])
        resolver.resolve.side_effect=dns.resolver.LifetimeTimeout()
        self.assertEqual(ti.dns_query('example.com','TXT',resolver)['status'],'Unavailable')
        with patch.object(ti,'settings',return_value={'dns_enabled':True}), patch.object(ti.dns.resolver,'Resolver',return_value=resolver):
            self.assertEqual(ti.domain_dns('example.com')['status'],'Unavailable')


class Providers(unittest.TestCase):
    def setUp(self):
        self.config={**copy.deepcopy(DEFAULTS),'enabled_providers':list(ti.CORE_PROVIDERS)}
        self.patches=[patch.object(ti,'settings',return_value=self.config),patch.object(ti,'db'),patch.object(ti,'secret',return_value='')]
        for p in self.patches:p.start();self.addCleanup(p.stop)
        ti.db.threat_intelligence.find_one.return_value=None

    def test_missing_keys_and_geoip_never_create_reputation(self):
        with patch.dict(os.environ,{'GEOIP_CITY_DB':'','GEOIP_ASN_DB':''}), patch.object(ti.httpx,'Client') as client:
            for provider in ('virustotal','abuseipdb','geoip'):
                result=ti.lookup_provider(provider,'ip','8.8.8.8')
                self.assertEqual(result['status'],'Not Configured');self.assertIsNone(result['result'])
            client.assert_not_called()
        result=ti.local_geoip('8.8.8.8') if not os.getenv('GEOIP_CITY_DB') else None
        if result:self.assertIsNone(result['result'])

    def test_rate_limits_errors_and_valid_abuse_summary(self):
        original_client=httpx.Client
        with patch.object(ti,'statuses',return_value={'virustotal':'Configured','abuseipdb':'Configured'}):
            for status in (401,403,429,500):
                transport=httpx.MockTransport(lambda request:httpx.Response(status,json={'error':'fixture'}))
                with patch.object(ti.httpx,'Client',side_effect=lambda **kw:original_client(transport=transport,**kw)):
                    result=ti.lookup_provider('virustotal','domain','example.com')
                    self.assertNotEqual(result['status'],'Available');self.assertIsNone(result['result'])
            payload={'data':{'abuseConfidenceScore':85,'totalReports':12,'countryCode':'US','isp':'Isolated fixture','lastReportedAt':'2026-09-18T00:00:00Z'}}
            with patch.object(ti.httpx,'Client',side_effect=lambda **kw:original_client(transport=httpx.MockTransport(lambda req:httpx.Response(200,json=payload)),**kw)):
                result=ti.lookup_provider('abuseipdb','ip','8.8.8.8')
                self.assertEqual(result['summary']['totalReports'],12)
                self.assertEqual(result['result'],payload)

    def test_malformed_provider_payload_is_unavailable(self):
        original_client=httpx.Client
        with patch.object(ti,'statuses',return_value={'virustotal':'Configured','abuseipdb':'Configured'}):
            for provider in ('virustotal','abuseipdb'):
                with patch.object(ti.httpx,'Client',side_effect=lambda **kw:original_client(transport=httpx.MockTransport(lambda req:httpx.Response(200,json={'data':'invalid'})),**kw)):
                    result=ti.lookup_provider(provider,'ip','8.8.8.8')
                    self.assertEqual(result['status'],'Unavailable');self.assertIsNone(result['result'])
        self.assertEqual(ti.malicious_signals([{'query':'example.com','providers':[{'provider':'virustotal','status':'Available','result':{'data':[]}}]}]),[])

    def test_invalid_resolver_configuration_is_unavailable(self):
        with patch.object(ti.dns.resolver,'Resolver',side_effect=OSError('No resolver configuration')):
            self.assertEqual(ti.dns_query('example.com','TXT')['status'],'Unavailable')

    def test_provider_timeout_is_isolated(self):
        with patch.object(ti,'statuses',return_value={'virustotal':'Configured'}), patch.object(ti.httpx,'Client') as client:
            client.return_value.__enter__.return_value.get.side_effect=httpx.ReadTimeout('fixture timeout')
            result=ti.lookup_provider('virustotal','domain','example.com')
            self.assertEqual(result['status'],'Unavailable');self.assertIsNone(result['result'])

    def test_private_ips_never_query_abuseipdb(self):
        with patch.object(ti.httpx,'Client') as client:
            result=ti.lookup_provider('abuseipdb','ip','127.0.0.1')
            self.assertEqual(result['status'],'Not Applicable');client.assert_not_called()

    def test_unreadable_geoip_database_is_unavailable(self):
        with tempfile.NamedTemporaryFile() as file:
            file.write(b'not a MaxMind database');file.flush()
            with patch.dict(os.environ,{'GEOIP_CITY_DB':file.name,'GEOIP_ASN_DB':''}):
                result=ti.local_geoip('8.8.8.8')
                self.assertEqual(result['status'],'Unavailable');self.assertIsNone(result['result'])

    def test_asn_only_does_not_fabricate_coordinates(self):
        with tempfile.NamedTemporaryFile() as file, patch.dict(os.environ,{'GEOIP_CITY_DB':'','GEOIP_ASN_DB':''}):
            os.environ['GEOIP_ASN_DB']=file.name
            with patch('geoip2.database.Reader') as reader:
                reader.return_value.__enter__.return_value.asn.return_value=SimpleNamespace(autonomous_system_number=64500,autonomous_system_organization='Isolated fixture')
                reader.return_value.__enter__.return_value.metadata.return_value=SimpleNamespace(build_epoch=1)
                result=ti.local_geoip('8.8.8.8')
                self.assertEqual(result['status'],'Available');self.assertEqual(result['result']['asn'],64500)
                self.assertNotIn('latitude',result['result']);self.assertEqual(result['databases']['city'],'Not Configured')

    def test_local_geoip_independent_of_external_toggle(self):
        with patch.object(ti,'lookup_provider',return_value={'provider':'geoip','status':'Not Configured','result':None}) as provider:
            row=ti.lookup('ip','8.8.8.8',allow_external=False)
            provider.assert_called_once_with('geoip','ip','8.8.8.8')
            self.assertTrue(all(p['result'] is None for p in row['providers']))

    def test_all_optional_enrichment_disabled(self):
        self.config.update(enabled_providers=[],dns_enabled=False,automatic_enrichment=False)
        with patch.object(ti.httpx,'Client') as client:
            row=ti.lookup('domain','example.com',allow_external=False)
            self.assertEqual(row['dns']['status'],'Not Configured')
            self.assertTrue(all(p['result'] is None for p in row['providers']))
            client.assert_not_called()


if __name__=='__main__':unittest.main()
