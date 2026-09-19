"""Regression coverage for missing relay evidence and correlated phishing risk."""
import copy
import unittest
from pathlib import Path

from app.platform.forensics import parse, registered, lookalike
from app.platform.pipeline import risk, geolocation_summary, select_indicators
from app.platform.store import DEFAULTS

FIXTURES=Path(__file__).parent/'fixtures'
UNKNOWN={'status':'Model unavailable','label':None,'confidence':None}

class ScoringAndLocation(unittest.TestCase):
    def setUp(self):
        self.raw=(FIXTURES/'phishing_no_received.eml').read_bytes()
        self.parsed=parse(self.raw)
        self.config=copy.deepcopy(DEFAULTS)

    def score(self,parsed=None,ml=None):
        return risk(parsed or self.parsed,ml or UNKNOWN,[],self.config)

    def test_unknown_suffix_does_not_hide_distinct_domains(self):
        self.assertNotEqual(registered('micr0soft-support.example'),registered('login-micr0soft-support.example'))
        self.assertEqual(registered('login.microsoft.com'),'microsoft.com')
        self.assertTrue(lookalike('login-micr0soft-support.example'))
        self.assertFalse(lookalike('login.microsoft.com'))

    def test_missing_received_is_missing_evidence_not_missing_database(self):
        result=geolocation_summary(self.parsed,[])
        self.assertEqual(result['status'],'Not Observable')
        self.assertIn('no sending IP',result['reason'])
        self.assertIsNone(self.parsed['origin']['candidate_ip'])
        self.assertEqual(result['observed_public_ips'],[])

    def test_phishing_detected_without_apis_or_model(self):
        result=self.score()
        self.assertEqual(result['verdict'],'PHISHING')
        self.assertGreaterEqual(result['risk_score'],60)
        self.assertEqual(result['severity'],'HIGH')
        self.assertIsNone(result['confidence'])
        self.assertTrue(result['correlation_rules'])
        self.assertEqual(round(sum(c['points'] for c in result['contributions'])),result['risk_score'])

    def test_model_disagreement_preserves_real_probabilities(self):
        ml={'status':'Available','label':'BENIGN','confidence':.9,'probabilities':{'BENIGN':.9,'PHISHING':.05,'BEC':.03,'SPAM':.02}}
        original=copy.deepcopy(ml);result=self.score(ml=ml)
        self.assertEqual(result['verdict'],'PHISHING')
        self.assertIsNone(result['confidence'])
        self.assertEqual(ml,original)

    def test_legitimate_account_notice_does_not_trigger_phishing_rule(self):
        raw=self.raw.replace(b'micr0soft-support.example',b'microsoft.com').replace(b'login-microsoft.com',b'login.microsoft.com')
        result=self.score(parse(raw))
        self.assertLess(result['risk_score'],30)
        self.assertFalse(result['correlation_rules'])

    def test_isolated_identity_flag_does_not_establish_phishing(self):
        result=self.score(parse((FIXTURES/'impersonation.eml').read_bytes()))
        self.assertFalse(result['correlation_rules'])
        self.assertLess(result['risk_score'],60)

    def test_repeated_weak_links_do_not_amplify_risk(self):
        raw=b'From: sender@example.com\nSubject: Links\n\n'
        one=parse(raw+b'http://example.com/account/1')
        many=parse(raw+b'\n'.join(f'http://example.com/account/{i}'.encode() for i in range(100)))
        self.assertEqual(self.score(one)['risk_score'],self.score(many)['risk_score'])

    def test_bec_requires_payment_change_pressure_and_secrecy(self):
        raw=(FIXTURES/'bec.eml').read_bytes()
        result=self.score(parse(raw))
        self.assertEqual(result['verdict'],'BEC')
        self.assertGreaterEqual(result['risk_score'],60)
        normal=b'From: finance@example.com\nSubject: Bank details\n\nOur bank details are on the new invoice. Please pay by the agreed due date.'
        self.assertFalse(self.score(parse(normal))['correlation_rules'])

    def test_zero_weight_disables_associated_correlation(self):
        self.config['risk_weights']['url']=0
        self.assertFalse(self.score()['correlation_rules'])

    def test_geoip_states_are_distinguished(self):
        parsed=parse((FIXTURES/'benign.eml').read_bytes())
        for state,expected in [('Disabled','Disabled'),('Not Configured','Not Configured'),('Unavailable','Unavailable'),('Not Found','Not Found')]:
            rows=[{'type':'ip','providers':[{'provider':'geoip','query':'8.8.8.8','status':state,'result':None}]}]
            self.assertEqual(geolocation_summary(parsed,rows)['status'],expected)
        rows[0]['providers'][0].update(status='Available',result={'asn':15169})
        self.assertEqual(geolocation_summary(parsed,rows)['status'],'No Coordinates')
        rows[0]['providers'][0]['result'].update(latitude=0,longitude=0)
        self.assertEqual(geolocation_summary(parsed,rows)['status'],'Available')

    def test_private_relay_cannot_produce_public_location(self):
        parsed=parse(b'Received: from local [10.0.0.1] by server; Fri, 18 Sep 2026 10:00:00 +0000\n'+self.raw)
        self.assertEqual(geolocation_summary(parsed,[])['status'],'Not Observable')

    def test_ip_in_link_is_not_sender_origin(self):
        parsed=parse(self.raw.replace(b'login-micr0soft-support.example',b'8.8.8.8'))
        self.assertIsNone(parsed['origin']['candidate_ip'])
        self.assertIn({'type':'ip','value':'8.8.8.8','source':'URL hostname (not sender origin)'},parsed['iocs'])

    def test_many_domains_cannot_starve_geoip_lookup(self):
        parsed={'iocs':[{'type':'domain','value':f'host{i}.example.com'} for i in range(40)]+[{'type':'ip','value':'8.8.8.8'}]}
        selected,omitted=select_indicators(parsed)
        self.assertIn({'type':'ip','value':'8.8.8.8'},selected)
        self.assertEqual(len(selected),25)
        self.assertEqual(omitted,16)

if __name__=='__main__':unittest.main()
