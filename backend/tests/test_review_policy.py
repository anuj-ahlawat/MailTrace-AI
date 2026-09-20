import copy
import unittest
from email.message import EmailMessage

from app.platform.forensics import parse
from app.platform.pipeline import risk
from app.platform.store import DEFAULTS


class ReviewPolicyTests(unittest.TestCase):
    def setUp(self):
        self.config=copy.deepcopy(DEFAULTS)
        self.parsed=parse(b'From: sender@example.com\nSubject: Rewards\n\nClaim your rewards today.')

    def model(self,label='PHISHING',probability=.7660587501958921):
        probabilities={'BENIGN':1-probability,'PHISHING':0,'BEC':0,'SPAM':0}
        probabilities[label]=probability
        return {'status':'Available','label':label,'confidence':probability,'probabilities':probabilities}

    def test_reported_bradesco_probabilities_require_high_review(self):
        ml=self.model()
        ml['probabilities']={'BENIGN':.13923866418797293,'PHISHING':.7660587501958921,'BEC':.0057921630156741975,'SPAM':.08891042260046081}
        original=copy.deepcopy(ml)
        result=risk(self.parsed,ml,[],self.config)
        self.assertEqual(result['weighted_score'],12.11)
        self.assertEqual(result['risk_score'],60)
        self.assertEqual(result['severity'],'HIGH')
        self.assertEqual(result['contributions'][-1]['points'],47.89)
        self.assertEqual(result['contributions'][-1]['category'],'model_review')
        self.assertEqual(ml,original)
        self.assertIn('analyst review required',result['review_recommendation'])

    def test_probability_boundary_and_bec(self):
        for label in ('PHISHING','BEC'):
            for probability,score in ((.699999,30),(.7,60),(.99,60)):
                with self.subTest(label=label,probability=probability):
                    result=risk(self.parsed,self.model(label,probability),[],self.config)
                    self.assertEqual(result['risk_score'],score)
                    self.assertEqual(round(sum(c['points'] for c in result['contributions'])),score)

    def test_custom_thresholds_and_disabled_ai(self):
        self.config['risk_thresholds']=[20,50,85]
        self.assertEqual(risk(self.parsed,self.model(),[],self.config)['risk_score'],50)
        self.config['risk_weights']['ai']=0
        result=risk(self.parsed,self.model(),[],self.config)
        self.assertIsNone(result['model_review'])
        self.assertEqual(result['risk_score'],0)

    def test_spam_and_missing_model_do_not_get_phishing_adjustment(self):
        self.assertIsNone(risk(self.parsed,self.model('SPAM',.9),[],self.config)['model_review'])
        result=risk(self.parsed,{'status':'Unavailable','label':None},[],self.config)
        self.assertIsNone(result['model_review'])
        self.assertIn('manual review required',result['review_recommendation'])

    def test_stronger_correlation_is_not_double_counted(self):
        parsed=parse(b'From: Microsoft <security@micr0soft-support.example>\nSubject: Urgent\n\nVerify your account immediately: https://login-micr0soft-support.example')
        result=risk(parsed,self.model(),[],self.config)
        self.assertEqual(result['risk_score'],75)
        self.assertNotIn('model_review',[c['category'] for c in result['contributions']])
        self.assertEqual(round(sum(c['points'] for c in result['contributions'])),75)

    def test_quoted_spf_address_alignment(self):
        parsed=parse(b'From: sender@example.com\nAuthentication-Results: mx.example; spf=pass smtp.mailfrom="bounce@mail.example.com"\nSubject: Hello\n\nHello')
        self.assertEqual(parsed['authentication']['spf']['domain'],'mail.example.com')
        self.assertTrue(parsed['authentication']['dmarc']['spf_alignment'])

    def test_plain_text_cannot_hide_distinct_html_from_model_or_rules(self):
        msg=EmailMessage();msg['From']='sender@example.com';msg['Subject']='Account notice'
        msg.set_content('Ordinary meeting notes.')
        msg.add_alternative('<p>Verify your account immediately</p><a href=" https://micr0soft-support.example/login ">Sign in</a>',subtype='html')
        parsed=parse(msg.as_bytes())
        self.assertIn('Ordinary meeting notes.',parsed['model_text'])
        self.assertIn('Verify your account immediately',parsed['model_text'])
        self.assertTrue(parsed['urls'])
        self.assertEqual(risk(parsed,self.model(),[],self.config)['risk_score'],75)

    def test_identical_mime_alternatives_not_duplicated(self):
        msg=EmailMessage();msg['From']='sender@example.com';msg['Subject']='Hello'
        msg.set_content('Unique message text.');msg.add_alternative('<p>Unique message text.</p>',subtype='html')
        self.assertEqual(parse(msg.as_bytes())['model_text'].count('Unique message text.'),1)

    def test_link_lookalike_is_not_counted_again_as_sender_evidence(self):
        from app.platform.forensics import lookalike
        parsed=parse(b'From: sender@example.com\nSubject: Link report\n\nhttps://micr0soft.com/')
        self.assertFalse(parsed['sender_identity']['lookalikes'])
        # Older saved analyses included every linked domain here; rescore must
        # also avoid counting that same URL evidence as sender evidence.
        parsed['sender_identity']['lookalikes']=lookalike('micr0soft.com')
        result=risk(parsed,{'status':'Unavailable','label':None},[],self.config)
        self.assertEqual(next(c['points'] for c in result['contributions'] if c['category']=='sender_identity'),0)
        self.assertGreater(next(c['points'] for c in result['contributions'] if c['category']=='url'),0)
