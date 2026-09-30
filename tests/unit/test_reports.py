"""Report regression tests: bounded PDF, correct semantics, lossless evidence."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from cryptography.fernet import Fernet

import backend.reporting.report_generator as reports
from backend.reporting.pdf_exporter import View, provider_summary, short_url, score_severity


def snapshot():
    return {
        'report_id': 'report-test', 'case_id': 'case-test', 'title': 'Report test',
        'generated_at': '2026-09-23T12:00:00+00:00', 'generated_by': 'analyst@example.test',
        'evidence_hashes': ['a' * 64],
        'sections': {
            'Case Information': {'status': 'OPEN'}, 'Executive Summary': {'emails_examined': 1},
            'Email Information': [{'sender': '<b>untrusted</b>@example.test', 'recipient': ['one@example.test', 'two@example.test'], 'subject': 'Português: você tem pontos'}],
            'Risk Score': [{'email_id': 'e1', 'score': 60, 'severity': 'HIGH', 'scoring_policy': {'thresholds': [20, 50, 85]}, 'contributions': [
                {'category': 'ai', 'maximum_points': 15, 'points': 12},
                {'category': 'model_review', 'maximum_points': 88, 'points': 48},
            ], 'component_scores': {'ml': {'score': 99, 'weight': .4}}}],
            'Threat Verdict': [{'email_id': 'e1', 'verdict': 'PHISHING', 'source': 'ML inference'}],
            'AI Analysis': [{'status': 'Available', 'label': 'PHISHING', 'confidence': .8, 'probabilities': {'BENIGN': .2, 'PHISHING': .8}, 'explanation': [{'term': '<img src="bad"/>', 'logit_contribution': 1}]}],
            'DKIM Analysis': [{'reported_result': 'PASS', 'local_verification': {'status': 'FAIL'}}],
            'SPF Analysis': [{'reported_result': 'PASS'}], 'DMARC Analysis': [{'spf_alignment': True}],
            'Origin IP': [{'value': {'candidate_ip': '192.0.2.1'}}],
            'Origin Confidence': [{'value': {'score': 30, 'level': 'LOW', 'probable_origin': {'ip': '192.0.2.1'}}}],
        },
    }


@unittest.skipUnless(shutil.which('pdfinfo') and shutil.which('pdftotext'), 'Poppler required for PDF validation')
class PDFTests(unittest.TestCase):
    def extract(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.pdf'
            path.write_bytes(data)
            info = subprocess.check_output(['pdfinfo', str(path)], text=True)
            self.assertEqual(int(re.search(r'Pages:\s+(\d+)', info).group(1)), 10)
            return subprocess.check_output(['pdftotext', '-layout', str(path), '-'], text=True)

    def test_empty_snapshot_is_ten_pages_not_fake_zero_risk(self):
        value = self.extract(reports.pdf_bytes({}))
        self.assertIn('Not Available', value)
        self.assertNotIn('RISK SCORE: 0', value)
        self.assertIn('Verification unavailable', value)
        self.assertIn('UNKNOWN', value)

    def test_network_origin_fields_disclaimer_and_unknown_privacy(self):
        from backend.intelligence.providers import ORIGIN_DISCLAIMER
        from backend.core.origin_confidence import compute_origin_confidence
        from tests.unit.test_ipinfo_origin import parsed, CORE, row
        from backend.intelligence.providers import normalize_ipinfo
        s=snapshot()
        assessment=compute_origin_confidence(parsed(),[{'type':'ip','query':'8.8.8.8','providers':[row('ipinfo',normalize_ipinfo(CORE,'8.8.8.8'))]}])
        s['sections']['Origin Confidence']=[{'value':assessment}]
        content=' '.join(self.extract(reports.pdf_bytes(s)).split())
        for expected in ('Probable Network Origin','IPinfo','Google / Gmail','VPN / Proxy / Tor','Unknown / not supplied',ORIGIN_DISCLAIMER):
            self.assertIn(expected,content)
        self.assertNotIn('Exact Sender Location',content)

    def test_zero_score_custom_thresholds_and_full_hash(self):
        s = snapshot()
        s['sections']['Risk Score'][0].update(score=0, severity='LOW', contributions=[])
        value = self.extract(reports.pdf_bytes(s))
        self.assertIn('RISK SCORE: 0 / 100', value)
        self.assertIn('CRITICAL 85-100', value)
        self.assertIn('a' * 64, value)
        self.assertIn('report-report-test.json', value)
        self.assertIn('one@example.test, two@example.test', value)
        self.assertIn('Português', value)

    def test_reported_authentication_and_local_result_remain_separate(self):
        value = self.extract(reports.pdf_bytes(snapshot()))
        self.assertIn('REPORTED - SPF: PASS; DKIM: PASS', value)
        self.assertIn('LOCAL CHECK - DKIM: FAIL', value)
        self.assertIn('Verification unavailable', value)
        self.assertIn('ALIGNED (observed)', value)
        self.assertIn('<b>untrusted</b>', value)

    def test_recorded_contributions_take_precedence_over_diagnostic_components(self):
        value = self.extract(reports.pdf_bytes(snapshot()))
        self.assertIn('Contribution sum: 60.00', value)
        self.assertIn('Model review adjustment', value)
        self.assertNotIn('39.6', value)

    def test_large_hostile_evidence_is_bounded_and_snapshot_unchanged(self):
        s = snapshot()
        long = 'x' * 12000
        sec = s['sections']
        sec['Email Information'][0].update(subject='<b>' + long, sender=long, recipient=[long] * 50)
        sec['Received Path'] = [{'value': [{'hop': i, 'hostname': long, 'parsed_ip': '192.0.2.1', 'raw': 'RAW-HEADER-MARKER' + long, 'confidence': long} for i in range(200)]}]
        sec['Header Forensics'] = [{'anomalies': [{'reason': long}] * 500}]
        sec['URL Analysis'] = [{'value': [{'domain': 'example.test', 'original_url': 'https://example.test/' + str(i) + '?tracking=' + long, 'signals': [{'type': 'URL signal'}]} for i in range(500)]}]
        sec['Attachment Analysis'] = [{'value': [{'filename': long + str(i), 'sha256': str(i).zfill(64), 'flags': ['executable']} for i in range(100)]}]
        sec['Threat Intelligence'] = [{'results': [{'type': 'domain', 'query': 'example.test', 'providers': [{'provider': 'virustotal', 'status': 'Available', 'result': {'data': {'attributes': {'last_analysis_stats': {'malicious': 8}, 'last_analysis_results': {'ENGINE-DUMP-MARKER': long}}}}}]}] * 200}]
        before = copy.deepcopy(s)
        value = self.extract(reports.pdf_bytes(s))
        self.assertNotIn('RAW-HEADER-MARKER', value)
        self.assertNotIn('ENGINE-DUMP-MARKER', value)
        self.assertNotIn('?tracking=', value)
        self.assertIn('Showing', value)
        self.assertIn('Investigation Conclusion', value)
        self.assertEqual(s, before)
        self.assertEqual(json.loads(reports.evidence_json(s)), before)

    def test_highest_risk_email_selected_consistently(self):
        s = snapshot()
        sec = s['sections']
        sec['Risk Score'].insert(0, {'email_id': 'e0', 'score': 0, 'severity': 'LOW'})
        for section in ['Email Information', 'Threat Verdict', 'AI Analysis', 'DKIM Analysis', 'SPF Analysis', 'DMARC Analysis', 'Origin IP', 'Origin Confidence']:
            sec[section].insert(0, {'subject': 'LOW-EMAIL-NOT-FEATURED', 'verdict': 'BENIGN'})
        sec['Executive Summary']['emails_examined'] = 2
        value = self.extract(reports.pdf_bytes(s))
        self.assertNotIn('LOW-EMAIL-NOT-FEATURED', value)
        self.assertIn('RISK SCORE: 60', value)
        self.assertEqual(View(s).email_id, 'e1')


class EvidenceTests(unittest.TestCase):
    def test_real_provider_shapes_and_missing_values(self):
        p = {'provider': 'virustotal', 'status': 'Available', 'result': {'data': {'attributes': {'last_analysis_stats': {'malicious': 9, 'suspicious': 2, 'harmless': 42, 'undetected': 5}, 'reputation': -7}}}}
        value = provider_summary(p)
        for expected in ('Malicious: 9', 'Suspicious: 2', 'Harmless: 42', 'Undetected: 5', 'Reputation: -7'):
            self.assertIn(expected, value)
        self.assertIn('Malicious: Not Available', provider_summary({'provider': 'virustotal', 'status': 'Available'}))
        self.assertIn('91%', provider_summary({'provider': 'abuseipdb', 'status': 'Available', 'result': {'data': {'abuseConfidenceScore': 91, 'totalReports': 8}}}))

    def test_url_credentials_query_and_fragment_are_not_printed(self):
        self.assertEqual(short_url('https://user:secret@example.test/path?token=private#fragment'), 'example.test/...')

    def test_distinct_urls_same_domain_are_not_lost(self):
        s = snapshot()
        s['sections']['URL Analysis'] = [{'value': [{'domain': 'example.test', 'original_url': u} for u in ['https://example.test/a', 'https://example.test/b', 'https://example.test/a']]}]
        self.assertEqual(len(View(s).urls), 2)

    def test_historical_thresholds_are_not_invented(self):
        s = snapshot()
        s['sections']['Risk Score'] = [{'score': 70}]
        self.assertEqual(score_severity(View(s)), 'UNKNOWN')

    def test_snapshot_preserves_full_collection_and_original_bytes(self):
        raw = b'From: test@example.test\r\nX-Raw: \xff\r\n\r\nOriginal\x00body'
        digest = hashlib.sha256(raw).hexdigest()
        evidence = {'_id': 'ev1', 'sha256': digest, 'original_filename': 'test.eml', 'processing_history': [], 'storage_location': '/private/internal'}
        analysis = {'email_id': 'e1', 'evidence_id': 'ev1', 'risk_score': 0, 'forensics': {'raw_headers': 'original headers', 'iocs': [{'type': 'url', 'value': 'https://example.test/?full=yes'}], 'unknown_future_field': {'do_not_drop': ['full', 'data']}}, 'intelligence': [{'type': 'domain', 'dns': {'full': 'response'}, 'rdap': {'full': 'response'}, 'providers': []}], 'scoring_policy': {'thresholds': [25, 50, 75]}}
        database = Mock()
        database.email_analysis.find.return_value = [analysis]
        database.evidence.find.return_value = [evidence]
        database.campaigns.find.return_value = []
        before = copy.deepcopy(analysis)
        with patch.object(reports, 'db', database), patch.object(reports, 'original', return_value=raw):
            value = reports.snapshot_case({'_id': 'c1', 'status': 'OPEN', 'related_emails': ['e1'], 'evidence': []}, {'_id': 'r1', 'title': 'test'}, {'email': 'analyst@example.test'})
        exported = json.loads(reports.evidence_json(value))
        self.assertEqual(exported['analyses'], [before])
        restored = base64.b64decode(exported['original_artifacts'][0]['original_bytes'])
        self.assertEqual(restored, raw)
        self.assertEqual(hashlib.sha256(restored).hexdigest(), digest)
        self.assertEqual(exported['evidence_hashes'], [digest])
        self.assertNotIn('storage_location', exported['sections']['Evidence'][0])
        self.assertEqual(analysis, before)

    def test_missing_original_fails_instead_of_claiming_complete_export(self):
        database = Mock()
        database.email_analysis.find.return_value = []
        database.evidence.find.return_value = []
        with patch.object(reports, 'db', database):
            with self.assertRaisesRegex(ValueError, 'missing'):
                reports.snapshot_case({'_id': 'c1', 'evidence': ['missing']}, {'_id': 'r1', 'title': 'test'}, {'email': 'analyst@example.test'})

    def test_build_writes_both_encrypted_exports_before_completion(self):
        database = Mock()
        database.reports.find_one.return_value = {'_id': 'report-test', 'case_id': 'case-test'}
        database.cases.find_one.return_value = {'_id': 'case-test', 'evidence': ['ev1']}
        database.users.find_one.return_value = {'_id': 'u1'}
        s = snapshot()
        s['schema_version'] = '3.0'
        encryption = Fernet(Fernet.generate_key())
        with tempfile.TemporaryDirectory() as directory, patch.object(reports, 'db', database), patch.object(reports, 'DATA', Path(directory)), patch.object(reports, 'cipher', return_value=encryption), patch.object(reports, 'snapshot_case', return_value=s), patch.object(reports, 'custody'), patch.object(reports, 'event'):
            reports.build_report({'_id': 'j1', 'report_id': 'report-test', 'user_id': 'u1'})
            pdf = Path(directory) / 'reports/report-test.pdf.enc'
            evidence = Path(directory) / 'reports/report-test.json.enc'
            self.assertFalse(pdf.read_bytes().startswith(b'%PDF'))
            self.assertTrue(encryption.decrypt(pdf.read_bytes()).startswith(b'%PDF'))
            self.assertEqual(json.loads(encryption.decrypt(evidence.read_bytes())), s)
            self.assertEqual(pdf.stat().st_mode & 0o777, 0o600)
            self.assertEqual(database.reports.update_one.call_args.args[1]['$set']['pdf_page_count'], 10)


if __name__ == '__main__':
    unittest.main()
