import base64
import copy
from datetime import timedelta
import unittest
from unittest.mock import Mock, patch
from fastapi import HTTPException
from backend.database.store import DEFAULTS, now
from backend.parsers.email_parser import parse
from backend.core.origin_confidence import compute_origin_confidence
from backend.core.attribution import infrastructure_indicators, assess_attribution
from backend.core.correlation_engine import compare
from backend.core.privacy import mask_sensitive
import backend.intelligence.providers as ti
import backend.forensics.authentication as authentication
import backend.integrations.mailbox_monitor as monitor
from backend.core.readiness import deployment_readiness


def parsed(ip='8.8.8.8'):
    return parse(f'From: Sender <sender@example.test>\nReceived: from mail.example.test [{ip}] by receiver.example.test; Tue, 22 Sep 2026 10:00:00 +0000\nSubject: Test\n\nHello'.encode())


def provider(result, ip='8.8.8.8', name='geoip'):
    return {'type': 'ip', 'query': ip, 'providers': [{'provider': name, 'status': 'Available', 'result': result}]}


class ReadinessRegression(unittest.TestCase):
    def test_credentials_alone_do_not_mean_automatic_or_live_coverage(self):
        result = deployment_readiness(DEFAULTS, 'Available', {'geoip': 'Configured', 'virustotal': 'Configured'}, True, 0)
        rows = {r['capability']: r for r in result['items']}
        self.assertEqual(rows['Automatic reputation enrichment']['status'], 'Needs setup')
        self.assertEqual(rows['New Gmail message monitoring']['status'], 'Needs connection')
        self.assertEqual(rows['Alerts before user interaction']['status'], 'Requires mail-server integration')
        self.assertIn('not a live-service test', result['assessment'])

    def test_configured_services_keep_attribution_and_gateway_limits(self):
        config = {**DEFAULTS, 'automatic_enrichment': True, 'rdap_enabled': True, 'dns_enabled': True}
        result = deployment_readiness(config, 'Model unavailable', {'virustotal': 'Configured'}, True, 1)
        rows = {r['capability']: r for r in result['items']}
        self.assertEqual(rows['Local AI analysis']['status'], 'Needs attention')
        self.assertEqual(rows['Automatic reputation enrichment']['status'], 'Configured')
        self.assertEqual(rows['Identity and compromise attribution']['status'], 'Investigative support only')


class OriginRegression(unittest.TestCase):
    def test_tor_substring_does_not_match_corporate_names(self):
        for organization in ('Vector Networks', 'Motorola', 'Contoso Corporation'):
            self.assertEqual(infrastructure_indicators([provider({'organization': organization})], '8.8.8.8'), [])

    def test_unrelated_ip_cannot_change_candidate_characteristics(self):
        self.assertEqual(infrastructure_indicators([provider({'data': {'isTor': True}}, '1.1.1.1', 'abuseipdb')], '8.8.8.8'), [])

    def test_hosting_is_not_vpn_and_remains_inferred(self):
        result = infrastructure_indicators([provider({'organization': 'Example Cloud Hosting'})], '8.8.8.8')
        self.assertEqual({s['kind'] for s in result}, {'HOSTING'})
        self.assertEqual(result[0]['basis'], 'INFERRED')

    def test_reported_spf_pass_cannot_authenticate_relay(self):
        p = parsed()
        before = compute_origin_confidence(p, [])
        p['authentication']['spf']['reported_result'] = 'PASS'
        p['authentication']['dkim']['local_verification'] = {'status': 'PASS'}
        self.assertEqual(compute_origin_confidence(p, [])['score'], before['score'])

    def test_dns_must_match_exact_candidate_and_provenance_caps_score(self):
        p = parsed()
        data = [provider({'country': 'US', 'asn': 123}), {'type': 'domain', 'query': 'example.test', 'dns': {'records': {'A': ['1.1.1.1']}}}]
        result = compute_origin_confidence(p, data)
        self.assertNotIn('DOMAIN_IP_RELATIONSHIP', [c['rule_id'] for c in result['contributions']])
        data[1]['dns']['records']['A'] = ['8.8.8.8']
        result = compute_origin_confidence(p, data)
        self.assertIn('DOMAIN_IP_RELATIONSHIP', [c['rule_id'] for c in result['contributions']])
        self.assertLess(result['score'], 60)
        self.assertEqual(sum(c['points'] for c in result['contributions']), result['score'])

    def test_private_headers_are_not_forgery(self):
        result = compute_origin_confidence(parsed('10.0.0.1'), [])
        self.assertIsNone(result['candidate_ip'])
        self.assertEqual(result['score'], 0)
        self.assertNotIn('SUSPECTED_FORGED_HEADER', [c['rule_id'] for c in result['contributions']])

    def test_unobserved_candidate_is_rejected(self):
        p = parsed('10.0.0.1'); p['origin']['candidate_ip'] = '8.8.8.8'
        self.assertIsNone(compute_origin_confidence(p, [provider({'country': 'US'})])['candidate_ip'])

    def test_attribution_does_not_claim_account_compromise_or_person(self):
        result = assess_attribution(parsed(), [], {'label': 'PHISHING'}, {'candidate_ip': '8.8.8.8'})
        findings = {f['kind']: f for f in result['findings']}
        self.assertEqual(findings['Compromised account']['status'], 'UNKNOWN')
        self.assertEqual(findings['Human actor identity']['status'], 'INSUFFICIENT EVIDENCE')


class IntelligenceRegression(unittest.TestCase):
    def setUp(self):
        self.db = patch.object(ti, 'db').start(); self.addCleanup(patch.stopall)
        self.db.threat_intelligence.find_one.return_value = None

    def test_rdap_real_jcard_registrar_and_full_raw_evidence(self):
        raw = {'ldhName': 'example.com', 'entities': [{'roles': ['registrant'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Owner']]]},
              {'roles': ['registrar'], 'vcardArray': ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Registrar Inc']]]}],
              'events': [{'eventAction': 'registration', 'eventDate': '2000-01-01'}], 'notices': [{'description': ['full evidence preserved']}]}
        with patch.object(ti, 'rdap_domain_response', return_value=(200, raw)):
            result = ti.rdap_lookup('domain', 'example.com')
        self.assertEqual(result['result']['registrar'], 'Registrar Inc')
        self.assertEqual(result['result']['organization'], 'Owner')
        self.assertEqual(result['result']['raw'], raw)

    def test_rdap_reserved_domains_never_call_network(self):
        with patch.object(ti, 'rdap_domain_response') as request:
            self.assertEqual(ti.rdap_lookup('domain', 'host.example')['status'], 'Not Applicable')
        request.assert_not_called()

    def test_rdap_failures_are_not_cached_for_a_day(self):
        with patch.object(ti, 'rdap_domain_response', return_value=(429, None)):
            self.assertEqual(ti.rdap_lookup('domain', 'example.com')['status'], 'Rate Limited')
        expiry = self.db.threat_intelligence.update_one.call_args.args[1]['$set']['expires_at']
        self.assertLess((expiry - now()).total_seconds(), 301)

    def test_spf_two_value_library_result_is_preserved_as_candidate_only(self):
        message = parsed(); message['return_path'] = ['actual-bounce@sender.example.test']
        with patch('spf.check2', return_value=('pass', 'candidate matches DNS')) as check:
            result = authentication.candidate_spf_check(message, True)
        self.assertEqual(check.call_args.kwargs['s'], 'actual-bounce@sender.example.test')
        self.assertEqual(check.call_args.kwargs['h'], 'mail.example.test')
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['verification_type'], 'candidate_verification')
        self.assertIn('cannot establish', result['limitation'])

    def test_spf_does_not_invent_envelope_from_sender_or_reply_to(self):
        message = parsed(); message['reply_to'] = ['payment@other.example.test']
        with patch('spf.check2') as check:
            result = authentication.candidate_spf_check(message, True)
        self.assertEqual(result['status'], 'Not Observable')
        check.assert_not_called()

    def test_external_enrichment_opt_out_also_blocks_rdap(self):
        config = {**DEFAULTS, 'rdap_enabled': True}
        with patch.object(ti, 'settings', return_value=config), patch.object(ti, 'statuses', return_value={p: 'Configured' for p in ti.CORE_PROVIDERS}), patch.object(ti, 'lookup_provider', return_value={'provider': 'geoip', 'status': 'Unavailable'}), patch.object(ti, 'reverse_dns', return_value={}), patch.object(ti, 'rdap_lookup') as rdap:
            result = ti.lookup('ip', '8.8.8.8', allow_external=False)
        rdap.assert_not_called()
        self.assertEqual(result['rdap']['status'], 'Not Requested')


class CorrelationPrivacyRegression(unittest.TestCase):
    def test_shared_cloud_alone_does_not_create_campaign_lead(self):
        one = {'iocs': [{'type': 'domain', 'value': 'provider.test'}, {'type': 'ip', 'value': '8.8.8.8'}]}
        self.assertIsNone(compare(one, copy.deepcopy(one)))

    def test_identical_attachment_or_thread_can_create_reviewable_lead(self):
        one = {'iocs': [{'type': 'hash', 'value': 'a' * 64}]}
        self.assertIsNotNone(compare(one, copy.deepcopy(one)))
        lead = compare({'message_id': '<parent@example.test>'}, {'in_reply_to': '<parent@example.test>'})
        self.assertEqual(lead['evidence'][0]['type'], 'message reference')
        self.assertIn('not a calibrated probability', lead['limitation'])

    def test_return_path_difference_is_observed_not_automatic_spoofing(self):
        p = parse(b'From: a@example.test\nReturn-Path: bounce@delivery.test\nSubject: Hi\n\nHello')
        self.assertTrue(p['sender_identity']['return_path_mismatch'])
        self.assertIn('legitimate', p['sender_identity']['return_path_assessment'])

    def test_privacy_preserves_integrity_and_hides_raw_provider_payloads(self):
        data = {'sha256': '1234567890' * 6 + 'abcd', 'raw': {'secret': 'personal data'}, 'subject': 'Personal', 'query': 'https://host.test/token?email=person@example.test', 'sender': 'person@example.test'}
        original = copy.deepcopy(data)
        redacted = mask_sensitive(data)
        self.assertEqual(redacted['sha256'], data['sha256'])
        self.assertEqual(redacted['raw'], '[Masked by privacy policy]')
        self.assertNotIn('person@example.test', str(redacted))
        self.assertEqual(data, original)


class GmailMonitorRegression(unittest.TestCase):
    def setUp(self):
        self.db = patch.object(monitor, 'db').start(); self.addCleanup(patch.stopall)
        self.db.gmail_connections.find_one.return_value = {'_id': 'u1', 'monitor': {'enabled': True}}
        patch.object(monitor, 'event').start()
        self.user = {'_id': 'u1'}

    def connection(self, **state):
        return {'monitor': {'enabled': True, 'history_id': '100', 'pending': [], **state}}

    def test_enable_uses_current_history_and_imports_nothing(self):
        with patch.object(monitor, 'gmail_get', return_value={'historyId': '123'}), patch.object(monitor, 'import_message') as imp:
            result = monitor.set_monitor(self.user, True)
        self.assertTrue(result['enabled']); imp.assert_not_called()
        self.assertEqual(self.db.gmail_connections.update_one.call_args.args[1]['$set']['monitor']['history_id'], '123')

    def test_stop_needs_no_external_request(self):
        with patch.object(monitor, 'gmail_get') as request:
            monitor.set_monitor(self.user, False)
        request.assert_not_called()

    def test_cursor_advances_only_after_all_pages(self):
        page = {'historyId': '120', 'nextPageToken': 'next', 'history': [{'messagesAdded': [{'message': {'id': 'm1'}}, {'message': {'id': 'm1'}}]}]}
        with patch.object(monitor, 'gmail_get', return_value=page), patch.object(monitor, 'import_message', return_value={}) as imp:
            state = monitor.poll_connection(self.connection(), self.user)
        self.assertEqual(imp.call_count, 1)
        self.assertEqual(state['history_id'], '100')
        self.assertEqual(state['page_token'], 'next')
        with patch.object(monitor, 'gmail_get', return_value={'historyId': '125', 'history': []}):
            state = monitor.poll_connection({'monitor': state}, self.user)
        self.assertEqual(state['history_id'], '125')

    def test_expired_cursor_pauses_instead_of_silently_missing_mail(self):
        with patch.object(monitor, 'gmail_get', side_effect=HTTPException(404)):
            state = monitor.poll_connection(self.connection(), self.user)
        self.assertFalse(state['enabled'])
        self.assertIn('History expired', state['status'])
        self.assertEqual(state['history_id'], '100')

    def test_provider_failure_does_not_mutate_saved_cursor(self):
        connection = self.connection(pending=['m1'])
        before = copy.deepcopy(connection)
        with patch.object(monitor, 'import_message', side_effect=HTTPException(429)):
            with self.assertRaises(HTTPException): monitor.poll_connection(connection, self.user)
        self.assertEqual(connection, before)

    def test_deleted_or_large_message_is_audited_and_does_not_block_later_mail(self):
        with patch.object(monitor, 'import_message', side_effect=[HTTPException(413), {}]):
            result = monitor.poll_connection(self.connection(pending=['big', 'ok'], page_history_id='110'), self.user)
        self.assertEqual(result['skipped_count'], 1)
        self.assertEqual(result['imported_count'], 1)
        self.assertEqual(result['history_id'], '110')

    def test_manual_and_background_import_share_duplicate_protection(self):
        self.db.gmail_imports.find_one.return_value = {'status': 'Completed', 'result': {'email_id': 'e1'}}
        with patch.object(monitor, 'gmail_get') as request:
            result = monitor.import_message(self.user, 'message1')
        self.assertTrue(result['already_imported']); request.assert_not_called()

    def test_import_recovery_reuses_preserved_email_and_queues_missing_job(self):
        self.db.gmail_imports.find_one.return_value = {'status': 'Pending'}
        self.db.gmail_imports.find_one_and_update.return_value = {'status': 'Pending'}
        self.db.emails.find_one.return_value = {'_id': 'e1', 'evidence_id': 'ev1'}
        self.db.jobs.find_one.return_value = None
        with patch.object(monitor, 'gmail_get') as request:
            result = monitor.import_message(self.user, 'message1')
        self.assertEqual(result['email_id'], 'e1'); request.assert_not_called()
        self.db.jobs.insert_one.assert_called_once()

    def test_retained_import_tombstone_does_not_return_broken_analysis_link(self):
        self.db.gmail_imports.find_one.return_value = {'status': 'Completed', 'result': {'email_id': 'gone'}}
        self.db.emails.find_one.return_value = None
        with patch.object(monitor, 'gmail_get') as request:
            with self.assertRaises(HTTPException) as caught:
                monitor.import_message(self.user, 'message1')
        self.assertEqual(caught.exception.status_code, 410)
        request.assert_not_called()

    def test_slow_poll_preserves_unprocessed_ids(self):
        with patch.object(monitor.time, 'monotonic', side_effect=[0, 1, 31]), patch.object(monitor, 'import_message', return_value={}):
            state = monitor.poll_connection(self.connection(pending=['m1', 'm2'], page_history_id='120'), self.user)
        self.assertEqual(state['pending'], ['m2'])
        self.assertEqual(state['history_id'], '100')

    def test_stop_during_poll_prevents_further_imports(self):
        self.db.gmail_connections.find_one.return_value = None
        with patch.object(monitor, 'import_message') as imp:
            state = monitor.poll_connection(self.connection(pending=['m1']), self.user)
        self.assertFalse(state['enabled']); imp.assert_not_called()

    def test_history_batch_size_does_not_drop_remaining_messages(self):
        connection = self.connection(pending=[str(i) for i in range(25)], page_history_id='150')
        with patch.object(monitor, 'import_message', return_value={}):
            state = monitor.poll_connection(connection, self.user)
        self.assertEqual(len(state['pending']), 5)
        self.assertEqual(state['history_id'], '100')
