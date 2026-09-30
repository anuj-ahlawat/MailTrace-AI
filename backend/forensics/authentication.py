"""Offline-message authentication: real DKIM plus qualified DNS policy inspection.

An uploaded message does not supply a trustworthy SMTP peer/envelope. Never turn
an observed Received-SPF header or an SPF DNS record into an independent PASS.
"""
import logging
import re
from time import monotonic

from backend.parsers.email_parser import registered
from backend.intelligence.providers import dns_query, validate
from backend.database.store import now


class LookupUnavailable(Exception):
    pass


def verify_dkim(raw, parsed, dns_enabled):
    signatures = parsed['authentication']['dkim']['signatures']
    result = {'status': 'Not Signed' if not signatures else 'Not Configured',
              'source': 'Local dkimpy verification over preserved original bytes',
              'timestamp': now().isoformat(), 'signatures': [],
              'limitation': 'Current DNS keys may differ from keys at receipt time. A valid signature does not establish benign content.'}
    if not signatures:
        return result
    if not dns_enabled:
        result['reason'] = 'Enable DNS lookups to retrieve DKIM public keys'
        return result
    try:
        import dkim
    except ImportError:
        return {**result, 'status': 'Unavailable', 'reason': 'dkimpy is not installed'}
    deadline = monotonic() + 20
    key_cache = {}
    logger = logging.getLogger('mailtrace.dkim')
    logger.addHandler(logging.NullHandler()) if not logger.handlers else None
    logger.propagate = False
    logger.setLevel(logging.CRITICAL)

    def public_key(name, timeout=3):
        domain = name.decode('ascii').rstrip('.')
        if monotonic() >= deadline:
            raise LookupUnavailable('DKIM DNS time budget exhausted')
        if domain not in key_cache:
            answer = dns_query(domain, 'TXT')
            if answer['status'] != 'Available':
                raise LookupUnavailable('DKIM key lookup ' + answer['status'].lower())
            values = [v for v in answer['values'] if re.search(r'(?:^|;)\s*p=', v, re.I)]
            if len(values) != 1:
                raise LookupUnavailable('No unique DKIM public-key record available')
            key_cache[domain] = values[0].encode()
        return key_cache[domain]

    for index, signature in enumerate(signatures[:5]):
        entry = {**signature, 'signature_index': index, 'status': 'Unavailable'}
        header = parsed['headers']['dkim-signature'][index]
        algorithm = re.search(r'(?:^|;)\s*a=([^;\s]+)', header, re.I)
        # Avoid silently accepting obsolete rsa-sha1; no extra crypto packages needed.
        if not algorithm or algorithm.group(1).lower() != 'rsa-sha256':
            entry['reason'] = 'This verifier supports rsa-sha256; signature algorithm unavailable'
        elif monotonic() >= deadline:
            entry['reason'] = 'DKIM verification time budget exhausted'
        else:
            try:
                verified = dkim.DKIM(raw, minkey=1024, timeout=3, logger=logger).verify(index, dnsfunc=public_key)
                entry['status'] = 'PASS' if verified else 'FAIL'
                entry['reason'] = 'Signature verified against current DNS key' if verified else 'Signature or signed content did not validate'
            except LookupUnavailable as exc:
                entry['reason'] = str(exc)
            except dkim.DKIMException:
                entry.update(status='FAIL', reason='DKIM signature validation failed')
            except Exception:
                entry['reason'] = 'DKIM verification unavailable'
        entry['verification_status'] = entry['status']
        result['signatures'].append(entry)
    states = [s['status'] for s in result['signatures']]
    result['status'] = 'PASS' if 'PASS' in states else 'FAIL' if states and all(s == 'FAIL' for s in states) and len(signatures) <= 5 else 'Unavailable'
    result['signature_limit'] = 5
    result['omitted_signatures'] = max(0, len(signatures) - 5)
    return result


def candidate_spf_check(parsed, dns_enabled):
    """SPF DNS policy check using the earliest public relay candidate IP.

    IMPORTANT LIMITATIONS:
    - An uploaded .eml cannot supply a trusted SMTP peer IP or envelope.
    - The candidate IP is the earliest observed public relay source, not verified.
    - Result is labeled 'candidate_verification', never 'authoritative'.
    - A PASS here does not mean the email is legitimate.
    - A FAIL here does not mean the email is spoofed.
    Only runs when dns_enabled=True (same toggle as DKIM). Stored at
    auth.spf.candidate_dns_check; never overwrites reported_result.
    """
    base = {
        'status': 'Not Configured',
        'source': 'pyspf DNS candidate check using earliest observed public relay IP',
        'timestamp': now().isoformat(),
        'verification_type': 'candidate_verification',
        'limitation': (
            'Uploaded email cannot establish a trusted SMTP peer IP or envelope sender. '
            'PASS does not establish legitimacy; FAIL does not establish spoofing. '
            'Supplementary forensic evidence only.'
        ),
    }
    if not dns_enabled:
        return {**base, 'reason': 'Enable DNS lookups to perform SPF candidate check'}
    origin = parsed.get('origin', {})
    candidate_ip = origin.get('candidate_ip')
    if not candidate_ip:
        return {**base, 'status': 'Not Observable',
                'reason': 'No public relay candidate IP in Received headers'}
    # From/Reply-To are not SMTP envelope identities. Do not fabricate a
    # postmaster address: SPF macros can depend on the complete local part.
    return_paths = parsed.get('return_path') or []
    if len(return_paths) != 1 or '@' not in return_paths[0]:
        return {**base, 'status': 'Not Observable', 'reason': 'One observed Return-Path mailbox is required for a candidate SPF check'}
    envelope_from = return_paths[0]
    relay = next((h for h in parsed.get('received_chain') or [] if
                  any(i.get('ip') == candidate_ip and i.get('role') == 'source' for i in h.get('ips') or [])), {})
    try:
        sender_domain = validate('domain', envelope_from.rsplit('@', 1)[-1])
        helo = validate('domain', relay.get('hostname') or '')
    except (ValueError, UnicodeError):
        return {**base, 'status': 'Not Observable', 'reason': 'Usable observed Return-Path and source relay hostname are required; neither is inferred from From or Reply-To'}
    try:
        import spf as pyspf
        result_code, smtp_comment = pyspf.check2(
            i=candidate_ip, s=envelope_from, h=helo, timeout=5)
        status_map = {
            'pass': 'PASS', 'fail': 'FAIL', 'softfail': 'SOFTFAIL',
            'neutral': 'NEUTRAL', 'none': 'NONE',
            'temperror': 'Unavailable', 'permerror': 'Invalid',
        }
        status = status_map.get((result_code or '').lower(), 'Unknown')
        return {
            **base, 'status': status, 'result_code': result_code,
            'candidate_ip': candidate_ip, 'envelope_from': envelope_from,
            'helo_candidate': helo, 'envelope_source': 'Untrusted supplied Return-Path header',
            'sender_domain': sender_domain, 'smtp_comment': smtp_comment,
            'reason': f'pyspf candidate check: {result_code} — {smtp_comment}',
        }
    except ImportError:
        return {**base, 'status': 'Unavailable', 'reason': 'pyspf is not installed'}
    except Exception as exc:
        return {**base, 'status': 'Unavailable', 'reason': f'SPF candidate check unavailable: {exc}'}


def policy_records(domain, prefix, enabled):
    if not enabled:
        return {'status': 'Not Configured', 'records': [], 'reason': 'DNS lookups disabled'}
    try:
        domain = validate('domain', domain)
    except (ValueError, UnicodeError, AttributeError):
        return {'status': 'Unavailable', 'records': [], 'reason': 'No usable policy domain in supplied message'}
    query = '_dmarc.' + domain if prefix == 'v=DMARC1' else domain
    answer = dns_query(query, 'TXT')
    records = [v for v in answer['values'] if re.match('^' + re.escape(prefix) + r'(?:\s|;|$)', v, re.I)]
    status = answer['status'] if answer['status'] == 'Unavailable' else 'Available' if len(records) == 1 else 'Invalid' if len(records) > 1 else 'Not Found'
    return {**answer, 'status': status, 'records': records, 'domain': domain}


def enrich_authentication(raw, parsed, config):
    auth = parsed['authentication']
    enabled = config['dns_enabled']
    dkim_result = verify_dkim(raw, parsed, enabled)
    auth['dkim']['local_verification'] = dkim_result
    auth['dkim']['verification_status'] = dkim_result['status']
    spf = policy_records(auth['spf'].get('domain'), 'v=spf1', enabled)
    spf.update(verification_status='Unknown',
               reason='SPF authorization requires the trusted SMTP peer IP and envelope sender, which an uploaded email cannot establish')
    auth['spf']['dns_policy'] = spf
    # pyspf candidate check — supplementary only, never authoritative
    auth['spf']['candidate_dns_check'] = candidate_spf_check(parsed, enabled)
    from_domain = auth['dmarc']['from_domain']
    dmarc = policy_records(from_domain, 'v=DMARC1', enabled)
    if dmarc['status'] == 'Not Found' and registered(from_domain) != from_domain:
        dmarc = policy_records(registered(from_domain), 'v=DMARC1', enabled)
        dmarc['organizational_domain_fallback'] = True
    tags = {}
    if dmarc['status'] == 'Available':
        pairs = [part.strip().split('=', 1) for part in dmarc['records'][0].split(';') if '=' in part]
        tags = {k.strip().lower(): v.strip() for k, v in pairs}
        if len(tags) != len(pairs) or tags.get('p') not in ('none', 'quarantine', 'reject') or tags.get('adkim', 'r') not in ('r', 's') or tags.get('aspf', 'r') not in ('r', 's'):
            dmarc['status'] = 'Invalid'
        dmarc['tags'] = tags
    strict = tags.get('adkim') == 's'
    aligned = [s for s in dkim_result['signatures'] if s['status'] == 'PASS' and
               (s['domain'].lower() == from_domain.lower() if strict else registered(s['domain']) == registered(from_domain))]
    single_sender = len(parsed['headers'].get('from', [])) == 1 and len(parsed.get('from_addresses', [])) == 1
    assessment = 'PASS' if dmarc['status'] == 'Available' and aligned and single_sender else 'Unknown'
    auth['dmarc'].update(dns_policy=dmarc, policy=tags.get('p', 'Unknown') if dmarc['status'] == 'Available' else 'Unknown',
        local_assessment={'status': assessment, 'basis': 'Verified DKIM with DMARC domain alignment' if assessment == 'PASS' else 'Insufficient verified authentication evidence',
            'aligned_verified_signatures': [s['signature_index'] for s in aligned],
            'adkim': 'strict' if strict else 'relaxed', 'timestamp': now().isoformat(),
            'limitation': 'No DMARC failure is asserted while SPF authorization is unknown; uploaded header assertions remain separate'})
    return auth
