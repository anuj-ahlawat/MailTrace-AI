"""Source-qualified infrastructure and identity hypotheses; never actor identification."""
import re

PATTERNS = {
    'TOR': r'\b(?:tor|torbsd|onion|exit node)\b',
    'VPN': r'\bvpn\b|virtual private network',
    'PROXY': r'\b(?:proxy|socks|anonymizer|anonymizing)\b',
    'HOSTING': r'\b(?:hosting|cloud|vps|datacenter|data center|linode|digitalocean|vultr|ovh|hetzner|amazonaws|amazon|cloudflare|google|microsoft)\b',
}

def mail_cloud_provider(organization):
    """Organization-name inference, never proof this IP operated a particular mail service."""
    for name,pattern in [('Google / Gmail',r'\bgoogle\b'),('Microsoft / Outlook',r'\bmicrosoft\b'),
                         ('AWS',r'\bamazon(?:aws)?\b'),('Cloudflare',r'\bcloudflare\b'),
                         ('DigitalOcean',r'\bdigitalocean\b'),('OVH',r'\bovh\b'),
                         ('Hetzner',r'\bhetzner\b'),('Akamai / Linode',r'\b(?:akamai|linode)\b')]:
        if re.search(pattern,str(organization or ''),re.I):return name
    return None


def infrastructure_indicators(enrichment, ip):
    """Only evidence for this exact IP can describe this IP's infrastructure."""
    signals = []
    if not ip:
        return signals
    def add(kind, basis, source, field, value, timestamp):
        row = {'kind': kind, 'basis': basis, 'source': source, 'field': field,
               'value': value, 'ip': ip, 'timestamp': timestamp,
               'limitation': 'Infrastructure characteristic; not proof of maliciousness or sender identity'}
        if row not in signals:
            signals.append(row)
    for item in enrichment or []:
        if item.get('type') != 'ip' or item.get('query') != ip:
            continue
        providers = list(item.get('providers') or [])
        if item.get('rdap'):
            providers.append(item['rdap'])
        for provider in providers:
            if provider.get('status') != 'Available':
                continue
            result = provider.get('result') or {}
            source, stamp = provider.get('provider', 'rdap'), provider.get('timestamp')
            data = result.get('data') or result
            attrs = data.get('attributes') or data
            # Explicit provider flags remain provider-reported assertions.
            for field, kind in [('isTor', 'TOR'), ('is_tor', 'TOR'), ('is_vpn', 'VPN'), ('is_proxy', 'PROXY'), ('is_hosting_provider', 'HOSTING'), ('is_hosting','HOSTING'), ('is_anonymous','ANONYMOUS'), ('is_relay','PRIVACY RELAY')]:
                if attrs.get(field) is True:
                    add(kind, 'REPORTED', source, field, True, stamp)
            for field in ('organization', 'asn_description', 'isp', 'org', 'network_name', 'as_owner', 'usageType'):
                value = attrs.get(field)
                if not isinstance(value, str):
                    continue
                for kind, pattern in PATTERNS.items():
                    if re.search(pattern, value, re.I):
                        add(kind, 'INFERRED', source, field, value, stamp)
    return signals


def assess_attribution(parsed, enrichment, ml, origin):
    identity = parsed.get('sender_identity') or {}
    findings = []
    def add(kind, status, reason, evidence):
        findings.append({'kind': kind, 'status': status, 'reason': reason, 'evidence': evidence})
    if identity.get('lookalikes') or identity.get('display_name_mismatch'):
        add('Sender impersonation', 'SUSPECTED', 'Local identity checks found a lookalike or claimed-brand mismatch; analyst confirmation is required.',
            {'lookalikes': identity.get('lookalikes'), 'display_name_mismatch': identity.get('display_name_mismatch')})
    elif identity.get('reply_to_mismatch'):
        add('Sender identity inconsistency', 'OBSERVED', 'Reply-To uses a different registered domain; legitimate mail services may also do this.',
            {'sender_domain': identity.get('sender_domain'), 'reply_to_domain': identity.get('reply_to_domain')})
    auth = parsed.get('authentication') or {}
    dmarc = auth.get('dmarc') or {}
    if dmarc.get('reported_result') == 'FAIL':
        add('Domain spoofing', 'SUSPECTED', 'Supplied headers report DMARC failure. The assertion is untrusted and failure alone does not prove spoofing.', dmarc.get('evidence', []))
    for signal in origin.get('infrastructure_indicators') or []:
        add(signal['kind'] + ' infrastructure', signal['basis'], 'Candidate relay infrastructure indicator; source and basis are retained.', signal)
    verified_auth = (dmarc.get('local_assessment') or {}).get('status') == 'PASS'
    add('Compromised account', 'UNKNOWN',
        'Suspicious content with locally verified aligned authentication warrants mailbox access-log review; compromise is not established.'
        if verified_auth and ml.get('label') in ('PHISHING', 'BEC') else
        'Account compromise requires mailbox, login or endpoint telemetry; email evidence alone does not establish it.',
        {'locally_verified_dmarc': verified_auth, 'model_label': ml.get('label')})
    add('Human actor identity', 'INSUFFICIENT EVIDENCE', 'No person is identified by headers, RDAP registrants or network geolocation.', [])
    return {'version': '1.0', 'findings': findings, 'candidate_ip': origin.get('candidate_ip'),
            'assessment': 'Investigative hypotheses, not attribution verdicts',
            'next_steps': ['Correlate source-qualified indicators with internal telemetry.',
                           'Validate suspected impersonation through a known independent contact channel.'] if len(findings) > 2 else ['Review available evidence and obtain receiving-server logs if origin tracing is required.']}
