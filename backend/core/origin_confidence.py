"""Bounded evidence completeness for a candidate relay, never a location probability."""
from backend.parsers.email_parser import ip_kind, classify_ip
from backend.core.attribution import infrastructure_indicators, mail_cloud_provider
from backend.core.scoring_config import ORIGIN_ENGINE_VERSION, ORIGIN_THRESHOLDS
from backend.intelligence.providers import network_geo, ORIGIN_DISCLAIMER
import ipaddress
import re


def compute_origin_confidence(parsed, enrichment):
    chain = parsed.get('received_chain') or []
    candidate = (parsed.get('origin') or {}).get('candidate_ip')
    sources = {i.get('ip') for h in chain for i in h.get('ips') or []
               if i.get('role') == 'source' and i.get('ip') and ip_kind(i['ip']) == 'Public'}
    if candidate not in sources:
        candidate = None
    contributions, supporting, conflicting = [], [], []
    limitations = list(parsed.get('limitations') or [])
    def add(rule, points, reason, evidence=None):
        contributions.append({'rule_id': rule, 'points': points, 'description': reason, 'evidence': evidence})
        if points > 0:
            supporting.append(reason)
        elif points < 0:
            conflicting.append(reason)
    relevant = [i for i in enrichment or [] if i.get('type') == 'ip' and i.get('query') == candidate] if candidate else []
    geo = network_geo(relevant[0]) if relevant else {}
    rdap = next(((i['rdap'].get('result') or {}) for i in relevant if (i.get('rdap') or {}).get('status') == 'Available'), {})
    if candidate:
        add('RELAY_CANDIDATE_OBSERVED', 25, 'A public source IP appears in the supplied Received headers.', {'candidate_ip': candidate})
        add('PUBLIC_IP_EXTRACTED', 15, 'The candidate is a routable public IP; this does not establish ownership.', candidate)
        linked_hops=all(a.get('destination_server') and str(a['destination_server']).lower().rstrip('.')==str(b.get('source_server') or '').lower().rstrip('.') for a,b in zip(chain,chain[1:]))
        if not parsed.get('anomalies') and len(chain) >= 2 and linked_hops and all(h.get('timestamp') for h in chain):
            add('RELAY_CHAIN_CONSISTENT', 10, 'Adjacent reported server names link and multi-hop timestamps contain no detected ordering anomaly; headers remain unverified.')
        if geo.get('country') or geo.get('city'):
            add('GEOIP_AVAILABLE', 10, 'IP intelligence provides approximate infrastructure location context.', {'source': geo.get('data_source'), 'country': geo.get('country'), 'accuracy_radius_km': geo.get('accuracy_radius_km')})
        if any(p.get('provider')=='ipinfo' and p.get('status')=='Available' for i in relevant for p in i.get('providers',[])):
            add('IPINFO_AVAILABLE', 5, 'IPinfo returned candidate-specific network intelligence; fields depend on the API plan.')
        if geo.get('asn') or rdap.get('asn'):
            add('ASN_RDAP_AVAILABLE', 10, 'ASN registration context is available for this candidate.', geo.get('asn') or rdap.get('asn'))
        linked = [i['query'] for i in enrichment or [] if i.get('type') == 'domain' and
                  any(candidate in ((i.get('dns') or {}).get('records', {}).get(kind) or []) for kind in ('A', 'AAAA'))]
        if linked:
            add('DOMAIN_IP_RELATIONSHIP', 10, 'DNS addresses match this candidate IP.', sorted(set(linked)))
    else:
        add('INSUFFICIENT_PUBLIC_RELAY', 0, 'No usable public sending candidate is established by the supplied relay headers.')
        limitations.append('Private-only, missing or incomplete relay headers are insufficient evidence; they are not proof of forgery.')
    # SPF assertions and DKIM signatures do not authenticate the Received chain.
    limitations.append('Header-reported SPF and DKIM PASS do not verify relay provenance. DKIM authenticates signed content, not sender physical location.')
    cross_check={'status':'Not Available','asn_match':None,'organization_match':None,'range_contains_ip':None}
    if candidate and rdap:
        def asn_number(value):
            match=re.fullmatch(r'(?:AS)?(\d+)',str(value or ''),re.I)
            return int(match[1]) if match else None
        # Compare independent providers, not RDAP against its own fallback value.
        provider_geo=network_geo({**relevant[0],'rdap':None})
        left,right=asn_number(provider_geo.get('asn')),asn_number(rdap.get('asn'))
        if left and right:cross_check['asn_match']=left==right
        def org_key(value):return re.sub(r'[^a-z0-9]','',str(value or '').lower())
        left,right=org_key(provider_geo.get('organization')),org_key(rdap.get('organization'))
        if left and right:cross_check['organization_match']=left==right
        cidr=rdap.get('network_cidr') or rdap.get('asn_cidr')
        if cidr:
            try:cross_check['range_contains_ip']=any(ipaddress.ip_address(classify_ip(candidate)['lookup_ip']) in ipaddress.ip_network(part.strip(),strict=False) for part in cidr.split(','))
            except (ValueError,TypeError):pass
        checks=[cross_check[k] for k in ('asn_match','organization_match','range_contains_ip')]
        cross_check['status']='Mismatch' if cross_check['asn_match'] is False or cross_check['range_contains_ip'] is False else 'Consistent' if any(x is True for x in checks) else 'Inconclusive'
        if cross_check['status']=='Consistent':add('RDAP_CORROBORATION',5,'RDAP corroborates the candidate ASN, organization or IP range.',cross_check.copy())
    # Apply the upload trust ceiling before obscuring-infrastructure penalties so
    # a cloud/VPN flag still reduces confidence even when many fields are present.
    positive_score=sum(c['points'] for c in contributions)
    if positive_score>59:
        add('UNTRUSTED_HEADER_BOUNDARY_CAP',59-positive_score,'Unverified uploaded headers cannot establish HIGH origin confidence.')
    if cross_check['status']=='Mismatch':add('RDAP_CONFLICT',-10,'RDAP ASN or registered range conflicts with the candidate intelligence.',cross_check.copy())
    if candidate and parsed.get('anomalies'):
        add('HEADER_INCONSISTENCY', -20, 'Recorded header anomalies reduce confidence in the relay reconstruction.', parsed['anomalies'])
    signals = infrastructure_indicators(enrichment, candidate)
    reported = {s['kind'] for s in signals if s['basis'] == 'REPORTED'}
    if reported & {'TOR', 'VPN', 'PROXY'}:
        add('REPORTED_ANONYMIZING_INFRASTRUCTURE', -15, 'Provider-reported ' + ', '.join(sorted(reported & {'TOR', 'VPN', 'PROXY'})) + ' infrastructure limits source tracing.', [s for s in signals if s['basis'] == 'REPORTED'])
    elif reported & {'ANONYMOUS','PRIVACY RELAY'}:
        add('REPORTED_PRIVACY_INFRASTRUCTURE',-15,'Provider reports anonymous or privacy-relay infrastructure; specific VPN/proxy/Tor flags may be unavailable.')
    provider=mail_cloud_provider(geo.get('organization')) or mail_cloud_provider(rdap.get('organization'))
    if provider or any(s['kind']=='HOSTING' for s in signals) or geo.get('network_type')=='hosting':
        add('CLOUD_INFRASTRUCTURE',-15,'Mail/cloud or hosting infrastructure can hide the originating client. Provider classification may be inferred from organization names.',provider)
    if provider in ('Google / Gmail','Microsoft / Outlook'):
        add('MAIL_PROVIDER_RELAY',-10,'A Google/Microsoft IP observed in Received is provider infrastructure, not evidence of the mailbox user’s physical location.',provider)
    for signal in signals:
        if signal['basis'] == 'INFERRED':
            limitations.append(f'{signal["kind"]} is an inferred organization-name clue, not verified usage by this email.')
    raw_score = sum(c['points'] for c in contributions)
    # No trusted SMTP receiving boundary is collected by the upload/import flow.
    score = max(0, min(59, raw_score)) if candidate else 0
    level = 'HIGH' if score>=ORIGIN_THRESHOLDS['HIGH'] else 'MEDIUM' if score>=ORIGIN_THRESHOLDS['MEDIUM'] else 'LOW'
    limitations.append('No trusted receiving-server boundary is available. Origin confidence is evidence completeness, not a calibrated probability or a human identity claim.')
    kinds = sorted({s['kind'] for s in signals})
    probable = {'ip': candidate, **{k: geo.get(k) for k in ('country', 'region', 'city', 'latitude', 'longitude', 'asn', 'organization', 'accuracy_radius_km','network_owner','network_cidr','network_type','is_vpn','is_proxy','is_tor','is_hosting','is_anonymous','data_source','field_sources')},
                'mail_cloud_provider':provider,'provider_classification_basis':'Organization-name inference' if provider else None,
                'rdap_cross_check':cross_check,
                'infrastructure_type': ', '.join(kinds) if kinds else 'Unknown', 'classification_basis': 'See source-qualified infrastructure indicators'}
    return {'score': score, 'raw_score': raw_score, 'level': level, 'candidate_ip': candidate,
            'label':'Probable Network Origin','disclaimer':ORIGIN_DISCLAIMER,
            'probable_origin': probable, 'contributions': contributions, 'infrastructure_indicators': signals,
            'supporting_evidence': supporting, 'conflicting_evidence': conflicting,
            'limitations': list(dict.fromkeys(limitations)), 'engine_version': ORIGIN_ENGINE_VERSION,
            'source': 'Untrusted relay observations and candidate-specific network intelligence',
            'interpretation': 'Confidence in the documented candidate infrastructure, separate from threat risk. No verified sender location or actor identity.'}
