"""Explainable campaign leads; shared providers alone do not imply a campaign."""
import re
from backend.parsers.email_parser import ip_kind

EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def indicators(parsed):
    result = set()
    for i in parsed.get('iocs') or []:
        kind, value = i.get('type'), i.get('value')
        if not value or (kind == 'ip' and ip_kind(value) != 'Public') or value == EMPTY_SHA256:
            continue
        result.add((kind, value))
    return result


def message_ids(parsed):
    own = str(parsed.get('message_id') or '').strip()
    refs = re.findall(r'<[^<>\s]+>', str(parsed.get('references') or '') + ' ' + str(parsed.get('in_reply_to') or ''))
    return ({own} if own else set()) | set(refs)


def compare(parsed, other):
    shared = indicators(parsed) & indicators(other)
    strong = [i for i in shared if i[0] in ('url', 'hash')]
    identities = []
    if parsed.get('sender') and parsed.get('sender') == other.get('sender'):
        identities.append({'type': 'sender address', 'value': parsed['sender'], 'basis': 'Header-reported'})
    for reply in set(parsed.get('reply_to') or []) & set(other.get('reply_to') or []):
        identities.append({'type': 'reply address', 'value': reply, 'basis': 'Header-reported'})
    threads = message_ids(parsed) & message_ids(other)
    kinds = {kind for kind, _ in shared}
    # Domain/IP overlap alone is common on shared mail platforms. Preserve as
    # a weak lead, never elevate it to a confirmed campaign or human identity.
    score = min(100, sum(45 if k == 'hash' else 25 if k == 'url' else 5 for k, _ in shared)
                + (20 if identities else 0) + (35 if threads else 0))
    enough = bool(threads or any(k == 'hash' for k, _ in strong) or len(strong) >= 2
                  or (strong and identities) or ({'domain', 'ip'} <= kinds and identities))
    if not enough:
        return None
    return {'shared_indicators': [v for _, v in sorted(shared)],
            'evidence': [{'type': k, 'value': v, 'basis': 'Observed in both emails'} for k, v in sorted(shared)] + identities +
                        [{'type': 'message reference', 'value': v, 'basis': 'Unverified supplied header'} for v in sorted(threads)],
            'association_score': score, 'confidence': 'MODERATE' if score >= 45 else 'LOW',
            'finding': 'Possible related messages; analyst association required',
            'limitation': 'Heuristic association strength, not a calibrated probability. Shared artifacts and supplied identities do not prove common authorship.'}


def related_emails(db, email_id, parsed, limit=50):
    values = indicators(parsed)
    strong = sorted(v for k, v in values if k in ('hash', 'url'))[:100]
    refs = sorted(message_ids(parsed))[:30]
    weak = sorted(v for k, v in values if k in ('domain', 'ip'))[:50]
    queries = []
    if strong:
        queries.append({'ioc_values': {'$in': strong}})
    if refs:
        queries.append({'forensics.message_id': {'$in': refs}})
        queries.append({'forensics.in_reply_to': {'$in': refs}})
    if weak and parsed.get('sender'):
        queries.append({'ioc_values': {'$in': weak}, 'forensics.sender': parsed['sender']})
    if not queries:
        return []
    results, seen = [], set()
    for query in queries:
        query = {**query, 'email_id': {'$ne': email_id}}
        for row in db.email_analysis.find(query, {'email_id': 1, 'forensics.iocs': 1, 'forensics.sender': 1, 'forensics.reply_to': 1,
                                                   'forensics.message_id': 1, 'forensics.references': 1, 'forensics.in_reply_to': 1}).limit(limit):
            if row['email_id'] in seen:
                continue
            seen.add(row['email_id'])
            result = compare(parsed, row.get('forensics') or {})
            if result:
                results.append({'email_id': row['email_id'], **result})
            if len(seen) >= limit:
                break
        if len(seen) >= limit:
            break
    return sorted(results, key=lambda r: (-r['association_score'], r['email_id']))
