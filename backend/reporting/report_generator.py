"""Encrypted report snapshots: concise investigation PDF and lossless evidence JSON."""
import base64
import json
from backend.reporting.pdf_exporter import pdf_bytes
from backend.parsers.email_parser import LIMITATIONS
from backend.intelligence.providers import network_geo, ORIGIN_DISCLAIMER
from backend.database.store import DATA, cipher, clean, custody, db, event, now, original


def evidence_json(snapshot):
    """Serialize the unabridged snapshot, never the bounded PDF view."""
    return json.dumps(snapshot, ensure_ascii=False, indent=2, default=str).encode('utf-8')


def snapshot_case(case, report, user):
    analyses = list(db.email_analysis.find({'email_id': {'$in': case.get('related_emails', [])}}))
    # Stable ordering ties every parallel section to the same featured email.
    analyses.sort(key=lambda a: (-(a.get('risk_score') or 0), a['email_id']))
    evidence_ids = list(dict.fromkeys(case.get('evidence', []) + [a['evidence_id'] for a in analyses if a.get('evidence_id')]))
    evidences = list(db.evidence.find({'_id': {'$in': evidence_ids}}))
    if set(evidence_ids) != {e['_id'] for e in evidences}:
        raise ValueError('Referenced original evidence is missing; report cannot claim complete preservation')

    artifacts = []
    for evidence in evidences:
        # original() verifies SHA-256 and the permitted storage path. Never
        # silently export a truncated or tampered original as complete evidence.
        raw = original(evidence)
        artifacts.append({
            'evidence_id': evidence['_id'], 'sha256': evidence['sha256'],
            'filename': evidence.get('original_filename'),
            'encoding': 'base64', 'original_bytes': base64.b64encode(raw).decode('ascii'),
            'integrity': 'VERIFIED',
        })

    def collect(key):
        return [{'email_id': a['email_id'], 'value': (a.get('forensics') or {}).get(key)} for a in analyses]

    def auth(control):
        return [((a.get('forensics') or {}).get('authentication') or {}).get(control) or {} for a in analyses]

    sections = {
        'Case Information': clean({k: v for k, v in case.items() if k not in {'notes', 'timeline', 'evidence', 'related_iocs', 'related_emails'}}),
        'Executive Summary': {'emails_examined': len(analyses), 'maximum_observed_risk': max((a.get('risk_score') or 0 for a in analyses), default=None), 'status': case.get('status')},
        'Email Information': [dict(email_id=a['email_id'], **{k: (a.get('forensics') or {}).get(k) for k in ['subject', 'sender', 'recipient', 'reply_to', 'return_path', 'date', 'message_id']}) for a in analyses],
        'Threat Verdict': [{'email_id': a['email_id'], 'verdict': a.get('verdict'), 'source': a.get('verdict_source'), 'category': a.get('category'), 'category_basis': a.get('category_basis')} for a in analyses],
        'Risk Score': [{
            'email_id': a['email_id'], 'score': a.get('risk_score'), 'severity': a.get('severity'),
            'contributions': a.get('contributions'), 'formula': a.get('formula'), 'version': a.get('risk_version'),
            'rules': a.get('correlation_rules', []), 'model_review': a.get('model_review'),
            'review_recommendation': a.get('review_recommendation'), 'component_scores': a.get('component_scores'),
            'weighted_score': a.get('weighted_score'), 'scoring_policy': a.get('scoring_policy'),
        } for a in analyses],
        'AI Analysis': [a.get('ml') or {} for a in analyses],
        'Header Forensics': [{'email_id': a['email_id'], 'anomalies': (a.get('forensics') or {}).get('anomalies'), 'raw_headers': (a.get('forensics') or {}).get('raw_headers')} for a in analyses],
        'SPF Analysis': auth('spf'), 'DKIM Analysis': auth('dkim'), 'DMARC Analysis': auth('dmarc'),
        'Sender Identity Analysis': collect('sender_identity'), 'Received Path': collect('received_chain'),
        'Origin IP': collect('origin'),
        'Probable Network Origin': [{'email_id': a['email_id'], 'value': (a.get('origin_confidence') or {}).get('probable_origin'), 'disclaimer': ORIGIN_DISCLAIMER} for a in analyses],
        'Origin Confidence': [{'email_id': a['email_id'], 'value': a.get('origin_confidence')} for a in analyses],
        'Geolocation': [{'email_id': a['email_id'], 'assessment': a.get('geolocation'), 'analyzed_hops': a.get('analyzed_hops', []),
                        'results': [{'query': i['query'], 'status': 'Available', 'result': network_geo(i)} for i in a.get('intelligence') or [] if i.get('type')=='ip' and network_geo(i)]} for a in analyses],
        'Domain Intelligence': [i for a in analyses for i in a.get('intelligence') or [] if i.get('type') == 'domain'],
        'URL Analysis': collect('urls'), 'Attachment Analysis': collect('attachments'),
        'Threat Intelligence': [{'email_id': a['email_id'], 'results': a.get('intelligence'), 'status': a.get('enrichment_status'), 'providers': a.get('provider_status')} for a in analyses],
        'Infrastructure Correlation': [a.get('graph') for a in analyses],
        'Campaign Correlation': {'suggestions': [a.get('related_emails') for a in analyses], 'reviewed_campaigns': clean(list(db.campaigns.find({'email_ids': {'$in': case.get('related_emails', [])}})))},
        'Timeline': sorted([e for a in analyses for e in a.get('timeline') or []] + clean(case.get('timeline', [])), key=lambda e: str(e.get('timestamp') or '')),
        'Evidence': clean(evidences), 'Chain of Custody': [clean(e.get('processing_history', [])) for e in evidences],
        'Analyst Notes': clean(case.get('notes', [])), 'Findings': [a.get('signals') for a in analyses], 'Limitations': LIMITATIONS,
    }
    return {
        'schema_version': '3.0', 'report_id': report['_id'], 'case_id': case['_id'],
        'title': report['title'], 'generated_at': now().isoformat(), 'generated_by': user['email'],
        'evidence_export_filename': f'report-{report["_id"]}.json',
        'sections': sections, 'evidence_hashes': [e['sha256'] for e in evidences],
        'raw_header_appendix': collect('raw_headers'),
        # Preserve full collection outputs, including future collector fields,
        # DNS, RDAP, IOC extraction, body variants, model outputs and timestamps.
        'analyses': analyses, 'case_snapshot': clean(case), 'original_artifacts': artifacts,
        'presentation': {'pages': 10, 'featured_email_id': analyses[0]['email_id'] if analyses else None,
                         'scope': 'Highest-risk email featured; every linked analysis preserved in JSON',
                         'transformations': 'PDF-only row deduplication, row limits, shortened URLs and text. Unsupported font characters shown as Unicode code points.'},
    }


def build_report(job):
    report = db.reports.find_one({'_id': job['report_id']})
    if not report:
        raise ValueError('Report is unavailable')
    case = db.cases.find_one({'_id': report['case_id']})
    user = db.users.find_one({'_id': job['user_id']})
    if not case or not user:
        raise ValueError('Report case or author is unavailable')
    snapshot = snapshot_case(case, report, user)
    directory = DATA / 'reports'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for fmt, content in [('pdf', pdf_bytes(snapshot)), ('json', evidence_json(snapshot))]:
        path = directory / (report['_id'] + '.' + fmt + '.enc')
        with path.open('wb') as f:
            f.write(cipher().encrypt(content))
        path.chmod(0o600)
    db.reports.update_one({'_id': report['_id']}, {'$set': {
        'status': 'Completed', 'completed_at': now(), 'evidence_hashes': snapshot['evidence_hashes'],
        'report_schema_version': snapshot['schema_version'], 'pdf_page_count': 10,
    }})
    db.jobs.update_one({'_id': job['_id']}, {'$set': {'status': 'Completed', 'updated_at': now()}, '$unset': {'lease_until': ''}})
    for evidence_id in case.get('evidence', []):
        custody(evidence_id, 'Report generated', job['user_id'], {'report_id': report['_id']})
    event('Report generated', user, 'report', report['_id'], {'case_id': case['_id']})
