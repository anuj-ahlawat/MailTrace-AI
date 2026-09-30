"""Explicit opt-in retention. Case- and campaign-linked analyses are held."""
from datetime import timedelta
from backend.config import resolve_runtime_file
from backend.database.store import db, now, settings, event, DATA

def apply_retention():
    config=settings()
    if not config['retention_enabled']:return {'status':'Disabled','deleted':0}
    count=0
    held=held_emails()
    for email in db.emails.find({'created_at':{'$lt':now()-timedelta(days=config['analysis_retention_days'])}}):
        if email['_id'] in held:continue
        if db.jobs.find_one({'email_id':email['_id'],'status':{'$nin':['Completed','Failed']}}):continue
        db.email_analysis.delete_one({'_id':email['_id']});db.emails.delete_one({'_id':email['_id']})
        db.iocs.update_many({'email_ids':email['_id']},{'$pull':{'email_ids':email['_id']}});count+=1
        db.jobs.delete_many({'email_id':email['_id']});db.alerts.delete_many({'email_id':email['_id']})
        db.iocs.delete_many({'email_ids':[]})
    for evidence in db.evidence.find({'acquisition_time':{'$lt':now()-timedelta(days=config['evidence_retention_days'])},'case_ids':[]}):
        if db.emails.find_one({'$or':[{'evidence_id':evidence['_id']},{'parent_evidence_id':evidence['_id']}]}):continue
        path=resolve_runtime_file(evidence['storage_location'], 'evidence', DATA)
        path.unlink(missing_ok=True)
        event('Evidence deleted by configured retention',resource='evidence',resource_id=evidence['_id'],metadata={'sha256':evidence['sha256']})
        db.evidence.delete_one({'_id':evidence['_id']});count+=1
    db.audit_logs.delete_many({'timestamp':{'$lt':now()-timedelta(days=config['audit_retention_days'])}})
    event('Retention applied',metadata={'deleted':count,'policy':config})
    return {'status':'Completed','deleted':count}


def held_emails():
    cases = {e for c in db.cases.find({}, {'related_emails': 1}) for e in c.get('related_emails', [])}
    campaigns = {e for c in db.campaigns.find({}, {'email_ids': 1}) for e in c.get('email_ids', [])}
    return cases | campaigns


def preview_retention():
    config = settings()
    held = held_emails()
    eligible, active = [], 0
    for email in db.emails.find({'created_at': {'$lt': now() - timedelta(days=config['analysis_retention_days'])}}, {'_id': 1}):
        if email['_id'] in held:
            continue
        if db.jobs.find_one({'email_id': email['_id'], 'status': {'$nin': ['Completed', 'Failed']}}):
            active += 1
        else:
            eligible.append(email['_id'])
    return {'enabled': config['retention_enabled'], 'eligible_analysis_count': len(eligible),
            'protected_case_or_campaign_emails': len(held), 'active_jobs_excluded': active,
            'policy': {k: config[k] for k in ('analysis_retention_days', 'evidence_retention_days', 'audit_retention_days')},
            'assessment': 'Read-only preview of analysis expiry. Evidence deletion also requires expiry and no remaining email or case references. Counts can change before execution.'}
