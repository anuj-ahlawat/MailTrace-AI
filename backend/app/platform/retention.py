"""Explicit opt-in retention. Case-linked evidence and analyses are held."""
from datetime import timedelta
from pathlib import Path
from .store import db,now,settings,event,DATA

def apply_retention():
    config=settings()
    if not config['retention_enabled']:return {'status':'Disabled','deleted':0}
    count=0
    held=set(e for c in db.cases.find({}, {'related_emails':1}) for e in c.get('related_emails',[]))
    for email in db.emails.find({'created_at':{'$lt':now()-timedelta(days=config['analysis_retention_days'])}}):
        if email['_id'] in held:continue
        if db.jobs.find_one({'email_id':email['_id'],'status':{'$nin':['Completed','Failed']}}):continue
        db.email_analysis.delete_one({'_id':email['_id']});db.emails.delete_one({'_id':email['_id']})
        db.iocs.update_many({'email_ids':email['_id']},{'$pull':{'email_ids':email['_id']}});count+=1
        db.jobs.delete_many({'email_id':email['_id']});db.alerts.delete_many({'email_id':email['_id']})
        db.iocs.delete_many({'email_ids':[]})
    for evidence in db.evidence.find({'acquisition_time':{'$lt':now()-timedelta(days=config['evidence_retention_days'])},'case_ids':[]}):
        if db.emails.find_one({'$or':[{'evidence_id':evidence['_id']},{'parent_evidence_id':evidence['_id']}]}):continue
        path=Path(evidence['storage_location']).resolve()
        if path.is_relative_to((DATA/'evidence').resolve()):path.unlink(missing_ok=True)
        event('Evidence deleted by configured retention',resource='evidence',resource_id=evidence['_id'],metadata={'sha256':evidence['sha256']})
        db.evidence.delete_one({'_id':evidence['_id']});count+=1
    db.audit_logs.delete_many({'timestamp':{'$lt':now()-timedelta(days=config['audit_retention_days'])}})
    event('Retention applied',metadata={'deleted':count,'policy':config})
    return {'status':'Completed','deleted':count}
