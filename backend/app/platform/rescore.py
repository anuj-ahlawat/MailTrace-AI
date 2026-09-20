"""Apply current scoring to saved evidence without running models or providers.

Dry run: PYTHONPATH=backend python -m app.platform.rescore
Apply:   PYTHONPATH=backend python -m app.platform.rescore --apply
Original evidence and generated report snapshots are never modified.
"""
import argparse
import json

from .pipeline import RISK_VERSION, risk
from .store import db, now, settings, event


def rescore_saved(apply=False, email_ids=None):
    config=settings()
    query={'risk_version':{'$ne':RISK_VERSION}}
    if email_ids is not None:query['_id']={'$in':email_ids}
    results=[]
    for analysis in db.email_analysis.find(query):
        email_id=analysis['_id']
        email=db.emails.find_one({'_id':email_id,'status':'Completed'})
        if not email or db.jobs.find_one({'email_id':email_id,'status':{'$nin':['Completed','Failed']}}):
            results.append({'email_id':email_id,'status':'Skipped: analysis not idle'});continue
        updated=risk(analysis['forensics'],analysis['ml'],analysis.get('intelligence',[]),config)
        summary={'email_id':email_id,'previous_score':analysis['risk_score'],'score':updated['risk_score'],
            'severity':updated['severity'],'version':RISK_VERSION,'status':'Preview'}
        if apply:
            stamp=now()
            previous={key:analysis[key] for key in updated if key in analysis}
            changed=db.email_analysis.update_one(
                {'_id':email_id,'created_at':analysis['created_at'],'risk_version':analysis.get('risk_version')},
                {'$set':{**updated,'rescored_at':stamp},'$push':{'scoring_history':{'replaced_at':stamp,'previous':previous}}})
            if not changed.modified_count:
                summary['status']='Skipped: analysis changed';results.append(summary);continue
            db.emails.update_one({'_id':email_id,'status':'Completed'},{'$set':{
                key:updated[key] for key in ('risk_score','severity','verdict')}})
            # Preserve analyst-managed alert status while refreshing its findings.
            alert_fields={'severity':updated['severity'],'reason':[s['reason'] for s in updated['signals']],
                'review_recommendation':updated['review_recommendation']}
            db.alerts.update_one({'_id':email_id},{'$set':alert_fields})
            if updated['risk_score']>=config['alert_threshold']:
                db.alerts.update_one({'_id':email_id},{'$setOnInsert':{'email_id':email_id,'type':'Email risk',
                    'created_at':stamp,'status':'OPEN',**alert_fields}},upsert=True)
            for case in db.cases.find({'related_emails':email_id}):
                highest=db.email_analysis.find_one({'email_id':{'$in':case['related_emails']}},sort=[('risk_score',-1)])
                if highest:db.cases.update_one({'_id':case['_id']},{'$set':{
                    'risk_score':highest['risk_score'],'severity':highest['severity'],'updated_at':stamp}})
            event('Scoring policy updated',resource='email',resource_id=email_id,
                metadata={'previous_score':analysis['risk_score'],'score':updated['risk_score'],
                    'previous_version':analysis.get('risk_version'),'version':RISK_VERSION,'original_evidence_unchanged':True})
            summary['status']='Updated'
        results.append(summary)
    return results


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--email-id',action='append')
    args=parser.parse_args()
    print(json.dumps(rescore_saved(args.apply,args.email_id),indent=2))
