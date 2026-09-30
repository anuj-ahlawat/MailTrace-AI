"""Dashboard."""
from datetime import timedelta
from fastapi import APIRouter, Depends
from backend.database.store import db, now, settings
from backend.core.security import current_user
from backend.intelligence.providers import statuses
from backend.detection.inference import ml_service
from backend.api.dependencies import output

router = APIRouter()

@router.get('/dashboard/summary')
def summary(user=Depends(current_user)):
    distribution=list(db.email_analysis.aggregate([{'$group':{'_id':'$verdict','count':{'$sum':1}}}]))
    risk_distribution=list(db.email_analysis.aggregate([{'$group':{'_id':'$severity','count':{'$sum':1}}}]))
    return {'emails_analyzed':db.email_analysis.count_documents({}),'high_risk':db.email_analysis.count_documents({'severity':'HIGH'}),
        'critical':db.email_analysis.count_documents({'severity':'CRITICAL'}),'open_investigations':db.cases.count_documents({'status':{'$nin':['CLOSED','RESOLVED']}}),
        'open_alerts':db.alerts.count_documents({'status':'OPEN'}),'distribution':[{'label':r['_id'],'count':r['count']} for r in distribution],
        'risk_distribution':[{'label':r['_id'],'count':r['count']} for r in risk_distribution],
        'provider_status':statuses(),'model_status':ml_service().status,'recent_emails':output(list(db.emails.find().sort('created_at',-1).limit(8)),user)}


@router.get('/dashboard/trends')
def trends(user=Depends(current_user)):
    pipeline=[{'$match':{'created_at':{'$gte':now()-timedelta(days=30)}}},{'$group':{'_id':{'date':{'$dateToString':{'format':'%Y-%m-%d','date':'$created_at'}},'verdict':'$verdict'},'count':{'$sum':1}}},{'$sort':{'_id.date':1}}]
    return [{'date':r['_id']['date'],'verdict':r['_id']['verdict'],'count':r['count']} for r in db.email_analysis.aggregate(pipeline)]


@router.get('/dashboard/infrastructure')
def top_infrastructure(user=Depends(current_user)):
    rows=list(db.email_analysis.aggregate([{'$match':{'risk_score':{'$gte':settings()['risk_thresholds'][1]}}},
        {'$unwind':'$forensics.iocs'},{'$match':{'forensics.iocs.type':{'$in':['ip','domain']}}},
        {'$group':{'_id':{'type':'$forensics.iocs.type','value':'$forensics.iocs.value'},'count':{'$sum':1}}},{'$sort':{'count':-1}},{'$limit':20}]))
    return output([{'type':r['_id']['type'],'value':r['_id']['value'],'count':r['count'],'assessment':'Observed in high-risk emails; not a maliciousness assertion'} for r in rows],user)


@router.get('/dashboard/geography')
def geography(user=Depends(current_user)):
    def group(field):
        return [{'label':str(r['_id']),'count':r['count']} for r in db.emails.aggregate([
            {'$match':{'status':'Completed'}},{'$unwind':'$'+field},
            {'$group':{'_id':'$'+field,'count':{'$sum':1}}},{'$sort':{'count':-1}},{'$limit':10}])]
    return {'countries':group('countries'),'asns':group('asns'),'source':'Configured GeoIP results; counts are emails per observed infrastructure location'}

