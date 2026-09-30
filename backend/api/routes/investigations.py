"""Investigations."""
import re
from fastapi import APIRouter, Depends, HTTPException, Query
from backend.database.store import db, now, uid, event, custody
from backend.core.security import current_user
from backend.intelligence.providers import validate
from backend.schemas.requests import CaseCreate, CaseUpdate, Note, LinkEvidence, LinkEmail, Indicator
from backend.api.dependencies import get, output, collection_page

router = APIRouter()

def attach_email(case_id,email_id,user):
    case=get('cases',case_id);email=get('emails',email_id);analysis=db.email_analysis.find_one({'_id':email_id})
    timestamp=now();evidence_ids=[email['evidence_id']]+([email['parent_evidence_id']] if email.get('parent_evidence_id') else [])
    update={'$addToSet':{'related_emails':email_id,'evidence':{'$each':evidence_ids}},
        '$set':{'updated_at':timestamp},'$push':{'timeline':{'timestamp':timestamp,'type':'Investigation timestamp','event':'Email attached','email_id':email_id,'user_id':user['_id']}}}
    if analysis:
        update['$max']={'risk_score':analysis['risk_score']}
        if analysis['risk_score']>=case.get('risk_score',0):update['$set']['severity']=analysis['severity']
    db.cases.update_one({'_id':case_id},update)
    if analysis:db.cases.update_one({'_id':case_id},{'$addToSet':{'related_iocs':{'$each':analysis['ioc_values']}}})
    for eid in evidence_ids:
        db.evidence.update_one({'_id':eid},{'$addToSet':{'case_ids':case_id}});custody(eid,'Evidence attached to investigation',user['_id'],{'case_id':case_id})
    db.alerts.update_many({'email_id':email_id},{'$set':{'case_id':case_id}})
    event('Email attached to case',user,'case',case_id,{'email_id':email_id})


@router.post('/cases',status_code=201)
def create_case(data:CaseCreate,user=Depends(current_user)):
    for eid in data.email_ids:get('emails',eid)
    row={'_id':'MT-'+now().strftime('%Y')+'-'+uid()[:8].upper(),'title':data.title,'description':data.description,'status':'OPEN',
        'assigned_to':user['_id'],'created_by':user['_id'],'created_at':now(),'updated_at':now(),
        'related_emails':[],'related_iocs':[],'evidence':[],'notes':[],'timeline':[],'risk_score':0,'severity':'LOW'}
    db.cases.insert_one(row)
    for eid in data.email_ids:attach_email(row['_id'],eid,user)
    event('Case created',user,'case',row['_id']);return output(get('cases',row['_id']),user)


@router.get('/cases')
def cases(skip:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100),q:str=Query('',max_length=250),status:str|None=None,user=Depends(current_user)):
    query={}
    if q:query['$or']=[{k:{'$regex':re.escape(q),'$options':'i'}} for k in ['_id','title','description']]
    if status:query['status']=status
    return collection_page('cases',user,skip,limit,query)


@router.get('/cases/{case_id}')
def case(case_id:str,user=Depends(current_user)):
    event('Case accessed',user,'case',case_id);return output(get('cases',case_id),user)


@router.patch('/cases/{case_id}')
def change_case(case_id:str,data:CaseUpdate,user=Depends(current_user)):
    row=get('cases',case_id);changes=data.model_dump(exclude_none=True)
    if user['role']=='ANALYST' and (row['assigned_to']!=user['_id'] or data.assigned_to or data.status in ('CLOSED','RESOLVED')):
        raise HTTPException(403,'Senior analyst required to reassign, close, resolve or manage another analyst’s case')
    if data.assigned_to:
        target=get('users',data.assigned_to)
        if target['status']!='active':raise HTTPException(422,'Assignee is inactive')
    db.cases.update_one({'_id':case_id},{'$set':{**changes,'updated_at':now()},'$push':{'timeline':{'timestamp':now(),'type':'Investigation timestamp','event':'Case updated','changes':changes,'user_id':user['_id']}}})
    event('Case modified',user,'case',case_id,changes);return output(get('cases',case_id),user)


@router.post('/cases/{case_id}/notes')
def note(case_id:str,data:Note,user=Depends(current_user)):
    get('cases',case_id);row={'id':uid(),'content':data.content,'author':user['name'],'user_id':user['_id'],'timestamp':now()}
    db.cases.update_one({'_id':case_id},{'$push':{'notes':row,'timeline':{'timestamp':now(),'type':'Investigation timestamp','event':'Note added','user_id':user['_id']}},'$set':{'updated_at':now()}})
    event('Investigation note added',user,'case',case_id);return output(row,user)


@router.post('/cases/{case_id}/emails')
def case_email(case_id:str,data:LinkEmail,user=Depends(current_user)):
    attach_email(case_id,data.email_id,user);return output(get('cases',case_id),user)


@router.post('/cases/{case_id}/evidence')
def case_evidence(case_id:str,data:LinkEvidence,user=Depends(current_user)):
    get('cases',case_id);get('evidence',data.evidence_id)
    db.cases.update_one({'_id':case_id},{'$addToSet':{'evidence':data.evidence_id}})
    db.evidence.update_one({'_id':data.evidence_id},{'$addToSet':{'case_ids':case_id}})
    custody(data.evidence_id,'Attached to case',user['_id'],{'case_id':case_id});return {'status':'Attached'}


@router.post('/cases/{case_id}/iocs')
def case_ioc(case_id:str,data:Indicator,user=Depends(current_user)):
    get('cases',case_id)
    try:value=validate(data.type,data.value)
    except ValueError as exc:raise HTTPException(422,str(exc))
    db.cases.update_one({'_id':case_id},{'$addToSet':{'related_iocs':value}})
    event('Case indicator added',user,'case',case_id,{'type':data.type,'value':value});return {'status':'Attached'}
