"""Reports."""
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Response, Query
from backend.database.store import db, now, uid, clean, settings, event, DATA, cipher
from backend.core.security import current_user
from backend.schemas.requests import ReportCreate
from backend.api.dependencies import get, output, collection_page

router = APIRouter()

@router.post('/reports',status_code=202)
def report(data:ReportCreate,user=Depends(current_user)):
    case=get('cases',data.case_id)
    if not case['related_emails']:raise HTTPException(422,'Attach analyzed emails before generating a report')
    if any(not db.email_analysis.find_one({'_id':eid}) for eid in case['related_emails']):raise HTTPException(409,'Wait for all linked analyses to complete')
    row={'_id':uid(),'case_id':data.case_id,'title':data.title,'created_at':now(),'generated_by':user['_id'],'status':'Uploaded'}
    job={'_id':uid(),'kind':'report','report_id':row['_id'],'user_id':user['_id'],'status':'Uploaded','created_at':now(),'attempts':0,'history':[]}
    row['job_id']=job['_id'];db.reports.insert_one(row);db.jobs.insert_one(job);event('Report requested',user,'report',row['_id']);return clean(row)


@router.get('/reports')
def reports(skip:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100),user=Depends(current_user)):return collection_page('reports',user,skip,limit)


@router.get('/reports/{report_id}')
def report_info(report_id:str,user=Depends(current_user)):return output(get('reports',report_id),user)


@router.get('/reports/{report_id}/download')
def report_download(report_id:str,format:Literal['pdf','json']='pdf',user=Depends(current_user)):
    row=get('reports',report_id)
    if row['status']!='Completed':raise HTTPException(409,'Report is not ready')
    if user['role']=='ANALYST' and settings()['mask_sensitive']:raise HTTPException(403,'Unmasked reports require a senior role under the masking policy')
    path=DATA/'reports'/(row['_id']+'.'+format+'.enc')
    content=cipher().decrypt(path.read_bytes());event('Report downloaded',user,'report',report_id,{'format':format})
    return Response(content,media_type='application/pdf' if format=='pdf' else 'application/json',headers={'Content-Disposition':f'attachment; filename="report-{report_id}.{format}"'})

