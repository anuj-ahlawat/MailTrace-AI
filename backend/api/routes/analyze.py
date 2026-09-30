"""Analyze."""
import csv
import io
import re
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from backend.database.store import db, now, uid, clean, settings, event
from backend.core.security import current_user
from backend.core.pipeline import acquire
from backend.schemas.requests import RawEmail
from backend.api.dependencies import get, output, collection_page, rate_limit

router = APIRouter()

@router.post('/emails/analyze',status_code=202)
def raw_email(data:RawEmail,user=Depends(current_user)):
    raw=data.raw_email.encode();config=settings()
    if len(raw)>config['max_upload_mb']*1024*1024:raise HTTPException(413,'Email exceeds upload limit')
    rate_limit('ingest:'+user['_id'],100)
    return acquire(raw,'pasted-email.eml',user['_id'],'raw RFC email')


@router.post('/emails/upload',status_code=202)
def upload(file:UploadFile=File(...),user=Depends(current_user)):
    rate_limit('ingest:'+user['_id'],100);config=settings();name=file.filename or ''
    suffix=Path(name).suffix.lower()
    if suffix not in ('.eml','.csv','.mime'):raise HTTPException(422,'Unsupported file: upload .eml, .mime or .csv')
    if file.content_type not in ('message/rfc822','application/octet-stream','text/plain','text/csv','application/vnd.ms-excel','application/x-eml','application/eml'):raise HTTPException(422,'Unsupported MIME type')
    raw=file.file.read(config['max_upload_mb']*1024*1024+1)
    if len(raw)>config['max_upload_mb']*1024*1024:raise HTTPException(413,'File exceeds configured upload limit')
    if not raw:raise HTTPException(422,'Empty file')
    if suffix!='.csv':return acquire(raw,name,user['_id'])
    csv.field_size_limit(10_000_000)
    try:
        reader=csv.DictReader(io.StringIO(raw.decode('utf-8-sig')));rows=[]
        for row in reader:
            if len(rows)>=config['csv_row_limit']:raise HTTPException(413,'CSV exceeds configured row limit')
            rows.append({str(k).lower():v for k,v in row.items() if k})
    except (UnicodeError,csv.Error):raise HTTPException(422,'Invalid UTF-8 CSV')
    if not rows:raise HTTPException(422,'No email rows in CSV')
    messages=[]
    for i,row in enumerate(rows):
        if row.get('raw_email'):content=row['raw_email'].encode()
        else:
            body=row.get('body') or row.get('text') or row.get('message')
            if not body:raise HTTPException(422,f'CSV row {i+2} has no raw_email/body/text/message')
            msg=EmailMessage();msg['Subject']=(row.get('subject') or 'Imported email').replace('\r',' ').replace('\n',' ')
            for header,key in [('From','sender'),('To','receiver'),('Reply-To','reply_to')]:
                if row.get(key):msg[header]=row[key].replace('\r',' ').replace('\n',' ')
            msg.set_content(body);content=msg.as_bytes()
        messages.append(content)
    from backend.database.store import preserve
    parent=preserve(raw,name,user['_id'],'CSV source')
    jobs=[acquire(content,f'row-{i+2}.eml',user['_id'],'CSV-derived message (headers may be synthesized)',parent['_id']) for i,content in enumerate(messages)]
    event('CSV dataset ingested',user,'evidence',parent['_id'],{'rows':len(jobs)})
    return {'jobs':jobs,'source_evidence_id':parent['_id']}


@router.get('/emails')
def emails(skip:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100),q:str=Query('',max_length=250),status:str|None=None,
    severity:Literal['LOW','MEDIUM','HIGH','CRITICAL']|None=None,verdict:Literal['BENIGN','PHISHING','BEC','SPAM','Unknown']|None=None,
    risk_min:int|None=Query(None,ge=0,le=100),country:str|None=None,asn:str|None=None,source:str|None=None,
    date_from:datetime|None=None,date_to:datetime|None=None,case_id:str|None=None,user=Depends(current_user)):
    query={}
    if q:query['$or']=[{k:{'$regex':re.escape(q),'$options':'i'}} for k in ['sender','subject','_id','recipient','content_hash']]
    if status:query['status']=status
    for key,value in [('severity',severity),('verdict',verdict),('countries',country),('asns',asn),('source',source)]:
        if value:query[key]=value
    if risk_min is not None:query['risk_score']={'$gte':risk_min}
    if date_from or date_to:
        query['created_at']={}
        if date_from:query['created_at']['$gte']=date_from
        if date_to:query['created_at']['$lte']=date_to
    if case_id:query['_id']={'$in':get('cases',case_id)['related_emails']}
    return collection_page('emails',user,skip,limit,query)


@router.get('/emails/{email_id}')
def email(email_id:str,user=Depends(current_user)):
    record=get('emails',email_id);analysis=db.email_analysis.find_one({'_id':email_id})
    event('Email viewed',user,'email',email_id)
    return output({'email':record,'analysis':analysis,'job':db.jobs.find_one({'email_id':email_id},sort=[('created_at',-1)])},user)


@router.get('/emails/{email_id}/analysis')
def analysis(email_id:str,user=Depends(current_user)):return output(get('email_analysis',email_id),user)


@router.post('/emails/{email_id}/analyze',status_code=202)
def reanalyze(email_id:str,user=Depends(current_user)):
    record=get('emails',email_id)
    if db.jobs.find_one({'email_id':email_id,'status':{'$nin':['Failed','Completed']}}):raise HTTPException(409,'Analysis already pending')
    stamp=now()
    job={'_id':uid(),'email_id':email_id,'evidence_id':record['evidence_id'],'user_id':user['_id'],'status':'Uploaded','created_at':stamp,'updated_at':stamp,'attempts':0,'history':[{'status':'Uploaded','timestamp':stamp}]}
    db.jobs.insert_one(job)
    db.emails.update_one({'_id':email_id},{'$set':{'status':'Uploaded'}})
    event('Reanalysis requested',user,'email',email_id,{'job_id':job['_id']})
    return clean(job)


@router.get('/jobs/{job_id}')
def job(job_id:str,user=Depends(current_user)):return output(get('jobs',job_id),user)


@router.get('/forensics/{email_id}/{section}')
def forensic_section(email_id:str,section:Literal['headers','received-chain','authentication'],user=Depends(current_user)):
    row=get('email_analysis',email_id)
    return output(row['forensics'][{'received-chain':'received_chain'}.get(section,section)],user)


@router.get('/graph/{email_id}')
def infrastructure(email_id:str,user=Depends(current_user)):return output(get('email_analysis',email_id)['graph'],user)

