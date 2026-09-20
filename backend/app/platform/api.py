"""Authenticated REST API for the complete investigation workflow."""
import csv
import hashlib
import io
import json
import os
import re
from datetime import timedelta,datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Literal
from fastapi import APIRouter,Depends,HTTPException,Request,Response,UploadFile,File,Query
from pydantic import BaseModel,Field,EmailStr,ConfigDict
from pymongo.errors import DuplicateKeyError
from .store import db,now,uid,clean,settings,DEFAULTS,event,custody,original,DATA,cipher
from .security import current_user,admin,senior,passwords,login_session
from .pipeline import acquire
from .intelligence import statuses,lookup,validate,KEYS,CORE_PROVIDERS,provider_health
from app.ml.service import ml_service,clear_model_cache,model_catalog

router=APIRouter(prefix='/api')

class Input(BaseModel):
    model_config=ConfigDict(extra='forbid')
class Login(Input):
    email:EmailStr
    password:str=Field(min_length=1,max_length=1024)
class NewUser(Input):
    email:EmailStr
    name:str=Field(min_length=1,max_length=120)
    password:str=Field(min_length=12,max_length=128)
    role:Literal['ANALYST','SENIOR_ANALYST','ADMINISTRATOR']='ANALYST'
class UserUpdate(Input):
    name:str|None=Field(default=None,min_length=1,max_length=120)
    role:Literal['ANALYST','SENIOR_ANALYST','ADMINISTRATOR']|None=None
    status:Literal['active','inactive']|None=None
class RawEmail(Input):
    raw_email:str=Field(min_length=20,max_length=10_000_000)
class PasswordChange(Input):
    current_password:str=Field(min_length=1,max_length=1024)
    new_password:str=Field(min_length=12,max_length=128)
class CaseCreate(Input):
    title:str=Field(min_length=1,max_length=250)
    description:str=Field(default='',max_length=20000)
    email_ids:list[str]=Field(default_factory=list,max_length=100)
class CaseUpdate(Input):
    title:str|None=Field(default=None,min_length=1,max_length=250)
    description:str|None=Field(default=None,max_length=20000)
    status:Literal['OPEN','IN_PROGRESS','ESCALATED','RESOLVED','CLOSED']|None=None
    assigned_to:str|None=None
class Note(Input):
    content:str=Field(min_length=1,max_length=20000)
class LinkEvidence(Input):
    evidence_id:str
class LinkEmail(Input):
    email_id:str
class Indicator(Input):
    type:Literal['ip','domain','url','hash']
    value:str=Field(min_length=1,max_length=4096)
class ReportCreate(Input):
    case_id:str
    title:str=Field(default='Forensic Investigation Report',min_length=1,max_length=250)
class AlertUpdate(Input):
    status:Literal['OPEN','ACKNOWLEDGED','RESOLVED']
class ProviderKey(Input):
    api_key:str=Field(min_length=1,max_length=4096)
class SystemUpdate(Input):
    max_upload_mb:int=Field(default=10,ge=1,le=25)
    csv_row_limit:int=Field(default=500,ge=1,le=1000)
    alert_threshold:int=Field(default=80,ge=1,le=100)
    mask_sensitive:bool=False
    retention_enabled:bool=False
    analysis_retention_days:int=Field(default=365,ge=1,le=36500)
    evidence_retention_days:int=Field(default=730,ge=1,le=36500)
    audit_retention_days:int=Field(default=1095,ge=30,le=36500)
    risk_weights:dict[str,float]=Field(default_factory=lambda:DEFAULTS['risk_weights'].copy())
    risk_thresholds:list[int]=Field(default_factory=lambda:[30,60,80],min_length=3,max_length=3)
    enabled_providers:list[Literal['virustotal','abuseipdb','urlscan','greynoise','geoip']]=Field(default_factory=lambda:list(CORE_PROVIDERS))
    dns_enabled:bool=False
    automatic_enrichment:bool=False
    model_name:Literal['production','baseline','cnn','bilstm','transformer']='production'
class CampaignCreate(Input):
    title:str=Field(min_length=1,max_length=250)
    email_ids:list[str]=Field(min_length=2,max_length=100)
    reason:str=Field(min_length=10,max_length=5000)

def get(collection,identifier):
    row=db[collection].find_one({'_id':identifier})
    if not row:raise HTTPException(404,'Record not found')
    return row

def output(row,user):
    value=clean(row)
    if user['role']=='ANALYST' and settings()['mask_sensitive']:
        def mask(v):
            if isinstance(v,dict):return {k:('[Masked by privacy policy]' if k in {'body','html_body','model_text','raw_headers','raw_header','headers','display_name','original_filename','plain_text_body','html_text'} else mask(x)) for k,x in v.items()}
            if isinstance(v,list):return [mask(x) for x in v]
            if isinstance(v,str):
                v=re.sub(r'[\w.+-]+@[\w.-]+','[masked email]',v)
                return re.sub(r'(?<!\w)\+?\d[\d ()-]{8,}\d','[masked number]',v)
            return v
        value=mask(value)
    return value

def collection_page(collection,user,skip=0,limit=25,query=None):
    query=query or {}
    return {'items':output(list(db[collection].find(query).sort('created_at',-1).skip(skip).limit(limit)),user),
            'total':db[collection].count_documents(query),'skip':skip,'limit':limit}

def rate_limit(key,limit=10,seconds=300):
    window=int(now().timestamp())//seconds;identifier=hashlib.sha256(f'{key}:{window}'.encode()).hexdigest()
    row=db.rate_limits.find_one_and_update({'_id':identifier},{'$inc':{'count':1},'$setOnInsert':{'expires_at':now()+timedelta(seconds=seconds*2)}},upsert=True,return_document=True)
    if row['count']>limit:raise HTTPException(429,'Rate limited; try again later',headers={'Retry-After':str(seconds)})

@router.post('/auth/login')
def login(data:Login,request:Request,response:Response):
    ip=request.client.host if request.client else 'unknown';rate_limit('login-ip:'+ip,30);rate_limit('login-account:'+str(data.email).lower(),10)
    user=db.users.find_one({'email':str(data.email).lower(),'status':'active'})
    valid=passwords.verify(data.password,user['password_hash'] if user else passwords.hash('nonexistent-account-password'))
    if not user or not valid:
        event('Login failed',ip=ip);raise HTTPException(401,'Invalid email or password')
    token,csrf,expires=login_session(user)
    secure=os.getenv('COOKIE_SECURE','false').lower()=='true'
    age=int((expires-now()).total_seconds())
    response.set_cookie('mt_session',token,httponly=True,secure=secure,samesite='lax',max_age=age,path='/')
    response.set_cookie('mt_csrf',csrf,httponly=False,secure=secure,samesite='lax',max_age=age,path='/')
    db.users.update_one({'_id':user['_id']},{'$set':{'last_login':now()}});event('Login',user,ip=ip)
    return {'user':clean(user)}

@router.get('/auth/me')
def me(user=Depends(current_user)):return clean(user)

@router.post('/auth/logout')
def logout(request:Request,response:Response,user=Depends(current_user)):
    db.sessions.delete_one({'_id':request.state.session_id})
    response.delete_cookie('mt_session',path='/');response.delete_cookie('mt_csrf',path='/');event('Logout',user)
    return {'status':'Signed out'}

@router.post('/auth/password')
def change_password(data:PasswordChange,user=Depends(current_user)):
    if not passwords.verify(data.current_password,user['password_hash']):raise HTTPException(403,'Current password is incorrect')
    db.users.update_one({'_id':user['_id']},{'$set':{'password_hash':passwords.hash(data.new_password)}})
    db.sessions.delete_many({'user_id':user['_id']});event('Password changed and sessions revoked',user)
    return {'status':'Password changed; sign in again'}

@router.get('/users')
def users(user=Depends(admin)):return {'items':clean(list(db.users.find({}).limit(500)))}

@router.post('/auth/register')
@router.post('/users',status_code=201)
def new_user(data:NewUser,user=Depends(admin)):
    row={'_id':uid(),'name':data.name,'email':str(data.email).lower(),'password_hash':passwords.hash(data.password),
         'role':data.role,'status':'active','created_at':now()}
    try:db.users.insert_one(row)
    except DuplicateKeyError:raise HTTPException(409,'Email already registered')
    event('User created',user,'user',row['_id'],{'role':data.role});return clean(row)

@router.patch('/users/{user_id}')
def update_user(user_id:str,data:UserUpdate,user=Depends(admin)):
    get('users',user_id);changes=data.model_dump(exclude_none=True)
    if user_id==user['_id'] and ('role' in changes or changes.get('status')=='inactive'):raise HTTPException(409,'Cannot remove your own administrative access')
    db.users.update_one({'_id':user_id},{'$set':changes});db.sessions.delete_many({'user_id':user_id})
    event('User changed',user,'user',user_id,changes);return clean(get('users',user_id))

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
    from .store import preserve
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

@router.get('/intelligence/status')
def provider_status(user=Depends(current_user)):return statuses()

@router.get('/intelligence/health')
def intelligence_health(user=Depends(current_user)):return provider_health()

@router.post('/intelligence/lookup')
def intelligence(data:Indicator,user=Depends(current_user)):
    rate_limit('intel:'+user['_id'],30)
    try:result=lookup(data.type,data.value)
    except ValueError as exc:raise HTTPException(422,str(exc))
    event('Intelligence queried',user,'indicator',data.value,{'type':data.type})
    return output(result,user)

@router.get('/intelligence/{kind}/{value:path}')
def intelligence_get(kind:Literal['ip','domain','hash'],value:str,user=Depends(current_user)):
    return intelligence(Indicator(type=kind,value=value),user)

@router.get('/iocs')
def iocs(skip:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100),q:str=Query('',max_length=250),user=Depends(current_user)):
    return collection_page('iocs',user,skip,limit,{'value':{'$regex':re.escape(q),'$options':'i'}} if q else {})

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

@router.get('/evidence')
def evidence_list(skip:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100),user=Depends(current_user)):
    return collection_page('evidence',user,skip,limit)

@router.get('/evidence/{evidence_id}')
def evidence(evidence_id:str,user=Depends(current_user)):
    row=get('evidence',evidence_id);custody(evidence_id,'Evidence accessed',user['_id']);return output(row,user)

@router.post('/evidence/{evidence_id}/verify')
def verify(evidence_id:str,user=Depends(current_user)):
    row=get('evidence',evidence_id)
    try:raw=original(row);result={'status':'VERIFIED','sha256':hashlib.sha256(raw).hexdigest(),'verified_at':now()}
    except Exception:result={'status':'FAILED','reason':'Original bytes unavailable or integrity check failed','verified_at':now()}
    custody(evidence_id,'Integrity verification',user['_id'],clean(result));return clean(result)

@router.get('/evidence/{evidence_id}/download')
def download_evidence(evidence_id:str,user=Depends(current_user)):
    if user['role']=='ANALYST' and settings()['mask_sensitive']:raise HTTPException(403,'Unmasked downloads require a senior role under the masking policy')
    row=get('evidence',evidence_id)
    try:raw=original(row)
    except Exception:raise HTTPException(409,'Evidence is unavailable or failed integrity verification')
    custody(evidence_id,'Original evidence downloaded',user['_id'])
    return Response(raw,media_type='application/octet-stream',headers={'Content-Disposition':f'attachment; filename="evidence-{evidence_id}.bin"'})

@router.get('/campaigns')
def campaigns(skip:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100),user=Depends(current_user)):return collection_page('campaigns',user,skip,limit)

@router.post('/campaigns')
def campaign(data:CampaignCreate,user=Depends(senior)):
    records=[get('email_analysis',eid) for eid in set(data.email_ids)]
    if len(records)<2:raise HTTPException(422,'At least two distinct emails required')
    shared=set(records[0]['ioc_values'])
    for row in records[1:]:shared &= set(row['ioc_values'])
    row={'_id':uid(),'title':data.title,'email_ids':list(set(data.email_ids)),'shared_indicators':sorted(shared),
        'reason':data.reason,'created_by':user['_id'],'created_at':now(),'severity':max(records,key=lambda a:a['risk_score'])['severity'],
        'assessment':'Analyst-associated campaign; shared infrastructure is not proof of common authorship'}
    db.campaigns.insert_one(row);event('Campaign correlated',user,'campaign',row['_id'],{'reason':data.reason});return output(row,user)

@router.get('/campaigns/{campaign_id}/graph')
def campaign_graph(campaign_id:str,user=Depends(current_user)):
    row=get('campaigns',campaign_id);nodes={};edges={}
    for a in db.email_analysis.find({'email_id':{'$in':row['email_ids']}}):
        for n in a['graph']['nodes']:nodes[n['id']]=n
        for e in a['graph']['edges']:edges[e['id']]=e
    return output({'nodes':list(nodes.values()),'edges':list(edges.values())},user)

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

@router.get('/alerts')
def alerts(skip:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100),status:str|None=None,user=Depends(current_user)):
    return collection_page('alerts',user,skip,limit,{'status':status} if status else {})

@router.patch('/alerts/{alert_id}')
def change_alert(alert_id:str,data:AlertUpdate,user=Depends(current_user)):
    get('alerts',alert_id);db.alerts.update_one({'_id':alert_id},{'$set':{'status':data.status,'updated_at':now(),'updated_by':user['_id']}})
    event('Alert status changed',user,'alert',alert_id,{'status':data.status});return clean(get('alerts',alert_id))

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

@router.get('/search')
def search(q:str=Query(min_length=2,max_length=250),user=Depends(current_user)):
    results=[]
    for collection,fields,url in [('emails',['_id','sender','recipient','subject','content_hash'],'/emails/'),('cases',['_id','title','related_iocs'],'/cases/'),('iocs',['value'],'/threat-intelligence')]:
        query={'$or':[{f:{'$regex':re.escape(q),'$options':'i'}} for f in fields]}
        for row in db[collection].find(query).limit(10):results.append({'type':collection,'id':row['_id'],'title':row.get('subject') or row.get('title') or row.get('value'),'url':url+(row['_id'] if url.endswith('/') else '')})
    return output(results,user)

@router.get('/audit-logs')
def audit(skip:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100),user=Depends(admin)):
    return {'items':clean(list(db.audit_logs.find().sort('timestamp',-1).skip(skip).limit(limit))),'total':db.audit_logs.count_documents({})}

@router.get('/settings')
def system_settings(user=Depends(admin)):return {'settings':settings(),'providers':statuses(),'provider_health':provider_health(),'available_models':model_catalog(),'model':ml_service().metadata,'worker_mode':os.getenv('WORKER_MODE','local')}

@router.put('/settings')
def save_settings(data:SystemUpdate,user=Depends(admin)):
    values=data.model_dump();weights=data.risk_weights
    if set(weights)!=set(DEFAULTS['risk_weights']) or any(not 0<=v<=100 for v in weights.values()) or abs(sum(weights.values())-100)>.001:
        raise HTTPException(422,'Risk category weights must be nonnegative and sum to 100')
    if weights['ai']>25:raise HTTPException(422,'AI may contribute at most 25 risk points')
    if not 0<data.risk_thresholds[0]<data.risk_thresholds[1]<data.risk_thresholds[2]<=100:raise HTTPException(422,'Risk thresholds must increase between 1 and 100')
    if data.model_name!=settings()['model_name']:
        candidate=next(m for m in model_catalog() if m['name']==data.model_name)
        if candidate['status']!='Artifact present':raise HTTPException(422,'Selected model artifact is unavailable')
    db.system_settings.replace_one({'_id':'system'},{'_id':'system',**values},upsert=True)
    event('System configuration changed',user,'settings','system',values);return {'settings':settings()}

@router.put('/settings/providers/{provider}')
def save_key(provider:Literal['virustotal','abuseipdb','urlscan','greynoise','geoip'],data:ProviderKey,user=Depends(admin)):
    db.provider_secrets.replace_one({'_id':provider},{'_id':provider,'secret':cipher().encrypt(data.api_key.encode()).decode(),'updated_at':now()},upsert=True)
    event('Provider credential changed',user,'provider',provider);return {'provider':provider,'status':statuses()[provider]}

@router.delete('/settings/providers/{provider}')
def remove_key(provider:Literal['virustotal','abuseipdb','urlscan','greynoise','geoip'],user=Depends(admin)):
    db.provider_secrets.delete_one({'_id':provider});event('Stored provider credential removed',user,'provider',provider)
    return {'provider':provider,'status':statuses()[provider]}

@router.post('/settings/model/reload')
def reload_model(user=Depends(admin)):
    clear_model_cache();event('Model reloaded',user);return {'status':ml_service().status}

@router.post('/settings/retention/run')
def retention(user=Depends(admin)):
    from .retention import apply_retention
    return apply_retention()
