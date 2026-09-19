"""Shared MongoDB, encrypted evidence and append-only application events."""
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from pymongo import MongoClient

ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / '.env')
DATA = Path(os.getenv('DATA_DIR', str(ROOT / 'data'))).resolve()
MODEL_DIR = Path(os.getenv('MODEL_DIR', str(ROOT / 'ml' / 'artifacts' / 'production'))).resolve()
client = MongoClient(os.getenv('MONGODB_URI','mongodb://localhost:27017'), serverSelectionTimeoutMS=5000, tz_aware=True)
db = client[os.getenv('MONGODB_DB_NAME','mailtrace_enterprise')]

def now(): return datetime.now(timezone.utc)
def uid(): return str(uuid.uuid4())
def clean(value):
    if isinstance(value,dict): return {('id' if k=='_id' else k):clean(v) for k,v in value.items() if k not in {'password_hash','storage_location','secret','token_hash'}}
    if isinstance(value,list): return [clean(v) for v in value]
    if isinstance(value,datetime): return value.isoformat()
    return value

def cipher():
    key=os.getenv('EVIDENCE_ENCRYPTION_KEY','')
    if not key: raise RuntimeError('EVIDENCE_ENCRYPTION_KEY must be configured')
    return Fernet(key.encode())

def event(action, user=None, resource=None, resource_id=None, metadata=None, ip=None):
    row={'_id':uid(),'timestamp':now(),'action':action,'user_id':user.get('_id') if user else None,
         'resource':resource,'resource_id':resource_id,'ip':ip,'metadata':metadata or {}}
    db.audit_logs.insert_one(row)
    return row

def custody(evidence_id, action, user_id, metadata=None):
    record={'id':uid(),'timestamp':now(),'action':action,'user_id':user_id,'metadata':metadata or {}}
    db.evidence.update_one({'_id':evidence_id},{'$push':{'processing_history':record}})
    event(action,{'_id':user_id},'evidence',evidence_id,metadata)

def preserve(raw, filename, user_id, source='upload'):
    eid=uid(); directory=DATA/'evidence'; directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    path=directory/(eid+'.enc')
    encrypted=cipher().encrypt(raw)
    with path.open('xb') as f: f.write(encrypted)
    path.chmod(0o400)
    digest=hashlib.sha256(raw).hexdigest()
    row={'_id':eid,'sha256':digest,'original_filename':Path(filename.replace('\\','/')).name[:255],
         'original_size':len(raw),'acquisition_time':now(),'uploaded_by':user_id,'source':source,
         'storage_location':str(path),'processing_history':[],'case_ids':[]}
    db.evidence.insert_one(row)
    custody(eid,'Evidence acquired and SHA-256 calculated',user_id,{'sha256':digest})
    return row

def original(evidence):
    path=Path(evidence['storage_location']).resolve()
    if not path.is_relative_to((DATA/'evidence').resolve()): raise ValueError('Invalid evidence storage path')
    raw=cipher().decrypt(path.read_bytes())
    if hashlib.sha256(raw).hexdigest()!=evidence['sha256']: raise ValueError('Evidence integrity mismatch')
    return raw

DEFAULTS={'max_upload_mb':10,'csv_row_limit':500,'alert_threshold':80,'mask_sensitive':False,
    'retention_enabled':False,'analysis_retention_days':365,'evidence_retention_days':730,'audit_retention_days':1095,
    'risk_weights':{'authentication':20,'sender_identity':15,'url':15,'attachment':10,'headers':5,'intelligence':20,'ai':15},
    'risk_thresholds':[30,60,80],'enabled_providers':['virustotal','abuseipdb','geoip'],
    'dns_enabled':False,'automatic_enrichment':False,'model_name':'production'}

def settings():
    saved=db.system_settings.find_one({'_id':'system'}) or {}
    return {**DEFAULTS,**{k:v for k,v in saved.items() if k!='_id'}}

def initialize():
    db.command('ping'); cipher()
    if len(os.getenv('JWT_SECRET',''))<32: raise RuntimeError('JWT_SECRET must contain at least 32 characters')
    indexes={'users':['email'],'emails':['evidence_id','created_at','sender','message_id','content_hash','status','severity','verdict','risk_score','countries','asns'],
        'email_analysis':['email_id','risk_score','verdict','created_at'],'evidence':['sha256','acquisition_time'],
        'cases':['status','assigned_to','created_at'],'iocs':['value','email_ids'],
        'jobs':['email_id','status','created_at'],'alerts':['email_id','status','created_at'],
        'reports':['case_id','created_at'],'audit_logs':['timestamp','resource_id'],
        'campaigns':['email_ids','created_at'],'threat_intelligence':['expires_at'],'sessions':['expires_at']}
    for collection,fields in indexes.items():
        for field in fields:
            if field != 'expires_at': db[collection].create_index(field, unique=collection=='users' and field=='email')
    db.sessions.create_index('expires_at',expireAfterSeconds=0,name='session_expiry')
    db.threat_intelligence.create_index('expires_at',expireAfterSeconds=0,name='intel_expiry')
