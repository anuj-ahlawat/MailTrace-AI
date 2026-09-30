"""Dependencies."""
import hashlib
from datetime import timedelta
from fastapi import HTTPException
from backend.database.store import db, now, clean, settings

def get(collection,identifier):
    row=db[collection].find_one({'_id':identifier})
    if not row:raise HTTPException(404,'Record not found')
    return row


def output(row,user):
    value=clean(row)
    if user['role']=='ANALYST' and settings()['mask_sensitive']:
        from backend.core.privacy import mask_sensitive
        value=mask_sensitive(value)
    return value


def collection_page(collection,user,skip=0,limit=25,query=None):
    query=query or {}
    return {'items':output(list(db[collection].find(query).sort('created_at',-1).skip(skip).limit(limit)),user),
            'total':db[collection].count_documents(query),'skip':skip,'limit':limit}


def rate_limit(key,limit=10,seconds=300):
    window=int(now().timestamp())//seconds;identifier=hashlib.sha256(f'{key}:{window}'.encode()).hexdigest()
    row=db.rate_limits.find_one_and_update({'_id':identifier},{'$inc':{'count':1},'$setOnInsert':{'expires_at':now()+timedelta(seconds=seconds*2)}},upsert=True,return_document=True)
    if row['count']>limit:raise HTTPException(429,'Rate limited; try again later',headers={'Retry-After':str(seconds)})

