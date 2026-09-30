"""Search."""
import re
from fastapi import APIRouter, Depends, Query
from backend.database.store import db, clean
from backend.core.security import current_user, admin
from backend.api.dependencies import output

router = APIRouter()

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

