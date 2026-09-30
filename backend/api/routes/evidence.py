"""Evidence."""
import hashlib
from fastapi import APIRouter, Depends, HTTPException, Response, Query
from backend.database.store import now, clean, settings, custody, original
from backend.core.security import current_user
from backend.api.dependencies import get, output, collection_page

router = APIRouter()

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

