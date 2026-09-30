"""Intelligence."""
import re
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from backend.database.store import event
from backend.core.security import current_user
from backend.intelligence.providers import statuses, lookup, provider_health
from backend.schemas.requests import Indicator
from backend.api.dependencies import output, collection_page, rate_limit

router = APIRouter()

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

