"""Alerts."""
from fastapi import APIRouter, Depends, Query
from backend.database.store import db, now, event
from backend.core.security import current_user
from backend.schemas.requests import AlertUpdate
from backend.api.dependencies import get, output, collection_page

router = APIRouter()

@router.get('/alerts')
def alerts(skip:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100),status:str|None=None,user=Depends(current_user)):
    return collection_page('alerts',user,skip,limit,{'status':status} if status else {})


@router.patch('/alerts/{alert_id}')
def change_alert(alert_id:str,data:AlertUpdate,user=Depends(current_user)):
    get('alerts',alert_id);db.alerts.update_one({'_id':alert_id},{'$set':{'status':data.status,'updated_at':now(),'updated_by':user['_id']}})
    event('Alert status changed',user,'alert',alert_id,{'status':data.status});return output(get('alerts',alert_id),user)

