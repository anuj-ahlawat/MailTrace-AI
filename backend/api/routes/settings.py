"""Settings."""
import os
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from backend.database.store import db, now, settings, DEFAULTS, event, cipher
from backend.core.security import admin
from backend.intelligence.providers import statuses, provider_health
from backend.detection.inference import ml_service, clear_model_cache, model_catalog
from backend.schemas.requests import ProviderKey, SystemUpdate

router = APIRouter()

@router.get('/settings')
def system_settings(user=Depends(admin)):
    from backend.core.readiness import deployment_readiness
    config = settings(); provider_states = statuses(); model = ml_service()
    readiness = deployment_readiness(config, model.status, provider_states,
        bool(os.getenv('GOOGLE_CLIENT_ID') and os.getenv('GOOGLE_CLIENT_SECRET')),
        db.gmail_connections.count_documents({'monitor.enabled': True}))
    return {'settings':config,'providers':provider_states,'provider_health':provider_health(),
            'available_models':model_catalog(),'model':model.metadata,'worker_mode':os.getenv('WORKER_MODE','local'),
            'readiness':readiness}


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
def save_key(provider:Literal['virustotal','abuseipdb','urlscan','greynoise','geoip','ipinfo'],data:ProviderKey,user=Depends(admin)):
    db.provider_secrets.replace_one({'_id':provider},{'_id':provider,'secret':cipher().encrypt(data.api_key.encode()).decode(),'updated_at':now()},upsert=True)
    event('Provider credential changed',user,'provider',provider);return {'provider':provider,'status':statuses()[provider]}


@router.delete('/settings/providers/{provider}')
def remove_key(provider:Literal['virustotal','abuseipdb','urlscan','greynoise','geoip','ipinfo'],user=Depends(admin)):
    db.provider_secrets.delete_one({'_id':provider});event('Stored provider credential removed',user,'provider',provider)
    return {'provider':provider,'status':statuses()[provider]}


@router.post('/settings/model/reload')
def reload_model(user=Depends(admin)):
    clear_model_cache();event('Model reloaded',user);return {'status':ml_service().status}


@router.post('/settings/retention/run')
def retention(user=Depends(admin)):
    from backend.core.retention import apply_retention
    return apply_retention()


@router.get('/settings/retention/preview')
def retention_preview(user=Depends(admin)):
    from backend.core.retention import preview_retention
    return preview_retention()

