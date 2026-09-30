"""Read-only service health."""
import os
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pymongo.errors import PyMongoError
from backend.database.store import db

router = APIRouter()

@router.get('/health')
def health():
    try:db.command('ping');return {'status':'Available','database':'Connected','worker_mode':os.getenv('WORKER_MODE','local')}
    except PyMongoError:return JSONResponse({'status':'Unavailable','database':'Unavailable'},status_code=503)
