"""MailTrace enterprise API entry point."""
import logging
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI,Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import PyMongoError
from app.platform.store import initialize,db,client
from app.platform.pipeline import dispatch_loop
from app.platform.api import router

logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger=logging.getLogger('mailtrace.api')
logging.getLogger('httpx').setLevel(logging.WARNING)

@asynccontextmanager
async def lifespan(app):
    initialize()
    for name in ['rate_limits','oauth_states']:db[name].create_index('expires_at',expireAfterSeconds=0)
    stop=threading.Event();thread=None
    if os.getenv('WORKER_MODE','local')=='local':
        thread=threading.Thread(target=dispatch_loop,args=(stop,),daemon=True);thread.start()
    yield
    stop.set()
    if thread:thread.join(timeout=5)
    client.close()

app=FastAPI(title='MailTrace AI',version='2.0.0',lifespan=lifespan,docs_url='/docs')
app.add_middleware(CORSMiddleware,allow_origins=os.getenv('CORS_ORIGINS','http://localhost:3000').split(','),
    allow_credentials=True,allow_methods=['GET','POST','PUT','PATCH','DELETE'],allow_headers=['Content-Type','Authorization','X-CSRF-Token'])
app.include_router(router)
from app.platform.gmail import router as gmail_router
app.include_router(gmail_router)

@app.middleware('http')
async def request_context(request:Request,call_next):
    request_id=str(uuid.uuid4());start=time.monotonic()
    length=request.headers.get('content-length')
    if length and (not length.isdigit() or int(length)>30*1024*1024):return JSONResponse({'detail':'Request too large'},status_code=413)
    if request.method in ('POST','PUT','PATCH'):
        chunks=[];total=0
        async for chunk in request.stream():
            total+=len(chunk)
            if total>30*1024*1024:return JSONResponse({'detail':'Request too large'},status_code=413)
            chunks.append(chunk)
        request._body=b''.join(chunks)
    try:response=await call_next(request)
    except PyMongoError:
        response=JSONResponse({'detail':'Database unavailable','request_id':request_id},status_code=503)
    except Exception as exc:
        logger.error('request_failed request_id=%s error_type=%s',request_id,type(exc).__name__)
        response=JSONResponse({'detail':'Operation unavailable','request_id':request_id},status_code=500)
    response.headers.update({'X-Request-ID':request_id,'X-Content-Type-Options':'nosniff','Cache-Control':'no-store',
        'Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'})
    route=getattr(request.scope.get('route'),'path','unmatched')
    logger.info('request request_id=%s user_id=%s operation=%s route=%s status=%s duration_ms=%d',request_id,
        getattr(request.state,'user_id','anonymous'),request.method,route,response.status_code,int((time.monotonic()-start)*1000))
    return response

@app.get('/health')
def health():
    try:db.command('ping');return {'status':'Available','database':'Connected','worker_mode':os.getenv('WORKER_MODE','local')}
    except PyMongoError:return JSONResponse({'status':'Unavailable','database':'Unavailable'},status_code=503)
