"""Read-only Gmail OAuth import with expiring state and encrypted tokens."""
import hashlib,json,os,secrets
from datetime import timedelta
from urllib.parse import urlencode
import httpx
from fastapi import APIRouter,Depends,HTTPException
from fastapi.responses import RedirectResponse
from backend.core.security import current_user
from backend.database.store import db, now, cipher, event
from pydantic import BaseModel
from backend.integrations.mailbox_monitor import import_message, set_monitor
router=APIRouter(prefix='/api')
def configured():return bool(os.getenv('GOOGLE_CLIENT_ID') and os.getenv('GOOGLE_CLIENT_SECRET'))
def redirect_uri():return os.getenv('GOOGLE_REDIRECT_URI','http://localhost:3000/api/gmail/callback')
@router.get('/gmail/status')
def status(user=Depends(current_user)):
    row=db.gmail_connections.find_one({'_id':user['_id']}) or {}
    monitor=row.get('monitor') or {}
    return {'status':'Configured' if configured() else 'Not Configured','connected':bool(row),'scope':'gmail.readonly',
            'monitor':{k:monitor.get(k) for k in ('enabled','status','last_checked_at','next_poll_at','imported_count','skipped_count')},'poll_interval_seconds':60}
@router.post('/gmail/connect')
def connect(user=Depends(current_user)):
    if not configured():raise HTTPException(503,'Gmail: Not Configured')
    state=secrets.token_urlsafe(32)
    db.oauth_states.insert_one({'_id':hashlib.sha256(state.encode()).hexdigest(),'user_id':user['_id'],'expires_at':now()+timedelta(minutes=10)})
    query={'client_id':os.environ['GOOGLE_CLIENT_ID'],'redirect_uri':redirect_uri(),'response_type':'code','scope':'https://www.googleapis.com/auth/gmail.readonly','access_type':'offline','prompt':'consent','state':state}
    event('Gmail authorization requested',user)
    return {'url':'https://accounts.google.com/o/oauth2/v2/auth?'+urlencode(query)}
@router.get('/gmail/callback')
def callback(state:str,code:str='',error:str=''):
    stored=db.oauth_states.find_one_and_delete({'_id':hashlib.sha256(state.encode()).hexdigest(),'expires_at':{'$gt':now()}})
    if not stored:raise HTTPException(400,'Invalid or expired OAuth state')
    if error or not code:raise HTTPException(400,'Gmail authorization was not completed')
    r=httpx.post('https://oauth2.googleapis.com/token',data={'client_id':os.environ['GOOGLE_CLIENT_ID'],'client_secret':os.environ['GOOGLE_CLIENT_SECRET'],'redirect_uri':redirect_uri(),'code':code,'grant_type':'authorization_code'},timeout=15)
    if r.status_code!=200:raise HTTPException(502,'Gmail token exchange failed')
    data=r.json();data['expires_at']=(now()+timedelta(seconds=data.get('expires_in',3600))).isoformat()
    db.gmail_connections.replace_one({'_id':stored['user_id']},{'_id':stored['user_id'],'secret':cipher().encrypt(json.dumps(data).encode()).decode()},upsert=True)
    event('Gmail connected',{'_id':stored['user_id']})
    return RedirectResponse('/gmail-inbox',status_code=303)
def token(user):
    row=db.gmail_connections.find_one({'_id':user['_id']})
    if not row:raise HTTPException(409,'Connect Gmail first')
    data=json.loads(cipher().decrypt(row['secret'].encode()))
    if data['expires_at']<now().isoformat():
        if not data.get('refresh_token'):raise HTTPException(409,'Reconnect Gmail to renew authorization')
        r=httpx.post('https://oauth2.googleapis.com/token',data={'client_id':os.environ['GOOGLE_CLIENT_ID'],'client_secret':os.environ['GOOGLE_CLIENT_SECRET'],'refresh_token':data['refresh_token'],'grant_type':'refresh_token'},timeout=15)
        if r.status_code!=200:raise HTTPException(502,'Gmail refresh failed; reconnect your account')
        data.update(r.json());data['expires_at']=(now()+timedelta(seconds=data.get('expires_in',3600))).isoformat()
        db.gmail_connections.update_one({'_id':user['_id']},{'$set':{'secret':cipher().encrypt(json.dumps(data).encode()).decode()}})
    return data['access_token']
@router.get('/gmail/emails')
def emails(page_token:str='',user=Depends(current_user)):
    with httpx.Client(timeout=15,headers={'Authorization':'Bearer '+token(user)}) as client:
        r=client.get('https://gmail.googleapis.com/gmail/v1/users/me/messages',params={'maxResults':20,'pageToken':page_token})
        if r.status_code!=200:raise HTTPException(502,'Gmail inbox unavailable')
        rows=[]
        for item in r.json().get('messages',[]):
            detail=client.get('https://gmail.googleapis.com/gmail/v1/users/me/messages/'+item['id'],params={'format':'metadata'})
            if detail.status_code!=200:continue
            headers={h['name'].lower():h['value'] for h in detail.json().get('payload',{}).get('headers',[])}
            rows.append({'id':item['id'],'subject':headers.get('subject',''),'sender':headers.get('from',''),'date':headers.get('date','')})
    from backend.api.dependencies import output
    return output({'items':rows,'next_page_token':r.json().get('nextPageToken')},user)
@router.post('/gmail/emails/{message_id}/import',status_code=202)
def import_email(message_id:str,user=Depends(current_user)):
    return import_message(user,message_id)

class MonitorSettings(BaseModel):
    enabled:bool

@router.put('/gmail/monitor')
def monitor(data:MonitorSettings,user=Depends(current_user)):
    return set_monitor(user,data.enabled)

@router.post('/gmail/disconnect')
def disconnect(user=Depends(current_user)):
    db.gmail_connections.delete_one({'_id':user['_id']});event('Gmail disconnected',user);return {'status':'Disconnected'}
