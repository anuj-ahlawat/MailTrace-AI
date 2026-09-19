import hashlib
import os
import secrets
from datetime import timedelta
from fastapi import HTTPException, Request, Depends
from jose import jwt, JWTError
from passlib.context import CryptContext
from .store import db, now, uid

passwords=CryptContext(schemes=['pbkdf2_sha256'],pbkdf2_sha256__rounds=600000)
ROLES=('ANALYST','SENIOR_ANALYST','ADMINISTRATOR')

def login_session(user):
    sid=uid(); csrf=secrets.token_urlsafe(32); expires=now()+timedelta(minutes=int(os.getenv('JWT_EXPIRE_MINUTES','480')))
    token=jwt.encode({'sub':user['_id'],'sid':sid,'exp':expires,'iss':'mailtrace','aud':'mailtrace'},os.environ['JWT_SECRET'],algorithm='HS256')
    db.sessions.insert_one({'_id':sid,'user_id':user['_id'],'csrf':hashlib.sha256(csrf.encode()).hexdigest(),'expires_at':expires})
    return token,csrf,expires

def current_user(request: Request):
    bearer=request.headers.get('authorization','')
    using_bearer=bearer.startswith('Bearer ')
    token=bearer[7:] if using_bearer else request.cookies.get('mt_session')
    if not token: raise HTTPException(401,'Not authenticated')
    try: claims=jwt.decode(token,os.environ['JWT_SECRET'],algorithms=['HS256'],audience='mailtrace',issuer='mailtrace')
    except (JWTError,KeyError): raise HTTPException(401,'Invalid or expired session')
    session=db.sessions.find_one({'_id':claims.get('sid'),'expires_at':{'$gt':now()}})
    user=db.users.find_one({'_id':claims.get('sub'),'status':'active'})
    if not session or not user or session['user_id']!=user['_id']: raise HTTPException(401,'Session expired or account inactive')
    if request.method not in ('GET','HEAD','OPTIONS') and not using_bearer:
        supplied=request.headers.get('x-csrf-token','')
        if not secrets.compare_digest(hashlib.sha256(supplied.encode()).hexdigest(),session['csrf']):
            raise HTTPException(403,'CSRF validation failed; sign in again')
    request.state.session_id=session['_id']
    request.state.user_id=user['_id']
    return user

def roles(*allowed):
    def check(user=Depends(current_user)):
        if user['role'] not in allowed: raise HTTPException(403,'Your role does not permit this operation')
        return user
    return check

admin=roles('ADMINISTRATOR')
senior=roles('SENIOR_ANALYST','ADMINISTRATOR')
