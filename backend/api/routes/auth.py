"""Auth."""
import os
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pymongo.errors import DuplicateKeyError
from backend.database.store import db, now, uid, clean, event
from backend.core.security import current_user, admin, passwords, login_session
from backend.schemas.requests import Login, NewUser, UserUpdate, PasswordChange
from backend.api.dependencies import get, rate_limit

router = APIRouter()

@router.post('/auth/login')
def login(data:Login,request:Request,response:Response):
    ip=request.client.host if request.client else 'unknown';rate_limit('login-ip:'+ip,30);rate_limit('login-account:'+str(data.email).lower(),10)
    user=db.users.find_one({'email':str(data.email).lower(),'status':'active'})
    valid=passwords.verify(data.password,user['password_hash'] if user else passwords.hash('nonexistent-account-password'))
    if not user or not valid:
        event('Login failed',ip=ip);raise HTTPException(401,'Invalid email or password')
    token,csrf,expires=login_session(user)
    secure=os.getenv('COOKIE_SECURE','false').lower()=='true'
    age=int((expires-now()).total_seconds())
    response.set_cookie('mt_session',token,httponly=True,secure=secure,samesite='lax',max_age=age,path='/')
    response.set_cookie('mt_csrf',csrf,httponly=False,secure=secure,samesite='lax',max_age=age,path='/')
    db.users.update_one({'_id':user['_id']},{'$set':{'last_login':now()}});event('Login',user,ip=ip)
    return {'user':clean(user)}


@router.get('/auth/me')
def me(user=Depends(current_user)):return clean(user)


@router.post('/auth/logout')
def logout(request:Request,response:Response,user=Depends(current_user)):
    db.sessions.delete_one({'_id':request.state.session_id})
    response.delete_cookie('mt_session',path='/');response.delete_cookie('mt_csrf',path='/');event('Logout',user)
    return {'status':'Signed out'}


@router.post('/auth/password')
def change_password(data:PasswordChange,user=Depends(current_user)):
    if not passwords.verify(data.current_password,user['password_hash']):raise HTTPException(403,'Current password is incorrect')
    db.users.update_one({'_id':user['_id']},{'$set':{'password_hash':passwords.hash(data.new_password)}})
    db.sessions.delete_many({'user_id':user['_id']});event('Password changed and sessions revoked',user)
    return {'status':'Password changed; sign in again'}


@router.get('/users')
def users(user=Depends(admin)):return {'items':clean(list(db.users.find({}).limit(500)))}


@router.post('/auth/register')
@router.post('/users',status_code=201)
def new_user(data:NewUser,user=Depends(admin)):
    row={'_id':uid(),'name':data.name,'email':str(data.email).lower(),'password_hash':passwords.hash(data.password),
         'role':data.role,'status':'active','created_at':now()}
    try:db.users.insert_one(row)
    except DuplicateKeyError:raise HTTPException(409,'Email already registered')
    event('User created',user,'user',row['_id'],{'role':data.role});return clean(row)


@router.patch('/users/{user_id}')
def update_user(user_id:str,data:UserUpdate,user=Depends(admin)):
    get('users',user_id);changes=data.model_dump(exclude_none=True)
    if user_id==user['_id'] and ('role' in changes or changes.get('status')=='inactive'):raise HTTPException(409,'Cannot remove your own administrative access')
    db.users.update_one({'_id':user_id},{'$set':changes});db.sessions.delete_many({'user_id':user_id})
    event('User changed',user,'user',user_id,changes);return clean(get('users',user_id))

