"""Generate local secrets and provision the first administrator without demo records."""
import argparse,os,secrets,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
from cryptography.fernet import Fernet
ap=argparse.ArgumentParser();ap.add_argument('--admin-email',default='admin@mailtrace.ai');ap.add_argument('--create-admin',action='store_true');args=ap.parse_args()
path=ROOT/'.env'
if not path.exists() and os.getenv('JWT_SECRET') and os.getenv('EVIDENCE_ENCRYPTION_KEY'):
    print('Using secrets supplied by the runtime environment.')
elif not path.exists():
    text=(ROOT/'.env.example').read_text()
    for key,value in {'JWT_SECRET':secrets.token_urlsafe(48),'EVIDENCE_ENCRYPTION_KEY':Fernet.generate_key().decode(),
            'MONGO_ROOT_PASSWORD':secrets.token_hex(24),'MONGO_APP_PASSWORD':secrets.token_hex(24),'REDIS_PASSWORD':secrets.token_hex(24)}.items():
        text=text.replace(key+'=\n',key+'='+value+'\n')
    path.write_text(text);path.chmod(0o600);print('Created private .env; no secrets printed.')
else:print('Existing .env preserved.')
if args.create_admin:
    from email_validator import validate_email
    admin_email=validate_email(args.admin_email,check_deliverability=False).normalized.lower()
    from app.platform.store import db,initialize,now,uid,DATA,event
    from app.platform.security import passwords
    initialize()
    if db.users.count_documents({'role':'ADMINISTRATOR','status':'active'}):print('An administrator already exists; no account changed.')
    else:
        password=secrets.token_urlsafe(24)
        row={'_id':uid(),'email':admin_email,'name':'Administrator','role':'ADMINISTRATOR','status':'active','password_hash':passwords.hash(password),'created_at':now()}
        db.users.insert_one(row);event('Initial administrator provisioned',row,'user',row['_id'])
        DATA.mkdir(parents=True,exist_ok=True,mode=0o700);credentials=DATA/'bootstrap-admin.txt'
        credentials.write_text('MailTrace initial administrator\nEmail: '+row['email']+'\nPassword: '+password+'\nChange this password after signing in.\n');credentials.chmod(0o600)
        print('Administrator provisioned. Credentials stored privately at',credentials)
