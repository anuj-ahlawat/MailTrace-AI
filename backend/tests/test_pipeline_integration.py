"""Opt-in checks against an isolated real MongoDB database and Redis/Celery worker.

Run only with the documented mailtrace_local_stack_validation database and broker.
Synthetic fixtures never enter the production database or external providers.
"""
import copy
import hashlib
import json
import os
import secrets
import time
import unittest
from pathlib import Path


@unittest.skipUnless(os.getenv('MAILTRACE_INTEGRATION') == '1', 'Opt-in real MongoDB/Redis workflow')
class PipelineIntegration(unittest.TestCase):
    def test_persisted_email_and_report_jobs_through_redis(self):
        self.assertEqual(os.environ.get('MONGODB_DB_NAME'), 'mailtrace_local_stack_validation')
        self.assertEqual(os.environ.get('REDIS_URL'), 'redis://127.0.0.1:16379/0')
        self.assertEqual(os.environ.get('WORKER_MODE'), 'celery')
        from fastapi.testclient import TestClient
        from redis import Redis
        from app.main import app
        from app.platform.store import db, uid, now, DEFAULTS, ROOT
        from app.platform.security import passwords
        from app.workers.celery_app import dispatch
        self.assertTrue(Redis.from_url(os.environ['REDIS_URL']).ping())
        db.system_settings.replace_one({'_id':'system'}, {'_id':'system',**copy.deepcopy(DEFAULTS),
            'enabled_providers':[], 'automatic_enrichment':False,'dns_enabled':False},upsert=True)
        password=secrets.token_urlsafe(24);email=uid()+'@mailtrace.ai'
        db.users.insert_one({'_id':uid(),'email':email,'name':'Isolated integration account','password_hash':passwords.hash(password),
            'role':'ADMINISTRATOR','status':'active','created_at':now()})
        results=[]
        with TestClient(app) as client:
            self.assertEqual(client.get('/api/emails').status_code,401)
            self.assertEqual(client.post('/api/auth/login',json={'email':email,'password':password}).status_code,200)
            self.assertEqual(client.post('/api/cases',json={'title':'CSRF must reject'}).status_code,403)
            client.headers['X-CSRF-Token']=client.cookies.get('mt_csrf')
            queued=[]
            for name in ('benign','phishing','bec','impersonation','suspicious_urls','phishing_no_received'):
                raw=(Path(__file__).parent/'fixtures'/(name+'.eml')).read_bytes()
                response=client.post('/api/emails/upload',files={'file':(name+'.eml',raw,'message/rfc822')})
                self.assertEqual(response.status_code,202,response.text)
                queued.append((name,raw,response.json()))
            def completed(job):
                deadline=time.monotonic()+120
                while time.monotonic()<deadline:
                    state=client.get('/api/jobs/'+job).json()
                    if state['status'] in ('Completed','Failed'):break
                    time.sleep(.25)
                self.assertEqual(state['status'],'Completed',state)
                return state
            dispatch.delay()  # A real broker message, consumed by the separately running worker.
            for name,raw,item in queued:
                state=completed(item['job_id'])
                self.assertEqual([h['status'] for h in state['history']], ['Uploaded','Parsing','Forensics','AI Analysis','Threat Intelligence','Correlation','Completed'])
                record=client.get('/api/emails/'+item['email_id']).json()
                analysis=record['analysis'];self.assertEqual(analysis['ml']['status'],'Available')
                self.assertAlmostEqual(sum(analysis['ml']['probabilities'].values()),1,places=5)
                self.assertTrue(analysis['category'])
                self.assertEqual(round(sum(c['points'] for c in analysis['contributions'])),analysis['risk_score'])
                if name in ('phishing','bec','phishing_no_received'):self.assertGreaterEqual(analysis['risk_score'],60)
                if name=='benign':self.assertLess(analysis['risk_score'],30)
                if name=='phishing_no_received':self.assertEqual(analysis['geolocation']['status'],'Not Observable')
                self.assertTrue(all(p['result'] is None for i in analysis['intelligence'] for p in i['providers']))
                self.assertEqual(client.get('/api/evidence/'+item['evidence_id']+'/download').content,raw)
                self.assertEqual(client.post('/api/evidence/'+item['evidence_id']+'/verify').json()['status'],'VERIFIED')
                evidence=db.evidence.find_one({'_id':item['evidence_id']})
                self.assertEqual(evidence['sha256'],hashlib.sha256(raw).hexdigest())
                self.assertNotEqual(Path(evidence['storage_location']).read_bytes(),raw)
                self.assertTrue(client.get('/api/graph/'+item['email_id']).json()['nodes'])
                results.append({'fixture':name,'verdict':analysis['verdict'],'category':analysis['category'],'risk_score':analysis['risk_score'],'confidence':analysis['confidence'],'job_status':state['status']})
            # Reanalysis uses the same evidence, and local GeoIP can run with all
            # external reputation requests disabled when real databases exist.
            if os.path.isfile(os.getenv('GEOIP_CITY_DB','')):
                configured={**copy.deepcopy(DEFAULTS),'enabled_providers':['geoip'],'automatic_enrichment':False,'dns_enabled':False}
                self.assertEqual(client.put('/api/settings',json=configured).status_code,200)
                item=queued[0][2]
                response=client.post('/api/emails/'+item['email_id']+'/analyze')
                self.assertEqual(response.status_code,202,response.text)
                self.assertEqual(client.get('/api/emails/'+item['email_id']).json()['email']['status'],'Uploaded')
                dispatch.delay();state=completed(response.json()['id'])
                self.assertEqual(state['history'][0]['status'],'Uploaded')
                analysis=client.get('/api/emails/'+item['email_id']+'/analysis').json()
                self.assertEqual(analysis['geolocation']['status'],'Available')
                self.assertEqual(client.get('/api/evidence/'+item['evidence_id']+'/download').content,queued[0][1])
            case=client.post('/api/cases',json={'title':'Local stack integration — synthetic fixtures','email_ids':[i['email_id'] for _,_,i in queued]}).json()
            report=client.post('/api/reports',json={'case_id':case['id']}).json()
            dispatch.delay();completed(report['job_id'])
            pdf=client.get('/api/reports/'+report['id']+'/download?format=pdf')
            self.assertTrue(pdf.content.startswith(b'%PDF'))
            snapshot=client.get('/api/reports/'+report['id']+'/download?format=json').json()
            self.assertEqual(len(snapshot['sections']),26)
            self.assertEqual(len(snapshot['evidence_hashes']),len(queued))
            client.post('/api/auth/logout')
            self.assertEqual(client.get('/api/auth/me').status_code,401)
        (ROOT/'tmp'/'local-stack-integration-results.json').write_text(json.dumps(results,indent=2))
        print('\nReal MongoDB + Redis/Celery results:',json.dumps(results))
