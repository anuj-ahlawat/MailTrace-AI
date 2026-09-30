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
        from backend.main import app
        from backend.database.store import db, uid, now, DEFAULTS, ROOT
        from backend.core.security import passwords
        from backend.workers.celery_app import dispatch
        self.assertTrue(Redis.from_url(os.environ['REDIS_URL']).ping())
        db.system_settings.replace_one({'_id':'system'}, {'_id':'system',**copy.deepcopy(DEFAULTS),
            'enabled_providers':[], 'automatic_enrichment':False,'dns_enabled':False,
            'alert_threshold':80},upsert=True)  # Old saved policy must not suppress HIGH alerts.
        password=secrets.token_urlsafe(24);email=uid()+'@mailtrace.ai'
        db.users.insert_one({'_id':uid(),'email':email,'name':'Isolated integration account','password_hash':passwords.hash(password),
            'role':'ADMINISTRATOR','status':'active','created_at':now()})
        results=[];model_predictions={}
        with TestClient(app) as client:
            self.assertEqual(client.get('/api/emails').status_code,401)
            self.assertEqual(client.post('/api/auth/login',json={'email':email,'password':password}).status_code,200)
            self.assertEqual(client.post('/api/cases',json={'title':'CSRF must reject'}).status_code,403)
            client.headers['X-CSRF-Token']=client.cookies.get('mt_csrf')
            readiness = client.get('/api/settings').json()['readiness']
            self.assertTrue(any(r['capability'] == 'Alerts before user interaction' and r['status'] == 'Requires mail-server integration' for r in readiness['items']))
            queued=[]
            for name in ('benign','phishing','bec','impersonation','suspicious_urls','phishing_no_received','mixed_hops','private_hops','public_ipv6','reserved_hops','spam'):
                raw=(Path(__file__).resolve().parents[1]/'fixtures'/(name+'.eml')).read_bytes()
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
                model_predictions[name]=copy.deepcopy(analysis['ml'])
                self.assertAlmostEqual(sum(analysis['ml']['probabilities'].values()),1,places=5)
                self.assertTrue(analysis['category'])
                self.assertEqual(round(sum(c['points'] for c in analysis['contributions'])),analysis['risk_score'])
                self.assertEqual(analysis['risk_version'],'2.2')
                self.assertEqual(analysis['origin_confidence']['engine_version'], '1.2')
                self.assertEqual(analysis['origin_confidence']['label'], 'Probable Network Origin')
                self.assertIn(analysis['origin_confidence']['level'], ('LOW','MEDIUM','HIGH'))
                self.assertLess(analysis['origin_confidence']['score'], 60)
                self.assertTrue(analysis['attribution']['findings'])
                if analysis['severity'] in ('HIGH', 'CRITICAL'):
                    self.assertIsNotNone(db.alerts.find_one({'email_id': item['email_id']}))
                if analysis['ml']['label'] in ('PHISHING','BEC'):
                    self.assertGreaterEqual(analysis['risk_score'],60 if analysis['ml']['confidence']>=.7 else 30)
                if name in ('phishing','bec','phishing_no_received'):self.assertGreaterEqual(analysis['risk_score'],60)
                if name=='benign':self.assertLess(analysis['risk_score'],30)
                if name=='phishing_no_received':self.assertEqual(analysis['geolocation']['status'],'Not Observable')
                if name in ('private_hops','reserved_hops'):
                    self.assertTrue(analysis['analyzed_hops'])
                    self.assertTrue(all(not r['location_available'] and r['location_reason'] for r in analysis['analyzed_hops']))
                if name=='mixed_hops':
                    self.assertEqual(len(analysis['mail_path']),4)
                    self.assertTrue(any(r['type']=='invalid' for r in analysis['analyzed_hops']))
                    self.assertTrue(any(r['type']=='private' for r in analysis['analyzed_hops']))
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
                for name,raw,item in queued:
                    if name not in ('benign','mixed_hops','public_ipv6'):continue
                    if name=='benign':
                        db.alerts.insert_one({'_id':item['email_id'],'email_id':item['email_id'],'severity':'CRITICAL','status':'RESOLVED','reason':['Old finding']})
                    response=client.post('/api/emails/'+item['email_id']+'/analyze')
                    self.assertEqual(response.status_code,202,response.text)
                    self.assertEqual(client.get('/api/emails/'+item['email_id']).json()['email']['status'],'Uploaded')
                    dispatch.delay();state=completed(response.json()['id'])
                    self.assertEqual(state['history'][0]['status'],'Uploaded')
                    analysis=client.get('/api/emails/'+item['email_id']+'/analysis').json()
                    self.assertEqual(analysis['ml'],model_predictions[name])
                    if name=='benign':
                        alert=db.alerts.find_one({'_id':item['email_id']})
                        self.assertEqual(alert['severity'],analysis['severity'])
                        self.assertEqual(alert['status'],'RESOLVED')
                    if name=='benign':self.assertEqual(analysis['geolocation']['status'],'Available')
                    public_rows=[r for r in analysis['analyzed_hops'] if r['type']=='public']
                    self.assertTrue(public_rows)
                    self.assertTrue(all(r['location_status'] in ('Available','Not Found') for r in public_rows))
                    self.assertTrue(all(r['location_available'] or r['location_reason'] for r in public_rows))
                    if name=='mixed_hops':self.assertGreaterEqual(len({r['ip'] for r in public_rows}),4)
                    print('Actual GeoIP coverage:',name,json.dumps([{k:r.get(k) for k in ('ip','type','location_status','location_available','location_reason','country','timezone')} for r in analysis['analyzed_hops']]))
                    self.assertEqual(client.get('/api/evidence/'+item['evidence_id']+'/download').content,raw)
            # A provider exception must not fail an API-uploaded analysis job.
            from unittest.mock import patch
            from backend.core.pipeline import process
            failure_job=client.post('/api/emails/upload',files={'file':('provider_failure.eml',queued[0][1],'message/rfc822')}).json()
            with patch('backend.intelligence.providers.lookup_provider',side_effect=TimeoutError('isolated provider timeout')):
                process(failure_job['job_id'])
            completed(failure_job['job_id'])
            failed_geo=client.get('/api/emails/'+failure_job['email_id']+'/analysis').json()
            self.assertTrue(all(not row['location_available'] for row in failed_geo['analyzed_hops']))
            case=client.post('/api/cases',json={'title':'Local stack integration — synthetic fixtures','email_ids':[i['email_id'] for _,_,i in queued]}).json()
            report=client.post('/api/reports',json={'case_id':case['id']}).json()
            dispatch.delay();completed(report['job_id'])
            pdf=client.get('/api/reports/'+report['id']+'/download?format=pdf')
            self.assertTrue(pdf.content.startswith(b'%PDF'))
            snapshot=client.get('/api/reports/'+report['id']+'/download?format=json').json()
            self.assertTrue({'Risk Score', 'Threat Intelligence', 'Evidence', 'Origin Confidence'} <= set(snapshot['sections']))
            self.assertEqual(snapshot['schema_version'],'3.0')
            self.assertEqual(len(snapshot['analyses']),len(queued))
            self.assertEqual(len(snapshot['original_artifacts']),len(queued))
            self.assertEqual(len(snapshot['evidence_hashes']),len(queued))
            self.assertTrue(all(s['version']=='2.2' for s in snapshot['sections']['Risk Score']))
            # Re-score saved findings without changing original bytes, model output,
            # or an already generated report snapshot. Repeat is a no-op.
            from backend.core.rescore import rescore_saved
            eid=queued[0][2]['email_id']
            previous=db.email_analysis.find_one({'_id':eid})
            db.email_analysis.update_one({'_id':eid},{'$set':{'risk_version':'2.0','risk_score':0}})
            self.assertEqual(rescore_saved(False,[eid])[0]['status'],'Preview')
            self.assertEqual(db.email_analysis.find_one({'_id':eid})['risk_score'],0)
            self.assertEqual(rescore_saved(True,[eid])[0]['status'],'Updated')
            refreshed=db.email_analysis.find_one({'_id':eid})
            self.assertEqual(refreshed['ml'],previous['ml'])
            self.assertEqual(refreshed['forensics'],previous['forensics'])
            self.assertEqual(refreshed['scoring_history'][-1]['previous']['risk_version'],'2.0')
            self.assertEqual(rescore_saved(True,[eid]),[])
            self.assertEqual(client.get('/api/reports/'+report['id']+'/download?format=json').json(),snapshot)
            # Lost workers must not leave email/report UI permanently processing.
            from datetime import timedelta
            from backend.core.pipeline import expire_jobs
            for collection,link in (('emails','email_id'),('reports','report_id')):
                identifier=uid();job_id=uid()
                db[collection].insert_one({'_id':identifier,'status':'Parsing'})
                db.jobs.insert_one({'_id':job_id,link:identifier,'status':'Claimed','created_at':now(),
                    'lease_until':now()-timedelta(minutes=1)})
                expire_jobs()
                self.assertEqual(db.jobs.find_one({'_id':job_id})['status'],'Failed')
                self.assertEqual(db[collection].find_one({'_id':identifier})['status'],'Failed')
            self.assertEqual(db.rate_limits.index_information()['expires_at_1']['expireAfterSeconds'],0)
            # Reject malformed inputs without server errors or creating evidence.
            for filename,content,mime,expected in [('empty.eml',b'','message/rfc822',422),('bad.exe',b'bad','application/octet-stream',422),('bad.csv',b'subject,body\nhello,\n','text/csv',422)]:
                self.assertEqual(client.post('/api/emails/upload',files={'file':(filename,content,mime)}).status_code,expected)
            # Real persistence and queue execution, with only Google's HTTP
            # responses replaced: no real mailbox is connected or read.
            import base64
            import backend.integrations.mailbox_monitor as mailbox_monitor
            user = db.users.find_one({'email': email})
            self.assertEqual(client.put('/api/gmail/monitor', json={'enabled': True}).status_code, 409)
            db.gmail_connections.insert_one({'_id': user['_id'], 'secret': 'test-only; token function is never invoked'})
            def google_response(_user, suffix, params=None):
                if suffix == '/profile': return {'historyId': '100'}
                if suffix == '/history': return {'historyId': '120', 'history': [{'messagesAdded': [{'message': {'id': 'synthetic1'}}]}]}
                if suffix == '/messages/synthetic1': return {'raw': base64.urlsafe_b64encode(queued[0][1]).decode()}
                raise AssertionError('Unexpected Gmail request: ' + suffix)
            with patch.object(mailbox_monitor, 'gmail_get', side_effect=google_response):
                self.assertEqual(client.put('/api/gmail/monitor', json={'enabled': True}).status_code, 200)
                mailbox_monitor.monitor_tick()
                imported = client.post('/api/gmail/emails/synthetic1/import')
                self.assertEqual(imported.status_code, 202, imported.text)
                self.assertTrue(imported.json()['already_imported'])
            status = client.get('/api/gmail/status').json()
            self.assertEqual(status['monitor']['imported_count'], 1)
            self.assertNotIn('secret', status)
            reference = {'kind': 'gmail', 'user_id': user['_id'], 'message_id': 'synthetic1'}
            self.assertEqual(db.emails.count_documents({'source_reference': reference}), 1)
            dispatch.delay(); completed(imported.json()['job_id'])
            self.assertEqual(client.put('/api/gmail/monitor', json={'enabled': False}).status_code, 200)
            self.assertFalse(client.get('/api/gmail/status').json()['monitor']['enabled'])
            self.assertEqual(client.post('/api/gmail/disconnect').status_code, 200)
            # Campaign search and retention preview protect campaign membership
            # without deleting anything during validation.
            campaign_title = 'SIH validation ' + uid()
            created = client.post('/api/campaigns', json={'title': campaign_title, 'email_ids': [imported.json()['email_id'], queued[0][2]['email_id']], 'reason': 'Synthetic test association only'})
            self.assertEqual(created.status_code, 200, created.text)
            found = client.get('/api/campaigns', params={'q': campaign_title}).json()
            self.assertEqual(found['total'], 1)
            eligible_before = client.get('/api/settings/retention/preview').json()['eligible_analysis_count']
            db.emails.update_one({'_id': imported.json()['email_id']}, {'$set': {'created_at': now() - timedelta(days=1000)}})
            before = db.emails.count_documents({})
            preview = client.get('/api/settings/retention/preview')
            self.assertEqual(preview.status_code, 200, preview.text)
            self.assertFalse(preview.json()['enabled'])
            self.assertEqual(preview.json()['eligible_analysis_count'], eligible_before)
            self.assertGreaterEqual(preview.json()['protected_case_or_campaign_emails'], len(queued) + 1)
            self.assertEqual(db.emails.count_documents({}), before)
            client.post('/api/auth/logout')
            self.assertEqual(client.get('/api/auth/me').status_code,401)
        output = ROOT / 'storage/temp/integration/results.json'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(results,indent=2))
        print('\nReal MongoDB + Redis/Celery results:',json.dumps(results))
