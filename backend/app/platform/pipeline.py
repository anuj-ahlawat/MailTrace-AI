"""Durable analysis stages and evidence-backed risk / infrastructure correlation."""
import hashlib
import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from .store import db,now,uid,settings,preserve,original,custody,event
from .forensics import parse,ip_kind
from .authentication import enrich_authentication
from .intelligence import lookup,malicious_signals,statuses
from app.ml.service import ml_service

logger=logging.getLogger('mailtrace.pipeline')

def correlation_rules(parsed,config):
    """Explicit review policy, not learned probabilities or external reputation.

    Require several observations together. Absent authentication, geography or
    provider responses never count as positive or negative threat evidence.
    """
    text=parsed['model_text'].lower()
    credential=re.search(r'\b(?:verify|confirm|validate|update|reset)\b.{0,70}\b(?:account|password|credentials|identity)\b|\b(?:sign|log)\s*in\b',text)
    pressure=re.search(r'\burgent\b|\bimmediately\b|\bwithin\s+\d+\s+hours?\b|\bsuspend\w*\b|\brestrictions?\b|\bconfidential\b',text)
    identity=parsed['sender_identity']
    sender_domains={identity.get('sender_domain'),identity.get('reply_to_domain')}
    identity_evidence=identity.get('display_name_mismatch',[])+[x for x in identity.get('lookalikes',[]) if x['observed_domain'] in sender_domains]
    if identity.get('reply_to_mismatch'):identity_evidence=identity_evidence+[{'reply_to_domain':identity['reply_to_domain'],'sender_domain':identity['sender_domain']}]
    rules=[];weights=config['risk_weights']
    if weights.get('url',0)>0 and weights.get('sender_identity',0)>0:
        deceptive=[u for u in parsed['urls'] if any(s['type'] in ('lookalike_domain','display_href_mismatch','url_userinfo') for s in u.get('signals',[]))]
        if credential and deceptive and (identity_evidence or pressure):
            rules.append({'id':'credential_lure_with_deception','minimum_score':75,'verdict':'PHISHING','category':'CREDENTIAL_THEFT',
                'reason':'Credential request combined with a deceptive destination and identity inconsistency or pressure',
                'evidence':{'credential_request':credential.group(),'deceptive_urls':deceptive,'identity':identity_evidence,'pressure':pressure.group() if pressure else None}})
    payment=re.search(r'\b(?:bank|payment) details\b|\bbeneficiary\b|\bwire transfer\b',text)
    change=re.search(r'\b(?:new|updated|changed)\b',text)
    secrecy=re.search(r'\bconfidential\b|\bsecret\b|\bdo not (?:call|tell|discuss)\b',text)
    if weights.get('sender_identity',0)>0 and payment and change and pressure and secrecy:
        rules.append({'id':'payment_redirection_with_pressure','minimum_score':75 if identity_evidence else 60,'verdict':'BEC','category':'BUSINESS_EMAIL_COMPROMISE',
            'reason':'Changed payment instructions combined with urgency and secrecy; review possible BEC',
            'evidence':{'payment':payment.group(),'change':change.group(),'pressure':pressure.group(),'secrecy':secrecy.group(),'identity':identity_evidence}})
    return rules

def risk(parsed,ml,enrichment,config):
    signals=[]
    def add(category,severity,reason,evidence,source='Forensic'):
        signals.append({'category':category,'strength':severity,'reason':reason,'evidence':evidence,'source':source})
    failures=[k for k,v in parsed['authentication'].items() if v.get('reported_result') in ('FAIL','SOFTFAIL')]
    if failures:add('authentication',min(.3,len(failures)*.1),'Supplied headers report authentication failures; not independently verified',failures)
    verified=parsed['authentication']['dkim'].get('local_verification',{})
    if verified.get('status')=='FAIL':add('authentication',.35,'DKIM did not validate against the preserved message; forwarding or modification can also invalidate a signature',verified,'Local DKIM verification')
    identity=parsed['sender_identity']
    if identity['reply_to_mismatch']:add('sender_identity',.4,'Reply-To registered domain differs from sender',identity)
    if identity['lookalikes']:add('sender_identity',.6,'Potential lookalike domains',identity['lookalikes'])
    if identity.get('display_name_mismatch'):add('sender_identity',.4,'Brand in display name differs from sender domain; review possible impersonation',identity['display_name_mismatch'])
    for url in parsed['urls']:
        strength=min(1,sum(s['strength'] for s in url.get('signals',[]))) if 'signals' in url else min(1,len(url['flags'])*.2)
        if strength:add('url',strength,'Local URL evidence warrants review; no single heuristic establishes maliciousness',url)
    for attachment in parsed['attachments']:
        if attachment['flags']:add('attachment',1 if 'Executable or script' in attachment['flags'] else .5,'Attachment type warrants review; no malware verdict',attachment)
    if parsed['anomalies']:add('headers',.5,'Potential relay timestamp anomaly',parsed['anomalies'])
    bad=malicious_signals(enrichment)
    # Repeated hits from the same provider do not become independent corroboration.
    provider_strength={}
    for evidence in bad:provider_strength[evidence['provider']]=max(provider_strength.get(evidence['provider'],0),evidence['strength'])
    for provider,strength in provider_strength.items():
        add('intelligence',strength,'Bounded provider reputation evidence; not an email verdict',[b for b in bad if b['provider']==provider],'Threat intelligence')
    if ml['status']=='Available':
        threat=ml['probabilities']['PHISHING']+ml['probabilities']['BEC']+.4*ml['probabilities']['SPAM']
        add('ai',threat,'Model-derived threat probability (not a forensic fact)',ml['probabilities'],'AI')
    weights=config['risk_weights'];contributions=[]
    for key,weight in weights.items():
        strengths=[s['strength'] for s in signals if s['category']==key]
        # Repeating the same weak URL pattern must not create corroboration.
        strength=min(1,max(strengths,default=0) if key=='url' else sum(strengths))
        contributions.append({'category':key,'maximum_points':weight,'strength':round(strength,4),'points':round(weight*strength,2)})
    weighted_score=min(100,sum(c['points'] for c in contributions))
    rules=correlation_rules(parsed,config)
    strongest=max(rules,key=lambda r:r['minimum_score'],default=None)
    floor=strongest['minimum_score'] if strongest else 0
    adjustment=round(max(0,floor-weighted_score),2)
    if adjustment:
        contributions.append({'category':'correlated_evidence','maximum_points':round(100-weighted_score,2),'strength':round(adjustment/(100-weighted_score),4),'points':adjustment})
    score=min(100,round(weighted_score+adjustment))
    low,high,critical=config['risk_thresholds']
    severity='CRITICAL' if score>=critical else 'HIGH' if score>=high else 'MEDIUM' if score>=low else 'LOW'
    category,category_basis=threat_category(parsed,ml)
    verdict=strongest['verdict'] if strongest else ml.get('label') or 'Unknown'
    if strongest:category,category_basis=strongest['category'],strongest['reason']+'; heuristic finding, not proof'
    for rule in rules:add('correlated_evidence',rule['minimum_score']/100,rule['reason'],rule['evidence'],'Local correlation rule: '+rule['id'])
    confidence=ml.get('confidence') if verdict==ml.get('label') else None
    return {'category':category,'category_basis':category_basis,'confidence':confidence,'confidence_source':'ML class probability only' if confidence is not None else 'Uncalibrated local rule; no probability assigned',
        'risk_score':score,'severity':severity,'contributions':contributions,'signals':signals,'risk_version':'2.0',
        'weighted_score':round(weighted_score,2),'correlation_rules':rules,
        'verdict':verdict,'verdict_source':'Local evidence correlation'+(' and ML inference' if verdict==ml.get('label') else '; model prediction retained separately') if strongest else 'ML inference' if ml['status']=='Available' else 'Model unavailable',
        'formula':'Maximum of weighted evidence score and strongest matched correlation-rule minimum; repeated URL signals use the strongest URL only',
        'interpretation':'Policy-based review priority, not a probability. Missing evidence does not indicate safety. Model prediction and correlation rules are shown separately.'}

def threat_category(parsed,ml):
    text=parsed['model_text'].lower()
    credential_links=any(any(s['type']=='credential_keywords' for s in u.get('signals',[])) for u in parsed['urls'])
    if ml.get('label')=='BEC':return 'BUSINESS_EMAIL_COMPROMISE','ML-derived category; inspect payment instructions and sender identity'
    if ml.get('label')=='PHISHING' and credential_links:return 'CREDENTIAL_THEFT','Phishing model verdict plus locally observed credential-link wording; analyst review required'
    identity=parsed['sender_identity']
    if identity['lookalikes'] or identity.get('display_name_mismatch'):return 'POSSIBLE_IMPERSONATION','Local identity/lookalike evidence; ownership and intent are not established'
    if re.search(r'wire transfer|bank details|payment details|beneficiary|gift cards',text) and re.search(r'changed|new|urgent|confidential|today',text):return 'PAYMENT_REDIRECTION_REVIEW','Payment and urgency/change wording observed locally; this does not override the ML verdict'
    if ml.get('label')=='PHISHING':return 'PHISHING','ML-derived category'
    if ml.get('label')=='SPAM':return 'UNSOLICITED_EMAIL','ML-derived category'
    if any(sum(s['strength'] for s in u.get('signals',[]))>=.4 for u in parsed['urls']):return 'SUSPICIOUS_LINK_REVIEW','Multiple local link indicators require review even when the ML prediction is benign'
    if re.search(r'wire transfer|bank details|payment details|beneficiary|gift cards',text):return 'PAYMENT_REQUEST_REVIEW','Payment wording observed locally; not a BEC verdict'
    return 'NO_SPECIFIC_CATEGORY','No specific threat category established by available evidence'

def geolocation_summary(parsed,enrichment):
    public=[i for i in parsed['iocs'] if i['type']=='ip' and ip_kind(i['value'])=='Public']
    rows=[p for item in enrichment if item['type']=='ip' for p in item.get('providers',[]) if p['provider']=='geoip']
    coordinates=[p for p in rows if p.get('status')=='Available' and isinstance((p.get('result') or {}).get('latitude'),(int,float)) and isinstance((p.get('result') or {}).get('longitude'),(int,float))]
    if coordinates:status,reason='Available','Local GeoIP coordinates are available for observed network IPs; they do not identify a person or establish sender origin.'
    elif not public:status,reason='Not Observable','This email contains no observed public IP address to geolocate. '+parsed['origin']['reason']+'. Domain names alone do not establish the sending location.'
    elif any(p.get('status')=='Available' for p in rows):status,reason='No Coordinates','Local GeoIP returned network information but no coordinates. An ASN database alone cannot place a marker.'
    elif any(p.get('status')=='Unavailable' for p in rows):status,reason='Unavailable','The configured local GeoIP database could not be read.'
    elif any(p.get('status')=='Not Found' for p in rows):status,reason='Not Found','The local GeoIP database has no location record for the observed public IPs.'
    elif rows and all(p.get('status')=='Disabled' for p in rows):status,reason='Disabled','Enable local GeoIP in Settings to locate the observed public IPs.'
    elif rows:status,reason='Not Configured','Configure a readable local GeoLite2 City database to obtain coordinates.'
    else:status,reason='Not Evaluated','Public IPs were observed but no GeoIP lookup result is present; re-analyze with GeoIP enabled.'
    return {'status':status,'reason':reason,'observed_public_ips':[i['value'] for i in public],
        'source':'Local GeoIP database and observed email evidence','origin_reason':parsed['origin']['reason'],
        'lookup_statuses':[{'query':p.get('query'),'status':p['status'],'databases':p.get('databases',{})} for p in rows]}

def select_indicators(parsed,limit=25):
    eligible=[i for i in parsed['iocs'] if i['type'] in ('domain','url','hash') or ip_kind(i['value'])=='Public']
    selected=sorted(eligible,key=lambda i:i['type']!='ip')[:limit]
    return selected,len(eligible)-len(selected)


def graph(email_id,parsed,enrichment):
    nodes={};edges=[]
    def node(kind,value,data=None):
        key=hashlib.sha256((kind+':'+str(value)).encode()).hexdigest()[:24]
        nodes[key]={'id':key,'type':kind,'label':str(value),'data':{**nodes.get(key,{}).get('data',{}),**(data or {})}}
        return key
    def edge(a,b,kind):
        entry={'id':hashlib.sha256((a+b+kind).encode()).hexdigest()[:24],'source':a,'target':b,'label':kind}
        if entry not in edges:edges.append(entry)
    email=node('Email',email_id,{'subject':parsed['subject']});sender=node('Sender',parsed['sender'])
    edge(email,sender,'SENT_FROM')
    if parsed['sender_identity']['sender_domain']:edge(sender,node('Domain',parsed['sender_identity']['sender_domain']),'ASSOCIATED_WITH')
    for reply in parsed['reply_to']:
        r=node('Reply-To',reply);edge(email,r,'REPLY_TO');edge(r,node('Domain',reply.rsplit('@',1)[-1]),'ASSOCIATED_WITH')
    for item in parsed['iocs']:
        kind={'ip':'IP','domain':'Domain','url':'URL','hash':'Attachment'}[item['type']]
        n=node(kind,item['value'],item);edge(n,email,'OBSERVED_IN')
    for u in parsed['urls']:edge(node('URL',u['original_url']),node('Domain',u['domain']),'LINKS_TO')
    for item in enrichment:
        n=node({'ip':'IP','domain':'Domain','url':'URL','hash':'Attachment'}[item['type']],item['query'])
        for provider in item.get('providers',[]):
            if provider['status']!='Available':continue
            if provider['provider']=='geoip':
                geo=provider['result'];g=node('Geo location',item['query']+' network location',geo);edge(n,g,'LOCATED_IN')
                if geo.get('asn'):edge(n,node('ASN',geo['asn'],{'organization':geo.get('organization')}),'HOSTED_ON')
            else:edge(n,node('Threat intelligence',provider['provider']+':'+item['query'],provider),'ASSOCIATED_WITH')
        dns=item.get('dns') or {}
        for kind,values in dns.get('records',{}).items():
            for value in values or []:
                if kind in ('A','AAAA'):edge(n,node('IP',value),'RESOLVES_TO')
                if kind in ('NS','MX'):edge(n,node(kind,value),'USES_'+kind)
    return {'nodes':list(nodes.values()),'edges':edges,'limitations':'Observed relationships and provider reports do not establish common ownership.'}

def acquire(raw,filename,user_id,source='upload',parent_evidence_id=None):
    evidence=preserve(raw,filename,user_id,source);email_id=uid();job_id=uid()
    db.emails.insert_one({'_id':email_id,'evidence_id':evidence['_id'],'content_hash':evidence['sha256'],
        'created_at':now(),'uploaded_by':user_id,'status':'Uploaded','source':source,'parent_evidence_id':parent_evidence_id})
    db.jobs.insert_one({'_id':job_id,'email_id':email_id,'evidence_id':evidence['_id'],'user_id':user_id,
        'status':'Uploaded','created_at':now(),'updated_at':now(),'attempts':0,'history':[{'status':'Uploaded','timestamp':now()}]})
    return {'email_id':email_id,'job_id':job_id,'evidence_id':evidence['_id'],'status':'Uploaded'}

def stage(job,name):
    stamp=now()
    db.jobs.update_one({'_id':job['_id']},{'$set':{'status':name,'updated_at':stamp,'lease_until':stamp+timedelta(minutes=30)},'$push':{'history':{'status':name,'timestamp':stamp}}})
    db.emails.update_one({'_id':job['email_id']},{'$set':{'status':name}})
    custody(job['evidence_id'],name,job['user_id'])

def process(job_id):
    # Atomic claim prevents local dispatcher and Celery delivery from processing the same job.
    job=db.jobs.find_one_and_update({'_id':job_id,'status':'Uploaded'},
        {'$set':{'status':'Claimed','lease_until':now()+timedelta(minutes=30)},'$inc':{'attempts':1}},return_document=True)
    if not job:return
    try:
        if job.get('kind')=='report':
            from .reports import build_report
            build_report(job);return
        evidence=db.evidence.find_one({'_id':job['evidence_id']});raw=original(evidence)
        stage(job,'Parsing');parsed=parse(raw)
        if len(parsed['body'])>1_000_000:raise ValueError('Decoded email body exceeds the analysis limit')
        stage(job,'Forensics');config=settings()
        enrich_authentication(raw,parsed,config)
        db.emails.update_one({'_id':job['email_id']},{'$set':{'sender':parsed['sender'],'subject':parsed['subject'],
            'recipient':parsed['recipient'],'message_id':parsed['message_id']}})
        stage(job,'AI Analysis')
        try:ml=ml_service().predict(parsed['model_text'])
        except Exception:
            logger.warning('model_inference_unavailable job=%s',job_id)
            ml={'status':'Model unavailable','label':None,'confidence':None,'probabilities':None}
        stage(job,'Threat Intelligence');enrichment=[]
        # Long link lists must not consume the entire budget before observed IPs.
        selected,omitted=select_indicators(parsed)
        for item in selected:
            try:enrichment.append(lookup(item['type'],item['value'],allow_external=config['automatic_enrichment']))
            except (ValueError,UnicodeError):continue
        risk_result=risk(parsed,ml,enrichment,config)
        stage(job,'Correlation');connections=graph(job['email_id'],parsed,enrichment)
        related=[]
        strong=[i['value'] for i in parsed['iocs'] if i['type'] in ('url','hash')]
        for other in db.email_analysis.find({'ioc_values':{'$in':strong},'email_id':{'$ne':job['email_id']}},{'email_id':1,'ioc_values':1}).limit(50):
            shared=sorted(set(other['ioc_values']) & set(strong))
            if len(shared)>=2:related.append({'email_id':other['email_id'],'shared_indicators':shared,'finding':'Possible shared infrastructure; analyst review required'})
        timeline=[{'timestamp':evidence['acquisition_time'].isoformat(),'type':'System timestamp','event':'Evidence acquired'}]
        if parsed['date_utc']:timeline.append({'timestamp':parsed['date_utc'],'type':'Email timestamp','event':'Declared email Date'})
        timeline += [{'timestamp':h['timestamp'],'type':'Server timestamp','event':f"Received hop {h['hop']}",'evidence':h['raw']} for h in parsed['received_chain'] if h['timestamp']]
        timeline += [{'timestamp':p['timestamp'],'type':'Intelligence timestamp','event':'Provider report retrieved',
            'provider':p['provider'],'query':i['query'],'status':p['status'],'cached':p.get('cached',False)}
            for i in enrichment for p in i.get('providers',[]) if p.get('timestamp')]
        timeline.append({'timestamp':now().isoformat(),'type':'System timestamp','event':'Analysis completed'})
        analysis={'_id':job['email_id'],'email_id':job['email_id'],'evidence_id':evidence['_id'],'created_at':now(),
            'forensics':parsed,'ml':ml,'intelligence':enrichment,'provider_status':statuses(),
            'geolocation':geolocation_summary(parsed,enrichment),
            'enrichment_status':'Local enrichment evaluated for up to 25 indicators; external API lookups '+('enabled' if config['automatic_enrichment'] else 'disabled'),
            'analysis_mode':'PASSIVE','enrichment_limit':25,'omitted_enrichment_indicators':omitted,
            'graph':connections,'related_emails':related,'timeline':sorted(timeline,key=lambda x:x['timestamp']),
            'ioc_values':[i['value'] for i in parsed['iocs']],**risk_result}
        db.email_analysis.replace_one({'_id':job['email_id']},analysis,upsert=True)
        geos=[p['result'] for i in enrichment for p in i.get('providers',[]) if p['provider']=='geoip' and p['status']=='Available']
        db.emails.update_one({'_id':job['email_id']},{'$set':{'verdict':analysis['verdict'],'severity':analysis['severity'],
            'risk_score':analysis['risk_score'],'countries':list({g['country'] for g in geos if g.get('country')}),
            'asns':list({str(g['asn']) for g in geos if g.get('asn')})}})
        for case in db.cases.find({'related_emails':job['email_id']}):
            highest=db.email_analysis.find_one({'email_id':{'$in':case['related_emails']}},sort=[('risk_score',-1)])
            if highest:db.cases.update_one({'_id':case['_id']},{'$set':{'risk_score':highest['risk_score'],'severity':highest['severity'],'updated_at':now()}})
        for item in parsed['iocs']:
            iid=hashlib.sha256((item['type']+':'+item['value']).encode()).hexdigest()
            db.iocs.update_one({'_id':iid},{'$set':{**item,'last_seen':now()},'$setOnInsert':{'first_seen':now()},'$addToSet':{'email_ids':job['email_id']}},upsert=True)
        if risk_result['risk_score']>=config['alert_threshold'] or malicious_signals(enrichment) or any(a['flags'] for a in parsed['attachments']):
            db.alerts.update_one({'_id':job['email_id']},{'$setOnInsert':{'email_id':job['email_id'],'severity':risk_result['severity'],
                'type':'Email risk','created_at':now(),'status':'OPEN','reason':[s['reason'] for s in risk_result['signals']]}},upsert=True)
        stage(job,'Completed')
        db.jobs.update_one({'_id':job_id},{'$unset':{'lease_until':''}})
    except Exception as exc:
        logger.error('analysis_failed job=%s error_type=%s',job_id,type(exc).__name__)
        reason=str(exc) if isinstance(exc,ValueError) else 'Analysis unavailable; inspect server logs using the job ID'
        db.jobs.update_one({'_id':job_id},{'$set':{'status':'Failed','error':reason,'updated_at':now()},'$unset':{'lease_until':''}})
        if job.get('report_id'):db.reports.update_one({'_id':job['report_id']},{'$set':{'status':'Failed','error':reason}})
        if job.get('email_id'):db.emails.update_one({'_id':job['email_id']},{'$set':{'status':'Failed'}})
        if job.get('evidence_id'):custody(job['evidence_id'],'Analysis failed',job['user_id'],{'reason':reason})

def dispatch_loop(stop):
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending={}
        while not stop.wait(1):
            try:
                pending={key:f for key,f in pending.items() if not f.done()}
                db.jobs.update_many({'lease_until':{'$lt':now()},'status':{'$nin':['Completed','Failed','Uploaded']}},
                    {'$set':{'status':'Failed','error':'Worker lease expired; retry explicitly'}})
                for job in db.jobs.find({'status':'Uploaded'}).sort('created_at',1).limit(max(0,2-len(pending)) or 1):
                    if len(pending)>=2:break
                    if job['_id'] not in pending:pending[job['_id']]=pool.submit(process,job['_id'])
            except Exception:logger.warning('dispatcher_database_unavailable')
