"""Durable analysis stages and evidence-backed risk / infrastructure correlation."""
import hashlib
import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import networkx as nx
from backend.database.store import db, now, uid, settings, preserve, original, custody, event
from backend.parsers.email_parser import parse, ip_kind
from backend.forensics.authentication import enrich_authentication
from backend.intelligence.providers import lookup, malicious_signals, statuses, enrich_mail_path, coordinates_available, network_geo, ORIGIN_DISCLAIMER
from backend.core.origin_confidence import compute_origin_confidence
from backend.core.attribution import assess_attribution
from backend.core.correlation_engine import related_emails
import backend.core.scoring_config as SC
from backend.detection.inference import ml_service

logger=logging.getLogger('mailtrace.pipeline')
from backend.core.risk_engine import RISK_VERSION, risk

def geolocation_summary(parsed,enrichment):
    public=[i for i in parsed['iocs'] if i['type']=='ip' and ip_kind(i['value'])=='Public']
    rows=[p for item in enrichment if item['type']=='ip' for p in item.get('providers',[]) if p['provider'] in ('ipinfo','geoip')]
    coordinates=[p for p in rows if p.get('status')=='Available' and coordinates_available(p.get('result'))]
    if coordinates:status,reason='Available','IP intelligence coordinates are available for observed network IPs; they do not identify a person or establish sender origin.'
    elif not public:status,reason='Not Observable','This email contains no observed public IP address to geolocate. '+parsed['origin']['reason']+'. Domain names alone do not establish the sending location.'
    elif any(p.get('status')=='Available' for p in rows):status,reason='No Coordinates','Local GeoIP returned network information but no coordinates. An ASN database alone cannot place a marker.'
    elif any(p.get('status')=='Unavailable' for p in rows):status,reason='Unavailable','The configured local GeoIP database could not be read.'
    elif any(p.get('status')=='Not Found' for p in rows):status,reason='Not Found','The local GeoIP database has no location record for the observed public IPs.'
    elif rows and all(p.get('status')=='Disabled' for p in rows):status,reason='Disabled','Enable local GeoIP in Settings to locate the observed public IPs.'
    elif rows:status,reason='Not Configured','Configure a readable local GeoLite2 City database to obtain coordinates.'
    else:status,reason='Not Evaluated','Public IPs were observed but no GeoIP lookup result is present; re-analyze with GeoIP enabled.'
    return {'status':status,'reason':reason,'observed_public_ips':[i['value'] for i in public],
        'source':'IPinfo / MaxMind fallback / RDAP network registration','disclaimer':ORIGIN_DISCLAIMER,'origin_reason':parsed['origin']['reason'],
        'locations':[{'ip':i['query'],**network_geo(i)} for i in enrichment if i['type']=='ip' and i.get('query') and network_geo(i)],
        'lookup_statuses':[{'query':p.get('query'),'status':p['status'],'databases':p.get('databases',{})} for p in rows]}

def select_indicators(parsed,limit=25):
    eligible=[i for i in parsed['iocs'] if i['type'] in ('domain','url','hash') or ip_kind(i['value'])=='Public']
    candidate=(parsed.get('origin') or {}).get('candidate_ip')
    selected=sorted(eligible,key=lambda i:(i['value']!=candidate,i['type']!='ip'))[:limit]
    return selected,len(eligible)-len(selected)


def graph(email_id, parsed, enrichment):
    """Build an infrastructure correlation graph using networkx.

    Computes:
    - connected-component cluster IDs for campaign grouping
    - betweenness centrality to flag pivot / shared infrastructure nodes

    Serialised as {nodes, edges} dict; schema is identical to the old version
    so the existing React InfrastructureGraph component needs no changes.
    """
    G = nx.DiGraph()

    def node_id(kind, value):
        return hashlib.sha256((kind + ':' + str(value)).encode()).hexdigest()[:24]

    node_data = {}  # nid -> display metadata

    def ensure_node(kind, value, data=None):
        nid = node_id(kind, value)
        existing = node_data.get(nid, {})
        # Strip keys that are reserved as explicit G.add_node arguments
        _safe = {k: v for k, v in (data or {}).items() if k not in ('type', 'label')}
        merged = {**existing, **_safe}
        node_data[nid] = merged
        G.add_node(nid, type=kind, label=str(value), **merged)
        return nid

    edges_set = set()

    def add_edge(a, b, kind):
        eid = hashlib.sha256((a + b + kind).encode()).hexdigest()[:24]
        if eid not in edges_set:
            edges_set.add(eid)
            G.add_edge(a, b, id=eid, label=kind)

    # Core email nodes
    email_nid = ensure_node('Email', email_id, {'subject': parsed['subject']})
    sender_nid = ensure_node('Sender', parsed['sender'])
    add_edge(email_nid, sender_nid, 'SENT_FROM')
    if parsed['sender_identity']['sender_domain']:
        add_edge(sender_nid,
                 ensure_node('Domain', parsed['sender_identity']['sender_domain']),
                 'ASSOCIATED_WITH')
    for reply in parsed['reply_to']:
        r_nid = ensure_node('Reply-To', reply)
        add_edge(email_nid, r_nid, 'REPLY_TO')
        add_edge(r_nid, ensure_node('Domain', reply.rsplit('@', 1)[-1]), 'ASSOCIATED_WITH')

    # Header identities are observations, not verified people.
    if parsed.get('display_name'):
        add_edge(sender_nid, ensure_node('Display name', parsed['display_name'], {'basis':'Unverified supplied header'}), 'CLAIMS_NAME')
    if parsed.get('message_id'):
        add_edge(email_nid, ensure_node('Message-ID', parsed['message_id']), 'DECLARES_ID')
    for reference in re.findall(r'<[^<>\s]+>', str(parsed.get('references') or '')+' '+str(parsed.get('in_reply_to') or '')):
        add_edge(email_nid, ensure_node('Message-ID', reference), 'REFERENCES')

    # IOC nodes
    for item in parsed['iocs']:
        kind = {'ip': 'IP', 'domain': 'Domain', 'url': 'URL', 'hash': 'Attachment'}[item['type']]
        n_nid = ensure_node(kind, item['value'], item)
        add_edge(n_nid, email_nid, 'OBSERVED_IN')
    for u in parsed['urls']:
        add_edge(ensure_node('URL', u['original_url']),
                 ensure_node('Domain', u['domain']), 'LINKS_TO')

    # Enrichment nodes
    for item in enrichment:
        kind = {'ip': 'IP', 'domain': 'Domain', 'url': 'URL', 'hash': 'Attachment'}[item['type']]
        n_nid = ensure_node(kind, item['query'])
        for provider in item.get('providers', []):
            if provider['status'] != 'Available':
                continue
            if provider['provider'] in ('ipinfo','geoip'):
                geo = network_geo(item)
                g_nid = ensure_node('Geo location',
                                    item['query'] + ' network location', geo)
                add_edge(n_nid, g_nid, 'LOCATED_IN')
                if geo.get('asn'):
                    add_edge(n_nid,
                             ensure_node('ASN', geo['asn'],
                                         {'organization': geo.get('organization')}),
                             'HOSTED_ON')
            else:
                add_edge(n_nid,
                         ensure_node('Threat intelligence',
                                     provider['provider'] + ':' + item['query'],
                                     provider),
                         'ASSOCIATED_WITH')
        dns = item.get('dns') or {}
        for rec_kind, values in dns.get('records', {}).items():
            for val in values or []:
                if rec_kind in ('A', 'AAAA'):
                    add_edge(n_nid, ensure_node('IP', val), 'RESOLVES_TO')
                if rec_kind in ('NS', 'MX'):
                    add_edge(n_nid, ensure_node(rec_kind, val), 'USES_' + rec_kind)
        # Surface RDAP org as a node when available
        rdap = item.get('rdap') or {}
        if rdap.get('status') == 'Available' and isinstance(rdap.get('result'), dict):
            org = rdap['result'].get('organization') or rdap['result'].get('network_name')
            if org:
                add_edge(n_nid,
                         ensure_node('Organization', org,
                                     {'asn': rdap['result'].get('asn'),
                                      'asn_cidr': rdap['result'].get('asn_cidr')}),
                         'REGISTERED_TO')

    # --- NetworkX algorithms ---
    # Cluster IDs from weakly-connected components (campaign grouping)
    undirected = G.to_undirected()
    components = list(nx.connected_components(undirected))
    node_to_cluster = {}
    for cluster_id, component in enumerate(components):
        for nid in component:
            node_to_cluster[nid] = cluster_id

    # Betweenness centrality on the undirected view (pivot node detection)
    # Only meaningful for graphs with >2 nodes; skip for tiny graphs.
    centrality = {}
    if len(G.nodes) > 2:
        try:
            centrality = nx.betweenness_centrality(undirected, normalized=True, k=32 if len(G) > 100 else None, seed=42)
        except Exception:
            pass  # Centrality is advisory; never block pipeline

    # Serialise back to the {nodes, edges} wire format
    nodes = []
    for nid, attrs in G.nodes(data=True):
        nodes.append({
            'id': nid,
            'type': attrs.get('type', 'Unknown'),
            'label': attrs.get('label', nid),
            'data': {k: v for k, v in attrs.items() if k not in ('type', 'label')},
            'cluster_id': node_to_cluster.get(nid, 0),
            'centrality': round(centrality.get(nid, 0.0), 4),
        })

    edges = [
        {'id': data['id'], 'source': src, 'target': tgt, 'label': data['label']}
        for src, tgt, data in G.edges(data=True)
    ]

    return {
        'nodes': nodes,
        'edges': edges,
        'cluster_count': len(components),
        'limitations': (
            'Observed relationships and provider reports do not establish common ownership. '
            'Cluster IDs group nodes by graph connectivity; they are not campaign verdicts. '
            'Centrality scores are advisory; a high-centrality node may be shared benign infrastructure.'
        ),
    }

def acquire(raw,filename,user_id,source='upload',parent_evidence_id=None,source_reference=None):
    evidence=preserve(raw,filename,user_id,source);email_id=uid();job_id=uid()
    db.emails.insert_one({'_id':email_id,'evidence_id':evidence['_id'],'content_hash':evidence['sha256'],
        'created_at':now(),'uploaded_by':user_id,'status':'Uploaded','source':source,'parent_evidence_id':parent_evidence_id,'source_reference':source_reference})
    db.jobs.insert_one({'_id':job_id,'email_id':email_id,'evidence_id':evidence['_id'],'user_id':user_id,
        'status':'Uploaded','created_at':now(),'updated_at':now(),'attempts':0,'history':[{'status':'Uploaded','timestamp':now()}]})
    return {'email_id':email_id,'job_id':job_id,'evidence_id':evidence['_id'],'status':'Uploaded'}

def expire_jobs():
    """Keep the job and its email/report state consistent after worker loss."""
    stamp=now();reason='Worker lease expired; retry explicitly'
    query={'lease_until':{'$lt':stamp},'status':{'$nin':['Completed','Failed','Uploaded']}}
    for job in db.jobs.find(query):
        changed=db.jobs.update_one({'_id':job['_id'],**query},
            {'$set':{'status':'Failed','error':reason,'updated_at':stamp},'$unset':{'lease_until':''}})
        if not changed.modified_count:continue
        if job.get('report_id'):
            db.reports.update_one({'_id':job['report_id'],'status':{'$ne':'Completed'}},
                {'$set':{'status':'Failed','error':reason}})
        if job.get('email_id'):
            latest=db.jobs.find_one({'email_id':job['email_id']},sort=[('created_at',-1)])
            if latest and latest['_id']==job['_id']:
                db.emails.update_one({'_id':job['email_id'],'status':{'$nin':['Completed','Failed']}},
                    {'$set':{'status':'Failed'}})

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
            from backend.reporting.report_generator import build_report
            build_report(job);return
        evidence=db.evidence.find_one({'_id':job['evidence_id']});raw=original(evidence)
        stage(job,'Parsing');parsed=parse(raw)
        if len(parsed['model_text'])>1_000_000:raise ValueError('Decoded email body exceeds the analysis limit')
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
            except Exception:
                enrichment.append({'type':item['type'],'query':item['value'],'providers':[],'status':'Unavailable','reason':'Indicator enrichment unavailable'})
        analyzed_hops=enrich_mail_path(parsed,enrichment)
        risk_result=risk(parsed,ml,enrichment,config)
        origin_confidence_result=compute_origin_confidence(parsed,enrichment)
        stage(job,'Correlation');connections=graph(job['email_id'],parsed,enrichment)
        related=related_emails(db,job['email_id'],parsed)
        attribution=assess_attribution(parsed,enrichment,ml,origin_confidence_result)
        timeline=[{'timestamp':evidence['acquisition_time'].isoformat(),'type':'System timestamp','event':'Evidence acquired'}]
        if parsed['date_utc']:timeline.append({'timestamp':parsed['date_utc'],'type':'Email timestamp','event':'Declared email Date'})
        timeline += [{'timestamp':h['timestamp'],'type':'Server timestamp','event':f"Received hop {h['hop']}",'evidence':h['raw']} for h in parsed['received_chain'] if h['timestamp']]
        timeline += [{'timestamp':p['timestamp'],'type':'Intelligence timestamp','event':'Provider report retrieved',
            'provider':p['provider'],'query':i['query'],'status':p['status'],'cached':p.get('cached',False)}
            for i in enrichment for p in i.get('providers',[]) if p.get('timestamp')]
        timeline.append({'timestamp':now().isoformat(),'type':'System timestamp','event':'Analysis completed'})
        analysis={'_id':job['email_id'],'email_id':job['email_id'],'evidence_id':evidence['_id'],'created_at':now(),
            'forensics':parsed,'ml':ml,'intelligence':enrichment,'provider_status':statuses(),
            'geolocation':geolocation_summary(parsed,enrichment),'analyzed_hops':analyzed_hops,'mail_path':parsed['mail_path'],
            'enrichment_status':'IPinfo then MaxMind fallback; external enrichment limited to 25 indicators with origin candidate first. Remaining public IPs use local GeoIP. External API lookups '+('enabled' if config['automatic_enrichment'] else 'disabled'),
            'analysis_mode':'PASSIVE','enrichment_limit':25,'omitted_enrichment_indicators':omitted,
            'graph':connections,'related_emails':related,'timeline':sorted(timeline,key=lambda x:x['timestamp']),
            'ioc_values':[i['value'] for i in parsed['iocs']],
            'origin_confidence': origin_confidence_result, 'attribution': attribution,
            **risk_result}
        db.email_analysis.replace_one({'_id':job['email_id']},analysis,upsert=True)
        geos=[network_geo(i) for i in enrichment if i['type']=='ip']
        db.emails.update_one({'_id':job['email_id']},{'$set':{'verdict':analysis['verdict'],'severity':analysis['severity'],
            'risk_score':analysis['risk_score'],'countries':list({g['country'] for g in geos if g.get('country')}),
            'asns':list({str(g['asn']) for g in geos if g.get('asn')})}})
        for case in db.cases.find({'related_emails':job['email_id']}):
            highest=db.email_analysis.find_one({'email_id':{'$in':case['related_emails']}},sort=[('risk_score',-1)])
            if highest:db.cases.update_one({'_id':case['_id']},{'$set':{'risk_score':highest['risk_score'],'severity':highest['severity'],'updated_at':now()}})
        for item in parsed['iocs']:
            iid=hashlib.sha256((item['type']+':'+item['value']).encode()).hexdigest()
            db.iocs.update_one({'_id':iid},{'$set':{**item,'last_seen':now()},'$setOnInsert':{'first_seen':now()},'$addToSet':{'email_ids':job['email_id']}},upsert=True)
        # Refresh an existing alert after reanalysis without reopening one that
        # an analyst already acknowledged or resolved.
        db.alerts.update_one({'_id':job['email_id']},{'$set':{'severity':analysis['severity'],
            'reason':[s['reason'] for s in risk_result['signals']],'review_recommendation':risk_result['review_recommendation']}})
        # High-priority findings must reach the analyst alert queue even when
        # an older saved policy still has the former CRITICAL-only threshold.
        if risk_result['severity'] in ('HIGH', 'CRITICAL') or risk_result['risk_score']>=config['alert_threshold'] or malicious_signals(enrichment) or any(a['flags'] for a in parsed['attachments']):
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
                expire_jobs()
                for job in db.jobs.find({'status':'Uploaded'}).sort('created_at',1).limit(max(0,2-len(pending)) or 1):
                    if len(pending)>=2:break
                    if job['_id'] not in pending:pending[job['_id']]=pool.submit(process,job['_id'])
            except Exception:logger.warning('dispatcher_database_unavailable')
