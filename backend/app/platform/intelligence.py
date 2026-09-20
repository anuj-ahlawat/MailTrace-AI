"""Read-only provider lookups. Never submit URLs for scanning or follow redirects."""
import base64
import hashlib
import ipaddress
import math
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from urllib.parse import quote, urlsplit
import httpx
import dns.resolver
import dns.reversename
from .store import db, now, settings, cipher
from .forensics import ip_kind,classify_ip

CORE_PROVIDERS=('virustotal','abuseipdb','geoip')
# Existing adapters remain opt-in for backwards compatibility.
KEYS={'virustotal':'VIRUSTOTAL_API_KEY','abuseipdb':'ABUSEIPDB_API_KEY',
      'urlscan':'URLSCAN_API_KEY','greynoise':'GREYNOISE_API_KEY','geoip':'GEOIP_LICENSE_KEY'}
PROVIDER_REASONS={
    'Not Configured':'Add an API key in Settings → Provider credentials',
    'Disabled':'Enable this provider in Settings',
    'Invalid Credentials':'The provider rejected the API key; replace it in Settings',
    'Access Denied':'The provider denied access; check the API key and account permissions',
    'Rate Limited':'Provider quota reached; retry after the provider cooldown',
    'Not Found':'The provider has no existing report for this indicator; this is not a safe verdict',
    'Unavailable':'Provider request failed; retry later',
    'Invalid Indicator':'The provider rejected this indicator as invalid or unsupported',
}

def secret(provider):
    row=db.provider_secrets.find_one({'_id':provider})
    return cipher().decrypt(row['secret'].encode()).decode() if row else os.getenv(KEYS[provider],'')

def statuses():
    enabled=settings()['enabled_providers']
    result={}
    for p in KEYS:
        try:
            configured=any(os.path.isfile(os.getenv(k,'')) for k in ('GEOIP_CITY_DB','GEOIP_ASN_DB')) if p=='geoip' else bool(secret(p))
            result[p]='Disabled' if p not in enabled else 'Configured' if configured else 'Not Configured'
        except Exception:result[p]='Unavailable'
    return result

def provider_health():
    """Configuration and most recent observation, without exposing query or key."""
    result={}
    for provider,state in statuses().items():
        latest=db.threat_intelligence.find_one({'data.provider':provider},sort=[('data.timestamp',-1)])
        observation=(latest or {}).get('data',{})
        result[provider]={'configuration':state,'last_lookup_status':observation.get('status','Not Checked'),
            'last_checked':observation.get('timestamp'),
            'reason':PROVIDER_REASONS.get(state) if state!='Configured' else observation.get('reason'),
            'scope':'Most recent lookup only; results vary by indicator'}
        if provider=='geoip' and state=='Not Configured':result[provider]['reason']='Configure a readable local GeoLite2 database'
    config=settings()
    return {'dns_enabled':config['dns_enabled'],'automatic_enrichment':config['automatic_enrichment'],'providers':result}

def validate(kind,value):
    value=value.strip()
    if len(value)>4096: raise ValueError('Indicator too long')
    if kind=='ip': return str(ipaddress.ip_address(value))
    if kind=='hash':
        if not re.fullmatch(r'[a-fA-F0-9]{64}',value): raise ValueError('A SHA-256 hash is required')
        return value.lower()
    if kind=='domain':
        value=value.encode('idna').decode().lower().rstrip('.')
        if len(value)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}',value):
            raise ValueError('Invalid domain')
        return value
    if kind=='url':
        parsed=urlsplit(value)
        try:parsed.port
        except ValueError:raise ValueError('Invalid URL port')
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username: raise ValueError('Invalid HTTP(S) URL')
        return value
    raise ValueError('Unsupported indicator type')

def lookup_provider(provider,kind,value):
    row={'provider':provider,'query':value,'type':kind,'timestamp':now().isoformat(),
         'source':'Provider report','confidence':'Unknown','status':'Not Configured','result':None}
    supported={'virustotal':{'ip','domain','url','hash'},'abuseipdb':{'ip'},'greynoise':{'ip'},'urlscan':{'url','domain','ip'},'geoip':{'ip'}}
    if kind not in supported[provider]: return {**row,'status':'Not Applicable'}
    if kind=='ip' and ip_kind(value)!='Public': return {**row,'status':'Not Applicable','reason':'Non-public address'}
    if kind in ('domain','url'):
        host=(urlsplit(value).hostname or '') if kind=='url' else value
        host=host.lower().rstrip('.')
        if host.rsplit('.',1)[-1] in ('example','invalid','test','localhost','local'):
            return {**row,'status':'Not Applicable','reason':'Reserved test or local-only hostname; public reputation lookup is not applicable'}
    state=statuses()[provider]
    if state!='Configured': return {**row,'status':state,'reason':('Configure a readable local GeoLite2 database' if provider=='geoip' and state=='Not Configured' else PROVIDER_REASONS.get(state,'Provider configuration unavailable'))}
    version=''
    if provider=='geoip':
        version='geoip-v2:'+':'.join(os.getenv(k,'')+':'+str(os.stat(os.getenv(k)).st_mtime_ns) for k in ('GEOIP_CITY_DB','GEOIP_ASN_DB') if os.path.isfile(os.getenv(k,'')))
    else:
        # Key rotation must immediately invalidate cached credential errors.
        key=secret(provider)
        version=hashlib.sha256(key.encode()).hexdigest()
    cache_value=classify_ip(value)['lookup_ip'] if provider=='geoip' else value
    cache_id=hashlib.sha256(f'{provider}:{kind}:{cache_value}:{version}'.encode()).hexdigest()
    cached=db.threat_intelligence.find_one({'_id':cache_id,'expires_at':{'$gt':now()}})
    if cached: return {**cached['data'],'query':value,'cached':True}
    if provider!='geoip':
        cooldown=db.provider_cooldowns.find_one({'_id':provider+':'+version,'until':{'$gt':now()}})
        if isinstance(cooldown,dict):
            return {**row,'status':'Rate Limited','reason':PROVIDER_REASONS['Rate Limited'],
                'retry_after':cooldown['until'].isoformat()}
    try:
        if provider=='geoip':
            geo=local_geoip(value)
            row.update(geo,source='MaxMind local database',confidence='Provider accuracy radius where available; not human attribution')
        else:
            params={}
            if provider=='virustotal':
                path={'ip':'ip_addresses','domain':'domains','url':'urls','hash':'files'}[kind]
                identifier=base64.urlsafe_b64encode(value.encode()).decode().rstrip('=') if kind=='url' else value
                url=f'https://www.virustotal.com/api/v3/{path}/{quote(identifier,safe="")}'; headers={'x-apikey':key}
            elif provider=='abuseipdb':
                url='https://api.abuseipdb.com/api/v2/check'; headers={'Key':key,'Accept':'application/json'}; params={'ipAddress':value,'maxAgeInDays':90}
            elif provider=='greynoise':
                url=f'https://api.greynoise.io/v3/ip/{quote(value,safe="")}'; headers={'key':key}
            else:
                field={'url':'page.url','ip':'page.ip','domain':'page.domain'}[kind]
                escaped=re.sub(r'([+\-=!(){}\[\]^"~*?:\\/<>|&])',r'\\\1',value)
                url='https://urlscan.io/api/v1/search/'; headers={'api-key':key}; params={'q':f'{field}:"{escaped}"','size':5}
            with httpx.Client(timeout=8,follow_redirects=False) as client:
                response=client.get(url,headers=headers,params=params)
            row['http_status']=response.status_code
            if response.status_code!=200:
                row['status']={400:'Invalid Indicator',422:'Invalid Indicator',404:'Not Found',429:'Rate Limited',401:'Invalid Credentials',403:'Access Denied'}.get(response.status_code,'Unavailable')
                row['reason']=PROVIDER_REASONS[row['status']]
                if response.status_code==429:
                    from email.utils import parsedate_to_datetime
                    delay=response.headers.get('Retry-After','60')
                    try:seconds=int(delay)
                    except ValueError:
                        try:seconds=int((parsedate_to_datetime(delay)-now()).total_seconds())
                        except (ValueError,TypeError,OverflowError):seconds=60
                    until=now()+timedelta(seconds=max(1,min(seconds,86400)))
                    db.provider_cooldowns.update_one({'_id':provider+':'+version},{'$set':{'until':until}},upsert=True)
                    row['retry_after']=until.isoformat()
            else:
                result=response.json()
                if not isinstance(result,dict):raise ValueError('Invalid provider response')
                if provider in ('virustotal','abuseipdb') and not isinstance(result.get('data'),dict):raise ValueError('Invalid provider data')
                if provider=='virustotal' and not isinstance(result['data'].get('attributes'),dict):raise ValueError('Invalid VirusTotal attributes')
                if provider=='urlscan' and not isinstance(result.get('results'),list):raise ValueError('Invalid URLScan results')
                if provider=='greynoise' and (not isinstance(result.get('ip'),str) or ipaddress.ip_address(result['ip'])!=ipaddress.ip_address(value)):raise ValueError('Invalid GreyNoise IP response')
                row.update(status='Available',result=result,confidence='Reported by provider')
                if provider=='abuseipdb':
                    data=result.get('data') or {}
                    row['summary']={k:data[k] for k in ('abuseConfidenceScore','totalReports','numDistinctUsers','countryCode','countryName','isp','asn','domain','lastReportedAt','usageType','isTor') if k in data}
    except httpx.TimeoutException:
        row.update(status='Unavailable',result=None,reason='Provider request timed out; retry later')
    except Exception:
        row.update(status='Unavailable',result=None,reason='Provider request or response unavailable; no reputation conclusion can be drawn')
    try:
        expires=until if row['status']=='Rate Limited' else now()+timedelta(hours=6 if row['status']=='Available' else .05)
        db.threat_intelligence.update_one({'_id':cache_id},{'$set':{'data':row,'expires_at':expires}},upsert=True)
    except Exception:pass  # A cache outage must not discard an otherwise valid provider response.
    return row

def local_geoip(value):
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
    info=classify_ip(value)
    if not info['valid']:return {'status':'Invalid','result':None,'databases':{},'reason':'Invalid IP address'}
    if not info['public']:return {'status':'Not Applicable','result':None,'databases':{},'reason':info['classification']+' / non-routable IP address'}
    value=info['lookup_ip'];result={};databases={}
    for kind,key in [('city','GEOIP_CITY_DB'),('asn','GEOIP_ASN_DB')]:
        path=os.getenv(key,'')
        if not path or not os.path.isfile(path):databases[kind]='Not Configured';continue
        try:
            with geoip2.database.Reader(path) as reader:
                if kind=='city':
                    geo=reader.city(value)
                    result.update(country=geo.country.name,country_code=geo.country.iso_code,region=geo.subdivisions.most_specific.name,
                        city=geo.city.name,latitude=geo.location.latitude,longitude=geo.location.longitude,accuracy_radius_km=geo.location.accuracy_radius,
                        timezone=geo.location.time_zone)
                else:
                    asn=reader.asn(value);result.update(asn=asn.autonomous_system_number,organization=asn.autonomous_system_organization)
                result[kind+'_database_build_epoch']=reader.metadata().build_epoch
                databases[kind]='Available'
        except AddressNotFoundError:databases[kind]='Not Found'
        except Exception:databases[kind]='Unavailable'
    status='Available' if result else 'Unavailable' if 'Unavailable' in databases.values() else 'Not Found' if 'Not Found' in databases.values() else 'Not Configured'
    return {'status':status,'result':result or None,'databases':databases}

def coordinates_available(result):
    if not isinstance(result,dict):return False
    lat,lon=result.get('latitude'),result.get('longitude')
    return all(isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v) for v in (lat,lon)) and -90<=lat<=90 and -180<=lon<=180

def enrich_mail_path(parsed,enrichment):
    """Use the existing provider/cache for every public IP, independent of API budget.

    Request-local memoization deduplicates repeated hops and mapped addresses.
    Keep non-routable and malformed observations with explicit reasons.
    """
    cached={};by_query={}
    for item in enrichment:
        if item['type']!='ip':continue
        info=classify_ip(item['query'])
        if not info['public']:continue
        by_query[item['query']]=item
        for p in item.get('providers',[]):
            if p['provider']=='geoip':cached[info['lookup_ip']]=p
    observations=list(parsed.get('ip_observations',[]))
    observed={i['ip'] for i in observations}
    for i in parsed['iocs']:
        if i['type']=='ip' and i['value'] not in observed:
            observations.append({**classify_ip(i['value']),'header':i['source'],'role':'URL infrastructure','hop':None,'raw_header':None,'timestamp':None})
            observed.add(i['value'])
    reasons={'Not Found':'Public IP has no matching GeoIP database record','Not Configured':'Local GeoIP database is not configured',
        'Disabled':'GeoIP lookup is disabled','Unavailable':'GeoIP data unavailable','Rate Limited':'GeoIP provider rate limit reached',
        'Invalid Credentials':'GeoIP provider credentials are invalid','Access Denied':'GeoIP provider access denied'}
    rows=[]
    for observation in observations:
        info=classify_ip(observation['ip']);geo={};provider={};status='Not Applicable'
        if not info['valid']:reason='Invalid IP address';status='Invalid'
        elif not info['public']:reason=info['classification']+' / non-routable IP address'
        else:
            key=info['lookup_ip']
            if key not in cached:
                try:cached[key]=lookup_provider('geoip','ip',key)
                except Exception:cached[key]={'provider':'geoip','type':'ip','query':key,'status':'Unavailable','result':None,'source':'MaxMind local database','timestamp':now().isoformat()}
            provider=cached[key]
            if not isinstance(provider,dict):
                provider={'provider':'geoip','query':key,'status':'Unavailable','result':None,'source':'MaxMind local database'}
                cached[key]=provider
            if provider.get('status')=='Available' and (not isinstance(provider.get('result'),dict) or not provider['result']):
                provider.update(status='Unavailable',result=None)
            status=provider.get('status','Unavailable')
            geo=provider.get('result') if status=='Available' and isinstance(provider.get('result'),dict) else {}
            if status=='Available' and not geo:status='Unavailable'
            reason=None if coordinates_available(geo) else 'GeoIP returned network data but no coordinates' if geo else reasons.get(status,'GeoIP data unavailable')
            if info['ip'] not in by_query:
                row={'type':'ip','query':info['ip'],'providers':[{**provider,'query':info['ip'],'lookup_ip':key}],
                    'dns':None,'reverse_dns':None,'scope':'Local GeoIP only; external reputation budget unchanged'}
                enrichment.append(row);by_query[info['ip']]=row
        rows.append({'ip':info['ip'],'type':info['classification'].lower(),'classification':info['classification'],'valid':info['valid'],
            'version':info.get('version'),'lookup_ip':info.get('lookup_ip'),'ipv4_mapped':info.get('ipv4_mapped'),
            'hop':observation.get('hop'),'role':observation.get('role'),'observation_source':observation.get('header'),
            'raw_header':observation.get('raw_header'),'timestamp':observation.get('timestamp'),
            'location_available':coordinates_available(geo),'location_status':status,'location_reason':reason,
            **{k:geo.get(k) for k in ('country','country_code','region','city','latitude','longitude','organization','asn','timezone','accuracy_radius_km')},
            'isp':geo.get('isp'),'source':provider.get('source') if provider else 'Email header; GeoIP not queried',
            'confidence':provider.get('confidence','Unverified header assertion'),'geoip':provider or None})
    for hop in parsed['received_chain']:
        hop['ip_analysis']=[r for r in rows if r['hop']==hop['hop']]
        hop['location_reason']=None if hop['ips'] else 'No IP literal found in this Received header'
    parsed['mail_path']=parsed['received_chain']
    return rows


def lookup(kind,value,allow_external=True):
    value=validate(kind,value)
    configured=settings();providers=list(CORE_PROVIDERS)
    for provider in ('urlscan','greynoise'):
        if provider in configured['enabled_providers']:providers.append(provider)
    def safely(provider):
        base={'provider':provider,'query':value,'type':kind,'timestamp':now().isoformat(),'result':None,'source':'Provider report'}
        if provider!='geoip' and not allow_external:
            state=statuses().get(provider,'Not Configured')
            return {**base,'status':state if state in ('Not Configured','Disabled','Unavailable') else 'Not Requested','reason':'Automatic external enrichment disabled'}
        try:return lookup_provider(provider,kind,value)
        except Exception:return {**base,'status':'Unavailable'}
    with ThreadPoolExecutor(max_workers=5) as pool:rows=list(pool.map(safely,providers))
    return {'type':kind,'query':value,'providers':rows,'dns':domain_dns(value) if kind=='domain' else None,
            'reverse_dns':reverse_dns(value) if kind=='ip' else None}


def reverse_dns(ip):
    if not settings()['dns_enabled']:return {'status':'Not Configured'}
    if ip_kind(ip)!='Public':return {'status':'Not Applicable'}
    try:
        values=dns.resolver.resolve(dns.reversename.from_address(ip),'PTR',lifetime=3)
        return {'status':'Available','hostnames':[str(v).rstrip('.') for v in values],'source':'DNS PTR lookup','timestamp':now().isoformat()}
    except dns.resolver.NXDOMAIN:return {'status':'Not Found','hostnames':[]}
    except Exception:return {'status':'Unavailable'}

def dns_query(name,record_type,resolver=None):
    """Bounded DNS with exact TXT string concatenation and explicit failures."""
    row={'query':name,'record_type':record_type,'source':'DNS resolver','timestamp':now().isoformat(),'values':[]}
    try:
        resolver=resolver or dns.resolver.Resolver()
        answer=resolver.resolve(name,record_type,lifetime=3,search=False)
        values=[b''.join(x.strings).decode('utf-8','replace') if record_type=='TXT' else str(x) for x in answer]
        return {**row,'status':'Available','values':values,'ttl':answer.rrset.ttl if answer.rrset else None}
    except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN):return {**row,'status':'Not Found'}
    except dns.exception.Timeout:return {**row,'status':'Unavailable','reason':'DNS timeout'}
    except Exception:return {**row,'status':'Unavailable','reason':'DNS lookup failed'}


def domain_dns(domain):
    if not settings()['dns_enabled']:return {'status':'Not Configured','records':{},'reason':'DNS lookups disabled'}
    try:domain=validate('domain',domain)
    except (ValueError,UnicodeError):return {'status':'Not Applicable','records':{},'reason':'Invalid DNS domain'}
    try:resolver=dns.resolver.Resolver()
    except Exception:return {'status':'Unavailable','records':{},'reason':'DNS resolver unavailable'}
    queries={k:dns_query('_dmarc.'+domain if k=='DMARC' else domain,'TXT' if k=='DMARC' else k,resolver) for k in ('A','AAAA','MX','NS','TXT','DMARC')}
    records={k:r['values'] if r['status']!='Unavailable' else None for k,r in queries.items()}
    records['SPF']=[r for r in records.get('TXT') or [] if re.match(r'^v=spf1(?:\s|$)',r,re.I)]
    queries['SPF']={**queries['TXT'],'values':records['SPF'],'status':queries['TXT']['status'] if queries['TXT']['status']=='Unavailable' else 'Available' if records['SPF'] else 'Not Found'}
    records['DMARC']=[r for r in records.get('DMARC') or [] if re.match(r'^v=DMARC1(?:;|$)',r,re.I)] if records['DMARC'] is not None else None
    states=[r['status'] for r in queries.values()]
    status='Unavailable' if all(x=='Unavailable' for x in states) else 'Partial' if 'Unavailable' in states else 'Available' if 'Available' in states else 'Not Found'
    return {'status':status,'source':'DNS resolver','timestamp':now().isoformat(),'records':records,'queries':queries}


def malicious_signals(enrichment):
    """Provider claims with bounded strength; a claim is not a final verdict."""
    signals=[]
    for item in enrichment:
        for provider in item.get('providers',[]):
            if provider['status']!='Available':continue
            data=provider.get('result') or {};name=provider['provider']
            if not isinstance(data,dict):continue
            if name=='virustotal':
                details=data.get('data') or {}
                attributes=details.get('attributes') if isinstance(details,dict) else None
                stats=attributes.get('last_analysis_stats') if isinstance(attributes,dict) else None
                if not isinstance(stats,dict):continue
                counts={k:v for k,v in stats.items() if isinstance(v,int) and not isinstance(v,bool) and v>=0}
                malicious=counts.get('malicious',0);total=sum(counts.values())
                if malicious:
                    signals.append({'provider':name,'query':item['query'],'strength':min(.35,.04*malicious+.15*malicious/max(1,total)),
                        'reason':f'{malicious} of {total} reported engine outcomes were malicious; engines are not independent',
                        'evidence':stats,'timestamp':provider.get('timestamp')})
            if name=='abuseipdb':
                evidence=data.get('data') or {}
                if not isinstance(evidence,dict):continue
                score=evidence.get('abuseConfidenceScore');reports=evidence.get('totalReports')
                if isinstance(score,(int,float)) and isinstance(reports,int) and 50<=score<=100 and reports>=3:
                    signals.append({'provider':name,'query':item['query'],'strength':min(.35,score/100*.35),
                        'reason':'IP abuse history warrants review; shared infrastructure may have unrelated users',
                        'evidence':{k:evidence.get(k) for k in ('abuseConfidenceScore','totalReports','numDistinctUsers','lastReportedAt')},'timestamp':provider.get('timestamp')})
            scanner=data.get('internet_scanner_intelligence') or {}
            if name=='greynoise' and (data.get('classification')=='malicious' or isinstance(scanner,dict) and scanner.get('classification')=='malicious'):
                signals.append({'provider':name,'query':item['query'],'strength':.25,'reason':'Legacy provider reports malicious activity; corroboration required'})
    return signals
