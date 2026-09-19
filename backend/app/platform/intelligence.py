"""Read-only provider lookups. Never submit URLs for scanning or follow redirects."""
import base64
import hashlib
import ipaddress
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from urllib.parse import quote, urlsplit
import httpx
import dns.resolver
import dns.reversename
from .store import db, now, settings, cipher
from .forensics import ip_kind

CORE_PROVIDERS=('virustotal','abuseipdb','geoip')
# Existing adapters remain opt-in for backwards compatibility.
KEYS={'virustotal':'VIRUSTOTAL_API_KEY','abuseipdb':'ABUSEIPDB_API_KEY',
      'urlscan':'URLSCAN_API_KEY','greynoise':'GREYNOISE_API_KEY','geoip':'GEOIP_LICENSE_KEY'}

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
    state=statuses()[provider]
    if state!='Configured': return {**row,'status':state}
    version=''
    if provider=='geoip':
        version=':'.join(str(os.stat(os.getenv(k)).st_mtime_ns) for k in ('GEOIP_CITY_DB','GEOIP_ASN_DB') if os.path.isfile(os.getenv(k,'')))
    cache_id=hashlib.sha256(f'{provider}:{kind}:{value}:{version}'.encode()).hexdigest()
    cached=db.threat_intelligence.find_one({'_id':cache_id,'expires_at':{'$gt':now()}})
    if cached: return {**cached['data'],'cached':True}
    try:
        if provider=='geoip':
            geo=local_geoip(value)
            row.update(geo,source='MaxMind local database',confidence='Provider accuracy radius where available; not human attribution')
        else:
            key=secret(provider); params={}
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
            if response.status_code!=200:
                row['status']={404:'Not Found',429:'Rate Limited',401:'Invalid Credentials',403:'Access Denied'}.get(response.status_code,'Unavailable')
            else:
                result=response.json()
                if not isinstance(result,dict):raise ValueError('Invalid provider response')
                if provider in ('virustotal','abuseipdb') and not isinstance(result.get('data'),dict):raise ValueError('Invalid provider data')
                if provider=='virustotal' and not isinstance(result['data'].get('attributes'),dict):raise ValueError('Invalid VirusTotal attributes')
                row.update(status='Available',result=result,confidence='Reported by provider')
                if provider=='abuseipdb':
                    data=result.get('data') or {}
                    row['summary']={k:data[k] for k in ('abuseConfidenceScore','totalReports','numDistinctUsers','countryCode','countryName','isp','asn','domain','lastReportedAt','usageType','isTor') if k in data}
        db.threat_intelligence.update_one({'_id':cache_id},{'$set':{'data':row,'expires_at':now()+timedelta(hours=6 if row['status']=='Available' else .05)}},upsert=True)
    except Exception:
        row.update(status='Unavailable',result=None)
    return row

def local_geoip(value):
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
    result={};databases={}
    for kind,key in [('city','GEOIP_CITY_DB'),('asn','GEOIP_ASN_DB')]:
        path=os.getenv(key,'')
        if not path or not os.path.isfile(path):databases[kind]='Not Configured';continue
        try:
            with geoip2.database.Reader(path) as reader:
                if kind=='city':
                    geo=reader.city(value)
                    result.update(country=geo.country.name,country_code=geo.country.iso_code,region=geo.subdivisions.most_specific.name,
                        city=geo.city.name,latitude=geo.location.latitude,longitude=geo.location.longitude,accuracy_radius_km=geo.location.accuracy_radius)
                else:
                    asn=reader.asn(value);result.update(asn=asn.autonomous_system_number,organization=asn.autonomous_system_organization)
                result[kind+'_database_build_epoch']=reader.metadata().build_epoch
                databases[kind]='Available'
        except AddressNotFoundError:databases[kind]='Not Found'
        except Exception:databases[kind]='Unavailable'
    status='Available' if result else 'Unavailable' if 'Unavailable' in databases.values() else 'Not Found' if 'Not Found' in databases.values() else 'Not Configured'
    return {'status':status,'result':result or None,'databases':databases}


def lookup(kind,value,allow_external=True):
    value=validate(kind,value)
    configured=settings();providers=list(CORE_PROVIDERS)
    for provider in ('urlscan','greynoise'):
        try:
            if provider in configured['enabled_providers'] and secret(provider):providers.append(provider)
        except Exception:pass  # A broken optional legacy credential cannot block local analysis.
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
