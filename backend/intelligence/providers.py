"""Read-only provider lookups. Never submit URLs for scanning or follow redirects."""
from backend.config import geoip_path
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
from backend.database.store import db, now, settings, cipher
from backend.parsers.email_parser import ip_kind, classify_ip

CORE_PROVIDERS=('virustotal','abuseipdb','ipinfo','geoip')
# Existing adapters remain opt-in for backwards compatibility.
KEYS={'virustotal':'VIRUSTOTAL_API_KEY','abuseipdb':'ABUSEIPDB_API_KEY',
      'urlscan':'URLSCAN_API_KEY','greynoise':'GREYNOISE_API_KEY','geoip':'GEOIP_LICENSE_KEY','ipinfo':'IPINFO_TOKEN'}
ORIGIN_DISCLAIMER = "Location is inferred from email relay infrastructure and IP intelligence. It represents an approximate network origin, not the sender's exact physical location. VPNs, proxies, Tor, NAT, cloud infrastructure, and email providers may obscure the true origin."
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
    rdap_on=settings().get('rdap_enabled',False)
    result={}
    for p in KEYS:
        try:
            configured=any(path and path.is_file() for path in (geoip_path(k) for k in ('city','asn'))) if p=='geoip' else bool(secret(p))
            result[p]='Disabled' if p not in enabled else 'Configured' if configured else 'Not Configured'
        except Exception:result[p]='Unavailable'
    result['rdap']='Configured' if rdap_on else 'Disabled'
    return result

def provider_health():
    """Configuration and most recent observation, without exposing query or key."""
    result={}
    for provider,state in statuses().items():
        if provider=='rdap':
            latest=db.threat_intelligence.find_one({'data.provider':'rdap'},sort=[('data.timestamp',-1)])
            observation=(latest or {}).get('data',{})
            result['rdap']={'configuration':state,'last_lookup_status':observation.get('status','Not Checked'),
                'last_checked':observation.get('timestamp'),
                'reason':PROVIDER_REASONS.get(state) if state=='Disabled' else observation.get('reason'),
                'scope':'RDAP registration data (no API key required); gated by rdap_enabled setting'}
            continue
        latest=db.threat_intelligence.find_one({'data.provider':provider},sort=[('data.timestamp',-1)])
        observation=(latest or {}).get('data',{})
        result[provider]={'configuration':state,'last_lookup_status':observation.get('status','Not Checked'),
            'last_checked':observation.get('timestamp'),
            'reason':PROVIDER_REASONS.get(state) if state!='Configured' else observation.get('reason'),
            'scope':'Most recent lookup only; results vary by indicator'}
        if provider=='geoip' and state=='Not Configured':result[provider]['reason']='Configure a readable local GeoLite2 database'
    config=settings()
    return {'dns_enabled':config['dns_enabled'],'automatic_enrichment':config['automatic_enrichment'],
            'rdap_enabled':config.get('rdap_enabled',False),'providers':result}

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
    supported={'virustotal':{'ip','domain','url','hash'},'abuseipdb':{'ip'},'greynoise':{'ip'},'urlscan':{'url','domain','ip'},'geoip':{'ip'},'ipinfo':{'ip'}}
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
        version='geoip-v2:'+':'.join(str(path)+':'+str(path.stat().st_mtime_ns) for path in (geoip_path(k) for k in ('city','asn')) if path and path.is_file())
    else:
        # Key rotation must immediately invalidate cached credential errors.
        key=secret(provider)
        version=hashlib.sha256(key.encode()).hexdigest()
        if provider=='ipinfo':version+=':ipinfo-v1:'+os.getenv('IPINFO_API_MODE','lookup')
    cache_value=classify_ip(value)['lookup_ip'] if provider in ('geoip','ipinfo') else value
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
            if provider=='ipinfo':
                mode=os.getenv('IPINFO_API_MODE','lookup')
                if mode not in ('lookup','lite','legacy'):raise ValueError('Unsupported IPinfo API mode')
                address=quote(cache_value,safe=':')
                url=f'https://ipinfo.io/{address}/json' if mode=='legacy' else f'https://api.ipinfo.io/{mode}/{address}'
                headers={'Authorization':'Bearer '+key,'Accept':'application/json'}
            elif provider=='virustotal':
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
                row['status']={400:'Invalid Indicator',422:'Invalid Indicator',404:'Not Found',429:'Rate Limited',401:'Invalid Credentials',406:'Invalid Credentials',403:'Access Denied'}.get(response.status_code,'Unavailable')
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
                if provider=='ipinfo':
                    row.update(result=normalize_ipinfo(result,cache_value),source='IPinfo',api_mode=mode)
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


def normalize_ipinfo(raw, ip):
    """Normalize documented Core/Plus, Lite and legacy schemas without guessing missing flags."""
    if not isinstance(raw,dict) or classify_ip(str(raw.get('ip',''))).get('lookup_ip')!=ip or raw.get('bogon'):
        raise ValueError('Invalid IPinfo address response')
    geo=raw.get('geo',raw)
    network=raw.get('as') or (raw.get('asn') if isinstance(raw.get('asn'),dict) else {})
    privacy=raw.get('anonymous') or raw.get('privacy') or {}
    if not all(isinstance(x,dict) for x in (geo,network,privacy)):raise ValueError('Invalid IPinfo schema')
    org=raw.get('org','')
    asn=network.get('asn') or (raw.get('asn') if isinstance(raw.get('asn'),str) else None)
    if not asn and isinstance(org,str) and re.match(r'^AS\d+\s',org):asn=org.split(' ',1)[0]
    asn_match=re.fullmatch(r'(?:AS)?(\d+)',str(asn or ''),re.I)
    result={k:geo.get(k) for k in ('country','country_code','region','city','latitude','longitude','timezone')}
    if 'geo' not in raw and raw.get('loc'):
        try:result['latitude'],result['longitude']=[float(x) for x in raw['loc'].split(',')]
        except (ValueError,TypeError,AttributeError):raise ValueError('Invalid IPinfo coordinates')
    if not coordinates_available(result):result.update(latitude=None,longitude=None)
    if raw.get('loc') and not raw.get('country_code'):result['country_code']=raw.get('country')
    result.update(asn=int(asn_match[1]) if asn_match else None,
        organization=network.get('name') or raw.get('as_name') or (re.sub(r'^AS\d+\s+','',org) if isinstance(org,str) else None),
        network_cidr=network.get('route'),network_type=network.get('type'),
        hostname=raw.get('hostname'),accuracy_radius_km=geo.get('radius'),
        privacy_provider=privacy.get('name') or privacy.get('service'))
    for field,legacy in (('is_vpn','vpn'),('is_proxy','proxy'),('is_tor','tor'),('is_relay','relay'),('is_hosting','hosting'),('is_anonymous','anonymous'),('is_anycast','anycast')):
        value=privacy.get(field,privacy.get(legacy,raw.get(field)))
        result[field]=value if isinstance(value,bool) else None
    for field in ('country','country_code','region','city','timezone','organization','network_cidr','network_type','hostname','privacy_provider'):
        value=result.get(field)
        result[field]=value[:512] if isinstance(value,str) and value.strip() else None
    radius=result.get('accuracy_radius_km')
    if not isinstance(radius,(int,float)) or isinstance(radius,bool) or not math.isfinite(radius) or radius<0:
        result['accuracy_radius_km']=None
    if not any(result.get(k) for k in ('country','country_code','asn','organization')):
        raise ValueError('IPinfo returned no usable intelligence')
    return result


def network_geo(item):
    """IPinfo first, MaxMind fallback, RDAP network-only fallback with field provenance.

    Coordinates and place labels travel together; never pair a MaxMind marker with
    an unrelated IPinfo city. Registration country is not geolocation.
    """
    available={p.get('provider'):p.get('result') for p in item.get('providers',[])
               if p.get('status')=='Available' and isinstance(p.get('result'),dict)}
    primary=available.get('ipinfo') or {};fallback=available.get('geoip') or {}
    result={};sources={}
    location=('country','country_code','region','city','latitude','longitude','timezone','accuracy_radius_km')
    place,source=(primary,'IPinfo') if coordinates_available(primary) or not coordinates_available(fallback) and primary else (fallback,'MaxMind')
    for key in location:
        if place.get(key) is not None:result[key]=place[key];sources[key]=source
    rdap=item.get('rdap') or {}
    registration=rdap.get('result') or {} if rdap.get('status')=='Available' else {}
    for data,source in ((primary,'IPinfo'),(fallback,'MaxMind'),(registration,'RDAP')):
        for key,value in data.items():
            if key not in location and key!='raw' and value is not None and key not in result:
                result[key]=value;sources[key]=source
    owner=registration.get('network_name') or registration.get('organization')
    if owner:result['network_owner']=owner;sources['network_owner']='RDAP'
    if not result.get('network_cidr') and registration.get('asn_cidr'):
        result['network_cidr']=registration['asn_cidr'];sources['network_cidr']='RDAP'
    if result:
        result['field_sources']=sources
        result['data_source']=' / '.join(s for s in ('IPinfo','MaxMind','RDAP') if s in sources.values())
    return result

def local_geoip(value):
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
    info=classify_ip(value)
    if not info['valid']:return {'status':'Invalid','result':None,'databases':{},'reason':'Invalid IP address'}
    if not info['public']:return {'status':'Not Applicable','result':None,'databases':{},'reason':info['classification']+' / non-routable IP address'}
    value=info['lookup_ip'];result={};databases={}
    for kind,key in [('city','GEOIP_CITY_DB'),('asn','GEOIP_ASN_DB')]:
        configured=geoip_path(kind)
        path=str(configured) if configured else ''
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
        geographic=[p for p in item.get('providers',[]) if p['provider'] in ('ipinfo','geoip')]
        if geographic:
            data=network_geo(item)
            p=next((p for p in geographic if p.get('status')=='Available'),geographic[-1])
            cached[info['lookup_ip']]={**p,'result':data or None,'source':data.get('data_source',p.get('source')),
                'status':'Available' if data else p.get('status','Unavailable')}
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
            **{k:geo.get(k) for k in ('country','country_code','region','city','latitude','longitude','organization','asn','timezone','accuracy_radius_km','network_owner','network_cidr','network_type','is_vpn','is_proxy','is_tor','is_hosting','data_source','field_sources')},
            'isp':geo.get('isp'),'source':provider.get('source') if provider else 'Email header; GeoIP not queried',
            'confidence':provider.get('confidence','Unverified header assertion'),'geoip':provider or None})
    for hop in parsed['received_chain']:
        hop['ip_analysis']=[r for r in rows if r['hop']==hop['hop']]
        hop['location_reason']=None if hop['ips'] else 'No IP literal found in this Received header'
    parsed['mail_path']=parsed['received_chain']
    return rows


def rdap_entity_name(entity):
    """RFC 9083 jCard names are vcardArray[1] property arrays."""
    card = entity.get('vcardArray') or []
    fields = card[1] if len(card) > 1 and isinstance(card[1], list) else []
    for preferred in ('fn', 'org'):
        for field in fields:
            if len(field) >= 4 and field[0] == preferred:
                return field[3] if isinstance(field[3], str) else ' '.join(str(v) for v in field[3])
    return None


def rdap_domain_response(value):
    """Fixed bootstrap service; bounded HTTPS redirects to public endpoints."""
    import socket
    from urllib.parse import urljoin
    url = 'https://rdap.org/domain/' + value
    with httpx.Client(timeout=8, follow_redirects=False) as client:
        for _ in range(4):
            parsed = urlsplit(url)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
                raise ValueError('Unsafe RDAP redirect')
            addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
            if not addresses or any(ip_kind(a[4][0]) != 'Public' for a in addresses):
                raise ValueError('Non-public RDAP endpoint')
            with client.stream('GET', url, headers={'Accept': 'application/rdap+json'}) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    url = urljoin(url, response.headers.get('location', ''))
                    continue
                if response.status_code != 200:
                    return response.status_code, None
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > 4 * 1024 * 1024:
                        raise ValueError('RDAP response exceeded 4 MB')
                import json
                return 200, json.loads(body)
    raise ValueError('RDAP redirect limit exceeded')


def rdap_lookup(kind, value):
    base = {'provider': 'rdap', 'type': kind, 'query': value,
            'timestamp': now().isoformat(), 'source': 'RDAP registration service',
            'confidence': 'Registration data, not attacker identity or a reputation verdict',
            'status': 'Unavailable', 'result': None}
    if kind not in ('ip', 'domain'):
        return {**base, 'status': 'Not Applicable'}
    try:
        value = validate(kind, value)
    except (ValueError, UnicodeError):
        return {**base, 'status': 'Invalid Indicator'}
    base['query'] = value
    if (kind == 'ip' and ip_kind(value) != 'Public') or (kind == 'domain' and value.rsplit('.', 1)[-1] in ('test', 'example', 'invalid', 'localhost', 'local')):
        return {**base, 'status': 'Not Applicable', 'reason': 'Reserved or non-public indicator'}
    cache_id = hashlib.sha256(f'rdap-v2:{kind}:{value}'.encode()).hexdigest()
    cached = db.threat_intelligence.find_one({'_id': cache_id, 'expires_at': {'$gt': now()}})
    if cached:
        return {**cached['data'], 'cached': True}
    try:
        if kind == 'ip':
            from ipwhois import IPWhois
            raw = IPWhois(value, timeout=8).lookup_rdap(depth=0, inc_raw=True, retry_count=0)
            network = raw.get('network') or {}
            base.update(status='Available', result={
                'asn': raw.get('asn'), 'asn_cidr': raw.get('asn_cidr'),
                'asn_country': raw.get('asn_country_code'), 'asn_registry': raw.get('asn_registry'),
                'network_name': network.get('name'), 'network_cidr': network.get('cidr'),
                'organization': raw.get('asn_description') or network.get('name'),
                'events': network.get('events', []), 'raw': raw})
        else:
            status_code, raw = rdap_domain_response(value)
            if status_code == 200 and isinstance(raw, dict):
                entities = raw.get('entities') or []
                registrar = next((rdap_entity_name(e) for e in entities if 'registrar' in (e.get('roles') or [])), None)
                registrant = next((rdap_entity_name(e) for e in entities if 'registrant' in (e.get('roles') or [])), None)
                base.update(status='Available', result={
                    'ldhName': raw.get('ldhName'), 'registrar': registrar,
                    'organization': registrant, 'status': raw.get('status') or [],
                    'events': raw.get('events') or [],
                    'nameservers': [n.get('ldhName') for n in raw.get('nameservers') or []],
                    'raw': raw})
            else:
                base.update(status={404: 'Not Found', 429: 'Rate Limited', 403: 'Access Denied'}.get(status_code, 'Unavailable'),
                            reason=f'RDAP HTTP {status_code}')
    except ImportError:
        base.update(reason='ipwhois is not installed')
    except Exception as exc:
        base.update(reason='RDAP lookup unavailable: ' + type(exc).__name__)
    ttl = 86400 if base['status'] == 'Available' else 300
    db.threat_intelligence.update_one({'_id': cache_id}, {'$set': {'data': base, 'expires_at': now() + timedelta(seconds=ttl)}}, upsert=True)
    return base


def lookup(kind,value,allow_external=True):
    value=validate(kind,value)
    configured=settings();providers=[p for p in CORE_PROVIDERS if p not in ('ipinfo','geoip')]
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
    # Geographic providers are sequential so MaxMind is a fallback, not a competing location.
    if kind=='ip':
        primary=safely('ipinfo');rows.append(primary)
        data=primary.get('result') or {}
        if primary.get('status')!='Available' or not coordinates_available(data) or not data.get('asn'):
            rows.append(safely('geoip'))
    # RDAP enrichment: runs for IP and domain, gated by rdap_enabled setting
    rdap_result = None
    if configured.get('rdap_enabled', False) and allow_external and kind in ('ip', 'domain'):
        try:
            rdap_result = rdap_lookup(kind, value)
        except Exception:
            rdap_result = {'provider': 'rdap', 'type': kind, 'query': value,
                           'status': 'Unavailable', 'result': None,
                           'timestamp': now().isoformat()}
    result = {'type':kind,'query':value,'providers':rows,'dns':domain_dns(value) if kind=='domain' else None,
            'reverse_dns':reverse_dns(value) if kind=='ip' else None}
    if rdap_result is not None:
        result['rdap'] = rdap_result
    elif kind in ('ip', 'domain'):
        result['rdap'] = {'provider':'rdap','query':value,'type':kind,'status':'Not Requested' if configured.get('rdap_enabled') else 'Disabled','result':None}
    return result


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
