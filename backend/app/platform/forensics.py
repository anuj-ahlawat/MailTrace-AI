"""Passive, byte-preserving email forensics. No links or attachments are opened."""
import hashlib
import ipaddress
import re
import unicodedata
from datetime import timezone
from difflib import SequenceMatcher
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from urllib.parse import urlsplit, urlunsplit, unquote, parse_qsl

from bs4 import BeautifulSoup
import tldextract

extract_domain = tldextract.TLDExtract(suffix_list_urls=(),cache_dir=None)
BRANDS = ['microsoft.com', 'google.com', 'apple.com', 'amazon.com', 'paypal.com',
          'adobe.com', 'dropbox.com', 'linkedin.com', 'github.com', 'office.com']
LIMITATIONS = [
    'IP geolocation estimates network infrastructure location, not a human location.',
    'VPN, TOR, proxy and cloud infrastructure can obscure the original sender.',
    'Email headers are supplied evidence and may be incomplete or manipulated.',
    'Authentication-Results are reported assertions, not independent cryptographic verification.',
    'Threat intelligence coverage is incomplete; no detection does not establish safety.',
    'Model probabilities are predictions, not proof. Infrastructure correlation does not establish human identity.',
]

def registered(domain):
    p = extract_domain(domain.lower().rstrip('.'))
    # Unknown/private test suffixes must not collapse unrelated hosts to "example".
    return '.'.join((p.domain,p.suffix)) if p.suffix else domain.lower().rstrip('.')

def timestamp(value):
    try:
        dt = parsedate_to_datetime(value)
        return dt.astimezone(timezone.utc).isoformat() if dt.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None

def ip_kind(value):
    category=classify_ip(value)['classification']
    return {'Loopback':'Internal','Link-local':'Internal','Multicast':'Reserved','Invalid':'Unknown'}.get(category,category)

def classify_ip(value):
    """Detailed classification without changing the existing ip_kind contract."""
    try:
        ip=ipaddress.ip_address(value)
        mapped=ip.ipv4_mapped if ip.version==6 else None
        effective=mapped or ip
        private=any(effective in ipaddress.ip_network(n) for n in
            (('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16') if effective.version==4 else ('fc00::/7',)))
        category=('Loopback' if effective.is_loopback else 'Link-local' if effective.is_link_local else
            'Multicast' if effective.is_multicast else 'Private' if private else
            'Reserved' if effective.is_reserved or effective.is_unspecified or not effective.is_global else 'Public')
        return {'ip':str(ip),'valid':True,'version':ip.version,'classification':category,'public':category=='Public',
            'lookup_ip':str(effective).split('%',1)[0],'ipv4_mapped':str(mapped) if mapped else None}
    except (ValueError,TypeError):
        return {'ip':value,'valid':False,'classification':'Invalid','public':False}


def analyze_url(value, display='', sender_domain=''):
    """Pure local evidence. Never requests the URL or expands a shortener."""
    p=urlsplit(value);domain=(p.hostname or '').lower();port=p.port
    if p.scheme.lower() not in ('http','https') or not domain:raise ValueError('Invalid HTTP(S) URL')
    signals=[]
    def add(code,description,strength,severity='low'):
        signals.append({'type':code,'description':description,'strength':strength,'severity':severity,'source':'Local URL analysis'})
    if p.scheme.lower()=='http':add('unencrypted_http','HTTP URL does not use TLS',.05)
    if classify_ip(domain)['valid']:add('ip_hostname','IP address used instead of a hostname',.15)
    if domain in {'bit.ly','t.co','tinyurl.com','shorturl.at','is.gd'}:add('shortener','URL shortener; destination is not expanded',.1)
    if extract_domain(domain).suffix in {'zip','mov','top','click','xyz'}:
        add('review_tld','TLD appears in the local review list; this is not reputation evidence',.05)
    if domain.count('.')>3:add('subdomains','Excessive subdomains',.1)
    if len(value)>250:add('long_url','URL is unusually long (over 250 characters)',.05)
    if p.username:add('url_userinfo','User-info can obscure the actual destination host',.25,'medium')
    if unquote(value)!=value:add('encoding','URL contains encoded components',.05)
    if 'xn--' in domain or any(ord(c)>127 for c in domain):add('internationalized_domain','Punycode or Unicode hostname; review for visual confusion',.1)
    keywords=sorted(set(re.findall(r'login|password|verify|account|security|credential|signin',unquote(p.path+'?'+p.query),re.I)))
    if keywords:add('credential_keywords','Credential/account keywords: '+', '.join(keywords),.1)
    redirects=[]
    for key,target in parse_qsl(p.query,keep_blank_values=True)[:100]:
        if key.lower() in {'redirect','redirect_uri','returnurl','next','continue','url','destination'}:
            decoded=unquote(target)
            try:host=urlsplit(decoded if not decoded.startswith('//') else p.scheme+':'+decoded).hostname
            except ValueError:host=None
            redirects.append({'parameter':key,'value':target,'destination_host':host,'followed':False})
    if redirects:add('redirect_parameter','Possible redirect destination is visible in the query; no redirect was followed',.1)
    visible=display.strip()
    visible_host=None
    if visible:
        try:
            displayed=urlsplit(visible if re.match(r'^https?://',visible,re.I) else '//'+visible)
            if displayed.hostname and '.' in displayed.hostname and not re.search(r'\s',visible):visible_host=displayed.hostname.lower()
        except ValueError:pass
    if visible_host and visible_host!=domain:add('display_href_mismatch','Displayed hostname differs from the actual link hostname',.65,'high')
    if sender_domain and registered(domain)!=registered(sender_domain):
        add('sender_link_domain_mismatch','Link registered domain differs from the sender; common for legitimate third-party services',0,'informational')
    lookalikes=lookalike(domain)
    if lookalikes:add('lookalike_domain','Potential lookalike hostname: '+lookalikes[0]['potential_target'],.4,'medium')
    return {'original_url':value,'normalized_url':urlunsplit((p.scheme.lower(),p.netloc.lower(),p.path,p.query,'')),
        'scheme':p.scheme.lower(),'domain':domain,'registered_domain':registered(domain),'path':p.path,'query':p.query,'port':port,
        'display_text':display,'flags':[x['description'] for x in signals],'signals':signals,'lookalikes':lookalikes,
        'redirect_parameters':redirects,'visited':False,'assessment':'Local structural indicators only; no maliciousness verdict'}


def ips_in(value):
    return [i['ip'] for i in header_ips(value) if i['valid']]

def header_ips(value):
    """Only call for IP-bearing header fields, never arbitrary body text.

    Keep malformed literals for analyst review. Whole tokens avoid extracting
    an IPv4 substring from a hostname or IPv4-mapped IPv6 address.
    """
    found=[]
    for match in re.finditer(r'\[([^\]\r\n]+)\]|([^\s()<>;,=\[\]]+)',value):
        raw=(match.group(1) or match.group(2)).strip()
        token=re.sub(r'^IPv6:', '',raw,flags=re.I).strip('"').rstrip('.')
        looks_ip=(raw.lower().startswith('ipv6:') or token.count(':')>=2 or bool(re.fullmatch(r'[0-9.]+',token) and '.' in token))
        if not looks_ip:continue
        info=classify_ip(token)
        found.append({**info,'observed_value':raw,'offset':match.start()})
    return found

def lookalike(domain):
    observed = registered(domain)
    try: decoded = observed.encode('ascii').decode('idna')
    except (UnicodeError, UnicodeEncodeError): decoded = observed
    normalized = unicodedata.normalize('NFKC', decoded).casefold()
    substituted = normalized.translate(str.maketrans({'0':'o','1':'l','3':'e','а':'a','е':'e','о':'o','р':'p','с':'c','х':'x'}))
    candidates = []
    for brand in BRANDS:
        if observed == brand: continue
        stem = brand.split('.')[0]
        ratio = SequenceMatcher(None, substituted.split('.')[0], stem).ratio()
        if stem in substituted: ratio = max(ratio, .85)
        if ratio >= .78:
            candidates.append({'observed_domain':domain,'potential_target':brand,
                'similarity':round(ratio,3),'technique':'Unicode / character substitution and registered-domain similarity',
                'confidence':'Heuristic','finding':'Potential lookalike; ownership is not established'})
    return sorted(candidates, key=lambda x:x['similarity'], reverse=True)[:1]

def parse(raw: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    if not list(msg.keys()) or not any(msg.get(k) for k in ['From','Subject','To','Received']):
        raise ValueError('Invalid email: RFC message headers are required')
    headers = {}
    for k,v in msg.raw_items(): headers.setdefault(k.lower(), []).append(v.encode('utf-8','replace').decode('utf-8'))
    raw_headers = re.split(br'\r?\n\r?\n', raw, maxsplit=1)[0].decode('utf-8','replace')
    text, html, attachments, mime_parts = [], [], [], []
    for part in msg.walk():
        if part.is_multipart(): continue
        payload = part.get_payload(decode=True) or b''
        filename = part.get_filename()
        mime_parts.append({'content_type':part.get_content_type(),'charset':part.get_content_charset(),'disposition':part.get_content_disposition(),'filename':filename,'decoded_size':len(payload),'transfer_encoding':str(part.get('Content-Transfer-Encoding',''))})
        if filename or part.get_content_disposition() == 'attachment':
            name = filename or 'unnamed'
            ext = name.rsplit('.',1)[-1].lower() if '.' in name else ''
            flags = []
            if ext in {'exe','dll','scr','com','bat','cmd','ps1','js','vbs','hta','msi','sh'}: flags.append('Executable or script')
            if ext in {'docm','xlsm','pptm'}: flags.append('Macro-enabled document')
            if ext in {'zip','rar','7z','iso','img','html','htm'}: flags.append('Archive, disk image or HTML')
            if re.search(r'\.[a-z0-9]{2,5}\.[a-z0-9]{2,5}$',name,re.I): flags.append('Multiple extensions')
            attachments.append({'filename':name,'extension':ext,'mime_type':part.get_content_type(),
                'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'flags':flags,'malware_scan':'Not Configured'})
        elif part.get_content_type() in ('text/plain','text/html'):
            try: decoded = payload.decode(part.get_content_charset() or 'utf-8','replace')
            except LookupError: decoded = payload.decode('utf-8','replace')
            (html if part.get_content_type() == 'text/html' else text).append(decoded)
    html_body = '\n'.join(html)
    soup = BeautifulSoup(html_body,'html.parser')
    for tag in soup(['script','style']): tag.decompose()
    body = '\n'.join(text) or soup.get_text(' ',strip=True)
    def addresses(key): return [a for _,a in getaddresses(msg.get_all(key,[])) if a]
    sender = addresses('From')
    reply = addresses('Reply-To')
    return_path = addresses('Return-Path')
    sender_domain = sender[0].rsplit('@',1)[-1].lower() if sender else ''
    reply_domain = reply[0].rsplit('@',1)[-1].lower() if reply else ''
    html_text=soup.get_text(' ',strip=True)
    urls = set(re.findall(r'https?://[^\s<>"\x27]+', body + '\n' + html_text + '\n' + raw_headers,re.I))
    displays = {}
    for a in soup.find_all('a', href=True):
        href = str(a['href']).strip()
        if href.lower().startswith(('http://','https://')):
            urls.add(href); displays[href] = a.get_text(' ',strip=True)
    url_info = []
    for value in sorted(urls)[:1000]:
        value = value if value in displays else value.rstrip('.,;)')
        try:url_info.append(analyze_url(value,displays.get(value,''),sender_domain))
        except ValueError:continue
    relay=[]
    for index, value in enumerate(reversed(headers.get('received',[]))):
        from_match = re.search(r'\bfrom\s+([^\s(;]+)',value,re.I)
        by_match = re.search(r'\bby\s+([^\s(;]+)',value,re.I)
        protocol = re.search(r'\bwith\s+([^\s;]+)',value,re.I)
        # Extract the entire path (including "by") but exclude the date suffix.
        candidates=header_ips(value.split(';',1)[0])
        ips=[]
        for info in candidates:
            role='destination' if by_match and info['offset']>=by_match.start() else 'source' if from_match and info['offset']>=from_match.start() else 'observed'
            ips.append({**info,'type':ip_kind(info['ip']),'role':role})
        relay.append({'hop':index+1,'hostname':from_match.group(1) if from_match else None,
            'by':by_match.group(1) if by_match else None,'protocol':protocol.group(1) if protocol else None,
            'source_server':from_match.group(1) if from_match else None,'destination_server':by_match.group(1) if by_match else None,
            'ips':ips,'parsed_ip':next((i['ip'] for i in ips if i['valid']),None),
            'timestamp':timestamp(value.rsplit(';',1)[-1]),'raw':value,'source':'Observed header','confidence':'Unverified'})
    observations=[{**i,'header':'Received','hop':h['hop'],'raw_header':h['raw'],'timestamp':h['timestamp']} for h in relay for i in h['ips']]
    for name in ('x-originating-ip','x-sender-ip','x-real-ip','received-spf'):
        for value in headers.get(name,[]):
            values=re.findall(r'\bclient-ip\s*=\s*([^;\s]+)',value,re.I) if name=='received-spf' else [value]
            for part in values:
                observations.extend({**i,'type':ip_kind(i['ip']),'role':'reported client','header':name,'hop':None,'raw_header':value,'timestamp':None} for i in header_ips(part))
    anomalies=[]
    for a,b in zip(relay,relay[1:]):
        if a['timestamp'] and b['timestamp'] and a['timestamp'] > b['timestamp']:
            anomalies.append({'finding':'Potential timestamp-order anomaly','evidence':[a['raw'],b['raw']],'confidence':'Low; clock skew is possible'})
    origin_candidates=list(dict.fromkeys(i['ip'] for h in relay for i in h['ips'] if i['public'] and i['role']=='source'))
    candidate=origin_candidates[0] if origin_candidates else None
    origin={'ip':None,'candidate_ip':candidate,'confidence':'Insufficient Evidence',
        'candidate_ips':origin_candidates,'selection_rule':'Legacy candidate_ip is the earliest observed public source-side relay IP, not a verified origin; all candidates are retained',
        'reason':('Header trust boundary is not established; earliest observed public sending node is a candidate only' if candidate else
            'No Received headers are present; no sending IP can be established from the mail path' if not relay else
            'Received headers contain no public sending IP; private/reserved addresses cannot establish a public location'),
        'evidence':next((h['raw'] for h in relay if any(i['ip']==candidate for i in h['ips'])),None)}
    auth={}
    combined=' '.join(headers.get('authentication-results',[]))
    for mechanism in ('spf','dkim','dmarc'):
        match=re.search(r'\b'+mechanism+r'=(pass|fail|softfail|neutral|none|temperror|permerror|policy)\b',combined,re.I)
        auth[mechanism]={'reported_result':match.group(1).upper() if match else 'Unknown',
            'verification_status':'Verification unavailable','source':'Supplied Authentication-Results header',
            'evidence':headers.get('authentication-results',[])}
    signatures=[]
    for signature in headers.get('dkim-signature',[]):
        fields=dict(re.findall(r'(?:^|;)\s*([a-z]+)=([^;]+)',signature,re.I))
        domain=fields.get('d','').strip()
        signatures.append({'domain':domain,'selector':fields.get('s','').strip(),
            'alignment':registered(domain)==registered(sender_domain) if domain and sender_domain else None,
            'verification_status':'Signature present; cryptographic verification unavailable'})
    auth['dkim']['signatures']=signatures
    spf_domain_match=re.search(r'smtp\.mailfrom=([^\s;]+)',combined,re.I)
    spf_domain=spf_domain_match.group(1).strip('"<>').rsplit('@',1)[-1].lower() if spf_domain_match else None
    received_spf=headers.get('received-spf',[])
    if auth['spf']['reported_result']=='Unknown' and received_spf:
        match=re.match(r'\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b',received_spf[0],re.I)
        if match:auth['spf'].update(reported_result=match.group(1).upper(),source='Supplied Received-SPF header',evidence=received_spf)
    spf_domain=spf_domain or (return_path[0].rsplit('@',1)[-1].lower() if return_path else None)
    auth['spf'].update(received_spf=received_spf,domain=spf_domain,ip=candidate,explanation='Result reported in supplied headers; DNS authorization not independently re-evaluated')
    auth['dmarc'].update(from_domain=sender_domain,policy='Unknown',
        spf_alignment=(registered(spf_domain)==registered(sender_domain)) if spf_domain and sender_domain else None,
        dkim_alignment=any(s['alignment'] is True for s in signatures) if signatures else None,
        alignment_basis='Relaxed registered-domain comparison; not cryptographic verification')
    domains=sorted({d for d in [sender_domain,reply_domain,spf_domain]+[s['domain'] for s in signatures]+[u['domain'] for u in url_info] if d})
    iocs=[{'type':'domain','value':d,'source':'Observed email'} for d in domains]
    iocs += [{'type':'ip','value':ip,'source':'Received header' if any(i['ip']==ip and i['header']=='Received' for i in observations) else 'IP-bearing email header'} for ip in sorted({i['ip'] for i in observations if i['valid']})]
    relay_ips={i['value'] for i in iocs if i['type']=='ip'}
    iocs += [{'type':'ip','value':ip,'source':'URL hostname (not sender origin)'} for ip in sorted({u['domain'] for u in url_info if classify_ip(u['domain'])['valid']}) if ip not in relay_ips]
    iocs += [{'type':'url','value':u['original_url'],'source':'Observed email'} for u in url_info]
    iocs += [{'type':'hash','value':a['sha256'],'source':'Attachment bytes'} for a in attachments]
    display_name=getaddresses(msg.get_all('From',[]))[0][0] if sender else ''
    display_mismatch=[{'display_name':display_name,'claimed_brand':brand,'sender_domain':sender_domain,'source':'Local display-name comparison','assessment':'Possible impersonation, not proof'} for brand in BRANDS if re.search(r'\b'+re.escape(brand.split('.')[0])+r'\b',display_name,re.I) and registered(sender_domain)!=brand]
    # Distinct HTML content must not be hidden by a benign plain-text alternative.
    model_body=body
    if html_text and ' '.join(html_text.split())!=' '.join(body.split()):model_body+='\n'+html_text
    return {'subject':str(msg.get('Subject','')),'sender':sender[0] if sender else '',
        'from_addresses':sender,'display_name':getaddresses(msg.get_all('From',[]))[0][0] if sender else '',
        'recipient':addresses('To'),'cc':addresses('Cc'),'bcc':addresses('Bcc'),
        'reply_to':reply,'return_path':return_path,'date':str(msg.get('Date','')),
        'date_utc':timestamp(msg.get('Date','')),'message_id':str(msg.get('Message-ID','')),
        'references':str(msg.get('References','')),'in_reply_to':str(msg.get('In-Reply-To','')),
        'headers':headers,'raw_headers':raw_headers,'body':body,'plain_text_body':'\n'.join(text),'html_body':html_body,'html_text':html_text,
        'mime':{'content_type':msg.get_content_type(),'multipart':msg.is_multipart(),'parts':mime_parts},
        'ip_analysis':[classify_ip(ip) for ip in sorted({i['ip'] for i in observations})],
        'ip_observations':observations,'mail_path':relay,
        'model_text':str(msg.get('Subject',''))+'\n'+model_body,'urls':url_info,'domains':domains,
        'attachments':attachments,'received_chain':relay,'origin':origin,'authentication':auth,
        'sender_identity':{'display_name_mismatch':display_mismatch,'sender_domain':sender_domain,'reply_to_domain':reply_domain,
            'reply_to_mismatch':bool(reply_domain and registered(reply_domain)!=registered(sender_domain)),
            'lookalikes':[x for d in sorted({sender_domain,reply_domain}-{''}) for x in lookalike(d)]},
        'anomalies':anomalies,'iocs':iocs,'parser_defects':[type(d).__name__ for d in msg.defects],
        'limitations':LIMITATIONS}
