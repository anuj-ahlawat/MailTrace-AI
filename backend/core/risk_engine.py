"""Authoritative scoring, review policy and threat categories."""
import re
from backend.core import scoring_config as SC
from backend.intelligence.providers import malicious_signals
RISK_VERSION = SC.RISK_ENGINE_VERSION

def model_review_policy(ml,config):
    """Review priority policy, separate from forensic evidence and probabilities."""
    if ml.get('status')!='Available' or config['risk_weights'].get('ai',0)<=0:return None
    label=ml.get('label')
    if label not in ('PHISHING','BEC'):return None
    probability=ml['probabilities'][label]
    high=probability>=.7
    return {'id':'model_threat_review','minimum_score':config['risk_thresholds'][1 if high else 0],
        'label':label,'class_probability':probability,'high_priority_probability_threshold':.7,
        'reason':f'Model predicts {label}: '+('class probability is at least 70%; HIGH review priority required' if high else 'MEDIUM review priority required'),
        'limitation':'Policy review minimum, not additional forensic evidence or a calibrated probability of harm'}

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

def risk(parsed, ml, enrichment, config):
    """Compute the Threat Risk Score (0–100) from actual investigation evidence.

    The configured seven-category contributions and explicit policy adjustments
    determine risk_score. Five component_scores are diagnostic details only;
    multiplying their weights does not reproduce the authoritative risk score.

    UNKNOWN / NOT_CONFIGURED authentication is never treated as FAIL.
    Unavailable threat intelligence is explicitly tracked, not silently zeroed.
    Per-group caps prevent correlated forensic signals from stacking arbitrarily.
    """
    # ------------------------------------------------------------------
    # 1. ML / AI component (0–100)
    # Converts 4-class probabilities to a threat score.
    # BENIGN probability does NOT contribute positively to threat score.
    # Formula: P(PHISHING) + P(BEC) + 0.4*P(SPAM)  clamped to [0,1].
    # ------------------------------------------------------------------
    ml_component = {'score': 0, 'weight': SC.COMPONENT_WEIGHTS['ml'],
                    'status': 'UNAVAILABLE', 'coverage': 0,
                    'source': 'Local ML model inference',
                    'limitation': 'Model output is not a calibrated probability of harm'}
    ml_signals = []
    if ml.get('status') == 'Available' and ml.get('probabilities'):
        probs = ml['probabilities']
        threat = min(1.0, probs.get('PHISHING', 0) + probs.get('BEC', 0)
                     + 0.4 * probs.get('SPAM', 0))
        ml_component.update(score=round(threat * 100, 2), status='AVAILABLE',
                            coverage=1,
                            predicted_class=ml.get('label'),
                            model_score=round(threat * 100, 2),
                            class_scores=probs,
                            formula='P(PHISHING) + P(BEC) + 0.4×P(SPAM); not a calibrated probability')
        ml_signals.append({'category': 'ai', 'strength': threat,
                           'reason': 'Policy-weighted model evidence: P(PHISHING) + P(BEC) + 0.4 × P(SPAM)',
                           'evidence': probs, 'source': 'AI'})
    else:
        ml_component['reason'] = ml.get('status', 'Model unavailable')

    # ------------------------------------------------------------------
    # 2. Authentication component (0–100)
    # UNKNOWN / NOT_CONFIGURED / MISSING -> 0 contribution (not treated as FAIL).
    # Header-reported results weighted less than live-verified results.
    # ------------------------------------------------------------------
    auth_raw = 0
    auth_signals = []
    auth_contributions = []
    auth = parsed.get('authentication', {})

    spf = auth.get('spf', {})
    spf_result = spf.get('reported_result', 'Unknown')
    if spf_result == 'FAIL':
        pts = SC.AUTH_POINTS['SPF_FAIL_REPORTED']
        auth_raw += pts
        auth_contributions.append({'rule_id': 'AUTH_SPF_FAIL_REPORTED', 'component': 'authentication',
            'signal_group': 'authentication', 'severity': 'medium', 'raw_points': pts, 'applied_points': pts,
            'evidence': spf_result, 'source': spf.get('source', 'Authentication-Results header')})
        auth_signals.append({'category': 'authentication', 'strength': pts/100,
            'reason': 'SPF result FAIL reported in header; not independently verified', 'evidence': spf, 'source': 'Header-reported SPF'})
    elif spf_result == 'SOFTFAIL':
        pts = SC.AUTH_POINTS['SPF_SOFTFAIL_REPORTED']
        auth_raw += pts
        auth_contributions.append({'rule_id': 'AUTH_SPF_SOFTFAIL_REPORTED', 'component': 'authentication',
            'signal_group': 'authentication', 'severity': 'low', 'raw_points': pts, 'applied_points': pts,
            'evidence': spf_result, 'source': spf.get('source', 'Authentication-Results header')})
        auth_signals.append({'category': 'authentication', 'strength': pts/100,
            'reason': 'SPF result SOFTFAIL reported in header; lower severity than FAIL', 'evidence': spf, 'source': 'Header-reported SPF'})
    # UNKNOWN, NONE, NOT_CONFIGURED, NEUTRAL -> 0 (not treated as FAIL)

    dkim_auth = auth.get('dkim', {})
    dkim_result = dkim_auth.get('reported_result', 'Unknown')
    verified = dkim_auth.get('local_verification', {})
    if verified.get('status') == 'FAIL':
        pts = SC.AUTH_POINTS['DKIM_FAIL_VERIFIED']
        auth_raw += pts
        auth_contributions.append({'rule_id': 'AUTH_DKIM_FAIL_VERIFIED', 'component': 'authentication',
            'signal_group': 'authentication', 'severity': 'high', 'raw_points': pts, 'applied_points': pts,
            'evidence': verified, 'source': 'Local dkimpy cryptographic verification'})
        auth_signals.append({'category': 'authentication', 'strength': pts/100,
            'reason': 'DKIM did not validate against the preserved message bytes',
            'evidence': verified, 'source': 'Local DKIM verification'})
    elif dkim_result == 'FAIL' and verified.get('status') not in ('PASS', 'FAIL'):
        pts = SC.AUTH_POINTS['DKIM_FAIL_REPORTED']
        auth_raw += pts
        auth_contributions.append({'rule_id': 'AUTH_DKIM_FAIL_REPORTED', 'component': 'authentication',
            'signal_group': 'authentication', 'severity': 'medium', 'raw_points': pts, 'applied_points': pts,
            'evidence': dkim_result, 'source': 'Authentication-Results header'})
        auth_signals.append({'category': 'authentication', 'strength': pts/100,
            'reason': 'DKIM FAIL reported in header; not independently verified', 'evidence': dkim_auth, 'source': 'Header-reported DKIM'})

    dmarc_auth = auth.get('dmarc', {})
    dmarc_result = dmarc_auth.get('reported_result', 'Unknown')
    if dmarc_result == 'FAIL':
        pts = SC.AUTH_POINTS['DMARC_FAIL_REPORTED']
        auth_raw += pts
        auth_contributions.append({'rule_id': 'AUTH_DMARC_FAIL', 'component': 'authentication',
            'signal_group': 'authentication', 'severity': 'high', 'raw_points': pts, 'applied_points': pts,
            'evidence': dmarc_result, 'source': 'Authentication-Results header'})
        auth_signals.append({'category': 'authentication', 'strength': pts/100,
            'reason': 'DMARC result FAIL reported in header', 'evidence': dmarc_auth, 'source': 'Header-reported DMARC'})

    identity = parsed['sender_identity']
    if identity['reply_to_mismatch']:
        pts = SC.AUTH_POINTS['REPLY_TO_MISMATCH']
        auth_raw += pts
        auth_contributions.append({'rule_id': 'AUTH_REPLY_TO_MISMATCH', 'component': 'authentication',
            'signal_group': 'authentication', 'severity': 'medium', 'raw_points': pts, 'applied_points': pts,
            'evidence': {'from_domain': identity.get('sender_domain'), 'reply_to_domain': identity.get('reply_to_domain')},
            'source': 'Header analysis'})
        auth_signals.append({'category': 'authentication', 'strength': pts/100,
            'reason': 'Reply-To registered domain differs from sender domain', 'evidence': identity, 'source': 'Forensic'})

    auth_score = min(SC.AUTH_CAP, auth_raw)
    auth_component = {'score': auth_score, 'weight': SC.COMPONENT_WEIGHTS['authentication'],
                      'status': 'AVAILABLE', 'coverage': 1,
                      'contributions': auth_contributions,
                      'note': 'UNKNOWN/NOT_CONFIGURED/MISSING authentication is not treated as failure'}

    # ------------------------------------------------------------------
    # 3. Header Forensics component (0–100) with per-group caps
    # ------------------------------------------------------------------
    header_group_totals: dict[str, int] = {}
    header_raw = 0
    header_signals = []
    header_contributions = []

    def _add_header(rule_id: str, pts_key: str, severity: str,
                    reason: str, evidence: object, source: str = 'Forensic') -> None:
        nonlocal header_raw
        group = SC.HEADER_SIGNAL_GROUP.get(pts_key, 'other')
        cap = SC.HEADER_GROUP_CAPS.get(group, SC.HEADER_CAP)
        current_in_group = header_group_totals.get(group, 0)
        raw_pts = SC.HEADER_POINTS.get(pts_key, 0)
        allowed = max(0, min(raw_pts, cap - current_in_group))
        header_group_totals[group] = current_in_group + allowed
        header_raw += allowed
        header_contributions.append({'rule_id': rule_id, 'component': 'header_forensics',
            'signal_group': group, 'severity': severity, 'raw_points': raw_pts,
            'applied_points': allowed, 'evidence': evidence, 'source': source,
            'group_cap_applied': allowed < raw_pts})
        header_signals.append({'category': 'headers', 'strength': allowed / 100,
            'reason': reason, 'evidence': evidence, 'source': source})

    if identity.get('display_name_mismatch'):
        _add_header('HEADER_DISPLAY_NAME_IMPERSONATION', 'DISPLAY_NAME_IMPERSONATION', 'high',
                    'Brand in display name differs from sender domain; possible impersonation',
                    identity['display_name_mismatch'])
    sender_lookalikes = [x for x in identity['lookalikes']
                         if x['observed_domain'] in {identity.get('sender_domain'), identity.get('reply_to_domain')}]
    if sender_lookalikes:
        _add_header('HEADER_LOOKALIKE_SENDER', 'LOOKALIKE_SENDER_DOMAIN', 'high',
                    'Potential sender or Reply-To domain lookalike detected',
                    sender_lookalikes)
    if identity['reply_to_mismatch']:
        _add_header('HEADER_REPLY_TO_MISMATCH', 'REPLY_TO_MISMATCH', 'medium',
                    'Reply-To registered domain differs from sender',
                    {'from_domain': identity.get('sender_domain'),
                     'reply_to_domain': identity.get('reply_to_domain')})
    if parsed.get('anomalies'):
        _add_header('HEADER_RELAY_ANOMALY', 'RELAY_ANOMALY', 'medium',
                    'Potential relay timestamp anomaly in Received header chain',
                    parsed['anomalies'])

    header_score = min(SC.HEADER_CAP, header_raw)
    header_component = {'score': header_score, 'weight': SC.COMPONENT_WEIGHTS['header_forensics'],
                        'status': 'AVAILABLE', 'coverage': 1,
                        'contributions': header_contributions,
                        'group_caps_applied': SC.HEADER_GROUP_CAPS}

    # ------------------------------------------------------------------
    # 4. IOC component (0–100)
    # IOC existence alone never adds risk; only suspicious characteristics do.
    # ------------------------------------------------------------------
    ioc_raw = 0
    ioc_signals = []
    ioc_contributions = []
    for url in parsed.get('urls', []):
        # Strength from all forensic signals (used by legacy contributions accumulation)
        raw_strength = (min(1.0, sum(s['strength'] for s in url.get('signals', [])))
                        if url.get('signals') else min(1.0, len(url.get('flags', [])) * 0.2))
        if raw_strength:
            ioc_signals.append({'category': 'url', 'strength': raw_strength,
                'reason': 'Local URL evidence warrants review; no heuristic establishes maliciousness',
                'evidence': url, 'source': 'Forensic'})
        # Structured IOC points for the new component_scores (only named signal types)
        url_pts = 0
        url_rules = []
        for sig in url.get('signals', []):
            if sig['type'] in ('lookalike_domain', 'display_href_mismatch'):
                pts = SC.IOC_POINTS['URL_DISPLAY_MISMATCH']
                url_pts += pts
                url_rules.append({'type': sig['type'], 'applied_points': pts})
            elif sig['type'] == 'url_userinfo':
                pts = SC.IOC_POINTS['OBFUSCATED_URL']
                url_pts += pts
                url_rules.append({'type': sig['type'], 'applied_points': pts})
            else:
                # Other URL signals (long_url, credential_keywords, etc.) — use strength-scaled points
                pts = int(sig.get('strength', 0) * 50)  # scale strength to rough 0-50 pts
                if pts:
                    url_pts += pts
                    url_rules.append({'type': sig['type'], 'applied_points': pts})
        if url.get('flags') and not url_pts:
            url_pts += SC.IOC_POINTS['MALICIOUS_URL']
            url_rules.append({'flags': url['flags']})
        if url_pts:
            ioc_contributions.append({'rule_id': 'IOC_URL', 'component': 'ioc',
                'signal_group': 'url', 'severity': 'medium', 'raw_points': url_pts,
                'applied_points': url_pts, 'evidence': {'url': url.get('original_url'), 'signals': url_rules},
                'source': 'Forensic URL analysis'})
            ioc_raw += url_pts
    for att in parsed.get('attachments', []):
        if att.get('flags'):
            pts = SC.IOC_POINTS['SUSPICIOUS_ATTACHMENT']
            if 'Executable or script' in att['flags']:
                pts = SC.IOC_POINTS['MALICIOUS_HASH']
            ioc_contributions.append({'rule_id': 'IOC_ATTACHMENT', 'component': 'ioc',
                'signal_group': 'attachment', 'severity': 'high', 'raw_points': pts,
                'applied_points': pts, 'evidence': att, 'source': 'Attachment analysis'})
            ioc_raw += pts
            ioc_signals.append({'category': 'attachment', 'strength': min(1.0, pts / 100),
                'reason': 'Attachment type warrants review; no malware verdict', 'evidence': att, 'source': 'Forensic'})
    # URL signals: strongest single URL, not cumulative (prevents 100 weak links inflating score)
    url_strengths = [s['strength'] for s in ioc_signals if s['category'] == 'url']
    url_applied = max(url_strengths, default=0)
    non_url = [s['strength'] for s in ioc_signals if s['category'] != 'url']
    ioc_effective = min(SC.IOC_CAP, int(url_applied * 100) + sum(int(s * 100) for s in non_url))
    ioc_component = {'score': ioc_effective, 'weight': SC.COMPONENT_WEIGHTS['ioc'],
                     'status': 'AVAILABLE', 'coverage': 1,
                     'contributions': ioc_contributions,
                     'note': 'URL score uses strongest single URL, not cumulative sum'}

    # ------------------------------------------------------------------
    # 5. Threat Intelligence component (0–100)
    # Unavailable = explicitly tracked, not silently zeroed.
    # ------------------------------------------------------------------
    intel_raw = 0
    intel_signals = []
    intel_contributions = []
    intel_coverage = 0
    intel_available = 0
    bad = malicious_signals(enrichment)
    for item in enrichment:
        for prov in item.get('providers', []):
            if prov.get('provider') not in ('virustotal', 'abuseipdb', 'greynoise', 'urlscan'):
                continue
            intel_coverage += 1
            if prov.get('status') == 'Available':
                intel_available += 1
    provider_strength: dict[str, float] = {}
    for evidence in bad:
        provider_strength[evidence['provider']] = max(
            provider_strength.get(evidence['provider'], 0), evidence['strength'])
    for provider, strength in provider_strength.items():
        pts = min(SC.INTEL_CAP, int(strength * 100))
        intel_raw += pts
        provider_bad = [b for b in bad if b['provider'] == provider]
        intel_contributions.append({'rule_id': f'INTEL_{provider.upper()}_MALICIOUS',
            'component': 'threat_intelligence', 'signal_group': 'reputation',
            'severity': 'high', 'raw_points': pts, 'applied_points': pts,
            'evidence': provider_bad, 'source': f'Threat intelligence: {provider}'})
        intel_signals.append({'category': 'intelligence', 'strength': strength,
            'reason': f'Bounded provider reputation evidence from {provider}; not an email verdict',
            'evidence': provider_bad, 'source': 'Threat intelligence'})
    intel_score = min(SC.INTEL_CAP, intel_raw)
    intel_status = ('AVAILABLE' if intel_available > 0 else
                    'UNAVAILABLE' if intel_coverage > 0 else
                    'NOT_CONFIGURED')
    intel_component = {'score': intel_score, 'weight': SC.COMPONENT_WEIGHTS['threat_intelligence'],
                       'status': intel_status,
                       'coverage': f'{intel_available}/{max(1, intel_coverage)} providers responded',
                       'contributions': intel_contributions,
                       'note': ('UNAVAILABLE means no data, not that the email is safe. '
                                'Threat intelligence is optional enrichment only.')}

    # ------------------------------------------------------------------
    # Diagnostic component details (not the final scoring formula)
    # ------------------------------------------------------------------
    component_scores = {
        'ml':                  ml_component,
        'authentication':      auth_component,
        'header_forensics':    header_component,
        'ioc':                 ioc_component,
        'threat_intelligence': intel_component,
    }
    signals = ml_signals + auth_signals + header_signals + ioc_signals + intel_signals

    # ------------------------------------------------------------------
    # Authoritative configured policy contributions. These reconcile with the
    # displayed final score after the explicit adjustments and rounding below.
    # ------------------------------------------------------------------
    weights = config.get('risk_weights', {})
    contributions = []
    for key, weight in (weights or {}).items():
        strengths = [s['strength'] for s in signals if s['category'] == key]
        strength = min(1.0, max(strengths, default=0) if key == 'url' else sum(strengths))
        contributions.append({'category': key, 'maximum_points': weight,
                              'strength': round(strength, 4),
                              'points': round(weight * strength, 2)})
    legacy_weighted = min(100, sum(c['points'] for c in contributions))

    # ------------------------------------------------------------------
    # Correlation rules and floor adjustment (unchanged logic)
    # ------------------------------------------------------------------
    rules = correlation_rules(parsed, config)
    strongest = max(rules, key=lambda r: r['minimum_score'], default=None)
    floor = strongest['minimum_score'] if strongest else 0
    adjustment = round(max(0, floor - legacy_weighted), 2)
    if adjustment:
        contributions.append({'category': 'correlated_evidence',
                              'maximum_points': round(100 - legacy_weighted, 2),
                              'strength': round(adjustment / (100 - legacy_weighted), 4),
                              'points': adjustment})
    model_review = model_review_policy(ml, config)
    after_correlation = round(legacy_weighted + adjustment, 2)
    review_adjustment = round(max(0, (model_review['minimum_score'] if model_review else 0) - after_correlation), 2)
    if review_adjustment:
        contributions.append({'category': 'model_review',
                              'maximum_points': round(100 - after_correlation, 2),
                              'strength': round(review_adjustment / (100 - after_correlation), 4),
                              'points': review_adjustment})
    score = min(100, round(after_correlation + review_adjustment))
    low, high, critical = config['risk_thresholds']
    severity = ('CRITICAL' if score >= critical else
                'HIGH'     if score >= high     else
                'MEDIUM'   if score >= low      else 'LOW')
    category, category_basis = threat_category(parsed, ml)
    verdict = strongest['verdict'] if strongest else ml.get('label') or 'Unknown'
    if strongest:
        category, category_basis = strongest['category'], strongest['reason'] + '; heuristic finding, not proof'
    for rule in rules:
        signals.append({'category': 'correlated_evidence', 'strength': rule['minimum_score'] / 100,
                        'reason': rule['reason'], 'evidence': rule['evidence'],
                        'source': 'Local correlation rule: ' + rule['id']})
    confidence = ml.get('confidence') if verdict == ml.get('label') else None

    # All contributions (structured)
    all_score_contributions = (auth_contributions + header_contributions +
                                ioc_contributions + intel_contributions)

    return {
        # --- existing keys (backwards compatible) ---
        'category': category, 'category_basis': category_basis,
        'confidence': confidence,
        'confidence_source': ('ML class probability only' if confidence is not None
                              else 'Uncalibrated local rule; no probability assigned'),
        'risk_score': score, 'severity': severity,
        'contributions': contributions, 'signals': signals,
        'risk_version': RISK_VERSION,
        'weighted_score': round(legacy_weighted, 2),
        'correlation_rules': rules, 'model_review': model_review,
        'scoring_policy': {'weights': dict(weights), 'thresholds': list(config['risk_thresholds']),
                           'model_high_priority_probability': .7},
        'review_recommendation': (
            'Suspected ' + verdict + ' — analyst review required' if verdict in ('PHISHING', 'BEC') else
            'Model unavailable — manual review required' if ml.get('status') != 'Available' else
            'Review the observed risk indicators' if score >= low else
            'Low observed risk; this is not a safety verdict'),
        'verdict': verdict,
        'verdict_source': (
            'Local evidence correlation' + (' and ML inference' if verdict == ml.get('label') else
                                            '; model prediction retained separately')
            if strongest else
            'ML inference' if ml['status'] == 'Available' else 'Model unavailable'),
        'formula': ('Maximum of weighted evidence, correlation-rule minimum, and model review minimum; '
                    'repeated URL signals use the strongest URL only'),
        'interpretation': ('Policy-based review priority, not a probability. '
                           'Missing evidence does not indicate safety. '
                           'Model review adjustments are policy decisions, not extra forensic evidence.'),
        # --- new explainability keys ---
        'component_scores':       component_scores,
        'component_scores_interpretation': 'Diagnostic evidence groups only. Use contributions, weighted_score and policy adjustments to explain risk_score.',
        'score_contributions':    all_score_contributions,
        'risk_engine_version':    SC.RISK_ENGINE_VERSION,
        'top_evidence': [
            c['evidence'] if isinstance(c['evidence'], str) else c.get('rule_id', '')
            for c in sorted(all_score_contributions, key=lambda x: x.get('applied_points', 0), reverse=True)[:5]
        ],
        'limitations': [
            'UNKNOWN / NOT_CONFIGURED authentication is not treated as failure.',
            'Unavailable threat intelligence is tracked explicitly, not silently treated as safe.',
            'Per-group caps prevent correlated forensic signals from artificially inflating the score.',
            'VPN / TOR / proxy presence affects Origin Confidence, not Threat Risk.',
            'Initial component weights are V1 heuristic baseline; not scientifically optimised.',
        ],
    }

def threat_category(parsed,ml):
    text=parsed['model_text'].lower()
    credential_links=any(any(s['type']=='credential_keywords' for s in u.get('signals',[])) for u in parsed['urls'])
    if ml.get('label')=='BEC':return 'BUSINESS_EMAIL_COMPROMISE','ML-derived category; inspect payment instructions and sender identity'
    if ml.get('label')=='PHISHING' and credential_links:return 'CREDENTIAL_THEFT','Phishing model verdict plus locally observed credential-link wording; analyst review required'
    identity=parsed['sender_identity']
    sender_lookalikes=[x for x in identity['lookalikes'] if x['observed_domain'] in {identity.get('sender_domain'),identity.get('reply_to_domain')}]
    if sender_lookalikes or identity.get('display_name_mismatch'):return 'POSSIBLE_IMPERSONATION','Local identity/lookalike evidence; ownership and intent are not established'
    if re.search(r'wire transfer|bank details|payment details|beneficiary|gift cards',text) and re.search(r'changed|new|urgent|confidential|today',text):return 'PAYMENT_REDIRECTION_REVIEW','Payment and urgency/change wording observed locally; this does not override the ML verdict'
    if ml.get('label')=='PHISHING':return 'PHISHING','ML-derived category'
    if ml.get('label')=='SPAM':return 'UNSOLICITED_EMAIL','ML-derived category'
    if any(sum(s['strength'] for s in u.get('signals',[]))>=.4 for u in parsed['urls']):return 'SUSPICIOUS_LINK_REVIEW','Multiple local link indicators require review even when the ML prediction is benign'
    if re.search(r'wire transfer|bank details|payment details|beneficiary|gift cards',text):return 'PAYMENT_REQUEST_REVIEW','Payment wording observed locally; not a BEC verdict'
    return 'NO_SPECIFIC_CATEGORY','No specific threat category established by available evidence'

