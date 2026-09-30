"""Configuration readiness, deliberately separate from live-service verification."""


def deployment_readiness(config, model_status, providers, gmail_configured, monitored_mailboxes):
    rows = []
    def add(capability, status, detail):
        rows.append({'capability': capability, 'status': status, 'detail': detail})
    add('Local AI analysis', 'Available' if model_status == 'Available' else 'Needs attention',
        'Loaded local model; probabilities are separate from review risk.' if model_status == 'Available' else 'Deploy or select a readable trusted model artifact.')
    add('Authentication verification', 'Enabled with limits' if config['dns_enabled'] else 'Disabled',
        'DNS enables local DKIM and DMARC alignment checks. Uploaded mail does not establish an authoritative SMTP peer or SPF envelope.')
    geo = providers.get('geoip', 'Not Configured')
    ipinfo = providers.get('ipinfo', 'Not Configured')
    add('Infrastructure geolocation', geo,
        'MaxMind fallback requires a readable local City and/or ASN database. Availability varies by IP; coordinates never identify a human sender.')
    add('IPinfo network intelligence', ipinfo if config['automatic_enrichment'] else 'Disabled for automatic analysis',
        'Enable ipinfo and automatic enrichment, then configure IPINFO_TOKEN. IPinfo is preferred; missing plan fields stay unknown or use source-labelled MaxMind fallback. Configuration is not a connectivity check.')
    reputation = [p for p in ('virustotal', 'abuseipdb', 'urlscan', 'greynoise') if providers.get(p) == 'Configured']
    add('Automatic reputation enrichment', 'Configured' if config['automatic_enrichment'] and reputation else 'Needs setup',
        ('Configured adapters: ' + ', '.join(reputation) + '. ' if reputation else 'Add a supported provider credential. ') +
        'Enable automatic enrichment for new analyses. Configuration alone does not verify connectivity or quota.')
    add('RDAP registration intelligence', 'Enabled' if config.get('rdap_enabled') and config['automatic_enrichment'] else 'Disabled for automatic analysis',
        'Enable RDAP and automatic enrichment for new analyses; manual lookups require RDAP enabled. Registrar responses may be unavailable or redacted.')
    add('New Gmail message monitoring', 'Enabled' if monitored_mailboxes else 'Needs connection' if gmail_configured else 'Needs OAuth setup',
        f'{monitored_mailboxes} mailbox(es) opted in. Monitoring requires a running worker, valid OAuth access and provider availability; it checks mail after inbox delivery.')
    add('High-risk analyst alerts', 'Implemented',
        'HIGH and CRITICAL analyses enter the alert queue. The configured alert threshold can include lower-risk findings; alerts refresh every five seconds in the UI.')
    add('Alerts before user interaction', 'Requires mail-server integration',
        'Uploads and read-only Gmail polling cannot hold delivery or guarantee a warning before an email is opened. No gateway or quarantine control is connected.')
    add('Identity and compromise attribution', 'Investigative support only',
        'Source-qualified infrastructure and campaign leads are available. Confirming a compromised account or a person requires independent login, endpoint or mail-server evidence.')
    add('Privacy and retention', 'Configured controls',
        f"Analyst masking is {'enabled' if config['mask_sensitive'] else 'disabled'}; automatic retention is {'enabled' if config['retention_enabled'] else 'disabled'}. Case/campaign holds apply. Review these controls against institutional policy.")
    return {'assessment': 'Configuration checklist, not a live-service test or a compliance certification', 'items': rows}
