// Mock analysis results for each demo email
// Full pre-computed analysis results — no API calls needed

export interface AuthResult {
  spf: 'pass' | 'fail' | 'unknown';
  spfDetail: string;
  dkim: 'pass' | 'fail' | 'unknown';
  dkimDetail: string;
  dmarc: 'pass' | 'fail' | 'unknown';
  dmarcDetail: string;
  replyToMismatch: boolean;
  replyToMismatchDetail?: string;
}

export interface IOC {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'email' | 'hash' | 'filename';
  indicator: string;
  reputation: 'malicious' | 'suspicious' | 'unknown' | 'clean';
  source: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'none';
  details?: string;
}

export interface URLAnalysis {
  displayedUrl: string;
  actualUrl: string;
  domain: string;
  httpsEnabled: boolean;
  redirectCount: number;
  urlLength: number;
  hasEncodedChars: boolean;
  suspiciousTld: boolean;
  lookalikeSimilarity: number;
  reputation: 'malicious' | 'suspicious' | 'unknown' | 'clean';
  riskScore: number;
  deception: boolean;
}

export interface DomainIntel {
  domain: string;
  registrar: string;
  registrationDate: string;
  domainAgeDays: number;
  expiryDate: string;
  nameServers: string[];
  mxRecords: string[];
  resolvedIp: string;
  asn: string;
  hostingProvider: string;
  country: string;
  reputation: 'malicious' | 'suspicious' | 'unknown' | 'clean';
  brandSimilarity?: {
    originalDomain: string;
    similarityScore: number;
    classification: string;
  };
}

export interface IPIntel {
  ip: string;
  country: string;
  region: string;
  city: string;
  asn: string;
  isp: string;
  hostingProvider: string;
  reverseDns: string;
  isProxy: boolean;
  isTor: boolean;
  isVpn: boolean;
  reputation: 'malicious' | 'suspicious' | 'unknown' | 'clean';
  confidenceScore: number;
  lat: number;
  lon: number;
  label: string;
}

export interface RelayHop {
  timestamp: string;
  label: string;
  ip: string;
  hostname: string;
  location: string;
  confidence: 'low' | 'observed' | 'trusted';
  lat: number;
  lon: number;
  notes?: string;
}

export interface ThreatClassification {
  phishing: number;
  bec: number;
  impersonation: number;
  credentialTheft: number;
  malwareDelivery: number;
  spamMarketing: number;
}

export interface SocialEngineering {
  urgency: number;
  authority: number;
  financialRequest: number;
  credentialRequest: number;
  executiveImpersonation: number;
  fearInduction: number;
  confidentialityPressure: number;
}

export interface RiskIndicator {
  id: string;
  label: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
}

export interface AnalysisResult {
  id: string;
  demoId: string;
  overallRiskScore: number;
  riskLevel: 'safe' | 'low' | 'suspicious' | 'high' | 'critical';
  classification: string;
  auth: AuthResult;
  classification_scores: ThreatClassification;
  socialEngineering: SocialEngineering;
  riskIndicators: RiskIndicator[];
  explainableAI: string;
  iocs: IOC[];
  urlAnalysis: URLAnalysis[];
  domainIntel: DomainIntel;
  ipIntel: IPIntel;
  relayPath: RelayHop[];
  scoringBreakdown: {
    nlpPhishing: number;
    authentication: number;
    domainRisk: number;
    urlAnalysis: number;
    infrastructureReputation: number;
    headerAnomalies: number;
    attachmentRisk: number;
  };
  evidenceHash: string;
  analysisTimestamp: string;
}

export const mockAnalysisResults: Record<string, AnalysisResult> = {
  'demo-1': {
    id: 'analysis-001',
    demoId: 'demo-1',
    overallRiskScore: 7,
    riskLevel: 'safe',
    classification: 'Legitimate',
    auth: {
      spf: 'pass',
      spfDetail: 'Sending IP 40.107.11.52 is authorized by microsoft.com SPF policy.',
      dkim: 'pass',
      dkimDetail: 'Valid DKIM signature. Selector: google. Domain: microsoft.com.',
      dmarc: 'pass',
      dmarcDetail: 'DMARC alignment passed. Policy: None. Action: No action taken.',
      replyToMismatch: false,
    },
    classification_scores: {
      phishing: 3,
      bec: 1,
      impersonation: 2,
      credentialTheft: 1,
      malwareDelivery: 0,
      spamMarketing: 4,
    },
    socialEngineering: {
      urgency: 5,
      authority: 12,
      financialRequest: 0,
      credentialRequest: 0,
      executiveImpersonation: 2,
      fearInduction: 0,
      confidentialityPressure: 0,
    },
    riskIndicators: [
      { id: 'ri-001', label: 'Legitimate Microsoft infrastructure', severity: 'low', category: 'Infrastructure' },
      { id: 'ri-002', label: 'SPF, DKIM, DMARC all pass', severity: 'low', category: 'Authentication' },
    ],
    explainableAI: 'This email has been classified as Legitimate. All authentication mechanisms (SPF, DKIM, DMARC) pass successfully, confirming the email originates from Microsoft\'s authorized sending infrastructure. The sending IP resolves to a known Microsoft mail server. The domain microsoft.com has a long registration history with excellent reputation. No social engineering signals or suspicious URLs were detected. Risk score: 7/100.',
    iocs: [
      { id: 'ioc-001', type: 'domain', indicator: 'microsoft.com', reputation: 'clean', source: 'Domain Intelligence', riskLevel: 'none', details: 'Legitimate Microsoft domain. Age: 29 years.' },
      { id: 'ioc-002', type: 'ip', indicator: '40.107.11.52', reputation: 'clean', source: 'IP Reputation', riskLevel: 'none', details: 'Microsoft Azure datacenter — Dublin, IE' },
      { id: 'ioc-003', type: 'url', indicator: 'https://account.microsoft.com/security', reputation: 'clean', source: 'URL Analysis', riskLevel: 'none', details: 'Legitimate Microsoft account portal' },
    ],
    urlAnalysis: [
      { displayedUrl: 'https://account.microsoft.com/security', actualUrl: 'https://account.microsoft.com/security', domain: 'account.microsoft.com', httpsEnabled: true, redirectCount: 0, urlLength: 40, hasEncodedChars: false, suspiciousTld: false, lookalikeSimilarity: 0, reputation: 'clean', riskScore: 2, deception: false },
    ],
    domainIntel: {
      domain: 'microsoft.com',
      registrar: 'MarkMonitor Inc.',
      registrationDate: '1991-05-02',
      domainAgeDays: 12906,
      expiryDate: '2027-05-03',
      nameServers: ['ns1-205.azure-dns.com', 'ns2-205.azure-dns.net'],
      mxRecords: ['microsoft-com.mail.protection.outlook.com'],
      resolvedIp: '20.112.250.133',
      asn: 'AS8075 (Microsoft Corporation)',
      hostingProvider: 'Microsoft Azure',
      country: 'United States',
      reputation: 'clean',
    },
    ipIntel: {
      ip: '40.107.11.52',
      country: 'Ireland',
      region: 'Leinster',
      city: 'Dublin',
      asn: 'AS8075 (Microsoft Corporation)',
      isp: 'Microsoft Corporation',
      hostingProvider: 'Microsoft Azure',
      reverseDns: 'mail-eopbgr110052.outbound.protection.outlook.com',
      isProxy: false,
      isTor: false,
      isVpn: false,
      reputation: 'clean',
      confidenceScore: 98,
      lat: 53.3498,
      lon: -6.2603,
      label: 'Microsoft Azure — Dublin, Ireland',
    },
    relayPath: [
      { timestamp: '09:15:18', label: 'Microsoft Exchange Online', ip: '40.107.11.52', hostname: 'mail-eopbgr110052.outbound.protection.outlook.com', location: 'Dublin, Ireland', confidence: 'trusted', lat: 53.3498, lon: -6.2603 },
      { timestamp: '09:15:21', label: 'Recipient Mail Server', ip: '203.88.140.22', hostname: 'mx.acmecorp.com', location: 'Mumbai, India', confidence: 'trusted', lat: 19.0760, lon: 72.8777 },
    ],
    scoringBreakdown: { nlpPhishing: 2, authentication: 0, domainRisk: 1, urlAnalysis: 0, infrastructureReputation: 0, headerAnomalies: 0, attachmentRisk: 0 },
    evidenceHash: 'sha256:a3f7c2b1d9e84f23a6c01847bd239f5e3c1a7d8b6e2f91a4c7832bd',
    analysisTimestamp: '2026-08-26T09:17:00Z',
  },

  'demo-2': {
    id: 'analysis-002',
    demoId: 'demo-2',
    overallRiskScore: 86,
    riskLevel: 'critical',
    classification: 'Credential Phishing',
    auth: {
      spf: 'fail',
      spfDetail: 'Sending IP 185.220.101.46 is NOT authorized by microsOft-support.com SPF policy. This IP is associated with known phishing infrastructure.',
      dkim: 'fail',
      dkimDetail: 'DKIM signature verification failed. No valid public key found for selector at microsOft-support.com.',
      dmarc: 'fail',
      dmarcDetail: 'DMARC alignment failed. Policy: Quarantine. SPF alignment: fail. DKIM alignment: fail.',
      replyToMismatch: true,
      replyToMismatchDetail: 'From: payroll@microsOft-support.com → Reply-To: payroll-verify@proton-example.com. Reply-to domain does not match sender domain.',
    },
    classification_scores: {
      phishing: 96,
      bec: 31,
      impersonation: 88,
      credentialTheft: 92,
      malwareDelivery: 12,
      spamMarketing: 8,
    },
    socialEngineering: {
      urgency: 91,
      authority: 73,
      financialRequest: 12,
      credentialRequest: 94,
      executiveImpersonation: 65,
      fearInduction: 88,
      confidentialityPressure: 41,
    },
    riskIndicators: [
      { id: 'ri-101', label: 'Lookalike sender domain detected (microsOft-support.com)', severity: 'critical', category: 'Domain' },
      { id: 'ri-102', label: 'Suspicious credential harvest URL detected', severity: 'critical', category: 'URL' },
      { id: 'ri-103', label: 'SPF, DKIM, DMARC all failed', severity: 'critical', category: 'Authentication' },
      { id: 'ri-104', label: 'Reply-To mismatch detected', severity: 'high', category: 'Header' },
      { id: 'ri-105', label: 'Domain age < 30 days', severity: 'high', category: 'Domain' },
      { id: 'ri-106', label: 'Urgency and fear-inducing language detected', severity: 'high', category: 'Content' },
      { id: 'ri-107', label: 'Source IP associated with known phishing infrastructure', severity: 'critical', category: 'Infrastructure' },
      { id: 'ri-108', label: 'PHPMailer mailer — common in phishing campaigns', severity: 'medium', category: 'Header' },
      { id: 'ri-109', label: 'Sending IP in TOR exit node range', severity: 'high', category: 'Infrastructure' },
    ],
    explainableAI: 'This email has been classified as Credential Phishing with Critical risk (86/100). Multiple high-confidence threat signals were detected: (1) The sender domain "microsOft-support.com" uses a zero-for-O substitution to impersonate Microsoft — brand similarity score 91%. (2) All three authentication mechanisms (SPF, DKIM, DMARC) fail, indicating the email was sent from unauthorized infrastructure. (3) The embedded URL "microsOft-support.com/payroll/verify" leads to a credential harvest page mimicking Microsoft\'s login interface. (4) The email employs high-urgency language and fear induction ("FAILURE TO VERIFY WILL RESULT IN PAYMENT SUSPENSION"), consistent with social engineering patterns. (5) The sending IP 185.220.101.46 is associated with known phishing infrastructure located in Frankfurt, Germany.',
    iocs: [
      { id: 'ioc-101', type: 'domain', indicator: 'microsOft-support.com', reputation: 'malicious', source: 'Domain Intelligence', riskLevel: 'critical', details: 'Lookalike Microsoft domain. Age: 14 days. Registered anonymously.' },
      { id: 'ioc-102', type: 'ip', indicator: '185.220.101.46', reputation: 'malicious', source: 'IP Reputation', riskLevel: 'critical', details: 'Known phishing infrastructure — Frankfurt, DE.' },
      { id: 'ioc-103', type: 'url', indicator: 'https://microsOft-support.com/payroll/verify?token=a7f3k9p2', reputation: 'malicious', source: 'URL Analysis', riskLevel: 'critical', details: 'Credential harvest page mimicking Microsoft login.' },
      { id: 'ioc-104', type: 'email', indicator: 'payroll-verify@proton-example.com', reputation: 'suspicious', source: 'Header Analysis', riskLevel: 'high', details: 'Reply-To address on anonymous email provider.' },
      { id: 'ioc-105', type: 'email', indicator: 'payroll@microsOft-support.com', reputation: 'malicious', source: 'Header Analysis', riskLevel: 'critical', details: 'Impersonation sender address.' },
    ],
    urlAnalysis: [
      {
        displayedUrl: 'https://microsOft-support.com/payroll/verify',
        actualUrl: 'https://microsOft-support.com/payroll/verify?token=a7f3k9p2&redirect=https://acmecorp.com',
        domain: 'microsOft-support.com',
        httpsEnabled: true,
        redirectCount: 2,
        urlLength: 89,
        hasEncodedChars: true,
        suspiciousTld: false,
        lookalikeSimilarity: 91,
        reputation: 'malicious',
        riskScore: 94,
        deception: true,
      },
    ],
    domainIntel: {
      domain: 'microsOft-support.com',
      registrar: 'Namecheap Inc.',
      registrationDate: '2026-08-12',
      domainAgeDays: 14,
      expiryDate: '2027-08-12',
      nameServers: ['ns1.bulletproof-dns.to', 'ns2.bulletproof-dns.to'],
      mxRecords: ['mail.microsOft-support.com'],
      resolvedIp: '185.220.101.46',
      asn: 'AS206337 (Frankenburg Internet KG)',
      hostingProvider: 'Bulletproof hosting — Frankfurt, DE',
      country: 'Germany',
      reputation: 'malicious',
      brandSimilarity: {
        originalDomain: 'microsoft.com',
        similarityScore: 91,
        classification: 'Likely Lookalike / Impersonation Domain',
      },
    },
    ipIntel: {
      ip: '185.220.101.46',
      country: 'Germany',
      region: 'Hesse',
      city: 'Frankfurt',
      asn: 'AS206337 (Frankenburg Internet KG)',
      isp: 'Frankenburg Internet KG',
      hostingProvider: 'Bulletproof Hosting Provider',
      reverseDns: 'tor-exit-46.frankenburg.de',
      isProxy: false,
      isTor: true,
      isVpn: false,
      reputation: 'malicious',
      confidenceScore: 91,
      lat: 50.1109,
      lon: 8.6821,
      label: 'Probable Infrastructure Location: Frankfurt, Germany',
    },
    relayPath: [
      { timestamp: '10:18:01', label: 'Origin node detected', ip: '185.220.101.46', hostname: 'tor-exit-46.frankenburg.de', location: 'Frankfurt, Germany', confidence: 'low', lat: 50.1109, lon: 8.6821, notes: 'TOR exit node. Low confidence on attribution.' },
      { timestamp: '10:18:04', label: 'Phishing mail server', ip: '185.220.101.46', hostname: 'mail.microsOft-support.com', location: 'Frankfurt, Germany', confidence: 'observed', lat: 50.1109, lon: 8.6821 },
      { timestamp: '10:18:05', label: 'Recipient mail server', ip: '203.88.140.22', hostname: 'mx.acmecorp.com', location: 'Mumbai, India', confidence: 'trusted', lat: 19.0760, lon: 72.8777 },
    ],
    scoringBreakdown: { nlpPhishing: 22, authentication: 20, domainRisk: 14, urlAnalysis: 15, infrastructureReputation: 9, headerAnomalies: 4, attachmentRisk: 2 },
    evidenceHash: 'sha256:7d4e2f18a93bc56789e1234f5a678bc9d0e12345f6789abcdef01234',
    analysisTimestamp: '2026-08-26T10:20:00Z',
  },

  'demo-3': {
    id: 'analysis-003',
    demoId: 'demo-3',
    overallRiskScore: 94,
    riskLevel: 'critical',
    classification: 'Business Email Compromise',
    auth: {
      spf: 'fail',
      spfDetail: 'Sending IP 185.231.72.12 is NOT authorized by micros0ft-secure.com SPF policy. The domain has no valid SPF record.',
      dkim: 'pass',
      dkimDetail: 'DKIM signature verification passed, however the signing domain micros0ft-secure.com was registered only 3 days ago. Newly observed domain DKIM signature.',
      dmarc: 'fail',
      dmarcDetail: 'DMARC alignment failed. Policy: Reject. SPF alignment: fail. DMARC reject policy indicates the legitimate domain owner would reject this email.',
      replyToMismatch: true,
      replyToMismatchDetail: 'From: ceo@micros0ft-secure.com → Reply-To: finance.verify@proton-example.com. The reply-to address is on a different anonymous provider, redirecting responses away from the apparent sender.',
    },
    classification_scores: {
      phishing: 96,
      bec: 94,
      impersonation: 89,
      credentialTheft: 21,
      malwareDelivery: 5,
      spamMarketing: 2,
    },
    socialEngineering: {
      urgency: 92,
      authority: 96,
      financialRequest: 98,
      credentialRequest: 14,
      executiveImpersonation: 94,
      fearInduction: 61,
      confidentialityPressure: 89,
    },
    riskIndicators: [
      { id: 'ri-201', label: 'Lookalike CEO impersonation domain detected (micros0ft-secure.com)', severity: 'critical', category: 'Domain' },
      { id: 'ri-202', label: 'Suspicious wire transfer request — USD 87,500', severity: 'critical', category: 'Content' },
      { id: 'ri-203', label: 'Reply-To mismatch detected → proton-example.com', severity: 'critical', category: 'Header' },
      { id: 'ri-204', label: 'SPF failed — unauthorized sending infrastructure', severity: 'critical', category: 'Authentication' },
      { id: 'ri-205', label: 'DMARC failed with Reject policy', severity: 'critical', category: 'Authentication' },
      { id: 'ri-206', label: 'Domain registered 3 days ago (micros0ft-secure.com)', severity: 'critical', category: 'Domain' },
      { id: 'ri-207', label: 'Source IP in Singapore datacenter — hosting abuse', severity: 'high', category: 'Infrastructure' },
      { id: 'ri-208', label: 'Executive impersonation language: "CEO", "board meeting"', severity: 'critical', category: 'Content' },
      { id: 'ri-209', label: 'Confidentiality pressure: "do not discuss with team"', severity: 'high', category: 'Content' },
      { id: 'ri-210', label: 'Urgency pressure: "EOD deadline", "final notice"', severity: 'high', category: 'Content' },
    ],
    explainableAI: 'This email has been classified as Business Email Compromise (BEC) with Critical risk (94/100). This is one of the highest-confidence BEC detections on this system. Seven independent threat signals converge: (1) The sender domain "micros0ft-secure.com" uses a zero-for-O substitution achieving 91% brand similarity to microsoft.com. The domain was registered just 3 days prior. (2) SPF authentication fails — the sending IP 185.231.72.12 is not authorized. (3) While DKIM passes, the signing domain is the same 3-day-old fraudulent domain, carrying no trust value. (4) DMARC fails with a Reject policy, confirming this email would be rejected by Microsoft\'s own policies. (5) The Reply-To is redirected to finance.verify@proton-example.com on an anonymous provider, ensuring responses go to the attacker. (6) The email requests an urgent wire transfer of USD 87,500 with specific banking details — a hallmark BEC pattern. (7) Multiple social engineering signals: executive impersonation, authority pressure, urgency framing, and confidentiality pressure.',
    iocs: [
      { id: 'ioc-201', type: 'domain', indicator: 'micros0ft-secure.com', reputation: 'malicious', source: 'Domain Intelligence', riskLevel: 'critical', details: 'Lookalike Microsoft domain. Age: 3 days. Singapore registrant.' },
      { id: 'ioc-202', type: 'ip', indicator: '185.231.72.12', reputation: 'suspicious', source: 'IP Reputation', riskLevel: 'high', details: 'Singapore datacenter — bulletproof hosting.' },
      { id: 'ioc-203', type: 'email', indicator: 'ceo@micros0ft-secure.com', reputation: 'malicious', source: 'Header Analysis', riskLevel: 'critical', details: 'Executive impersonation sender.' },
      { id: 'ioc-204', type: 'email', indicator: 'finance.verify@proton-example.com', reputation: 'suspicious', source: 'Header Analysis', riskLevel: 'high', details: 'Reply-To hijack address on anonymous provider.' },
      { id: 'ioc-205', type: 'domain', indicator: 'sbi-verification.net', reputation: 'malicious', source: 'Campaign Correlation', riskLevel: 'critical', details: 'Related domain from same BEC campaign infrastructure.' },
    ],
    urlAnalysis: [],
    domainIntel: {
      domain: 'micros0ft-secure.com',
      registrar: 'Pte. Reg. Services Ltd.',
      registrationDate: '2026-08-23',
      domainAgeDays: 3,
      expiryDate: '2027-08-23',
      nameServers: ['ns1.cloudflare-bypass.net', 'ns2.cloudflare-bypass.net'],
      mxRecords: ['mail.micros0ft-secure.com'],
      resolvedIp: '185.231.72.12',
      asn: 'AS56478 (Emerald Isle Hosting Pte Ltd)',
      hostingProvider: 'Bulletproof Hosting — Singapore',
      country: 'Singapore',
      reputation: 'malicious',
      brandSimilarity: {
        originalDomain: 'microsoft.com',
        similarityScore: 91,
        classification: 'Likely Lookalike / Impersonation Domain',
      },
    },
    ipIntel: {
      ip: '185.231.72.12',
      country: 'Singapore',
      region: 'Central Singapore',
      city: 'Singapore',
      asn: 'AS56478 (Emerald Isle Hosting Pte Ltd)',
      isp: 'Emerald Isle Hosting Pte Ltd',
      hostingProvider: 'Bulletproof Hosting Provider',
      reverseDns: 'vps-185-231-72-12.eihosting.sg',
      isProxy: false,
      isTor: false,
      isVpn: false,
      reputation: 'suspicious',
      confidenceScore: 82,
      lat: 1.3521,
      lon: 103.8198,
      label: 'Probable Infrastructure Location: Singapore',
    },
    relayPath: [
      { timestamp: '02:12:31', label: 'Origin node detected', ip: '185.231.72.12', hostname: 'vps-185-231-72-12.eihosting.sg', location: 'Singapore', confidence: 'low', lat: 1.3521, lon: 103.8198, notes: 'Probable origin. Low confidence — VPS infrastructure.' },
      { timestamp: '02:12:34', label: 'Relay server', ip: '104.18.24.10', hostname: 'relay-104-18-24.cloudflare.net', location: 'Frankfurt, Germany', confidence: 'observed', lat: 50.1109, lon: 8.6821 },
      { timestamp: '02:12:37', label: 'Microsoft mail infrastructure', ip: '40.97.128.4', hostname: 'mail-protection.outlook.com', location: 'Amsterdam, Netherlands', confidence: 'trusted', lat: 52.3676, lon: 4.9041 },
      { timestamp: '02:12:40', label: 'Recipient mail server', ip: '203.88.140.22', hostname: 'mx.acmecorp.com', location: 'Mumbai, India', confidence: 'trusted', lat: 19.0760, lon: 72.8777 },
    ],
    scoringBreakdown: { nlpPhishing: 24, authentication: 19, domainRisk: 15, urlAnalysis: 8, infrastructureReputation: 10, headerAnomalies: 10, attachmentRisk: 8 },
    evidenceHash: 'sha256:3e8b7c2a1d4f96e5b3a79f2c8d41e6b0a5c3f8d9e2b4a7c1f3d6e9b2',
    analysisTimestamp: '2026-08-26T11:47:00Z',
  },
};
