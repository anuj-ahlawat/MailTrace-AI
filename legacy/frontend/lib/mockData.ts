// Mock cases data — 24 seeded investigation cases

export type CaseStatus = 'new' | 'investigating' | 'escalated' | 'resolved';
export type CaseClassification = 'Business Email Compromise' | 'Credential Phishing' | 'Suspicious' | 'Legitimate' | 'Malware Delivery' | 'Invoice Fraud' | 'Executive Impersonation';

export interface Case {
  id: string;
  sender: string;
  subject: string;
  classification: CaseClassification;
  riskScore: number;
  origin: string;
  status: CaseStatus;
  timestamp: string;
  analyst: string;
  demoId?: string;
}

export const mockCases: Case[] = [
  { id: 'MT-2026-00124', sender: 'ceo@micros0ft-secure.com', subject: 'Urgent Vendor Payment Approval', classification: 'Business Email Compromise', riskScore: 94, origin: 'Singapore', status: 'investigating', timestamp: 'Today 11:45 AM', analyst: 'AM', demoId: 'demo-3' },
  { id: 'MT-2026-00123', sender: 'payroll@microsOft-support.com', subject: 'Action required: verify your payroll account', classification: 'Credential Phishing', riskScore: 86, origin: 'Frankfurt, DE', status: 'investigating', timestamp: 'Today 10:18 AM', analyst: 'AM', demoId: 'demo-2' },
  { id: 'MT-2026-00122', sender: 'invoice@vendor-portal.co', subject: 'Invoice #8841 ready for payment', classification: 'Invoice Fraud', riskScore: 67, origin: 'Amsterdam, NL', status: 'new', timestamp: 'Yesterday 4:30 PM', analyst: 'SK' },
  { id: 'MT-2026-00121', sender: 'security-noreply@microsoft.com', subject: 'Your security summary', classification: 'Legitimate', riskScore: 7, origin: 'Dublin, IE', status: 'resolved', timestamp: 'Yesterday 2:06 PM', analyst: 'AM', demoId: 'demo-1' },
  { id: 'MT-2026-00120', sender: 'hr-team@acm3-corp.com', subject: 'Important HR Update for All Employees', classification: 'Executive Impersonation', riskScore: 78, origin: 'Bucharest, RO', status: 'escalated', timestamp: 'Yesterday 11:22 AM', analyst: 'RK' },
  { id: 'MT-2026-00119', sender: 'noreply@amazonn-prime.com', subject: 'Your order has shipped', classification: 'Credential Phishing', riskScore: 82, origin: 'Lagos, NG', status: 'new', timestamp: 'Yesterday 09:14 AM', analyst: 'SK' },
  { id: 'MT-2026-00118', sender: 'cfo@company-finance.net', subject: 'Q3 Budget Approval Required', classification: 'Business Email Compromise', riskScore: 89, origin: 'Hong Kong', status: 'escalated', timestamp: 'Aug 25, 3:22 PM', analyst: 'AM' },
  { id: 'MT-2026-00117', sender: 'admin@it-helpdesk-support.info', subject: 'Your account will be suspended', classification: 'Credential Phishing', riskScore: 74, origin: 'Kyiv, UA', status: 'resolved', timestamp: 'Aug 25, 1:07 PM', analyst: 'RK' },
  { id: 'MT-2026-00116', sender: 'shipping@fedexpress-track.com', subject: 'Package delivery failed — action required', classification: 'Credential Phishing', riskScore: 81, origin: 'Sofia, BG', status: 'resolved', timestamp: 'Aug 25, 10:49 AM', analyst: 'SK' },
  { id: 'MT-2026-00115', sender: 'ceo@internal-board.co', subject: 'Confidential: Board resolution — transfer approval', classification: 'Business Email Compromise', riskScore: 96, origin: 'Moscow, RU', status: 'escalated', timestamp: 'Aug 24, 4:38 PM', analyst: 'AM' },
  { id: 'MT-2026-00114', sender: 'vendor@globalparts-supply.com', subject: 'Updated bank account details for payments', classification: 'Invoice Fraud', riskScore: 71, origin: 'Accra, GH', status: 'investigating', timestamp: 'Aug 24, 2:15 PM', analyst: 'RK' },
  { id: 'MT-2026-00113', sender: 'noreply@paypa1-secure.com', subject: 'Unusual activity on your PayPal account', classification: 'Credential Phishing', riskScore: 88, origin: 'Minsk, BY', status: 'resolved', timestamp: 'Aug 24, 11:04 AM', analyst: 'SK' },
  { id: 'MT-2026-00112', sender: 'info@sbi-alerts.net', subject: 'Your SBI account requires KYC update', classification: 'Credential Phishing', riskScore: 83, origin: 'Lahore, PK', status: 'resolved', timestamp: 'Aug 23, 5:22 PM', analyst: 'AM' },
  { id: 'MT-2026-00111', sender: 'chairman@board-group.org', subject: 'Urgent wire approval — confidential', classification: 'Business Email Compromise', riskScore: 91, origin: 'Kowloon, HK', status: 'escalated', timestamp: 'Aug 23, 3:11 PM', analyst: 'RK' },
  { id: 'MT-2026-00110', sender: 'support@dropb0x-secure.com', subject: 'Files shared with you — view now', classification: 'Malware Delivery', riskScore: 69, origin: 'Warsaw, PL', status: 'investigating', timestamp: 'Aug 23, 1:33 PM', analyst: 'SK' },
  { id: 'MT-2026-00109', sender: 'procurement@vendor-billing.io', subject: 'Invoice INV-2026-0782 overdue', classification: 'Invoice Fraud', riskScore: 62, origin: 'Cairo, EG', status: 'new', timestamp: 'Aug 22, 4:50 PM', analyst: 'AM' },
  { id: 'MT-2026-00108', sender: 'hr@emp-portal.net', subject: 'Salary revision letter — download attached', classification: 'Malware Delivery', riskScore: 79, origin: 'Riyadh, SA', status: 'resolved', timestamp: 'Aug 22, 2:28 PM', analyst: 'RK' },
  { id: 'MT-2026-00107', sender: 'alert@gooogIe-security.com', subject: 'Critical security alert for your Google account', classification: 'Credential Phishing', riskScore: 90, origin: 'Dhaka, BD', status: 'resolved', timestamp: 'Aug 22, 10:14 AM', analyst: 'SK' },
  { id: 'MT-2026-00106', sender: 'noreply@linkedln-jobs.com', subject: 'You have a new job opportunity', classification: 'Credential Phishing', riskScore: 55, origin: 'Tehran, IR', status: 'new', timestamp: 'Aug 21, 3:47 PM', analyst: 'AM' },
  { id: 'MT-2026-00105', sender: 'admin@enterprise-helpdesk.in', subject: 'Your Microsoft license expires today', classification: 'Credential Phishing', riskScore: 72, origin: 'Colombo, LK', status: 'resolved', timestamp: 'Aug 21, 1:22 PM', analyst: 'RK' },
  { id: 'MT-2026-00104', sender: 'ceo@acme-secure.co', subject: 'Urgent: Vendor Contract Modification', classification: 'Business Email Compromise', riskScore: 87, origin: 'Kuala Lumpur, MY', status: 'resolved', timestamp: 'Aug 20, 4:38 PM', analyst: 'SK' },
  { id: 'MT-2026-00103', sender: 'finance@acmecorp.com', subject: 'Q3 Financial Report — Internal', classification: 'Legitimate', riskScore: 5, origin: 'Mumbai, IN', status: 'resolved', timestamp: 'Aug 20, 2:11 PM', analyst: 'AM' },
  { id: 'MT-2026-00102', sender: 'no-reply@hdfc-bank-alert.net', subject: 'HDFC Bank — transaction alert', classification: 'Credential Phishing', riskScore: 85, origin: 'Istanbul, TR', status: 'resolved', timestamp: 'Aug 19, 5:03 PM', analyst: 'RK' },
  { id: 'MT-2026-00101', sender: 'it-security@acmecorp.com', subject: 'Password expiry notice', classification: 'Legitimate', riskScore: 9, origin: 'Mumbai, IN', status: 'resolved', timestamp: 'Aug 19, 11:22 AM', analyst: 'SK' },
];

export const dashboardStats = {
  emailsAnalyzed: 1284,
  criticalThreats: 86,
  phishingDetected: 214,
  becDetected: 37,
  activeCampaigns: 12,
  avgRiskScore: 42,
  emailsAnalyzedChange: 12.8,
  criticalThreatsChange: -8.4,
  phishingChange: -16.2,
  becChange: -4.1,
  activeCampaignsChange: 2.3,
  avgRiskScoreChange: -6.7,
};

export const threatActivityData = [
  { date: 'Aug 1', threats: 28, critical: 8 },
  { date: 'Aug 3', threats: 42, critical: 12 },
  { date: 'Aug 5', threats: 35, critical: 9 },
  { date: 'Aug 7', threats: 58, critical: 18 },
  { date: 'Aug 9', threats: 47, critical: 14 },
  { date: 'Aug 11', threats: 38, critical: 11 },
  { date: 'Aug 13', threats: 52, critical: 16 },
  { date: 'Aug 15', threats: 63, critical: 21 },
  { date: 'Aug 17', threats: 45, critical: 13 },
  { date: 'Aug 19', threats: 71, critical: 24 },
  { date: 'Aug 21', threats: 55, critical: 17 },
  { date: 'Aug 23', threats: 48, critical: 15 },
  { date: 'Aug 25', threats: 66, critical: 22 },
  { date: 'Aug 26', threats: 41, critical: 12 },
];

export const threatDistributionData = [
  { name: 'Phishing', value: 214, color: '#ef4444' },
  { name: 'BEC', value: 37, color: '#f97316' },
  { name: 'Invoice Fraud', value: 52, color: '#eab308' },
  { name: 'Malware', value: 29, color: '#8b5cf6' },
  { name: 'Legitimate', value: 819, color: '#22c55e' },
  { name: 'Suspicious', value: 133, color: '#3b82f6' },
];

export const authFailuresData = [
  { date: 'Aug 20', spf: 24, dkim: 18, dmarc: 31 },
  { date: 'Aug 21', spf: 19, dkim: 14, dmarc: 27 },
  { date: 'Aug 22', spf: 33, dkim: 21, dmarc: 38 },
  { date: 'Aug 23', spf: 28, dkim: 19, dmarc: 34 },
  { date: 'Aug 24', spf: 41, dkim: 29, dmarc: 47 },
  { date: 'Aug 25', spf: 36, dkim: 24, dmarc: 42 },
  { date: 'Aug 26', spf: 22, dkim: 15, dmarc: 28 },
];

export const topMaliciousDomains = [
  { domain: 'micros0ft-secure.com', count: 23, risk: 'critical' },
  { domain: 'paypa1-alert.net', count: 17, risk: 'critical' },
  { domain: 'sbi-verify.in', count: 14, risk: 'critical' },
  { domain: 'vendor-billing.io', count: 11, risk: 'high' },
  { domain: 'it-helpdesk-support.info', count: 9, risk: 'high' },
];

export const topSourceCountries = [
  { country: 'Germany', count: 312, flag: 'DE' },
  { country: 'Singapore', count: 187, flag: 'SG' },
  { country: 'Nigeria', count: 143, flag: 'NG' },
  { country: 'Russia', count: 128, flag: 'RU' },
  { country: 'Pakistan', count: 94, flag: 'PK' },
];

export const mockAuditLogs = [
  { id: 'log-001', timestamp: '2026-08-26 11:45:33', user: 'alex.morgan', action: 'Email analysis initiated', caseId: 'MT-2026-00124', ip: '10.20.30.41', result: 'Success' },
  { id: 'log-002', timestamp: '2026-08-26 11:47:12', user: 'alex.morgan', action: 'IOC viewed', caseId: 'MT-2026-00124', ip: '10.20.30.41', result: 'Success' },
  { id: 'log-003', timestamp: '2026-08-26 11:52:08', user: 'alex.morgan', action: 'Case opened', caseId: 'MT-2026-00124', ip: '10.20.30.41', result: 'Success' },
  { id: 'log-004', timestamp: '2026-08-26 11:54:22', user: 'alex.morgan', action: 'Report generated', caseId: 'MT-2026-00124', ip: '10.20.30.41', result: 'Success' },
  { id: 'log-005', timestamp: '2026-08-26 10:18:45', user: 'alex.morgan', action: 'Email analysis initiated', caseId: 'MT-2026-00123', ip: '10.20.30.41', result: 'Success' },
  { id: 'log-006', timestamp: '2026-08-26 10:21:17', user: 'alex.morgan', action: 'Case status changed', caseId: 'MT-2026-00123', ip: '10.20.30.41', result: 'Investigating' },
  { id: 'log-007', timestamp: '2026-08-26 09:02:11', user: 'alex.morgan', action: 'Analyst login', caseId: '-', ip: '10.20.30.41', result: 'Success' },
  { id: 'log-008', timestamp: '2026-08-25 16:44:38', user: 'sarah.kim', action: 'Email upload', caseId: 'MT-2026-00122', ip: '10.20.30.55', result: 'Success' },
  { id: 'log-009', timestamp: '2026-08-25 16:47:02', user: 'sarah.kim', action: 'Email analysis initiated', caseId: 'MT-2026-00122', ip: '10.20.30.55', result: 'Success' },
  { id: 'log-010', timestamp: '2026-08-25 15:38:19', user: 'raj.kumar', action: 'Case status changed', caseId: 'MT-2026-00120', ip: '10.20.30.62', result: 'Escalated' },
  { id: 'log-011', timestamp: '2026-08-25 14:22:05', user: 'raj.kumar', action: 'Report generated', caseId: 'MT-2026-00120', ip: '10.20.30.62', result: 'Success' },
  { id: 'log-012', timestamp: '2026-08-25 08:55:41', user: 'sarah.kim', action: 'Analyst login', caseId: '-', ip: '10.20.30.55', result: 'Success' },
];
