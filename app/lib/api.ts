/**
 * MailTrace AI — Typed API client
 * All frontend<->backend communication goes through this module.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

class APIError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T = unknown>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token =
    typeof window !== "undefined" ? localStorage.getItem("mt_token") : null;

  const headers: HeadersInit = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {}
    throw new APIError(res.status, detail);
  }

  // 204 No Content
  if (res.status === 204) return undefined as T;
  return res.json();
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const authAPI = {
  login: (email: string, password: string) =>
    request<{ access_token: string; token_type: string; user: User }>(
      "/auth/login",
      { method: "POST", body: JSON.stringify({ email, password }) }
    ),
  logout: () => request("/auth/logout", { method: "POST" }),
  me: () => request<User>("/auth/me"),
};

// ─── Dashboard ─────────────────────────────────────────────────────────────────

export const dashboardAPI = {
  stats: () => request<DashboardStats>("/dashboard/stats"),
  threatTrends: () => request<ThreatTrend[]>("/dashboard/threat-trends"),
  recentCases: (limit = 10) =>
    request<RecentCase[]>(`/dashboard/recent-cases?limit=${limit}`),
  threatDistribution: () =>
    request<ThreatDistributionItem[]>("/dashboard/threat-distribution"),
  authFailures: () => request<AuthFailure[]>("/dashboard/auth-failures"),
  topDomains: () => request<TopDomain[]>("/dashboard/top-domains"),
};

// ─── Email Analysis ────────────────────────────────────────────────────────────

export const emailAPI = {
  listDemos: () => request<DemoEmail[]>("/demo/emails"),
  analyzeDemo: (demoId: string) =>
    request<AnalysisResult>(`/demo/emails/${demoId}/analyze`, {
      method: "POST",
    }),
  analyzeRaw: (rawEmail: string, caseId?: string) =>
    request<AnalysisResult>("/emails/analyze", {
      method: "POST",
      body: JSON.stringify({ raw_email: rawEmail, case_id: caseId }),
    }),
  uploadEml: (file: File) => {
    const token =
      typeof window !== "undefined" ? localStorage.getItem("mt_token") : null;
    const form = new FormData();
    form.append("file", file);
    return fetch(`${API_BASE}/emails/upload`, {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: form,
      credentials: "include",
    }).then(async (r) => {
      if (!r.ok) {
        const b = await r.json().catch(() => ({}));
        throw new APIError(r.status, b.detail || `Upload failed ${r.status}`);
      }
      return r.json() as Promise<AnalysisResult>;
    });
  },
  get: (id: string) => request<AnalysisResult>(`/emails/${id}`),
  list: (skip = 0, limit = 20) =>
    request<AnalysisResult[]>(`/emails?skip=${skip}&limit=${limit}`),
};

// ─── Cases ─────────────────────────────────────────────────────────────────────

export const casesAPI = {
  list: (params?: { skip?: number; limit?: number; status?: string }) => {
    const qs = new URLSearchParams();
    if (params?.skip) qs.set("skip", String(params.skip));
    if (params?.limit) qs.set("limit", String(params.limit));
    if (params?.status) qs.set("status", params.status);
    return request<{ cases: Case[]; total: number }>(`/cases?${qs}`);
  },
  create: (data: CreateCaseRequest) =>
    request<Case>("/cases", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  get: (id: string) => request<Case>(`/cases/${id}`),
  update: (id: string, data: UpdateCaseRequest) =>
    request<Case>(`/cases/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),
  addNote: (id: string, content: string) =>
    request(`/cases/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ content }),
    }),
};

// ─── Intelligence ──────────────────────────────────────────────────────────────

export const intelAPI = {
  domain: (domain: string) => request<DomainIntel>(`/intel/domain/${domain}`),
  ip: (ip: string) => request<IPIntel>(`/intel/ip/${ip}`),
  url: (url: string) =>
    request(`/intel/url`, {
      method: "POST",
      body: JSON.stringify({ url }),
    }),
  listIOCs: (type?: string) =>
    request<IOCItem[]>(`/intel/iocs${type ? `?ioc_type=${type}` : ""}`),
};

// ─── Reports ───────────────────────────────────────────────────────────────────

export const reportsAPI = {
  list: () => request<Report[]>("/reports"),
  create: (caseId: string, title?: string) =>
    request<Report>("/reports", {
      method: "POST",
      body: JSON.stringify({ case_id: caseId, title }),
    }),
  get: (id: string) => request<Report>(`/reports/${id}`),
  downloadUrl: (id: string) => `${API_BASE}/reports/${id}/download`,
};

// ─── Audit ─────────────────────────────────────────────────────────────────────

export const auditAPI = {
  list: (skip = 0, limit = 100) =>
    request<{ logs: AuditLog[]; total: number }>(
      `/audit-logs?skip=${skip}&limit=${limit}`
    ),
};

// ─── Campaigns ─────────────────────────────────────────────────────────────────

export const campaignsAPI = {
  list: () => request<Campaign[]>("/campaigns"),
  graph: (id: string) =>
    request<CampaignGraph>(`/campaigns/${id}/graph`),
};

// ─── Users ─────────────────────────────────────────────────────────────────────

export const usersAPI = {
  list: () => request<User[]>("/users"),
  create: (data: CreateUserRequest) =>
    request<User>("/users", { method: "POST", body: JSON.stringify(data) }),
  update: (id: string, data: Partial<User>) =>
    request(`/users/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  deactivate: (id: string) =>
    request(`/users/${id}`, { method: "DELETE" }),
};

// ─── Gmail ─────────────────────────────────────────────────────────────────────

export const gmailAPI = {
  status: () => request<GmailStatus>("/gmail/status"),
  authUrl: () => request<{ auth_url: string }>("/auth/gmail"),
  listEmails: (maxResults = 20) =>
    request<GmailInbox>(`/gmail/emails?max_results=${maxResults}`),
  analyzeEmail: (messageId: string) =>
    request<AnalysisResult>(`/gmail/emails/${messageId}/analyze`, {
      method: "POST",
    }),
  disconnect: () =>
    request("/gmail/disconnect", { method: "POST" }),
};

// ─── Notifications ─────────────────────────────────────────────────────────────

export const notificationsAPI = {
  list: () => request<Notification[]>("/notifications"),
  markRead: (id: string) =>
    request(`/notifications/${id}/read`, { method: "POST" }),
};

// ─── Search ────────────────────────────────────────────────────────────────────

export const searchAPI = {
  global: (q: string) =>
    request<SearchResult[]>(`/search?q=${encodeURIComponent(q)}`),
};

// ─── Settings ──────────────────────────────────────────────────────────────────

export const settingsAPI = {
  get: () => request<SystemSettings>("/settings"),
  testVirusTotal: (apiKey: string) =>
    request<{ status: string; message: string }>("/settings/virustotal/test", {
      method: "POST",
      body: JSON.stringify({ api_key: apiKey }),
    }),
};

export { APIError };

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface User {
  id: string;
  name: string;
  email: string;
  role: "ANALYST" | "SENIOR_ANALYST" | "ADMINISTRATOR";
  status: string;
  created_at: string;
  last_login?: string;
}

export interface DashboardStats {
  emails_analyzed: number;
  critical_threats: number;
  phishing_detected: number;
  bec_detected: number;
  active_cases: number;
  active_campaigns: number;
  avg_risk_score: number;
}

export interface ThreatTrend {
  date: string;
  threats: number;
  critical: number;
}

export interface RecentCase {
  id: string;
  case_id: string;
  sender: string;
  subject: string;
  classification: string;
  risk_score: number;
  origin: string;
  status: string;
  created_at: string;
}

export interface ThreatDistributionItem {
  name: string;
  value: number;
  color: string;
}

export interface AuthFailure {
  date: string;
  spf: number;
  dkim: number;
  dmarc: number;
}

export interface TopDomain {
  domain: string;
  count: number;
  risk: string;
}

export interface DemoEmail {
  id: string;
  title: string;
  description: string;
  risk_preview: number;
}

export interface AuthResult {
  spf: string;
  spf_detail: string;
  dkim: string;
  dkim_detail: string;
  dmarc: string;
  dmarc_detail: string;
  reply_to_mismatch: boolean;
  reply_to_mismatch_detail: string;
}

export interface IOCItem {
  id: string;
  type: string;
  indicator: string;
  reputation: string;
  risk_level: string;
  source: string;
  related_cases: string[];
}

export interface URLAnalysisItem {
  displayed_url: string;
  actual_url: string;
  deception: boolean;
  https_enabled: boolean;
  url_length: number;
  has_encoded_chars: boolean;
  suspicious_tld: boolean;
  reputation: string;
  risk_score: number;
}

export interface RelayHop {
  hop_number: number;
  ip: string;
  hostname: string;
  timestamp: string;
  location: string;
  label: string;
  confidence: string;
  notes: string;
}

export interface RiskIndicator {
  id: string;
  label: string;
  severity: string;
  category: string;
}

export interface AnalysisResult {
  id: string;
  case_id?: string;
  email_metadata: {
    from_address: string;
    to: string[];
    cc: string[];
    subject: string;
    date: string;
    message_id: string;
    reply_to: string;
    return_path: string;
    x_originating_ip: string;
    mailer: string;
    raw_headers: string;
    body_text: string;
    body_html: string;
  };
  auth: AuthResult;
  overall_risk_score: number;
  risk_level: string;
  classification: string;
  classification_scores: Record<string, number>;
  risk_indicators: RiskIndicator[];
  iocs: IOCItem[];
  url_analysis: URLAnalysisItem[];
  relay_path: RelayHop[];
  social_engineering: Record<string, number>;
  scoring_breakdown: Record<string, number>;
  explainable_ai: string;
  evidence_hash: string;
  evidence_id?: string;
  sha256?: string;
  analysis_timestamp: string;
  is_demo: boolean;
  demo_label?: string;
}

export interface Case {
  id: string;
  case_id: string;
  title: string;
  classification: string;
  risk_score: number;
  severity: string;
  sender: string;
  subject: string;
  origin: string;
  analyst_id?: string;
  analyst_name?: string;
  status: string;
  created_at: string;
  updated_at: string;
  email_analysis_id?: string;
  evidence_ids: string[];
  ioc_ids: string[];
  campaign_id?: string;
  notes: Array<{ id: string; content: string; author: string; created_at: string }>;
}

export interface CreateCaseRequest {
  title: string;
  classification: string;
  sender: string;
  subject: string;
  risk_score?: number;
  email_analysis_id?: string;
}

export interface UpdateCaseRequest {
  status?: string;
  title?: string;
  classification?: string;
  analyst_id?: string;
}

export interface DomainIntel {
  domain: string;
  registrar: string;
  registered: string;
  domain_age_days: number;
  expires: string;
  nameservers: string[];
  mx_records: string[];
  a_records: string[];
  asn: string;
  isp: string;
  country: string;
  reputation: string;
  brand_similarity?: { brand: string; score: number; method: string };
  new_domain: boolean;
  is_demo: boolean;
  data_source: string;
}

export interface IPIntel {
  ip: string;
  country: string;
  city: string;
  region: string;
  asn: string;
  isp: string;
  reputation: string;
  confidence: number;
  probable_location: string;
  is_vpn: boolean;
  is_tor: boolean;
  location_disclaimer: string;
  is_demo: boolean;
  data_source: string;
  lat?: number;
  lon?: number;
}

export interface Report {
  id: string;
  report_id: string;
  case_id: string;
  case_ref: string;
  title: string;
  analyst_name: string;
  analyst_email: string;
  created_at: string;
  status: string;
  risk_score: number;
  classification: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  user_email: string;
  user_role: string;
  action: string;
  resource?: string;
  resource_id?: string;
  case_id?: string;
  ip_address?: string;
  result: string;
  details: Record<string, unknown>;
}

export interface Campaign {
  id: string;
  campaign_id: string;
  name: string;
  description: string;
  status: string;
  case_count: number;
  ioc_count: number;
  infrastructure_countries: string[];
  created_at: string;
  last_activity: string;
}

export interface CampaignGraph {
  nodes: Array<{ id: string; type: string; label: string; data: Record<string, unknown> }>;
  edges: Array<{ source: string; target: string; label: string }>;
  campaign: string;
}

export interface GmailStatus {
  connected: boolean;
  email?: string;
  connected_at?: string;
  demo_mode?: boolean;
  message?: string;
}

export interface GmailInbox {
  emails: GmailEmail[];
  demo_mode: boolean;
  message?: string;
}

export interface GmailEmail {
  id: string;
  from: string;
  subject: string;
  date: string;
  snippet: string;
  is_read: boolean;
  risk_badge?: string | null;
  source: string;
}

export interface Notification {
  id: string;
  user_id: string;
  title: string;
  message: string;
  type: string;
  read: boolean;
  created_at: string;
  case_id?: string;
}

export interface SearchResult {
  type: string;
  id: string;
  title: string;
  subtitle: string;
  url: string;
}

export interface SystemSettings {
  virustotal_configured: boolean;
  gmail_configured: boolean;
  environment: string;
}

export interface CreateUserRequest {
  name: string;
  email: string;
  password: string;
  role: string;
}
