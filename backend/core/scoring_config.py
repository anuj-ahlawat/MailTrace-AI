"""Centralized scoring configuration for MailTrace AI.

Diagnostic component constants live here. The authoritative risk calculation
uses the configurable seven-category weights in store.DEFAULTS and the
correlation/model-review policy in pipeline.risk. Diagnostic component scores
are retained for inspection; their weighted sum is not the final risk score.

Version history:
  RISK_ENGINE_VERSION  2.2 — authoritative contribution display and sender evidence
  ORIGIN_ENGINE_VERSION 1.2 — candidate-scoped evidence and untrusted-header cap
"""

# ---------------------------------------------------------------------------
# Engine version strings
# ---------------------------------------------------------------------------
RISK_ENGINE_VERSION   = "2.2"
ORIGIN_ENGINE_VERSION = "1.2"

# ---------------------------------------------------------------------------
# THREAT RISK — Component weights (must sum to 1.0)
# V1 heuristic baseline; tune against labelled validation data.
# ---------------------------------------------------------------------------
COMPONENT_WEIGHTS: dict[str, float] = {
    "ml":                  0.30,
    "authentication":      0.25,
    "header_forensics":    0.20,
    "ioc":                 0.15,
    "threat_intelligence": 0.10,
}

# ---------------------------------------------------------------------------
# AUTHENTICATION component — raw contribution points (0–100 scale)
# UNKNOWN / NOT_CONFIGURED / MISSING -> 0 contribution.  Only FAIL adds risk.
# ---------------------------------------------------------------------------
AUTH_POINTS: dict[str, int] = {
    # Header-reported results (lower weight — supplied by sender infrastructure)
    "SPF_FAIL_REPORTED":      16,
    "SPF_SOFTFAIL_REPORTED":   6,
    "DKIM_FAIL_REPORTED":     16,
    "DMARC_FAIL_REPORTED":    24,
    # Live-verified (higher weight — cryptographically checked locally)
    "DKIM_FAIL_VERIFIED":     30,
    # Identity signals that relate to authentication flow
    "REPLY_TO_MISMATCH":      10,
    "RETURN_PATH_MISMATCH":   10,
    "AUTH_ANOMALY":            8,
}
AUTH_CAP: int = 100

# ---------------------------------------------------------------------------
# HEADER FORENSICS component — raw contribution points
# ---------------------------------------------------------------------------
HEADER_POINTS: dict[str, int] = {
    "REPLY_TO_MISMATCH":           15,
    "RETURN_PATH_MISMATCH":        15,
    "SUSPICIOUS_MESSAGE_ID":       10,
    "DISPLAY_NAME_IMPERSONATION":  20,
    "LOOKALIKE_SENDER_DOMAIN":     25,
    "RELAY_ANOMALY":               15,
}

# Signal-group caps prevent correlated signals from stacking arbitrarily.
# e.g. lookalike + display-name + mismatch likely describe ONE identity event.
HEADER_GROUP_CAPS: dict[str, int] = {
    "identity_spoofing": 40,
    "routing":           25,
}
HEADER_CAP: int = 100

HEADER_SIGNAL_GROUP: dict[str, str] = {
    "REPLY_TO_MISMATCH":           "identity_spoofing",
    "RETURN_PATH_MISMATCH":        "identity_spoofing",
    "DISPLAY_NAME_IMPERSONATION":  "identity_spoofing",
    "LOOKALIKE_SENDER_DOMAIN":     "identity_spoofing",
    "SUSPICIOUS_MESSAGE_ID":       "routing",
    "RELAY_ANOMALY":               "routing",
}

# ---------------------------------------------------------------------------
# IOC component — raw contribution points
# ---------------------------------------------------------------------------
IOC_POINTS: dict[str, int] = {
    "MALICIOUS_URL":          35,
    "MALICIOUS_DOMAIN":       30,
    "MALICIOUS_IP":           25,
    "MALICIOUS_HASH":         40,
    "SUSPICIOUS_ATTACHMENT":  20,
    "OBFUSCATED_URL":         15,
    "URL_DISPLAY_MISMATCH":   10,
}
IOC_CAP: int = 100

# ---------------------------------------------------------------------------
# THREAT INTELLIGENCE component — raw contribution points
# ---------------------------------------------------------------------------
INTEL_POINTS: dict[str, int] = {
    "CONFIRMED_MALICIOUS_URL":    35,
    "CONFIRMED_MALICIOUS_DOMAIN": 35,
    "CONFIRMED_MALICIOUS_IP":     30,
    "KNOWN_MALICIOUS_HASH":       50,
}
INTEL_CAP: int = 100

# ---------------------------------------------------------------------------
# RISK LEVEL thresholds (inclusive lower bound)
# ---------------------------------------------------------------------------
RISK_THRESHOLDS: dict[str, int] = {
    "LOW":      0,
    "MEDIUM":  30,
    "HIGH":    60,
    "CRITICAL":80,
}

# ---------------------------------------------------------------------------
# ORIGIN CONFIDENCE — positive evidence points
# ---------------------------------------------------------------------------
ORIGIN_POSITIVE: dict[str, int] = {
    "RELIABLE_RELAY_IDENTIFIED": 25,
    "RELAY_CHAIN_CONSISTENT":    15,
    "PUBLIC_IP_EXTRACTED":       15,
    "GEOIP_AVAILABLE":           10,
    "ASN_RDAP_AVAILABLE":        10,
    "DOMAIN_IP_RELATIONSHIP":    10,
    "AUTH_PATH_CONSISTENT":      15,
}

# ---------------------------------------------------------------------------
# ORIGIN CONFIDENCE — uncertainty penalties
# Only applied when actual evidence exists; not for missing optional data.
# VPN/TOR/proxy -> reduces tracing confidence; does NOT make email malicious.
# ---------------------------------------------------------------------------
ORIGIN_PENALTIES: dict[str, int] = {
    "VPN_DETECTED":              -20,
    "TOR_DETECTED":              -30,
    "PROXY_DETECTED":            -15,
    "HEADER_INCONSISTENCY":      -20,
    "MISSING_RELAY_INFO":        -20,
    "SUSPECTED_FORGED_HEADER":   -25,
    "INSUFFICIENT_PUBLIC_RELAY": -25,
}

# ---------------------------------------------------------------------------
# ORIGIN CONFIDENCE level labels (inclusive lower bound)
# ---------------------------------------------------------------------------
ORIGIN_THRESHOLDS: dict[str, int] = {
    "LOW":      0,
    "MEDIUM":   30,
    "HIGH":     80,
}

# ---------------------------------------------------------------------------
# Infrastructure characteristic indicators (origin uncertainty only)
# ---------------------------------------------------------------------------
TOR_INDICATORS: tuple[str, ...] = ("tor", "onion", "exit node", "torbsd")
PROXY_INDICATORS: tuple[str, ...] = ("proxy", "anonymiz", "squid", "socks")
VPN_HOSTING_INDICATORS: tuple[str, ...] = (
    "vpn", "hosting", "cloud", "vps", "datacenter", "data center",
    "linode", "digitalocean", "vultr", "ovh", "hetzner",
    "amazonaws", "google cloud", "microsoft azure", "cloudflare",
)
