"""
Hybrid threat scoring engine.
Deterministic weighted system — same email always produces same score.
NO random numbers used.

Weights:
  NLP / phishing language : 25%
  Authentication failures : 20%
  Domain risk             : 15%
  URL analysis            : 15%
  Infrastructure rep.     : 10%
  Header anomalies        : 10%
  Attachment risk         :  5%
"""
import re
import uuid
from typing import Dict, List, Tuple
from difflib import SequenceMatcher
import logging

logger = logging.getLogger(__name__)

# ─── Scoring constants ────────────────────────────────────────────────────────

WEIGHTS = {
    "nlp_phishing": 0.25,
    "authentication": 0.20,
    "domain_risk": 0.15,
    "url_analysis": 0.15,
    "infrastructure_reputation": 0.10,
    "header_anomalies": 0.10,
    "attachment_risk": 0.05,
}

SEVERITY_THRESHOLDS = {
    (0, 20): ("SAFE", "Legitimate"),
    (21, 40): ("LOW", "Suspicious"),
    (41, 60): ("SUSPICIOUS", "Suspicious"),
    (61, 80): ("HIGH", "Phishing"),
    (81, 100): ("CRITICAL", "Critical Threat"),
}

# Known brand domains for similarity checking
KNOWN_BRANDS = [
    "microsoft.com", "google.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "twitter.com", "linkedin.com", "dropbox.com", "adobe.com",
    "netflix.com", "spotify.com", "zoom.us", "salesforce.com", "github.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "iciciprudential.com",
    "fedex.com", "dhl.com", "ups.com", "usps.com",
]

# Phishing / social engineering keywords (with weights)
PHISHING_SIGNALS: List[Tuple[List[str], int, str]] = [
    # (keywords, score, category)
    (["urgent", "immediately", "right away", "asap", "time sensitive", "act now", "don't delay"], 15, "urgency"),
    (["wire transfer", "bank transfer", "payment required", "send money", "transfer funds", "account details"], 20, "financial_request"),
    (["verify your account", "confirm your password", "click here to verify", "validate your", "login to confirm"], 18, "credential_request"),
    (["dear ceo", "dear president", "on behalf of", "executive", "board of directors", "chairman"], 15, "authority"),
    (["invoice", "overdue", "payment due", "outstanding balance", "past due"], 12, "invoice_fraud"),
    (["confidential", "strictly confidential", "do not share", "private and confidential"], 8, "confidentiality_pressure"),
    (["suspended", "restricted", "blocked", "locked", "deactivated", "unauthorized access"], 15, "fear_induction"),
    (["unusual activity", "suspicious login", "security alert", "breach detected"], 12, "fear_induction"),
    (["gift card", "itunes", "amazon gift", "google play card"], 18, "gift_card_scam"),
    (["ceo", "cfo", "cto", "president", "director", "vp", "vice president"], 12, "executive_impersonation"),
    (["new bank account", "updated banking details", "change in payment", "new account number"], 22, "financial_request"),
    (["click here", "click the link", "tap here", "follow this link"], 8, "url_lure"),
    (["limited time", "expires today", "offer ends", "last chance", "final notice"], 12, "urgency"),
    (["verify now", "update now", "confirm now", "login now", "sign in now"], 14, "credential_request"),
]

# Suspicious TLDs
SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".info", ".biz", ".site", ".online", ".click", ".loan"}

# Suspicious email infrastructure keywords
SUSPICIOUS_INFRA_KEYWORDS = ["secure", "alert", "verify", "account", "update", "support", "help", "service",
                              "billing", "payment", "invoice", "portal", "login", "auth"]


# ─── Domain similarity ────────────────────────────────────────────────────────

def brand_similarity(domain: str) -> Tuple[str, int, str]:
    """
    Compare domain against known brands.
    Returns (closest_brand, similarity_score_0_100, method).
    Uses difflib.SequenceMatcher — pure Python, no Rust.
    """
    domain_clean = re.sub(r'\.[a-z]{2,}$', '', domain.lower())

    best_brand = ""
    best_score = 0
    best_method = ""

    for brand in KNOWN_BRANDS:
        brand_clean = re.sub(r'\.[a-z]{2,}$', '', brand.lower())

        # Sequence similarity
        ratio = SequenceMatcher(None, domain_clean, brand_clean).ratio()
        score = int(ratio * 100)

        # Check for character substitution attacks
        # e.g., micros0ft → microsoft
        substitutions = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '@': 'a', 'vv': 'w'}
        normalized = domain_clean
        for fake, real in substitutions.items():
            normalized = normalized.replace(fake, real)

        norm_ratio = SequenceMatcher(None, normalized, brand_clean).ratio()
        norm_score = int(norm_ratio * 100)

        if norm_score > score:
            score = norm_score
            best_method = "character_substitution"
        else:
            best_method = "string_similarity"

        if score > best_score:
            best_score = score
            best_brand = brand

    return best_brand, best_score, best_method


# ─── NLP social engineering scorer ────────────────────────────────────────────

def score_nlp(body_text: str, body_html: str, subject: str) -> Tuple[float, dict, List[dict]]:
    """
    Score the email for phishing/social engineering signals.
    Returns (raw_score_0_100, se_breakdown, risk_indicators).
    """
    combined = f"{subject}\n{body_text}\n{body_html}".lower()
    total_score = 0
    se_breakdown = {
        "urgency": 0,
        "authority": 0,
        "financial_request": 0,
        "credential_request": 0,
        "executive_impersonation": 0,
        "fear_induction": 0,
        "confidentiality_pressure": 0,
    }
    risk_indicators = []

    for keywords, score, category in PHISHING_SIGNALS:
        for kw in keywords:
            if kw in combined:
                total_score = min(100, total_score + score)
                # Map to se_breakdown fields
                if category in se_breakdown:
                    se_breakdown[category] = min(100, se_breakdown[category] + score * 5)
                elif category == "invoice_fraud":
                    se_breakdown["financial_request"] = min(100, se_breakdown["financial_request"] + score * 3)
                elif category in ("url_lure", "gift_card_scam"):
                    se_breakdown["credential_request"] = min(100, se_breakdown["credential_request"] + score * 2)

                # Deduplicate indicators by category
                if not any(r.get("category") == category for r in risk_indicators):
                    risk_indicators.append({
                        "id": str(uuid.uuid4()),
                        "label": f"{category.replace('_', ' ').title()} detected",
                        "severity": "high" if score >= 15 else "medium",
                        "category": category,
                    })
                break  # Only count each signal group once

    # Normalize se_breakdown to 0–100
    for key in se_breakdown:
        se_breakdown[key] = min(100, se_breakdown[key])

    return min(100.0, total_score), se_breakdown, risk_indicators


# ─── Authentication scorer ────────────────────────────────────────────────────

def score_authentication(auth_results: dict) -> Tuple[float, List[dict]]:
    """Score SPF/DKIM/DMARC failures. Returns (0-100, risk_indicators)."""
    score = 0
    indicators = []

    if auth_results.get("spf") == "fail":
        score += 35
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": "SPF check failed — sender not authorized",
            "severity": "high",
            "category": "authentication",
        })
    elif auth_results.get("spf") == "unknown":
        score += 10  # No SPF record is mildly suspicious

    if auth_results.get("dkim") == "fail":
        score += 30
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": "DKIM signature invalid or missing",
            "severity": "high",
            "category": "authentication",
        })
    elif auth_results.get("dkim") == "unknown":
        score += 8

    if auth_results.get("dmarc") == "fail":
        score += 35
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": "DMARC policy violation detected",
            "severity": "critical",
            "category": "authentication",
        })
    elif auth_results.get("dmarc") == "unknown":
        score += 10

    if auth_results.get("reply_to_mismatch"):
        score += 25
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": "Reply-To domain mismatch — replies diverted",
            "severity": "high",
            "category": "authentication",
        })

    return min(100.0, score), indicators


# ─── Domain risk scorer ────────────────────────────────────────────────────────

def score_domain_risk(from_address: str, iocs: List[dict]) -> Tuple[float, List[dict]]:
    """Evaluate sender domain risk."""
    score = 0
    indicators = []

    if not from_address or "@" not in from_address:
        return 50.0, []

    domain = from_address.split("@")[-1].lower()

    # Brand similarity check
    closest_brand, similarity, method = brand_similarity(domain)
    if similarity >= 85 and domain != closest_brand:
        score += 60
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": f"Lookalike domain detected — {similarity}% similar to {closest_brand}",
            "severity": "critical",
            "category": "domain_spoofing",
        })
    elif similarity >= 70:
        score += 30
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": f"Suspicious domain similarity to {closest_brand} ({similarity}%)",
            "severity": "high",
            "category": "domain_spoofing",
        })

    # Suspicious TLD
    tld = "." + domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 25
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": f"Suspicious top-level domain: {tld}",
            "severity": "medium",
            "category": "domain_risk",
        })

    # Suspicious keywords in domain
    domain_base = domain.split(".")[0]
    for kw in SUSPICIOUS_INFRA_KEYWORDS:
        if kw in domain_base and kw not in ["service", "support"]:  # common legit uses
            score += 15
            indicators.append({
                "id": str(uuid.uuid4()),
                "label": f"Suspicious keyword in sender domain: '{kw}'",
                "severity": "medium",
                "category": "domain_risk",
            })
            break

    # Numeric characters in domain (obfuscation)
    if re.search(r'\d', domain_base):
        score += 10
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": "Domain contains digits — possible character substitution",
            "severity": "low",
            "category": "domain_risk",
        })

    return min(100.0, score), indicators


# ─── URL risk scorer ──────────────────────────────────────────────────────────

def score_url_risk(iocs: List[dict], url_deceptions: List[dict]) -> Tuple[float, List[dict], List[dict]]:
    """Score URL risks. Returns (score, indicators, analyzed_urls)."""
    score = 0
    indicators = []
    analyzed_urls = []

    # URL deception is severe
    if url_deceptions:
        score += 40
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": f"URL deception: displayed URL ≠ actual destination ({len(url_deceptions)} instances)",
            "severity": "critical",
            "category": "url_deception",
        })

    urls = [ioc["indicator"] for ioc in iocs if ioc["type"] == "url"]
    for url in urls[:10]:  # Cap at 10 URLs
        risk = 0
        analyzed = {
            "displayed_url": url,
            "actual_url": url,
            "deception": False,
            "https_enabled": url.startswith("https://"),
            "url_length": len(url),
            "has_encoded_chars": "%" in url or "%2" in url.lower(),
            "suspicious_tld": False,
            "reputation": "unknown",
            "risk_score": 0,
        }

        # Length
        if len(url) > 200:
            risk += 15

        # Encoded chars
        if analyzed["has_encoded_chars"]:
            risk += 10

        # No HTTPS
        if not analyzed["https_enabled"]:
            risk += 10

        # Check TLD
        try:
            import tldextract
            ext = tldextract.extract(url)
            if f".{ext.suffix}" in SUSPICIOUS_TLDS:
                analyzed["suspicious_tld"] = True
                risk += 20
        except Exception:
            pass

        analyzed["risk_score"] = min(100, risk)
        analyzed_urls.append(analyzed)
        score = min(100, score + risk // 3)

    # Check deceptions into analyzed_urls
    for deception in url_deceptions:
        analyzed_urls.append({
            "displayed_url": deception.get("displayed_url", ""),
            "actual_url": deception.get("actual_url", ""),
            "deception": True,
            "https_enabled": deception.get("actual_url", "").startswith("https://"),
            "url_length": len(deception.get("actual_url", "")),
            "has_encoded_chars": "%" in deception.get("actual_url", ""),
            "suspicious_tld": False,
            "reputation": "suspicious",
            "risk_score": 85,
        })

    return min(100.0, score), indicators, analyzed_urls


# ─── Infrastructure scorer ────────────────────────────────────────────────────

def score_infrastructure(relay_path: List[dict], x_originating_ip: str) -> Tuple[float, List[dict]]:
    """Score based on relay path anomalies."""
    score = 0
    indicators = []

    if not relay_path:
        return 10.0, []

    # Too many hops
    if len(relay_path) > 5:
        score += 15
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": f"Unusually long relay chain ({len(relay_path)} hops)",
            "severity": "medium",
            "category": "infrastructure",
        })

    # Check for high-risk countries in relay path
    high_risk_countries = ["russia", "russia", "nigeria", "pakistan", "north korea", "dprk", "belarus", "iran"]
    for hop in relay_path:
        location = hop.get("location", "").lower()
        for country in high_risk_countries:
            if country in location:
                score += 20
                indicators.append({
                    "id": str(uuid.uuid4()),
                    "label": f"Email relay through high-risk region: {hop.get('location', 'Unknown')}",
                    "severity": "high",
                    "category": "infrastructure",
                })
                break

    if x_originating_ip:
        score += 5  # Presence of X-Originating-IP is worth noting

    return min(100.0, score), indicators


# ─── Header anomaly scorer ────────────────────────────────────────────────────

def score_header_anomalies(parsed: dict) -> Tuple[float, List[dict]]:
    """Detect header-level anomalies."""
    score = 0
    indicators = []

    # Missing Message-ID
    if not parsed.get("message_id"):
        score += 20
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": "Missing Message-ID header — non-standard mail client",
            "severity": "medium",
            "category": "header_anomaly",
        })

    # Suspicious X-Mailer
    mailer = parsed.get("mailer", "").lower()
    if mailer and any(kw in mailer for kw in ["mass", "bulk", "blast", "sender", "campaign"]):
        score += 15
        indicators.append({
            "id": str(uuid.uuid4()),
            "label": f"Suspicious mailer software detected: {parsed.get('mailer', '')}",
            "severity": "medium",
            "category": "header_anomaly",
        })

    # Return-Path domain mismatch with From
    from_addr = parsed.get("from_address", "")
    return_path = parsed.get("return_path", "")
    if from_addr and return_path and "@" in from_addr and "@" in return_path:
        from_domain = from_addr.split("@")[-1]
        rp_addr = re.search(r'<([^>]+)>', return_path)
        rp_email = rp_addr.group(1) if rp_addr else return_path
        if "@" in rp_email:
            rp_domain = rp_email.split("@")[-1]
            if from_domain.lower() != rp_domain.lower():
                score += 20
                indicators.append({
                    "id": str(uuid.uuid4()),
                    "label": f"Return-Path domain mismatch: {rp_domain} ≠ {from_domain}",
                    "severity": "high",
                    "category": "header_anomaly",
                })

    return min(100.0, score), indicators


# ─── Attachment scorer ────────────────────────────────────────────────────────

def score_attachments(attachments: List[dict]) -> Tuple[float, List[dict]]:
    """Score based on attachment risk."""
    if not attachments:
        return 0.0, []

    score = 0
    indicators = []
    dangerous_exts = {".exe", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".jar", ".dll", ".scr", ".com"}
    medium_exts = {".doc", ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".iso", ".img"}

    for att in attachments:
        filename = att.get("filename", "").lower()
        ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""

        if ext in dangerous_exts:
            score += 50
            indicators.append({
                "id": str(uuid.uuid4()),
                "label": f"Dangerous attachment type: {att.get('filename', '')} ({ext})",
                "severity": "critical",
                "category": "attachment",
            })
        elif ext in medium_exts:
            score += 25
            indicators.append({
                "id": str(uuid.uuid4()),
                "label": f"Potentially risky attachment: {att.get('filename', '')}",
                "severity": "medium",
                "category": "attachment",
            })

    return min(100.0, score), indicators


# ─── Classification logic ──────────────────────────────────────────────────────

def classify_threat(
    final_score: int,
    se_breakdown: dict,
    auth_indicators: List[dict],
    domain_indicators: List[dict],
    attachment_indicators: List[dict],
    url_deceptions: List[dict],
) -> Tuple[str, dict]:
    """Determine primary threat classification and per-class scores."""
    cls_scores = {
        "phishing": 0,
        "bec": 0,
        "impersonation": 0,
        "credential_theft": 0,
        "malware_delivery": 0,
    }

    # BEC signals: executive impersonation + financial request + no attachments
    if se_breakdown.get("executive_impersonation", 0) > 30 and se_breakdown.get("financial_request", 0) > 20:
        cls_scores["bec"] = min(100, se_breakdown["executive_impersonation"] + se_breakdown["financial_request"])

    # Credential phishing signals
    if se_breakdown.get("credential_request", 0) > 25 or url_deceptions:
        cls_scores["credential_theft"] = min(100, se_breakdown.get("credential_request", 0) + (40 if url_deceptions else 0))

    # Impersonation
    if any("lookalike" in i.get("label", "").lower() or "similarity" in i.get("label", "").lower() for i in domain_indicators):
        cls_scores["impersonation"] = min(100, final_score)

    # Phishing general
    cls_scores["phishing"] = min(100, max(
        se_breakdown.get("urgency", 0),
        se_breakdown.get("fear_induction", 0),
        se_breakdown.get("credential_request", 0),
        final_score - 10,
    ))

    # Malware
    if attachment_indicators:
        cls_scores["malware_delivery"] = min(100, sum(
            50 if "dangerous" in i.get("label", "").lower() else 25
            for i in attachment_indicators
        ))

    # Primary classification
    if final_score <= 20:
        classification = "Legitimate"
    elif final_score <= 40:
        classification = "Suspicious"
    elif cls_scores["bec"] >= 60:
        classification = "Business Email Compromise"
    elif cls_scores["malware_delivery"] >= 60:
        classification = "Malware Delivery"
    elif cls_scores["impersonation"] >= 60 and se_breakdown.get("financial_request", 0) < 20:
        classification = "Executive Impersonation"
    elif cls_scores["credential_theft"] >= 50:
        classification = "Credential Phishing"
    elif cls_scores["phishing"] >= 40:
        classification = "Phishing"
    else:
        classification = "Suspicious"

    return classification, cls_scores


# ─── Explainability ───────────────────────────────────────────────────────────

def generate_explanation(
    final_score: int,
    classification: str,
    se_breakdown: dict,
    scoring_breakdown: dict,
    all_indicators: List[dict],
) -> str:
    """Generate human-readable explanation of why this email scored as it did."""
    lines = []
    lines.append(
        f"This email was classified as **{classification}** with a risk score of **{final_score}/100**."
    )

    top_indicators = sorted(all_indicators, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "low"), 3))[:5]

    if top_indicators:
        lines.append("\n**Key factors contributing to this score:**")
        for ind in top_indicators:
            lines.append(f"• {ind['label']} (Severity: {ind['severity'].upper()})")

    # Auth summary
    auth_score = scoring_breakdown.get("authentication", 0)
    if auth_score > 50:
        lines.append(f"\n**Authentication failures** were a major factor ({auth_score:.0f}/100 contribution), indicating the email did not originate from an authorized server.")

    # Domain risk
    domain_score = scoring_breakdown.get("domain_risk", 0)
    if domain_score > 40:
        lines.append(f"\n**Domain risk analysis** ({domain_score:.0f}/100) detected the sender domain resembles a well-known brand, which is a hallmark of impersonation attacks.")

    # Social engineering
    nlp_score = scoring_breakdown.get("nlp_phishing", 0)
    if nlp_score > 30:
        lines.append(f"\n**Social engineering signals** ({nlp_score:.0f}/100) were detected in the email body, including urgency, authority, and/or financial pressure tactics.")

    # URL
    url_score = scoring_breakdown.get("url_analysis", 0)
    if url_score > 30:
        lines.append(f"\n**URL analysis** ({url_score:.0f}/100) found suspicious links including possible hyperlink deception where displayed URLs differ from actual destinations.")

    if final_score <= 20:
        lines.append("\n**Assessment:** The email shows no significant threat indicators. Authentication records are consistent and no social engineering signals were detected.")
    elif final_score >= 80:
        lines.append("\n**Recommendation:** Quarantine this email immediately, block the sending domain and IP, and alert the intended recipient.")
    elif final_score >= 60:
        lines.append("\n**Recommendation:** This email should be investigated further. Block the sending domain pending investigation.")

    return "\n".join(lines)


# ─── Master score function ────────────────────────────────────────────────────

def compute_threat_score(parsed_email: dict) -> dict:
    """
    Main entry point: takes parsed email dict, returns complete threat scoring result.
    """
    import hashlib
    import json
    from datetime import datetime, timezone

    # ── Extract parsed fields ──────────────────────────────────────────────────
    auth_results = parsed_email.get("auth_results", {})
    body_text = parsed_email.get("body_text", "")
    body_html = parsed_email.get("body_html", "")
    subject = parsed_email.get("subject", "")
    from_address = parsed_email.get("from_address", "")
    iocs = parsed_email.get("iocs", [])
    relay_path = parsed_email.get("relay_path", [])
    url_deceptions = parsed_email.get("url_deceptions", [])
    attachments = parsed_email.get("attachments", [])
    x_originating_ip = parsed_email.get("x_originating_ip", "")

    # ── Run all scorers ────────────────────────────────────────────────────────
    nlp_score, se_breakdown, nlp_indicators = score_nlp(body_text, body_html, subject)
    auth_score, auth_indicators = score_authentication(auth_results)
    domain_score, domain_indicators = score_domain_risk(from_address, iocs)
    url_score, url_indicators, analyzed_urls = score_url_risk(iocs, url_deceptions)
    infra_score, infra_indicators = score_infrastructure(relay_path, x_originating_ip)
    header_score, header_indicators = score_header_anomalies(parsed_email)
    attach_score, attach_indicators = score_attachments(attachments)

    # ── Weighted final score ────────────────────────────────────────────────────
    scoring_breakdown = {
        "nlp_phishing": nlp_score,
        "authentication": auth_score,
        "domain_risk": domain_score,
        "url_analysis": url_score,
        "infrastructure_reputation": infra_score,
        "header_anomalies": header_score,
        "attachment_risk": attach_score,
    }

    final_score = int(sum(
        score * WEIGHTS[key]
        for key, score in scoring_breakdown.items()
    ))
    final_score = max(0, min(100, final_score))

    # ── Severity ────────────────────────────────────────────────────────────────
    risk_level = "SAFE"
    for (low, high), (severity, _) in SEVERITY_THRESHOLDS.items():
        if low <= final_score <= high:
            risk_level = severity
            break

    # ── Classification ──────────────────────────────────────────────────────────
    all_domain_indicators = domain_indicators
    classification, cls_scores = classify_threat(
        final_score, se_breakdown, auth_indicators,
        domain_indicators, attach_indicators, url_deceptions
    )

    # ── All risk indicators ──────────────────────────────────────────────────────
    all_indicators = (
        nlp_indicators + auth_indicators + domain_indicators +
        url_indicators + infra_indicators + header_indicators + attach_indicators
    )

    # ── Explainability ──────────────────────────────────────────────────────────
    explanation = generate_explanation(
        final_score, classification, se_breakdown, scoring_breakdown, all_indicators
    )

    # ── Evidence hash ────────────────────────────────────────────────────────────
    evidence_data = json.dumps({
        "from": from_address,
        "subject": subject,
        "body": body_text[:1000],
    }, sort_keys=True)
    evidence_hash = hashlib.sha256(evidence_data.encode()).hexdigest()

    return {
        "overall_risk_score": final_score,
        "risk_level": risk_level,
        "classification": classification,
        "classification_scores": cls_scores,
        "scoring_breakdown": scoring_breakdown,
        "social_engineering": se_breakdown,
        "risk_indicators": all_indicators,
        "url_analysis": analyzed_urls,
        "explainable_ai": explanation,
        "evidence_hash": evidence_hash,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
    }
