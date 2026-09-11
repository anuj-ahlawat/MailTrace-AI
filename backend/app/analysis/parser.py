"""
Email parser — uses Python's email library to extract all forensic data.
Handles both raw RFC 2822 emails and multipart MIME messages.
"""
import email
import email.policy
import hashlib
import re
import uuid
from email.header import decode_header
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

# ─── Header decoders ──────────────────────────────────────────────────────────

def decode_mime_words(s: str) -> str:
    """Decode RFC 2047 encoded header words."""
    if not s:
        return ""
    try:
        parts = decode_header(s)
        result = []
        for part, charset in parts:
            if isinstance(part, bytes):
                result.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                result.append(str(part))
        return " ".join(result).strip()
    except Exception:
        return str(s)


def extract_email_address(header: str) -> str:
    """Extract bare email address from 'Name <email>' format."""
    if not header:
        return ""
    match = re.search(r'<([^>]+)>', header)
    if match:
        return match.group(1).strip().lower()
    # Plain email without angle brackets
    plain = re.search(r'[\w.+-]+@[\w.-]+\.\w+', header)
    if plain:
        return plain.group(0).lower()
    return header.strip().lower()


# ─── SPF/DKIM/DMARC parser ────────────────────────────────────────────────────

def parse_auth_results(headers: Dict[str, List[str]]) -> dict:
    """
    Parse Authentication-Results headers.
    Returns dict with spf, dkim, dmarc results.
    NEVER invents results — returns 'unknown' when data is absent.
    """
    auth_data = {
        "spf": "unknown",
        "spf_detail": "Authentication-Results header not found",
        "dkim": "unknown",
        "dkim_detail": "Authentication-Results header not found",
        "dmarc": "unknown",
        "dmarc_detail": "Authentication-Results header not found",
    }

    auth_headers = headers.get("authentication-results", [])
    if not auth_headers:
        return auth_data

    combined = " ".join(auth_headers).lower()

    # SPF
    spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|permerror|temperror)', combined)
    if spf_match:
        auth_data["spf"] = spf_match.group(1) if spf_match.group(1) in ("pass",) else "fail" if spf_match.group(1) in ("fail", "softfail", "permerror") else "unknown"
        auth_data["spf_detail"] = f"SPF check result: {spf_match.group(1).upper()}"

        # Extract domain
        smtp_from = re.search(r'smtp\.(?:mailfrom|from)=([^\s;]+)', combined)
        if smtp_from:
            auth_data["spf_detail"] += f" for {smtp_from.group(1)}"

    # DKIM
    dkim_match = re.search(r'dkim=(pass|fail|neutral|policy|none|permerror|temperror)', combined)
    if dkim_match:
        auth_data["dkim"] = "pass" if dkim_match.group(1) == "pass" else "fail"
        auth_data["dkim_detail"] = f"DKIM signature verification: {dkim_match.group(1).upper()}"

        selector = re.search(r'header\.(?:i|s)=([^\s;]+)', combined)
        if selector:
            auth_data["dkim_detail"] += f" (selector: {selector.group(1)})"

    # DMARC
    dmarc_match = re.search(r'dmarc=(pass|fail|none|temperror|permerror)', combined)
    if dmarc_match:
        auth_data["dmarc"] = "pass" if dmarc_match.group(1) == "pass" else "fail"
        auth_data["dmarc_detail"] = f"DMARC policy evaluation: {dmarc_match.group(1).upper()}"

        from_header = re.search(r'from=([^\s;]+)', combined)
        if from_header:
            auth_data["dmarc_detail"] += f" for domain {from_header.group(1)}"

    return auth_data


# ─── Received header parser ───────────────────────────────────────────────────

def parse_received_headers(received_headers: List[str]) -> List[dict]:
    """
    Parse Received headers to reconstruct the email relay path.
    Returns list of hops with IP, hostname, timestamp, confidence.
    """
    hops = []
    ip_pattern = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    
    # Received headers are in reverse order (latest first)
    for i, header in enumerate(reversed(received_headers)):
        hop = {
            "hop_number": i + 1,
            "ip": "",
            "hostname": "",
            "timestamp": "",
            "location": "Unknown",
            "label": f"Relay {i + 1}",
            "confidence": "observed",
            "notes": "",
            "raw": header[:200],
        }

        # Extract IPs
        ips = ip_pattern.findall(header)
        # Filter private/loopback IPs
        public_ips = [ip for ip in ips if not _is_private_ip(ip)]
        if public_ips:
            hop["ip"] = public_ips[0]
            hop["confidence"] = "observed"
        elif ips:
            hop["ip"] = ips[0]
            hop["confidence"] = "low"

        # Extract hostname
        hostname_match = re.search(r'from\s+([^\s\[]+)', header, re.IGNORECASE)
        if hostname_match:
            hop["hostname"] = hostname_match.group(1).strip("()")

        # Extract timestamp
        ts_match = re.search(
            r';\s*((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d+\s+\w+\s+\d{4}\s+[\d:]+\s+[+-]\d{4})',
            header, re.IGNORECASE
        )
        if ts_match:
            hop["timestamp"] = ts_match.group(1).strip()

        # Label first and last hops meaningfully
        if i == 0:
            hop["label"] = "Origin Infrastructure"
        elif i == len(received_headers) - 1:
            hop["label"] = "Recipient Mail Server"
        elif "microsoft" in header.lower() or "outlook" in header.lower():
            hop["label"] = "Microsoft Exchange"
            hop["confidence"] = "trusted"
        elif "google" in header.lower() or "gmail" in header.lower():
            hop["label"] = "Google Mail Server"
            hop["confidence"] = "trusted"
        elif "amazon" in header.lower() or "aws" in header.lower():
            hop["label"] = "Amazon SES"
            hop["confidence"] = "trusted"

        hops.append(hop)

    return hops


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/loopback."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    first = int(parts[0])
    second = int(parts[1])
    return (
        first == 10 or
        first == 127 or
        (first == 172 and 16 <= second <= 31) or
        (first == 192 and second == 168)
    )


# ─── IOC extractor ────────────────────────────────────────────────────────────

def extract_iocs(text: str, html: str = "", headers: Dict[str, List[str]] = None) -> List[dict]:
    """Extract all IOCs from email text, HTML and headers."""
    iocs = []
    seen = set()

    def add_ioc(ioc_type: str, value: str, source: str = "email_body"):
        key = f"{ioc_type}:{value}"
        if key not in seen and value:
            seen.add(key)
            iocs.append({
                "id": str(uuid.uuid4()),
                "type": ioc_type,
                "indicator": value,
                "source": source,
                "reputation": "unknown",
                "risk_level": "medium",
            })

    combined_text = f"{text}\n{html}"

    # IPv4
    for ip in re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', combined_text):
        if not _is_private_ip(ip):
            add_ioc("ip", ip)

    # Domains (from URLs and text)
    url_pattern = re.compile(
        r'https?://([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)',
        re.IGNORECASE
    )
    for match in url_pattern.finditer(combined_text):
        domain = match.group(1).lower()
        add_ioc("domain", domain)

    # Full URLs
    full_url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
    for match in full_url_pattern.finditer(combined_text):
        url = match.group(0).rstrip('.,;)')
        add_ioc("url", url)

    # Email addresses
    for email_addr in re.findall(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', combined_text):
        add_ioc("email", email_addr.lower())

    # SHA256 hashes
    for sha256 in re.findall(r'\b[a-fA-F0-9]{64}\b', combined_text):
        add_ioc("hash", sha256.lower())

    # Extract URLs from HTML href attributes (catches hidden URLs)
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in href_pattern.finditer(html):
        url = match.group(1)
        if url.startswith("http"):
            add_ioc("url", url)

    return iocs


# ─── URL deception detector ───────────────────────────────────────────────────

def detect_url_deception(html: str) -> List[dict]:
    """Find hyperlinks where displayed text URL != actual href."""
    deceptions = []
    pattern = re.compile(
        r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>',
        re.IGNORECASE | re.DOTALL
    )
    url_in_text = re.compile(r'https?://[^\s]+', re.IGNORECASE)

    for match in pattern.finditer(html):
        href = match.group(1).strip()
        link_text = match.group(2).strip()

        # Check if link text looks like a URL
        text_url_match = url_in_text.match(link_text)
        if text_url_match:
            displayed = text_url_match.group(0).rstrip('.,;)')
            actual = href.rstrip('.,;)')

            # Extract domains for comparison
            displayed_domain = re.search(r'https?://([^/\s?]+)', displayed)
            actual_domain = re.search(r'https?://([^/\s?]+)', actual)

            if displayed_domain and actual_domain:
                if displayed_domain.group(1).lower() != actual_domain.group(1).lower():
                    deceptions.append({
                        "displayed_url": displayed,
                        "actual_url": actual,
                        "deception": True,
                    })

    return deceptions


# ─── Main parse function ──────────────────────────────────────────────────────

def parse_email(raw_email: str) -> dict:
    """
    Parse a raw RFC 2822 email string into a structured forensic dict.
    """
    try:
        msg = email.message_from_string(raw_email, policy=email.policy.compat32)
    except Exception as e:
        logger.error(f"Email parse error: {e}")
        return {"error": str(e), "raw": raw_email[:500]}

    # Collect all headers (lowercase keys, list values)
    headers: Dict[str, List[str]] = {}
    for key, value in msg.items():
        k = key.lower()
        if k not in headers:
            headers[k] = []
        headers[k].append(str(value))

    # Core fields
    from_raw = decode_mime_words(msg.get("From", ""))
    to_raw = decode_mime_words(msg.get("To", ""))
    reply_to_raw = decode_mime_words(msg.get("Reply-To", ""))
    return_path_raw = decode_mime_words(msg.get("Return-Path", ""))
    subject = decode_mime_words(msg.get("Subject", ""))
    date = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    x_originating_ip = msg.get("X-Originating-IP", msg.get("X-Google-Original-IP", ""))
    mailer = msg.get("X-Mailer", msg.get("User-Agent", ""))

    from_addr = extract_email_address(from_raw)
    reply_to_addr = extract_email_address(reply_to_raw)
    return_path_addr = extract_email_address(return_path_raw)

    # Reply-To mismatch detection
    reply_to_mismatch = False
    reply_to_mismatch_detail = ""
    if reply_to_addr and from_addr and reply_to_addr != from_addr:
        reply_to_mismatch = True
        from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        reply_domain = reply_to_addr.split("@")[-1] if "@" in reply_to_addr else ""
        if from_domain != reply_domain:
            reply_to_mismatch_detail = (
                f"From domain ({from_domain}) does not match Reply-To domain ({reply_domain}). "
                f"Replies will go to {reply_to_addr}, not the apparent sender."
            )

    # To list
    to_list = [t.strip() for t in to_raw.split(",") if t.strip()] if to_raw else []

    # Body extraction
    body_text = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition.lower():
                filename = part.get_filename() or "unknown"
                payload = part.get_payload(decode=True) or b""
                sha256 = hashlib.sha256(payload).hexdigest()
                attachments.append({
                    "filename": decode_mime_words(filename),
                    "mime_type": content_type,
                    "size": len(payload),
                    "sha256": sha256,
                })
            elif content_type == "text/plain":
                try:
                    charset = part.get_content_charset() or "utf-8"
                    body_text += part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    body_text += str(part.get_payload())
            elif content_type == "text/html":
                try:
                    charset = part.get_content_charset() or "utf-8"
                    body_html += part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    body_html += str(part.get_payload())
    else:
        content_type = msg.get_content_type()
        try:
            charset = msg.get_content_charset() or "utf-8"
            payload = msg.get_payload(decode=True)
            if payload:
                decoded = payload.decode(charset, errors="replace")
                if content_type == "text/html":
                    body_html = decoded
                else:
                    body_text = decoded
            else:
                body_text = str(msg.get_payload())
        except Exception:
            body_text = str(msg.get_payload() or "")

    # Auth results
    auth_results = parse_auth_results(headers)
    auth_results["reply_to_mismatch"] = reply_to_mismatch
    auth_results["reply_to_mismatch_detail"] = reply_to_mismatch_detail

    # Relay path
    received_headers = headers.get("received", [])
    relay_path = parse_received_headers(received_headers)

    # IOCs
    iocs = extract_iocs(body_text, body_html, headers)

    # URL deception
    url_deceptions = detect_url_deception(body_html)

    # Raw headers string
    raw_header_str = "\n".join(f"{k}: {v}" for k, vals in headers.items() for v in vals)

    return {
        "from_raw": from_raw,
        "from_address": from_addr,
        "to": to_list,
        "cc": [],
        "reply_to": reply_to_raw,
        "return_path": return_path_raw,
        "subject": subject,
        "date": date,
        "message_id": message_id,
        "x_originating_ip": x_originating_ip,
        "mailer": mailer,
        "headers": headers,
        "raw_headers": raw_header_str[:8000],
        "body_text": body_text[:10000],
        "body_html": body_html[:20000],
        "attachments": attachments,
        "auth_results": auth_results,
        "relay_path": relay_path,
        "iocs": iocs,
        "url_deceptions": url_deceptions,
    }
