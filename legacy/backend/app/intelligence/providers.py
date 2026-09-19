"""Intelligence providers — MockThreatIntelProvider and VirusTotalProvider."""
import re
import random
import hashlib
from typing import Dict, Optional
from difflib import SequenceMatcher
from datetime import datetime, timezone
import httpx
import logging

logger = logging.getLogger(__name__)

MOCK_IP_DATA = {
    "185.231.72.12": {"country": "Singapore", "city": "Singapore", "asn": "AS14618", "isp": "Amazon.com, Inc.", "reputation": "malicious", "confidence": 82},
    "91.108.4.1": {"country": "Germany", "city": "Frankfurt", "asn": "AS1299", "isp": "Telia Company AB", "reputation": "suspicious", "confidence": 75},
    "198.51.100.1": {"country": "United States", "city": "Chicago", "asn": "AS7922", "isp": "Comcast", "reputation": "clean", "confidence": 90},
    "203.0.113.5": {"country": "Netherlands", "city": "Amsterdam", "asn": "AS60781", "isp": "LeaseWeb", "reputation": "suspicious", "confidence": 68},
    "45.33.32.156": {"country": "United States", "city": "Atlanta", "asn": "AS63949", "isp": "Linode", "reputation": "clean", "confidence": 88},
}

MOCK_DOMAIN_DATA = {
    "micros0ft-secure.com": {
        "registrar": "Pte. Reg. Services Ltd.",
        "registered": "2026-06-14",
        "age_days": 73,
        "expires": "2027-06-14",
        "nameservers": ["ns1.cheaphost.net"],
        "mx_records": [],
        "a_records": ["185.231.72.12"],
        "asn": "AS14618",
        "isp": "Amazon.com, Inc.",
        "country": "Singapore",
        "reputation": "malicious",
        "brand_similarity": {"brand": "microsoft.com", "score": 91, "method": "character_substitution"},
    },
    "paypa1-alert.net": {
        "registrar": "NameCheap Inc.",
        "registered": "2026-07-01",
        "age_days": 56,
        "expires": "2027-07-01",
        "nameservers": ["dns1.registrar-servers.com"],
        "mx_records": [],
        "a_records": ["91.108.4.1"],
        "asn": "AS1299",
        "isp": "Telia Company AB",
        "country": "Germany",
        "reputation": "malicious",
        "brand_similarity": {"brand": "paypal.com", "score": 87, "method": "character_substitution"},
    },
}

HIGH_RISK_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".info", ".biz", ".site", ".online", ".click", ".loan", ".win", ".science"}


class MockThreatIntelProvider:
    """
    Always-available mock intelligence provider.
    All results are clearly labeled as Demo Intelligence.
    Never fabricates live real-world data.
    """
    name = "MockThreatIntelProvider"
    is_live = False
    label = "Demo Intelligence"

    async def lookup_ip(self, ip: str) -> dict:
        if ip in MOCK_IP_DATA:
            data = MOCK_IP_DATA[ip].copy()
        else:
            # Deterministic mock based on IP hash
            h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
            countries = ["Germany", "Singapore", "Nigeria", "Netherlands", "Russia", "Ukraine", "Bulgaria", "Romania"]
            isps = ["Digital Ocean", "Linode", "Vultr", "OVH SAS", "Hetzner Online"]
            reputation_opts = ["suspicious", "suspicious", "clean", "clean", "clean", "malicious"]
            data = {
                "country": countries[h % len(countries)],
                "city": "Unknown",
                "asn": f"AS{10000 + (h % 50000)}",
                "isp": isps[h % len(isps)],
                "reputation": reputation_opts[h % len(reputation_opts)],
                "confidence": 60 + (h % 30),
            }

        return {
            "ip": ip,
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "region": data.get("region", ""),
            "asn": data.get("asn", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "hosting_provider": data.get("isp", "Unknown"),
            "reverse_dns": f"mail.{ip.replace('.', '-')}.example.com",
            "is_vpn": False,
            "is_tor": False,
            "is_proxy": False,
            "reputation": data.get("reputation", "unknown"),
            "confidence": data.get("confidence", 65),
            "probable_location": data.get("country", "Unknown"),
            "location_disclaimer": (
                "IP geolocation represents observed infrastructure and may not represent "
                "the physical location of the threat actor."
            ),
            "is_demo": True,
            "data_source": self.label,
        }

    async def lookup_domain(self, domain: str) -> dict:
        if domain in MOCK_DOMAIN_DATA:
            d = MOCK_DOMAIN_DATA[domain].copy()
        else:
            h = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
            age_days = 30 + (h % 3000)
            registrars = ["GoDaddy LLC", "NameCheap Inc.", "Google LLC", "Cloudflare, Inc.", "Tucows Inc."]
            countries = ["United States", "Germany", "Singapore", "Netherlands", "Russia"]
            tld = "." + domain.split(".")[-1] if "." in domain else ".com"
            reputation = "malicious" if tld in HIGH_RISK_TLDS else ("suspicious" if age_days < 180 else "clean")
            d = {
                "registrar": registrars[h % len(registrars)],
                "registered": "2024-01-01",
                "age_days": age_days,
                "expires": "2027-01-01",
                "nameservers": [f"ns{i + 1}.example-dns.com" for i in range(2)],
                "mx_records": [],
                "a_records": [],
                "asn": f"AS{10000 + (h % 50000)}",
                "isp": "Unknown Hosting Provider",
                "country": countries[h % len(countries)],
                "reputation": reputation,
                "brand_similarity": None,
            }

        # Brand similarity
        from app.analysis.scorer import brand_similarity
        brand, similarity, method = brand_similarity(domain)
        brand_sim = d.get("brand_similarity") or {"brand": brand, "score": similarity, "method": method}

        return {
            "domain": domain,
            "registrar": d.get("registrar", "Unknown"),
            "registered": d.get("registered", "Unknown"),
            "domain_age_days": d.get("age_days", 0),
            "expires": d.get("expires", "Unknown"),
            "nameservers": d.get("nameservers", []),
            "mx_records": d.get("mx_records", []),
            "a_records": d.get("a_records", []),
            "asn": d.get("asn", "Unknown"),
            "isp": d.get("isp", "Unknown"),
            "country": d.get("country", "Unknown"),
            "reputation": d.get("reputation", "unknown"),
            "brand_similarity": brand_sim,
            "new_domain": d.get("age_days", 0) < 180,
            "is_demo": True,
            "data_source": self.label,
        }

    async def lookup_url(self, url: str) -> dict:
        return {
            "url": url,
            "reputation": "unknown",
            "is_safe": None,
            "categories": [],
            "scan_date": None,
            "is_demo": True,
            "data_source": self.label,
        }


class VirusTotalProvider:
    """VirusTotal API provider. Requires VIRUSTOTAL_API_KEY in settings."""
    name = "VirusTotalProvider"
    is_live = True
    label = "VirusTotal Live Intelligence"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}

    async def lookup_ip(self, ip: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{self.base_url}/ip_addresses/{ip}", headers=self.headers)
                if r.status_code == 200:
                    data = r.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) or 1
                    reputation = "malicious" if malicious > 2 else ("suspicious" if suspicious > 0 or malicious > 0 else "clean")
                    return {
                        "ip": ip,
                        "country": data.get("country", "Unknown"),
                        "city": "",
                        "asn": str(data.get("asn", "")),
                        "isp": data.get("as_owner", "Unknown"),
                        "reputation": reputation,
                        "malicious_count": malicious,
                        "detection_ratio": f"{malicious + suspicious}/{total}",
                        "confidence": min(95, int((malicious / total) * 100) + 60) if malicious > 0 else 70,
                        "is_demo": False,
                        "data_source": self.label,
                    }
        except Exception as e:
            logger.error(f"VirusTotal IP lookup error: {e}")
        return await MockThreatIntelProvider().lookup_ip(ip)

    async def lookup_domain(self, domain: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{self.base_url}/domains/{domain}", headers=self.headers)
                if r.status_code == 200:
                    data = r.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) or 1
                    reputation = "malicious" if malicious > 2 else ("suspicious" if suspicious > 0 or malicious > 0 else "clean")
                    return {
                        "domain": domain,
                        "registrar": data.get("registrar", "Unknown"),
                        "registered": data.get("creation_date", "Unknown"),
                        "reputation": reputation,
                        "malicious_count": malicious,
                        "detection_ratio": f"{malicious + suspicious}/{total}",
                        "is_demo": False,
                        "data_source": self.label,
                    }
        except Exception as e:
            logger.error(f"VirusTotal domain lookup error: {e}")
        return await MockThreatIntelProvider().lookup_domain(domain)

    async def lookup_url(self, url: str) -> dict:
        return await MockThreatIntelProvider().lookup_url(url)


class LiveIPGeolocation:
    """Free IP geolocation using ip-api.com (no API key required)."""

    @staticmethod
    async def lookup(ip: str) -> Optional[dict]:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,as,org,lat,lon")
                if r.status_code == 200:
                    data = r.json()
                    if data.get("status") == "success":
                        return {
                            "country": data.get("country", "Unknown"),
                            "region": data.get("regionName", ""),
                            "city": data.get("city", ""),
                            "isp": data.get("isp", "Unknown"),
                            "asn": data.get("as", "Unknown"),
                            "lat": data.get("lat"),
                            "lon": data.get("lon"),
                        }
        except Exception as e:
            logger.warning(f"IP geolocation lookup failed for {ip}: {e}")
        return None


# ─── Provider factory ─────────────────────────────────────────────────────────

def get_intel_provider():
    """Return best available provider based on config."""
    from app.core.config import settings
    if settings.virustotal_enabled:
        return VirusTotalProvider(settings.VIRUSTOTAL_API_KEY)
    return MockThreatIntelProvider()
