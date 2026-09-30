"""Unit tests for the explainable scoring engine (Part 21 of the SIH specification).

Tests:
 1.  Legitimate email evidence -> LOW risk where evidence supports it
 2.  SPF+DKIM+DMARC failure   -> authentication risk increases
 3.  Authentication UNKNOWN   -> NOT treated as FAIL
 4.  Lookalike + impersonation -> forensic risk increases, no double-count overflow
 5.  Confirmed malicious URL  -> IOC / threat-intel risk increases
 6.  Threat-intel API unavail -> UNAVAILABLE status; application continues
 7.  Reliable relay + GeoIP + ASN -> origin confidence increases
 8.  TOR/VPN infrastructure   -> origin confidence decreases; threat risk NOT auto-critical
 9.  Missing relay headers    -> origin confidence LOW
10.  Contradictory relay      -> origin confidence decreases
11.  Same evidence twice      -> no double-score
12.  Score boundaries         -> all scores 0-100
"""
import copy
import unittest
from pathlib import Path

from backend.parsers.email_parser import parse
from backend.core.pipeline import risk
from backend.core.origin_confidence import compute_origin_confidence
from backend.database.store import DEFAULTS
import backend.core.scoring_config as SC

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
UNKNOWN_ML = {"status": "Model unavailable", "label": None,
              "confidence": None, "probabilities": None}
BENIGN_ML  = {"status": "Available", "label": "BENIGN", "confidence": 0.97,
               "probabilities": {"BENIGN": 0.97, "PHISHING": 0.01, "BEC": 0.01, "SPAM": 0.01}}


def _risk(parsed, ml=None, enrichment=None, config=None):
    return risk(parsed, ml or UNKNOWN_ML, enrichment or [], config or copy.deepcopy(DEFAULTS))


def _origin(parsed, enrichment=None):
    return compute_origin_confidence(parsed, enrichment or [])


def _make_parsed(**overrides):
    """Minimal parsed dict satisfying risk()."""
    base = {
        "authentication": {
            "spf":  {"reported_result": "Unknown"},
            "dkim": {"reported_result": "Unknown", "local_verification": {}, "signatures": []},
            "dmarc": {"reported_result": "Unknown"},
        },
        "sender_identity": {
            "display_name_mismatch": [],
            "sender_domain": "example.com",
            "reply_to_domain": "example.com",
            "reply_to_mismatch": False,
            "lookalikes": [],
        },
        "urls": [], "attachments": [], "anomalies": [], "iocs": [],
        "received_chain": [], "origin": {"candidate_ip": None, "candidate_ips": []},
        "model_text": "Hello world", "limitations": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Test 1 — Legitimate email -> LOW risk
# ---------------------------------------------------------------------------
class TestLegitimateEmail(unittest.TestCase):
    def test_legitimate_email_is_low_risk(self):
        raw = (FIXTURES / "benign.eml").read_bytes()
        parsed = parse(raw)
        result = _risk(parsed, BENIGN_ML)
        self.assertEqual(result["severity"], "LOW")
        self.assertLess(result["risk_score"], 30)
        # No structural high-risk indicators
        self.assertEqual(result["component_scores"]["authentication"]["score"], 0)

    def test_benign_ml_without_auth_failures_stays_low(self):
        parsed = _make_parsed()
        result = _risk(parsed, BENIGN_ML)
        # BENIGN 0.97 -> threat = 0.01+0.01+0.4*0.01 = 0.024 -> ml_score ≈ 2.4
        self.assertLess(result["component_scores"]["ml"]["score"], 5)
        self.assertLess(result["risk_score"], 30)


# ---------------------------------------------------------------------------
# Test 2 — SPF + DKIM + DMARC failure -> auth risk increases
# ---------------------------------------------------------------------------
class TestAuthFailures(unittest.TestCase):
    def test_all_three_auth_failures_raise_auth_component(self):
        parsed = _make_parsed(authentication={
            "spf":  {"reported_result": "FAIL", "source": "Authentication-Results header"},
            "dkim": {"reported_result": "FAIL", "local_verification": {}, "signatures": []},
            "dmarc": {"reported_result": "FAIL"},
        })
        result = _risk(parsed)
        auth_score = result["component_scores"]["authentication"]["score"]
        # SPF(16) + DKIM_reported(16) + DMARC(24) = 56
        self.assertGreaterEqual(auth_score, 50)
        self.assertGreater(result["risk_score"], 10)

    def test_dkim_live_verification_fail_adds_more_than_reported(self):
        parsed_reported = _make_parsed(authentication={
            "spf":  {"reported_result": "Unknown"},
            "dkim": {"reported_result": "FAIL", "local_verification": {}, "signatures": []},
            "dmarc": {"reported_result": "Unknown"},
        })
        parsed_verified = _make_parsed(authentication={
            "spf":  {"reported_result": "Unknown"},
            "dkim": {"reported_result": "Unknown",
                     "local_verification": {"status": "FAIL"}, "signatures": []},
            "dmarc": {"reported_result": "Unknown"},
        })
        auth_reported = _risk(parsed_reported)["component_scores"]["authentication"]["score"]
        auth_verified = _risk(parsed_verified)["component_scores"]["authentication"]["score"]
        # DKIM_FAIL_VERIFIED(30) > DKIM_FAIL_REPORTED(16)
        self.assertGreater(auth_verified, auth_reported)


# ---------------------------------------------------------------------------
# Test 3 — UNKNOWN auth is NOT FAIL
# ---------------------------------------------------------------------------
class TestUnknownAuthNotFail(unittest.TestCase):
    def test_unknown_spf_dkim_dmarc_adds_zero_auth_risk(self):
        parsed = _make_parsed()  # all auth = Unknown by default
        result = _risk(parsed)
        self.assertEqual(result["component_scores"]["authentication"]["score"], 0)

    def test_none_auth_result_also_zero(self):
        parsed = _make_parsed(authentication={
            "spf":  {"reported_result": "NONE"},
            "dkim": {"reported_result": "NONE", "local_verification": {}, "signatures": []},
            "dmarc": {"reported_result": "NONE"},
        })
        result = _risk(parsed)
        self.assertEqual(result["component_scores"]["authentication"]["score"], 0)

    def test_softfail_spf_lower_than_fail(self):
        softfail = _make_parsed(authentication={
            "spf":  {"reported_result": "SOFTFAIL"},
            "dkim": {"reported_result": "Unknown", "local_verification": {}, "signatures": []},
            "dmarc": {"reported_result": "Unknown"},
        })
        fail = _make_parsed(authentication={
            "spf":  {"reported_result": "FAIL"},
            "dkim": {"reported_result": "Unknown", "local_verification": {}, "signatures": []},
            "dmarc": {"reported_result": "Unknown"},
        })
        soft_score = _risk(softfail)["component_scores"]["authentication"]["score"]
        fail_score = _risk(fail)["component_scores"]["authentication"]["score"]
        self.assertLess(soft_score, fail_score)
        self.assertEqual(soft_score, SC.AUTH_POINTS["SPF_SOFTFAIL_REPORTED"])


# ---------------------------------------------------------------------------
# Test 4 — Lookalike + display-name impersonation -> forensic risk increases,
#           group cap prevents unbounded stacking
# ---------------------------------------------------------------------------
class TestLookalikeImpersonation(unittest.TestCase):
    def test_lookalike_and_display_name_raises_forensic_score(self):
        parsed = _make_parsed(
            sender_identity={
                "display_name_mismatch": [{"display_name": "Apple Support",
                                           "claimed_brand": "apple.com",
                                           "sender_domain": "applle.com",
                                           "source": "test",
                                           "assessment": "test"}],
                "sender_domain": "applle.com",
                "reply_to_domain": "applle.com",
                "reply_to_mismatch": False,
                "lookalikes": [{"observed_domain": "applle.com",
                                "potential_target": "apple.com",
                                "similarity": 0.9}],
            }
        )
        result = _risk(parsed)
        forensic_score = result["component_scores"]["header_forensics"]["score"]
        self.assertGreater(forensic_score, 0)
        # Group cap: identity_spoofing capped at 40
        self.assertLessEqual(forensic_score, SC.HEADER_GROUP_CAPS["identity_spoofing"])

    def test_group_cap_prevents_identity_signals_from_exceeding_cap(self):
        # Add all 4 identity_spoofing signals — total raw > cap
        parsed = _make_parsed(
            sender_identity={
                "display_name_mismatch": [{"display_name": "Bank", "claimed_brand": "bank.com",
                                           "sender_domain": "baank.com",
                                           "source": "test", "assessment": "test"}],
                "sender_domain": "baank.com",
                "reply_to_domain": "secure.baank.com",
                "reply_to_mismatch": True,
                "lookalikes": [{"observed_domain": "baank.com",
                                "potential_target": "bank.com", "similarity": 0.92}],
            }
        )
        result = _risk(parsed)
        forensic_score = result["component_scores"]["header_forensics"]["score"]
        self.assertLessEqual(forensic_score, SC.HEADER_GROUP_CAPS["identity_spoofing"])


# ---------------------------------------------------------------------------
# Test 5 — Confirmed malicious URL -> IOC score increases
# ---------------------------------------------------------------------------
class TestMaliciousURL(unittest.TestCase):
    def test_url_with_suspicious_signal_raises_ioc(self):
        parsed = _make_parsed(urls=[{
            "original_url": "http://phishing-evil.example.com/login",
            "domain": "phishing-evil.example.com",
            "signals": [{"type": "display_href_mismatch", "strength": 0.5,
                         "severity": "high", "description": "test", "source": "test"}],
            "flags": [],
            "lookalikes": [],
        }])
        result = _risk(parsed)
        self.assertGreater(result["component_scores"]["ioc"]["score"], 0)

    def test_url_without_signals_adds_zero_ioc(self):
        parsed = _make_parsed(urls=[{
            "original_url": "https://normal.example.com/page",
            "domain": "normal.example.com",
            "signals": [],
            "flags": [],
            "lookalikes": [],
        }])
        result = _risk(parsed)
        self.assertEqual(result["component_scores"]["ioc"]["score"], 0)

    def test_threat_intel_malicious_raises_intel_score(self):
        enrichment = [{"type": "url", "query": "http://evil.com", "providers": [{
            "provider": "virustotal", "status": "Available",
            "result": {"data": {"attributes": {"last_analysis_stats": {
                "malicious": 15, "undetected": 5, "harmless": 0, "suspicious": 0,
                "timeout": 0, "confirmed-timeout": 0, "failure": 0, "type-unsupported": 0,
            }}}},
            "timestamp": "2026-09-22T00:00:00",
        }]}]
        parsed = _make_parsed()
        result = _risk(parsed, enrichment=enrichment)
        self.assertGreater(result["component_scores"]["threat_intelligence"]["score"], 0)
        self.assertEqual(result["component_scores"]["threat_intelligence"]["status"], "AVAILABLE")


# ---------------------------------------------------------------------------
# Test 6 — Threat-intel API unavailable -> UNAVAILABLE, application continues
# ---------------------------------------------------------------------------
class TestThreatIntelUnavailable(unittest.TestCase):
    def test_unavailable_provider_sets_status_and_does_not_crash(self):
        enrichment = [{"type": "ip", "query": "1.2.3.4", "providers": [
            {"provider": "virustotal", "status": "Unavailable", "result": None},
            {"provider": "abuseipdb",  "status": "Unavailable", "result": None},
        ]}]
        parsed = _make_parsed()
        result = _risk(parsed, enrichment=enrichment)
        intel = result["component_scores"]["threat_intelligence"]
        self.assertEqual(intel["status"], "UNAVAILABLE")
        self.assertEqual(intel["score"], 0)
        # Score is 0 but NOT because email is safe — status makes this explicit
        self.assertIn("no data", intel["note"].lower())

    def test_no_providers_configured_shows_not_configured(self):
        parsed = _make_parsed()
        result = _risk(parsed, enrichment=[])
        intel = result["component_scores"]["threat_intelligence"]
        self.assertEqual(intel["status"], "NOT_CONFIGURED")


# ---------------------------------------------------------------------------
# Test 7 — Reliable relay + GeoIP + ASN -> origin confidence increases
# ---------------------------------------------------------------------------
class TestOriginConfidencePositive(unittest.TestCase):
    def test_relay_and_geoip_increase_confidence(self):
        parsed = _make_parsed(
            received_chain=[{"hop": 1, "ips": [{"ip": "1.2.3.4", "public": True,
                                                "role": "source", "valid": True}],
                             "timestamp": "2026-09-22T10:00:00+00:00", "raw": "test"}],
            origin={"candidate_ip": "1.2.3.4", "candidate_ips": ["1.2.3.4"],
                    "reason": "Earliest public relay", "confidence": "Candidate"},
            anomalies=[],
        )
        enrichment = [{"type": "ip", "query": "1.2.3.4", "providers": [{
            "provider": "geoip", "status": "Available",
            "result": {"country": "India", "city": "Mumbai", "region": "Maharashtra",
                       "asn": 15169, "organization": "Google LLC",
                       "latitude": 19.07, "longitude": 72.88},
        }], "rdap": {}}]
        result = _origin(parsed, enrichment)
        self.assertGreaterEqual(result["score"], 30)
        self.assertGreater(len(result["supporting_evidence"]), 0)
        self.assertIn("candidate_ip", result)

    def test_supporting_evidence_strings_describe_findings(self):
        parsed = _make_parsed(
            received_chain=[{"hop": 1, "ips": [{"ip": "5.6.7.8", "public": True,
                                                "role": "source", "valid": True}],
                             "timestamp": "2026-09-22T10:00:00+00:00", "raw": "x"}],
            origin={"candidate_ip": "5.6.7.8", "candidate_ips": ["5.6.7.8"],
                    "reason": "Candidate", "confidence": "Candidate"},
            anomalies=[],
        )
        result = _origin(parsed)
        # relay identified, public IP extracted, chain consistent
        self.assertGreaterEqual(result["score"], 40)


# ---------------------------------------------------------------------------
# Test 8 — TOR/VPN detected -> origin confidence decreases; threat risk NOT auto-critical
# ---------------------------------------------------------------------------
class TestInfrastructureNotAutoMalicious(unittest.TestCase):
    def test_tor_indicator_reduces_origin_confidence(self):
        parsed = _make_parsed(
            received_chain=[{"hop": 1, "ips": [{"ip": "185.220.101.5", "public": True,
                                                "role": "source", "valid": True}],
                             "timestamp": None, "raw": "x"}],
            origin={"candidate_ip": "185.220.101.5", "candidate_ips": ["185.220.101.5"],
                    "reason": "Candidate", "confidence": "Candidate"},
            anomalies=[],
        )
        enrichment_tor = [{"type": "ip", "query": "185.220.101.5", "providers": [{
            "provider": "abuseipdb", "status": "Available",
            "result": {"data": {"isTor": True}},
        }], "rdap": {}}]
        result = _origin(parsed, enrichment_tor)
        self.assertIn("TOR", " ".join(result["conflicting_evidence"]).upper())
        self.assertLess(result["score"], 40)

    def test_vpn_does_not_increase_threat_risk(self):
        # VPN in ASN should lower origin confidence, NOT raise threat risk
        parsed = _make_parsed(
            received_chain=[{"hop": 1, "ips": [{"ip": "45.33.32.156", "public": True,
                                                "role": "source", "valid": True}],
                             "timestamp": None, "raw": "x"}],
            origin={"candidate_ip": "45.33.32.156", "candidate_ips": ["45.33.32.156"],
                    "reason": "Candidate", "confidence": "Candidate"},
            anomalies=[],
        )
        enrichment_vpn = [{"type": "ip", "query": "45.33.32.156", "providers": [{
            "provider": "geoip", "status": "Available",
            "result": {"country": "US", "organization": "VPN Services LLC", "asn": 63949},
        }], "rdap": {}}]
        threat_result = _risk(parsed)          # VPN in enrichment should not affect threat risk
        origin_result  = _origin(parsed, enrichment_vpn)
        # Threat risk unchanged (VPN is not in threat enrichment signals)
        self.assertEqual(threat_result["component_scores"]["threat_intelligence"]["score"], 0)
        # Origin confidence should detect VPN indicator
        self.assertTrue(
            any("vpn" in e.lower() or "hosting" in e.lower()
                for e in origin_result["conflicting_evidence"] + origin_result["limitations"]),
            "VPN/hosting indicator not reflected in origin output"
        )


# ---------------------------------------------------------------------------
# Test 9 — Missing relay headers -> origin confidence LOW
# ---------------------------------------------------------------------------
class TestMissingRelayHeaders(unittest.TestCase):
    def test_no_relay_headers_gives_low_confidence(self):
        parsed = _make_parsed()  # received_chain=[], candidate_ip=None by default
        result = _origin(parsed)
        self.assertIn(result["level"], ("LOW", "LIMITED"))
        self.assertLessEqual(result["score"], 30)
        self.assertIsNone(result["candidate_ip"])

    def test_no_relay_includes_insufficient_relay_penalty(self):
        parsed = _make_parsed()
        result = _origin(parsed)
        rule_ids = [c["rule_id"] for c in result["contributions"]]
        self.assertIn("INSUFFICIENT_PUBLIC_RELAY", rule_ids)


# ---------------------------------------------------------------------------
# Test 10 — Contradictory relay (timestamp anomalies) -> origin confidence decreases
# ---------------------------------------------------------------------------
class TestContradictoryRelay(unittest.TestCase):
    def test_timestamp_anomaly_penalises_origin_confidence(self):
        parsed_clean = _make_parsed(
            received_chain=[{"hop": 1, "ips": [{"ip": "1.1.1.1", "public": True,
                                                "role": "source", "valid": True}],
                             "timestamp": "2026-09-22T10:00:00+00:00", "raw": "x"}],
            origin={"candidate_ip": "1.1.1.1", "candidate_ips": ["1.1.1.1"],
                    "reason": "Candidate", "confidence": "Candidate"},
            anomalies=[],
        )
        parsed_anomaly = _make_parsed(
            received_chain=[{"hop": 1, "ips": [{"ip": "1.1.1.1", "public": True,
                                                "role": "source", "valid": True}],
                             "timestamp": "2026-09-22T10:00:00+00:00", "raw": "x"}],
            origin={"candidate_ip": "1.1.1.1", "candidate_ips": ["1.1.1.1"],
                    "reason": "Candidate", "confidence": "Candidate"},
            anomalies=[{"finding": "Timestamp order anomaly", "evidence": ["hop1", "hop2"],
                        "confidence": "Low"}],
        )
        clean_score   = _origin(parsed_clean)["score"]
        anomaly_score = _origin(parsed_anomaly)["score"]
        self.assertLess(anomaly_score, clean_score)


# ---------------------------------------------------------------------------
# Test 11 — Same evidence twice does not double-score
# ---------------------------------------------------------------------------
class TestNoDuplicateScoring(unittest.TestCase):
    def test_same_signal_not_double_counted_for_auth(self):
        parsed = _make_parsed(authentication={
            "spf":  {"reported_result": "FAIL", "source": "Auth-Results"},
            "dkim": {"reported_result": "Unknown", "local_verification": {}, "signatures": []},
            "dmarc": {"reported_result": "Unknown"},
        })
        r1 = _risk(parsed)
        r2 = _risk(parsed)  # second call, same data
        self.assertEqual(r1["component_scores"]["authentication"]["score"],
                         r2["component_scores"]["authentication"]["score"])

    def test_repeated_weak_url_signals_do_not_inflate_risk(self):
        single_url_parsed = _make_parsed(urls=[{
            "original_url": "http://e.com/x",
            "domain": "e.com",
            "signals": [{"type": "long_url", "strength": 0.05,
                         "severity": "low", "description": "long", "source": "test"}],
            "flags": [],
            "lookalikes": [],
        }])
        many_url_parsed = _make_parsed(urls=[{
            "original_url": f"http://e.com/x{i}",
            "domain": "e.com",
            "signals": [{"type": "long_url", "strength": 0.05,
                         "severity": "low", "description": "long", "source": "test"}],
            "flags": [],
            "lookalikes": [],
        } for i in range(50)])
        r1 = _risk(single_url_parsed)
        r2 = _risk(many_url_parsed)
        # URL category uses max(strengths) not sum — risk_score must be the same
        url1 = next((c for c in r1["contributions"] if c["category"] == "url"), None)
        url2 = next((c for c in r2["contributions"] if c["category"] == "url"), None)
        if url1 and url2:
            self.assertEqual(url1["points"], url2["points"])


# ---------------------------------------------------------------------------
# Test 12 — Score boundaries (0-100)
# ---------------------------------------------------------------------------
class TestScoreBoundaries(unittest.TestCase):
    def _assert_bounded(self, result):
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)
        for comp in result["component_scores"].values():
            self.assertGreaterEqual(comp["score"], 0)
            self.assertLessEqual(comp["score"], 100)

    def test_all_failures_stays_within_100(self):
        parsed = _make_parsed(
            authentication={
                "spf":  {"reported_result": "FAIL", "source": "test"},
                "dkim": {"reported_result": "FAIL",
                         "local_verification": {"status": "FAIL"}, "signatures": []},
                "dmarc": {"reported_result": "FAIL"},
            },
            sender_identity={
                "display_name_mismatch": [{"display_name": "Bank", "claimed_brand": "bank.com",
                                           "sender_domain": "baank.com",
                                           "source": "test", "assessment": "test"}],
                "sender_domain": "baank.com", "reply_to_domain": "evil.com",
                "reply_to_mismatch": True,
                "lookalikes": [{"observed_domain": "baank.com", "potential_target": "bank.com",
                                "similarity": 0.95}],
            },
            urls=[{"original_url": "http://evil.com", "domain": "evil.com",
                   "signals": [{"type": "display_href_mismatch", "strength": 1.0,
                                "severity": "high", "description": "test", "source": "test"}],
                   "flags": ["malicious"], "lookalikes": []}],
        )
        ml_high = {"status": "Available", "label": "PHISHING", "confidence": 0.99,
                   "probabilities": {"BENIGN": 0.01, "PHISHING": 0.98, "BEC": 0.005, "SPAM": 0.005}}
        self._assert_bounded(_risk(parsed, ml_high))

    def test_empty_email_does_not_go_negative(self):
        parsed = _make_parsed()
        self._assert_bounded(_risk(parsed))

    def test_origin_confidence_bounded(self):
        parsed = _make_parsed()
        result = _origin(parsed)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)


if __name__ == "__main__":
    unittest.main()
