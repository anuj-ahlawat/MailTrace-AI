# Scoring and missing-location correction — 2026-09-19

The supplied `mailtrace_phishing_test.eml` reproduced a PHISHING model prediction with probability 0.999536 but a LOW risk score of 23. It contains no Received headers or public IP. Therefore it cannot provide a sending location, even with valid GeoLite2 databases.

## Fixes

- `forensics.py`: preserve full hostnames when the public suffix is unknown. Previously unrelated `.example` hosts collapsed to `example`, suppressing lookalike and mismatch detection. Origin reasons now distinguish absent relay headers and absence of a public sending IP. Literal IP URL hosts are extracted as URL infrastructure, never as sender origin.
- `pipeline.py`: scoring version 2.0 retains weighted evidence and adds explicit correlation rules. A credential request plus a deceptive destination plus identity inconsistency or pressure has a minimum review score of 75. Changed payment instructions plus urgency and secrecy have a minimum of 60 (75 with identity evidence). These are documented heuristic policy values, not calibrated probabilities. Rules require their associated scoring categories to be enabled. Repeating weak links uses the strongest URL contribution instead of accumulating risk. Model outputs are retained unchanged; a different rule verdict never borrows the model's confidence.
- The score is `max(weighted evidence, strongest matched rule minimum)`. The contribution table includes only the additional points necessary to reach that minimum. Missing APIs, authentication evidence, and geolocation never produce fabricated evidence. Thresholds and individual category weights remain configurable. Correlation policy values are versioned in code; they are not probability estimates or fitted accuracy metrics.
- Observed public IPs are prioritized within the existing 25-indicator enrichment budget so long domain/link lists cannot prevent GeoIP evaluation. Geolocation assessment distinguishes no observed public IP, disabled lookup, missing database, unavailable database, missing record, ASN-only results, and available coordinates.
- `api.py`: reanalysis now records its initial Uploaded stage, updates the email's processing state, and writes an audit event.
- `Platform.tsx` and `NetworkMap.tsx`: show the analysis verdict and model prediction separately, explain the risk calculation, show the actual reason for an empty map, and recenter when the selected coordinates change.
- `reports.py`: new reports contain scoring version/rules and the geolocation assessment. Previously generated report snapshots are retained.

## Verification

All 33 backend checks passed, including the opt-in integration workflow against isolated real MongoDB, Redis, and Celery. The integration also exercised real local GeoLite2 data, missing optional providers, reanalysis, original byte/hash verification, encrypted storage, graph generation, case creation, PDF/JSON exports, authentication and CSRF rejection. Frontend TypeScript, ESLint, and the production webpack build passed.

| Input | Analysis verdict | Risk | Notes |
|---|---|---:|---|
| Benign fixture | BENIGN | 1 | No correlated threat pattern |
| Phishing fixture | PHISHING | 75 | Credential lure and deceptive identity/link |
| BEC fixture | BEC | 60 | Correlated payment-change, urgency and secrecy; model prediction remains PHISHING |
| Impersonation fixture | PHISHING | 27 | Model verdict; identity evidence alone does not trigger the strong rule |
| Suspicious URLs fixture | BENIGN | 25 | Real model prediction retained; local review evidence remains visible |
| User-supplied phishing fixture | PHISHING | 75 | Location explicitly Not Observable; no public IP was supplied |

These examples are regression scenarios, not a held-out accuracy evaluation. No model was retrained. Detection can have false positives and false negatives; this correction does not certify that every possible project defect has been eliminated.

Run from the repository root:

```bash
PYTHONPATH=backend backend/venv/bin/python -m unittest discover -s backend/tests -v
```

See [local stack instructions](LOCAL_STACK.md) for the real MongoDB/Redis integration command and startup commands. Existing stored results require reanalysis to use scoring version 2.0.
