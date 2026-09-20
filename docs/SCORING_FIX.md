# Scoring and missing-location correction — 2026-09-19

**Superseded for new/current scores by policy 2.1:** see [the September 20 scoring and workflow corrections](QUALITY_CHECK_2026-09-20.md). The following sections document the earlier 2.0 behavior and its historical test results.

## Score display correction — later on 2026-09-19

The reported 6.37 example was traced to an existing SPAM analysis with 81.34% model class probability. Its arithmetic is consistent with scoring policy 2.0: 0.75 URL points plus 5.62 AI points, rounded to a final risk of 6/100. AI points are `15 × (P(PHISHING) + P(BEC) + 0.4 × P(SPAM))`. Class probability is not the risk score. No probability, weight, threshold, or stored evidence was changed to inflate this result.

The actual display defect used a fixed maximum of 100 for every category bar. `RiskBreakdown.tsx` now uses each category's configured maximum, including custom weights, and handles disabled zero-weight categories without invalid meters. For example, 5.62/15 fills approximately 37.47% of its category bar. The panel explains rounding, any correlation adjustment, and the model formula. It distinguishes unverified header assertions, unavailable reputation/model results, missing relay evidence, and absent URLs/attachments from completed checks. GeoIP results cannot masquerade as reputation coverage. This also works with existing stored analyses; refresh the page, with no reanalysis required for the display correction.

Verification for this change: 47 backend tests passed (one integration test skipped), five real-component render tests passed, TypeScript and ESLint passed, and the production webpack build passed. The authenticated browser panel could not be visually checked because the test browser required sign-in. Run the component regressions with `cd app && node --test tests/risk-breakdown.test.mjs`. The earlier integration results below describe the prior scoring change, not a fresh integration run.

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
