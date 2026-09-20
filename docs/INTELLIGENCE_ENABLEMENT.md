# Enabled intelligence — September 20, 2026

The local system settings now enable `dns_enabled`, `automatic_enrichment`, and all five existing provider adapters. Retention, masking, model selection, and scoring weights were left unchanged. New installations still require explicit opt-in to external lookups.

Live checks against public test indicators confirmed:

| Service | Observed result |
|---|---|
| VirusTotal | Available with the stored API key |
| AbuseIPDB | Available with the stored API key |
| GeoIP | Available from local MaxMind databases |
| DNS TXT | Available through the local DNS resolver |
| URLScan | Enabled, but no API key configured |
| GreyNoise | Enabled, but no API key configured |

To finish configuring the last two services, enter their keys in **Settings → Provider credentials**. Keys are encrypted and never returned by the API. Adding an adapter to the enabled list cannot create credentials or expand provider account permissions.

## Corrections

- Enabled optional providers remain visible even when credentials are missing. Previously they silently disappeared from per-indicator results.
- `/api/intelligence/health` distinguishes configuration from the most recent actual lookup outcome. It includes DNS/automatic-enrichment switches and safe failure reasons, without disclosing keys, queried indicators, or report contents. Settings and the intelligence page display this information.
- Credential errors, denied access, rate limits, absent reports, and network timeouts have separate explanations. An unavailable lookup never becomes a clean reputation verdict.
- A provider's HTTP 429 starts a cooldown shared across analysis workers and indicators. `Retry-After` is respected; default cooldown is 60 seconds when no usable header is supplied. Other providers and local checks continue.
- Cache/cooldown identity changes when credentials change, so replacing a rejected key does not reuse its cached credential error. GeoIP cache identity remains tied to the local database version.
- Timeout/failure outcomes are cached for status visibility. Cache-write failure does not discard an otherwise valid response.
- Reserved `.example`, `.test`, `.invalid`, `.localhost`, and `.local` hostnames are explicitly Not Applicable for public reputation lookups. Five observed VirusTotal failures were HTTP 400 `InvalidArgumentError` for `.example` domains; these are test indicators, not provider outages. Other HTTP 400/422 responses are labeled Invalid Indicator and retain the HTTP status.

## Interpretation and boundaries

DNS enables DKIM key retrieval and SPF/DMARC policy inspection. Uploaded emails still do not establish a trusted SMTP envelope or peer, so independent SPF PASS is not fabricated. An old email's DKIM key may no longer exist in current DNS.

A successful provider response adds risk points only when supported suspicious evidence meets the scoring rules. Provider 404, missing attachments, absent relay headers, or missing reputation reports are not software errors and do not establish safety. No original message or attachment is uploaded for scanning; the adapters retrieve existing reports for observed indicators. Suspicious links are not opened.

Provider quotas still apply. See [VirusTotal's API limits](https://docs.virustotal.com/reference/public-vs-premium-api) and [URLScan's API reference](https://docs.urlscan.io/apis/urlscan-openapi/search). Cooldown handling is not a way to bypass account limits; some analyses can legitimately have partial reputation coverage.

Validation: 63 backend tests passed with the opt-in integration test skipped; six scoring-component tests passed. Full ESLint, TypeScript, the production webpack build, and `git diff --check` passed. Live DNS and provider checks were performed separately from mocked regression tests. All 17 saved analyses completed their refresh and passed original-evidence integrity verification. Nine analyses received reputation reports (43 VirusTotal and 12 AbuseIPDB report entries, including cached/repeated indicators); DKIM results were two PASS, three FAIL, and twelve Not Signed. No report supplied evidence sufficient to add intelligence risk points under the current policy. Coverage totals are summarized here; obsolete temporary diagnostics were removed during project cleanup. The three analyses containing rejected test domains were separately refreshed after the final adapter correction.
