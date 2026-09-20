# IP / GeoIP investigation pipeline

The existing implementation is in `app/` (Next.js frontend), `backend/app/platform/` (FastAPI investigation pipeline), and `ml/` (training and local model artifacts). No second API or GeoIP service was introduced.

## Changed files for this update

- `backend/app/platform/forensics.py`: whole Received-header parsing; source/destination roles; malformed IP observations; IPv4/IPv6/mapped-address classification; IP-bearing X-Originating-IP, X-Sender-IP, X-Real-IP and Received-SPF client-ip headers; complete chronological mail path.
- `backend/app/platform/intelligence.py`: existing GeoLite2 provider/cache reused for all public IPs; mapped IPv4 lookup normalization; timezone; per-IP availability and reasons; request-level deduplication; empty/malformed results and exceptions isolated; validation for existing URLScan/GreyNoise result shapes.
- `backend/app/platform/pipeline.py`: adds enriched mail path and analyzed hops to the existing response. Local GeoIP is no longer restricted by the 25-indicator external reputation/DNS budget. The scoring rules and model artifacts are unchanged by this update.
- `backend/app/platform/api.py`: applies the existing privacy masking policy to new raw-header fields.
- `backend/app/platform/reports.py`: includes analyzed hops in new report snapshots.
- `app/components/Platform.tsx`: per-IP table showing classification, role, hop, availability/reason, country/region/city, organization/ISP/ASN, coordinates, accuracy radius, timezone and source.
- `app/components/NetworkMap.tsx`: fits multiple observed locations in the initial view, preserving the corrected tile referrer policy.
- `backend/tests/test_mail_path.py`: parser, IPv4/IPv6/mapped classes, origin-role safeguards, GeoIP failure isolation, caching, legacy provider adapters, and all-public-IP coverage beyond the reputation budget.
- `backend/tests/test_pipeline_integration.py`: eleven API-uploaded scenarios, real MongoDB/Redis/Celery/GeoLite2 reanalysis, unchanged model predictions, a simulated provider-timeout scenario, original evidence integrity and report exports.
- `backend/tests/fixtures/{mixed_hops,private_hops,public_ipv6,reserved_hops,spam}.eml`: isolated synthetic regression fixtures; never uploaded to the production database by tests.
- `docs/IP_GEOIP_PIPELINE.md`, `docs/LOCAL_STACK.md`, `README.md`: current behavior and configuration notes.

## Backward-compatible response

Existing `forensics.received_chain`, `forensics.origin`, `forensics.ip_analysis`, `intelligence`, `geolocation`, model and scoring fields remain. `candidate_ip` remains an explicitly unverified legacy candidate: the earliest observed public **source-side** relay IP. `origin.ip` remains null without an established trust boundary. `candidate_ips` retains all public source candidates; destination-only IPs are not selected as origin.

New `mail_path` retains every Received header in original path order, its raw text, parsed servers, timestamp, classified IPs and enriched `ip_analysis`. Headers without IPs remain in this path with a reason. `analyzed_hops` contains one row per observed IP occurrence, including invalid and internal addresses; extra IP-bearing headers have no invented hop number.

Each analyzed row includes `ip`, `type`, `classification`, `version`, `role`, `hop`, `observation_source`, `location_available`, `location_status`, `location_reason`, geographic fields, `organization`, `isp`, `asn`, `timezone`, source and confidence. Unavailable fields stay null. ASN organization is not mislabeled as an independently verified ISP. Coordinates alone determine whether a map marker is available; ASN or country information can still be useful without a marker.

Only appropriate headers are scanned for bare IP literals. The existing URL-host IP extraction is retained and explicitly labeled URL infrastructure, never sender origin. No arbitrary body numbers, user/device geolocation, hostname DNS addresses, or model guesses are substituted for observed mail-path IPs.

## Classification and lookup policy

Python `ipaddress` validates every candidate. Private RFC1918/ULA, loopback, link-local, reserved/documentation/shared-use, multicast and invalid addresses are reported separately and never sent for public GeoIP or public-IP reputation lookup. IPv4-mapped IPv6 is classified using its embedded IPv4 address and uses that IPv4 for lookup, while preserving the observed IPv6 literal.

Every distinct public IP can use the **existing local** GeoLite2 adapter; the 25-indicator budget still bounds external reputation and DNS requests. MongoDB caches successful provider responses for six hours and unavailable results for three minutes. GeoIP cache keys include database paths/modification times and normalize mapped IPs. Repeated hops also reuse results within the request. No new dependencies, external APIs, or credentials were added.

## Configuration

Use the already-configured environment variables:

```dotenv
GEOIP_CITY_DB=/absolute/path/GeoLite2-City.mmdb
GEOIP_ASN_DB=/absolute/path/GeoLite2-ASN.mmdb
```

Enable `geoip` in Settings. City and ASN databases work independently. Restart the backend and any Celery worker after changing their environment paths. VirusTotal, AbuseIPDB and optional legacy URLScan/GreyNoise settings remain unchanged. No GeoIP API license key is required for local lookups.

## Limits

Private/internal-only emails cannot be geolocated on a public map. No Received/IP evidence means no observable mail-server location. Public address classification does not guarantee a matching database record, useful coordinates, or network reachability. Real tests confirmed that some public addresses return ASN/network information without coordinates. Email headers can be forged; neither relay order nor a map marker establishes the sender's physical location.

Existing analysis snapshots require reanalysis to receive the new per-hop fields. Saved report snapshots are not rewritten. Regression tests validate functionality, not classifier accuracy: the synthetic promotional fixture is still predicted BENIGN by the unchanged model. Live external reputation credentials/quotas are not exercised; adapter successes and failures are verified with isolated HTTP transports.

## Reproduce checks

Verified on 2026-09-19: **47 backend checks passed** with integration enabled. The offline run passed 46 checks and skipped the integration check. Eleven representative uploads, three reanalyses using real GeoLite2, and an additional API-uploaded provider-failure scenario completed. TypeScript, ESLint and the production webpack build passed. VirusTotal/AbuseIPDB/URLScan/GreyNoise adapter success/error cases passed using isolated test HTTP transports; no live credential validation is claimed.

```bash
PYTHONPATH=backend backend/venv/bin/python -m unittest discover -s backend/tests -v
cd app
npx --no-install tsc --noEmit
npm run lint
npm run build -- --webpack
```

See [LOCAL_STACK.md](LOCAL_STACK.md) for the isolated real MongoDB/Redis integration command and complete application startup commands.
