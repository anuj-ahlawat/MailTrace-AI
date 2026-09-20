# Implementation reference

## Supported architecture and files

- `app/app/`: protected SOC routes and login.
- `app/components/Workspace.tsx`: session-checked navigation and global search.
- `app/components/Platform.tsx`: live dashboard, ingestion, investigations, evidence, reports, administration and account security.
- `app/components/InfrastructureGraph.tsx`, `NetworkMap.tsx`: React Flow relationships and provider-only coordinates.
- `app/lib/platform.ts`: same-origin API client with CSRF protection.
- `backend/app/main.py`: FastAPI lifecycle, limits, errors, request IDs and logging.
- `backend/app/platform/api.py`: validated authenticated REST endpoints and RBAC.
- `backend/app/platform/store.py`: database, encrypted evidence, settings, custody and audit.
- `backend/app/platform/security.py`: password hashing, revocable JWT sessions, CSRF and roles.
- `backend/app/platform/forensics.py`: MIME parser, headers, URLs, attachments, relay candidates and identity signals.
- `backend/app/platform/intelligence.py`: provider adapters, caching, local GeoIP and DNS.
- `backend/app/platform/authentication.py`: original-byte DKIM verification and qualified SPF/DMARC DNS inspection.
- `backend/app/platform/pipeline.py`: durable job states, risk, graphs, correlation and alerts.
- `backend/app/platform/gmail.py`: Gmail read-only OAuth and import.
- `backend/app/platform/reports.py`: evidence snapshots, PDF and JSON exports.
- `backend/app/platform/retention.py`: explicit retention with case holds.
- `backend/app/ml/service.py`: trusted local model loading and inference.
- `backend/app/workers/celery_app.py`: Redis broker, job dispatch, workers and retention scheduling.
- `ml/prepare.py`, `train.py`, `train_deep.py`, `select_model.py`, `models/networks.py`: corpus preparation, four model families, measured selection.
- `scripts/setup.py`: private secret generation and first-administrator provisioning.
- `docker-compose.yml`, `docker/`: container deployment.

## Collections

`users`, `sessions`, `emails`, `email_analysis`, `jobs`, `evidence`, `cases`, `iocs`, `threat_intelligence`, `campaigns`, `alerts`, `audit_logs`, `reports`, `system_settings`, `provider_secrets`, `rate_limits`, `gmail_connections`, `oauth_states`.

Application-generated UUIDs or case references are used as identifiers; MongoDB ObjectIds are not exposed. `emails` retains acquisition metadata, while `email_analysis` contains forensic detail, ML output, risk evidence, intelligence provenance, graph and timeline. Domains/IPs/URLs/attachment hashes are typed records in `iocs`; their detailed evidence is embedded in the analysis to preserve the snapshot.

Unique user email, search/time/status indexes and session/OAuth/rate/cache expiry indexes are created at startup. Evidence and analysis retention never use an unconditional MongoDB TTL index: configured retention must check case holds first.

## Endpoint groups

All application endpoints use `/api`:

| Group | Implemented operations |
|---|---|
| Authentication | `POST /auth/login`, `/auth/logout`, `/auth/password`; `GET /auth/me`; admin-only `POST /auth/register` |
| Users | `GET/POST /users`, `PATCH /users/{id}` |
| Ingestion | `POST /emails/upload`, `POST /emails/analyze` (raw input), `POST /emails/{id}/analyze` (retry/reanalysis) |
| Analysis | `GET /emails`, `/emails/{id}`, `/emails/{id}/analysis`, `/jobs/{id}` |
| Forensics | `GET /forensics/{id}/headers`, `/received-chain`, `/authentication`; `GET /graph/{id}` |
| Intelligence | `POST /intelligence/lookup`; `GET /intelligence/status`, `/intelligence/ip/{ip}`, `/domain/{domain}`, `/hash/{hash}`, `/iocs` |
| Cases | `GET/POST /cases`; `GET/PATCH /cases/{id}`; `POST /cases/{id}/notes`, `/emails`, `/evidence`, `/iocs` |
| Evidence | `GET /evidence`, `/evidence/{id}`, `/evidence/{id}/download`; `POST /evidence/{id}/verify` |
| Campaigns | `GET/POST /campaigns`, `GET /campaigns/{id}/graph` |
| Reports | `GET/POST /reports`, `GET /reports/{id}`, `/reports/{id}/download?format=pdf|json` |
| Alerts | `GET /alerts`, `PATCH /alerts/{id}` |
| Dashboard | `GET /dashboard/summary`, `/dashboard/trends`, `/dashboard/infrastructure`, `/dashboard/geography` |
| Search/audit | `GET /search?q=...`, `GET /audit-logs` (admin) |
| Settings | `GET/PUT /settings`; `PUT/DELETE /settings/providers/{provider}`; `POST /settings/model/reload`, `/settings/retention/run` |
| Gmail | `GET /gmail/status`, `/gmail/emails`, `/gmail/callback`; `POST /gmail/connect`, `/gmail/disconnect`, `/gmail/emails/{id}/import` |

Health is `/health`; generated API reference is `/docs`. Email/CSV uploads return job IDs with HTTP 202. Report generation also returns a persisted job. Errors use `detail` and request IDs rather than stack traces. Limits apply to body size, CSV rows, pagination and selected expensive endpoints.

## Frontend routes

`/`, `/login`, `/overview`, `/dashboard`, `/analyze`, `/emails`, `/emails/[id]`, `/cases`, `/cases/[id]`, `/investigations`, `/investigations/[id]`, `/threat-intelligence`, `/geolocation`, `/route-trace`, `/graph`, `/campaign-graph`, `/alerts`, `/reports`, `/evidence`, `/gmail-inbox`, `/account`, `/settings`, `/admin/users`, `/audit-logs`, `/admin/audit-logs`.

Aliases preserve existing links. Session verification precedes protected page content; every data endpoint also authenticates and enforces its required role. User state in localStorage is not treated as authorization.

## What the forensic engine does

- Preserves encrypted source bytes; SHA-256 is calculated before decoding and recalculated from recovered bytes during verification.
- Retains every raw header plus complete raw-header text; RFC/MIME parsing supports multipart bodies, encoded headers, HTML-derived text, and attachment bytes/metadata.
- Extracts sender/recipient/CC/BCC, Reply-To, Return-Path, Message-ID and threading references. DKIM and ARC/X headers remain available in the full header record.
- Parses chronological Received hops, IPv4/IPv6 candidates, hostnames, timestamps, protocols and public/private/internal/reserved status. Reversed timestamps are potential anomalies with evidence, not proof of forgery.
- Separates reported SPF/DKIM/DMARC results from independent verification. Preserves SoftFail, Neutral, None, and error states. Signature domain/selector and domain alignment are inspected. Separate local DKIM verification uses dkimpy and current DNS keys when enabled; it never copies a header-reported result into a verified result.
- Detects registered-domain mismatch and potential lookalikes using offline public-suffix data, Unicode normalization, character substitutions and similarity heuristics.
- Extracts HTTP(S) URLs without visiting them and flags structural signals, displayed/destination differences and redirect parameters. No attachment is executed.
- Provides source-separated AI, forensic and threat-intelligence signals, configurable maximum contributions, and configurable risk boundaries (defaults 30/60/80).
- Builds observed infrastructure nodes/edges and timestamps with their evidence sources. Campaign suggestions require multiple strong shared URL/hash indicators; final association is a senior analyst action with a rationale.

## Credential-dependent capabilities

VirusTotal and AbuseIPDB are optional reputation APIs. Local MaxMind enrichment requires a City and/or ASN database; no geolocation API key is needed. Gmail remains an optional import integration. URLScan/GreyNoise are legacy opt-in adapters and are not needed for local analysis. Adapters are implemented, but credential presence is not evidence of a successful live request. Provider connectivity must be verified using the deployment's own credentials. API quotas and failures remain visible.

## Concrete limitations

- SPF authorization remains unknown without trusted SMTP peer/envelope information. DKIM verification supports RSA-SHA256; unsupported algorithms and DNS failures are unavailable. A verified aligned DKIM signature can establish the DKIM branch of DMARC; no DMARC failure is asserted from unknown SPF. Trusted receiving-boundary origin attribution, executable attachment sandboxing, active probing and human attribution are not claimed.
- Registration/WHOIS, VPN/TOR/proxy/hosting details and ASN/organization fields are available only when a configured provider returns them. Absence is unknown, not negative.
- Search covers stored identities/subjects/indicators/cases/hashes. Email filters include processing status, severity, verdict, minimum risk, date interval, source, case, provider-reported country and ASN.
- Public-IP reverse DNS is queried when DNS is enabled. Geographical jumps are not treated as proof of maliciousness; estimates remain provider data without invented confidence.
- Automatic provider enrichment is capped at 25 indicators per message; the result labels this cap. Other indicators remain available for manual lookup.
- The current map uses public OSM tiles; air-gapped deployments need a local tile source.
- Password-only authentication and application-managed audit records do not constitute SSO/MFA, signed custody notarization, WORM storage or an independent security certification.
- BEC-2 is synthetic and minority classes are small. Within-corpus validation is not proof of performance on current enterprise traffic. No calibrated-probability or independent external-corpus claim is made.
- No optional probability ensemble or active investigation tooling has been added.

## Migration

The unused Flask prototype, seed scripts, mock libraries, disconnected components and old API modules were removed during cleanup; their source remains available in Git history. The supported application did not import them. The new database is isolated; no legacy record is silently copied into evidence or reclassified as authentic. Original messages must be reacquired to establish a real preservation hash and custody history.
