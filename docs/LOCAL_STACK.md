# Local threat intelligence and forensic update

This follow-up extends the existing MailTrace implementation. It preserves the API structure, MongoDB collections, Redis/Celery jobs, trained models, evidence storage and frontend layout. No production records or credentials are replaced.

## Changes

| File | Change |
|---|---|
| `backend/app/platform/forensics.py` | MIME part metadata, separate plain/HTML text, Received-SPF evidence, detailed IP classes, display-name impersonation indicators, and local URL signals. |
| `backend/app/platform/authentication.py` | New helper within the existing forensic pipeline: original-byte DKIM verification, SPF DNS policy inspection and qualified DMARC assessment. |
| `backend/app/platform/intelligence.py` | Local DNS/GeoIP independent of external lookups, exact TXT concatenation, failure statuses, City/ASN independence, bounded reputation signals and AbuseIPDB summaries. |
| `backend/app/platform/pipeline.py` | Connects local authentication/enrichment; retains real model outputs; adds explained review categories; limits repeated claims from the same provider. |
| `backend/app/platform/store.py`, `api.py` | Default providers are VirusTotal, AbuseIPDB and local GeoIP; existing saved configurations are preserved; masking includes newly extracted message text. |
| `backend/app/platform/reports.py` | Includes threat category and its basis in the existing report structure. |
| `app/components/Platform.tsx`, `NetworkMap.tsx` | Existing tabs display local authentication, MIME/HTML source, IP/domain/URL evidence and category. Settings explain the independent DNS and external-enrichment controls. |
| `backend/requirements.txt` | Adds only `dkimpy==1.1.8`. Existing dnspython, geoip2, email/URL parsing, hashing and ML dependencies are reused. |
| `backend/tests/` | Isolated synthetic `.eml` fixtures, regression checks and opt-in real MongoDB/Redis/Celery integration check. No fixtures enter production. |
| `.env.example`, `README.md`, `docs/IMPLEMENTATION.md`, `docs/DELIVERY.md` | Updated configuration, behavior and limitations. |

Redis was installed with Homebrew for local broker verification. No new reputation or geolocation API was added. Existing URLScan/GreyNoise adapters remain available only for compatibility; they are not required and new default configurations do not enable them.

## Configuration and behavior

Required application settings remain `MONGODB_URI`, `MONGODB_DB_NAME`, `JWT_SECRET`, `EVIDENCE_ENCRYPTION_KEY` and the existing cookie/CORS settings. Celery mode uses `REDIS_URL` and `WORKER_MODE=celery`.

Optional enrichment:

```dotenv
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
GEOIP_CITY_DB=/absolute/path/GeoLite2-City.mmdb
GEOIP_ASN_DB=/absolute/path/GeoLite2-ASN.mmdb
```

Leave missing GeoIP paths empty. Either database works independently. No GeoIP API key is needed. Obtain current GeoLite2 files through MaxMind's legitimate distribution process; none are fabricated or bundled.

In **Settings**, DNS enables DNS policy lookups and DKIM public-key retrieval. Automatic enrichment enables external indicator-only reputation requests. These controls are independent; both are off by default. Local URL/header analysis always runs. GeoIP runs when its provider is enabled and a local database is available, even with external enrichment disabled. No message body/file is submitted, no attachment executed, and no suspect URL or redirect visited.

The response retains the existing `analysis.forensics`, `analysis.intelligence`, `analysis.signals` and risk `contributions`. New data lives under `forensics.authentication.*`, `forensics.mime`, `forensics.ip_analysis`, URL `signals`, plus `analysis.category`, `category_basis` and `confidence` (the actual model class probability only when its label agrees with the analysis verdict). There is no competing response schema.

## Authentication and reputation limits

- DKIM verifies RSA-SHA256 against preserved original bytes and current DNS keys using dkimpy. It checks at most five signatures with bounded DNS requests. DNS errors, absent keys and unsupported algorithms produce unavailable results, not invented failures. Older messages may reference rotated keys; a valid signature does not make the content benign.
- SPF records and Received-SPF are inspected and preserved, but an uploaded `.eml` does not establish a trusted SMTP peer and envelope sender. Independent SPF authorization therefore remains unknown.
- DMARC can pass through a locally verified aligned DKIM signature and a valid current DNS policy. SPF unknown is never converted into DMARC FAIL. Policy and supplied Authentication-Results remain separate evidence.
- URL/TLD/keyword/display-name flags are heuristics. TLDs in the static review list are not a real-time reputation feed. No organization ownership or human location is inferred.
- One VirusTotal/AbuseIPDB claim contributes at most 35% of the configured intelligence category budget. Repeated hits from the same provider do not count as independent corroboration. Engine outcomes and abuse-report counts are retained as evidence.
- Live VirusTotal/AbuseIPDB credentials were not exercised by these checks. Failure behavior is checked with isolated HTTP transports, not fake production results. No real GeoLite2 database is configured on this machine, so actual geographical coverage is not claimed.

## Checks and observed model behavior

The subsequent [scoring and geolocation correction](SCORING_FIX.md) documents the current 33-check run and scoring version 2.0. Results below describe the earlier local-stack implementation.

Verified on 2026-09-19:

- Offline backend suite: **19 passed**, with the opt-in integration check skipped.
- Real MongoDB/Redis/Celery run: **18 passed** (17 regression checks plus the integration workflow; the two additional GeoIP checks passed in the subsequent offline run).
- All five uploaded fixtures completed their real queued analysis. Original bytes, encrypted evidence, hashes, graph, case, PDF/JSON reports and session revocation were checked successfully.
- Frontend TypeScript, ESLint and production webpack build passed. The build generated all 25 static pages. No separate frontend test suite is configured.

The checks cover benign, phishing, BEC, impersonation and suspicious-URL `.eml` inputs; true DKIM signing/verification and tampering; untrusted Authentication-Results; DNS TXT concatenation/timeouts; missing keys; private-IP restrictions; provider 401/403/429/500/timeouts/malformed responses; unavailable GeoIP; ASN-only output without invented coordinates; and all enrichment disabled.

The opt-in integration check uses real MongoDB and a separate Redis broker/worker. It uploads each fixture through the API, verifies persisted job stages and actual ML probabilities, compares original downloaded bytes and SHA-256, checks encrypted storage, creates a case and generates both 26-section PDF and JSON exports. Fixture labels describe test scenarios, not asserted model predictions.

The existing baseline correctly labels the benign and phishing examples. It labels the synthetic BEC fixture PHISHING (probability about 0.499) and the suspicious-URL fixture BENIGN (about 0.494). Those model predictions remain unchanged. The subsequent [scoring correction](SCORING_FIX.md) adds explicit correlation rules: the combined BEC analysis can differ from the model, with its rule basis shown and no invented confidence. No new accuracy claim or model retraining is made.

Run offline regression checks:

```bash
PYTHONPATH=backend backend/venv/bin/python -m unittest discover -s backend/tests -v
```

The external-service integration check is opt-in and skipped by this command. To reproduce it, use a separate Redis instance on port 16379 and run a Celery worker and the check with the environment below (worker in its own terminal):

```bash
mkdir -p tmp
redis-server --bind 127.0.0.1 --port 16379 --save '' --appendonly no --dir "$PWD/tmp"
```

```bash
MONGODB_DB_NAME=mailtrace_local_stack_validation DATA_DIR="$PWD/data/local-stack-validation" \
REDIS_URL=redis://127.0.0.1:16379/0 WORKER_MODE=celery PYTHONPATH=backend \
backend/venv/bin/celery -A app.workers.celery_app:celery worker --pool=solo --concurrency=1
```

```bash
MAILTRACE_INTEGRATION=1 MONGODB_DB_NAME=mailtrace_local_stack_validation \
DATA_DIR="$PWD/data/local-stack-validation" REDIS_URL=redis://127.0.0.1:16379/0 \
WORKER_MODE=celery PYTHONPATH=backend \
backend/venv/bin/python -m unittest discover -s backend/tests -v
```

Frontend checks:

```bash
cd app
npx --no-install tsc --noEmit
npm run lint
npm run build -- --webpack
```

## Exact local startup

From the repository root, with local MongoDB running (or `MONGODB_URI` configured):

```bash
backend/venv/bin/python -m pip install -r backend/requirements.txt
npm --prefix app ci
backend/venv/bin/python scripts/setup.py --create-admin --admin-email admin@mailtrace.ai
mkdir -p data/redis
```

The setup command preserves an existing administrator and private `.env`. For a fresh checkout, create `backend/venv` first with `python3 -m venv backend/venv`. The existing trained artifacts remain under `ml/artifacts`; the selected baseline requires no neural runtime dependencies.

Run each command in a separate terminal, from the repository root:

```bash
redis-server --bind 127.0.0.1 --port 6379 --appendonly yes --dir "$PWD/data/redis"
```

```bash
WORKER_MODE=celery REDIS_URL=redis://127.0.0.1:6379/0 \
backend/venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --no-access-log
```

```bash
WORKER_MODE=celery REDIS_URL=redis://127.0.0.1:6379/0 PYTHONPATH=backend \
backend/venv/bin/celery -A app.workers.celery_app:celery worker --beat --pool=solo --concurrency=1 --loglevel=INFO --schedule="$PWD/data/celerybeat-schedule"
```

```bash
BACKEND_URL=http://127.0.0.1:8000 npm --prefix app run dev -- --hostname 127.0.0.1 --port 3000
```

Open `http://127.0.0.1:3000`; API docs are at `http://127.0.0.1:8000/docs`. Stop processes with Ctrl+C. Run only one beat scheduler. The root README also documents a simpler `WORKER_MODE=local` setup without Redis and the authenticated Docker stack. Docker startup/build was not rerun as part of this follow-up.

The dkimpy behavior and DNS timeout APIs follow the [dkimpy package documentation](https://pypi.org/project/dkimpy/) and [dnspython resolver documentation](https://dnspython.readthedocs.io/en/stable/resolver-class.html).

The subsequent [IP/GeoIP pipeline update](IP_GEOIP_PIPELINE.md) adds complete source/destination mail paths, IPv6 and per-hop results. Local GeoIP now covers every observed public IP independently of the 25-indicator external reputation/DNS budget.
