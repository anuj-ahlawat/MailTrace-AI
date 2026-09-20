# Delivery reference

This document maps the requested completion summary to the implemented application. The core end-to-end workflow is connected; credential-dependent services and deployment validation limits are identified explicitly.

| Requested item | Delivery |
|---|---|
| 1. Implementation | Email/CSV/Gmail ingestion → encrypted evidence → passive forensics → real ML → optional intelligence → transparent risk → graph → case → PDF/JSON. |
| 2. Architecture | Next.js/React → FastAPI/Pydantic → MongoDB; local dispatcher or Celery/Redis; filesystem encryption and local model artifacts. |
| 3. Files | Production modules in `backend/app/platform/`, `backend/app/ml/`, `backend/app/workers/`; frontend `app/components/` and dashboard routes; `ml/`, `docker/`, `scripts/`, `.env.example`, root README. See IMPLEMENTATION.md for file descriptions. |
| 4. Collections | users, sessions, emails, email_analysis, jobs, evidence, cases, iocs, threat_intelligence, campaigns, alerts, audit_logs, reports, system_settings, provider_secrets, rate_limits, gmail_connections, oauth_states. |
| 5. APIs | Auth/users, email ingestion/analysis/jobs, forensics, intelligence/IOCs, graphs/campaigns, cases/notes/evidence, reports, alerts, dashboard/search, audit/settings and Gmail. Generated reference: `/docs`. |
| 6. Routes | Login, overview/dashboard, analyze, emails/detail, cases/investigations/detail, evidence, intelligence, geolocation/route-trace, graph/campaign-graph, alerts, reports, Gmail, account, settings and admin users/audits. |
| 7. Models | Actually trained TF-IDF/logistic, CNN, BiLSTM and pretrained compact BERT. Validation-selected baseline is deployed. All artifacts can be selected in Settings. |
| 8. Data pipeline | Canonical records, real label mapping, exact deduplication/conflict removal, thread/subject/near-duplicate grouping, seeded 70/15/15 target split; 32,010 accepted records. |
| 9. Intelligence | Optional VirusTotal/AbuseIPDB, local MaxMind, DNS/PTR and dkimpy; URLScan/GreyNoise remain legacy opt-in adapters; timeouts, caches, source/time/status and isolated failures. |
| 10. Forensics | MIME/headers, reported auth and alignment, sender mismatches/lookalikes, chronological Received chain, qualified origin candidate, safe URL extraction, attachment hashes/metadata, observed indicators. |
| 11. Geolocation | Provider-only coordinates, accuracy radius, country/city/ASN where available, map and country/ASN aggregation. No inferred human location. |
| 12. Graphs | Observed email/sender/domain/IP/URL/hash/ASN/geolocation/provider/DNS relationships; node details; reviewed campaign graphs. |
| 13. Cases | Create/edit, role-constrained status/assignment, notes, email/evidence/indicator attachment, max risk, timeline, campaign rationale and audit events. |
| 14. Reports | Background case snapshots in PDF and JSON; all 26 required sections, hashes, provenance, custody and limitations. |
| 15. Configuration | MongoDB, Redis, JWT, Fernet key, worker mode, cookie/CORS, paths, provider credentials, GeoIP files and optional Gmail OAuth; see `.env.example`. |
| 16. Start | Follow root README for setup/admin provisioning; start Uvicorn and Next.js, or `docker compose up --build -d`. Neural container inference uses `INSTALL_DEEP=true`. |
| 17. External setup | VirusTotal and AbuseIPDB currently show Configured (credential presence only). URLScan and GreyNoise are unnecessary for the default local stack; GeoIP needs local MaxMind database files. Gmail needs OAuth app configuration and user consent. Settings accurately shows credential presence, not verified connectivity. |
| 18. Limits | Docker Compose validates, but Docker build/start was not executed because Docker startup was declined. Live credential-dependent integrations were not end-to-end verified. SPF cannot be independently verified without trusted SMTP context; real local RSA-SHA256 DKIM verification is implemented. No active probing, malware execution sandbox, optional ensemble or human attribution is claimed. |
| 19. Dataset problems | BEC source is human-reviewed synthetic, with only 30 held-out BEC examples; SPAM held-out support is 72. Ambiguous CEAS spam/phishing positives were excluded. One parser failure, short messages and duplicate records were excluded. Source and historical-data bias remain. |
| 20. Migration | Unused prototype removed from the working tree; source remains in Git history and the old database is preserved. Production uses separate `mailtrace_enterprise` with authentic acquisitions only; no seeded records were silently migrated. |

See [implementation reference](IMPLEMENTATION.md), [dataset provenance](DATASETS.md), [measured models](MODELS.md), and [run instructions](../README.md).

The follow-up local-stack changes and actual validation results are documented in [LOCAL_STACK.md](LOCAL_STACK.md).
