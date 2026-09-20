# Scoring and workflow corrections — 2026-09-20

## Scoring policy 2.1

The reported Bradesco/Livelo email had a PHISHING model probability of 0.7660587501958921 but only 12.11 weighted evidence points. With AI capped at 15 points, model-only phishing could never reach the default MEDIUM threshold of 30. The UI calculation was accurate, but the policy understated review priority.

With AI enabled, a PHISHING or BEC prediction now requires at least the configured MEDIUM score. A predicted class probability of 70% or above requires at least the configured HIGH score. Defaults are 30 and 60. This is an explicit review policy, not a calibrated estimate of harm. It does not change model probabilities or invent forensic evidence. SPAM and BENIGN predictions do not receive this adjustment. Setting the AI weight to zero explicitly disables the model minimum.

The final score is the rounded maximum of weighted evidence, the strongest correlation minimum, and the model review minimum. Contribution rows account for each additional point exactly once. The Bradesco example becomes 12.11 evidence points plus 47.89 model review points: **60/100 HIGH**. Stronger correlation rules still take precedence. Each result stores its scoring weights and thresholds. UI and newly generated reports explain the policy adjustment and required review.

## Other corrections

- Lookalike URLs no longer also contribute sender-identity points unless the sender or Reply-To itself is a lookalike. Older stored evidence is handled correctly during rescoring.
- Quoted `smtp.mailfrom` values no longer produce domains containing a trailing quote or incorrect relaxed SPF alignment.
- Distinct HTML text is included in model input alongside plain text, preventing a harmless plain-text MIME alternative from hiding a different HTML message. Identical alternatives are not duplicated. The model input size limit covers both representations. HTML remains an inert preview.
- Leading/trailing whitespace around HTML links no longer prevents extraction.
- Expired worker leases update the associated email/report to Failed so the UI can stop displaying a permanently running job.
- Reanalysis refreshes existing alert severity and reasons while preserving analyst-managed acknowledgement/resolution.
- Unavailable checks, scoring contribution bars, rounding, and policy adjustments remain explicit in the risk panel.

## Existing analyses

`PYTHONPATH=backend backend/venv/bin/python -m app.platform.rescore` previews results. Add `--apply` to update idle completed analyses, or `--email-id ID` to restrict the operation. The migration is idempotent by scoring version, checks for concurrent analysis replacement, stores previous scoring fields in `scoring_history`, and audits each update. It refreshes email list scores, case maximum scores, and existing alerts. It does not retrain/run models, call providers, modify original email evidence, or overwrite generated report snapshots. Parser changes take effect on a full reanalysis; rescoring intentionally preserves the saved model prediction and forensic observations.

## Verification scope and limits

Final results: all **57 backend tests passed**, including the live isolated integration workflow, and all **6 React component tests passed**. Full ESLint, TypeScript, the production webpack build, Python dependency consistency, and `git diff --check` passed. The applied migration updated 17 completed analyses; five numeric scores changed. Original evidence hashes and saved model/forensic payloads matched before and after for all 17. The reported Bradesco record is persisted as 60/HIGH, version 2.1. No eligible old-version records remained after migration. The test browser reached the sign-in screen, so authenticated visual verification was not completed.

The regression suite covers the exact reported class probabilities, the 70% boundary, BEC, custom severity thresholds, disabled AI, model unavailability, correlation precedence, URL double-counting, MIME alternatives, and SPF quoting. Component tests render the real React scoring component. Integration uses isolated MongoDB, Redis, and Celery for upload, model inference, GeoIP, reanalysis, original-byte/hash verification, encrypted storage, graphs, cases, PDF/JSON generation, scoring migration, expired jobs, alert refresh, authentication, CSRF rejection, and malformed uploads.

No external reputation API credentials were exercised by these tests. The existing classifier can still make false-positive and false-negative predictions; the synthetic spam fixture remains classified BENIGN. This change improves parsing and review policy, not classifier accuracy. The English correlation rules are not a multilingual detector. No verification can certify the absence of every possible software defect.

Commands:

```bash
PYTHONPATH=backend backend/venv/bin/python -m unittest discover -s backend/tests -v
cd app
node --test tests/risk-breakdown.test.mjs
npx --no-install tsc --noEmit
npm run lint
npm run build -- --webpack
```

For the isolated worker setup and integration environment variables, see [LOCAL_STACK.md](LOCAL_STACK.md).
