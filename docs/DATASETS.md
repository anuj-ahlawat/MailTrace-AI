# Dataset preparation record

These statistics were generated from the actual local files. No sample counts or scores are invented.

- Dataset version: `86163c10613ec3805728889e847359c220b438a33bf84252007a4bb3c99555dd`
- Seed: 42. Target split: 70% / 15% / 15%.
- Enron: seeded reservoir of 10,000 messages from 517401 eligible files; use `--enron-limit 0` to include all.
- Accepted after cleanup: 32010.

| Split | BENIGN | PHISHING | BEC | SPAM | Total |
|---|---:|---:|---:|---:|---:|
| train | 20792 | 1085 | 209 | 336 | 22422 |
| validation | 4455 | 233 | 37 | 72 | 4797 |
| test | 4455 | 234 | 30 | 72 | 4791 |

## Sources and label mapping

| Source | Accepted label mapping | Provenance and limitations |
|---|---|---|
| Enron | BENIGN, as specified for this project | Local raw corpus; historical messages, source release version not supplied |
| SpamAssassin ham/spam | BENIGN / SPAM by supplied subset | Public corpus; legacy distribution, not current enterprise prevalence |
| Nazario | CSV 1 → PHISHING; 0 → BENIGN | Existing dataset labels, not keyword-derived |
| CEAS-08 | 0 → BENIGN; positive rows quarantined | Binary positives mix spam/phishing; not safely separable into the four target labels |
| BEC-2 | Human=positive → BEC; neutral quarantined | Synthetic, human-reviewed corpus; not real victim correspondence |

Source references: [BEC authors](https://github.com/r-dube/bec), [SpamAssassin](https://spamassassin.apache.org/old/publiccorpus/), [Enron](https://www.cs.cmu.edu/~enron/), [Nazario](https://monkey.org/~jose/phishing/).

## Local source fingerprints

- `BEC/BEC-2-human.csv`: SHA-256 `ae818988b4fce7d25a8d02ac46825e4ca80f39b1b0d770017e82f4fd3463064c`.
- `phishing/Nazario.csv`: SHA-256 `b8fbc4158fbdfaff1ed98584c43d72e283c6352d7ade4d457d34c1d79488d184`.
- `phishing/CEAS_08.csv`: SHA-256 `22375e7d5f5a8229dbe987914ee9b3705656c590038662a7df6054629b376074`.

## Preparation and leakage controls

MIME and raw messages normalize to the canonical schema in `ml/prepare.py`; CSV field names are case-normalized. Labels come from the documented subset or explicit label field. No keywords produce BEC labels. Unknown/ambiguous rows are quarantined. Raw/HTML content remains traceable to the source path.

Exact normalized-content hashes are deduplicated; conflicting labels are excluded. Message-ID, References/In-Reply-To and normalized subjects group related threads. 64-bit SimHash with four LSH bands groups near-duplicates within three bit differences. Connected groups are assigned through 20 shuffled stratified group folds: 14 training, three validation and three test folds. Vocabulary/model fitting never sees validation/test data. The training runner verifies that content hashes and group IDs do not overlap.

Observed cleanup counts:

- parse failure: 1
- empty or short: 12
- ambiguous label: 21845
- exact duplicates: 380
- conflicting content hashes: 0
- near duplicate links: 420

Grouping is conservative but approximate: semantic paraphrases and unknown campaign affiliations may remain. Source-specific language and synthetic BEC style can inflate internal performance. Only 30 BEC messages are in the held-out split. External contemporary data and independent analyst review are required before operational performance claims.

## Reproducible artifacts

`ml/artifacts/dataset/manifest.json` records counts, source references, split distribution and dataset version. `quarantine.json` records CSV source rows and original ambiguous labels. Split JSONL files retain the canonical fields and source metadata. These files contain email content and are ignored by Git. Model metrics are generated under each candidate artifact, and `production/selection.json` records validation-based selection.
