# Measured model comparison

All four candidates were trained on the same prepared corpus and fixed grouped splits. The production choice uses **validation macro-F1 only**. Test results below describe this historical corpus, not expected accuracy on current enterprise mail.

| Candidate | Validation macro-F1 | Test macro-F1 | Test accuracy | Test BEC F1 |
|---|---:|---:|---:|---:|
| baseline | 0.9567 | 0.9554 | 0.9923 | 1.0000 |
| cnn | 0.9242 | 0.9269 | 0.9900 | 0.9831 |
| bilstm | 0.9086 | 0.9237 | 0.9875 | 1.0000 |
| transformer | 0.8295 | 0.8256 | 0.9795 | 0.9524 |

The selected model is TF-IDF (60,000 unigram/bigram features) with class-balanced logistic regression, selected across C values 0.5, 2 and 8. Its coefficients provide actual per-term logit contributions. CNN uses 128-dimensional embeddings and convolution widths 3/4/5. BiLSTM uses bidirectional recurrent encoding. The transformer is a fine-tuned `prajjwal1/bert-tiny` checkpoint, a compact pretrained BERT, not a full-size BERT benchmark. Each neural family was trained for three epochs with seed 42; the best validation epoch was retained. Neural inference averages chunk probabilities for long messages.

Dataset version: `86163c10613ec3805728889e847359c220b438a33bf84252007a4bb3c99555dd`.

The prepared corpus contains 32,010 messages: 22,422 training, 4,797 validation and 4,791 test messages. BEC test support is only 30 messages and originates from a human-reviewed synthetic corpus; the SPAM test support is 72 messages. Small minority classes, historical sources and source-specific artifacts limit the strength of these measurements. Probabilities have not been independently calibrated. See [dataset details](DATASETS.md).

Actual artifacts, full precision/recall/F1 by class, confusion matrices, training history and manifest are stored under `ml/artifacts/{baseline,cnn,bilstm,transformer}`. `production/selection.json` records the cross-family selection. These local artifacts and datasets are deliberately excluded from Git. Reproduce them with the commands in the root README, or distribute trusted artifacts separately.

Administrators can select any installed candidate in Settings and save system policy. API and worker processes detect changes to the selected model and metadata. Install `ml/requirements-deep.txt` locally, or build Docker with `INSTALL_DEEP=true`, before serving neural candidates. Missing artifacts/dependencies are reported as Model unavailable rather than substituted with fake output.
