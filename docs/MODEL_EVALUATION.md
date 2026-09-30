# Model evaluation graphs

Run from the repository root:

```bash
backend/venv/bin/python -m pip install -r ml/requirements-evaluation.txt
backend/venv/bin/python ml/evaluation/model_graphs.py
```

The evaluator uses the existing `MLService.predict` implementation on every email in the frozen train, validation and test splits. It neither retrains nor selects a deployed model. It verifies the concatenated dataset fingerprint, class counts, label mapping and disjoint content/group IDs. Per-model artifact hashes and per-split prediction CSV hashes accompany the outputs. Matching caches can be reused; changing model weights, metadata, split files or inference code invalidates them.

## Outputs

`ml/evaluation/plots/{transformer,bilstm,cnn}/` contains:

- `loss_curves.png` and `accuracy_curves.png`: only the recorded epoch measurements; missing series are explicitly disclosed.
- `confusion_matrix.png`: validation and test confusion matrices with counts.
- `precision_recall_f1.png`: per-class test metrics, retaining all four trained classes.
- `roc_auc.png` and `roc_points.csv`: class-probability one-vs-rest ROC curves for validation and test.
- `checkpoint_fit.png`: current saved checkpoint accuracy, macro-F1 and mean log loss on all three splits. These are not historical epoch measurements.
- `metrics.json`, `metrics.csv`, `per_class_metrics.csv`: actual scores, support, provenance and limitations.
- `training_history.json` and `training_history.csv`: recorded history; missing observations remain JSON null / empty CSV cells.
- `{train,validation,test}_predictions.csv`: content identifiers, true/predicted labels and all four class probabilities. Email text is not exported.

The top-level `model_comparison.csv`, `.json`, `.png` and `README.md` compare held-out test metrics. Precision, recall and F1 use macro averaging across BENIGN, PHISHING, BEC and SPAM. AUC is macro one-vs-rest, calculated from probabilities; absent positive/negative examples make that class's AUC unavailable.

The evaluator checks whether an ensemble artifact exists and reports its actual status in `plots/ensemble/status.json`. A learned ensemble can be fitted with `ml/training/train_ensemble.py`: its convex voting weights are learned from training predictions of frozen members, with the best checkpoint selected on validation macro-F1. Members are bundled and hash-verified at inference. The trained transformer is `prajjwal1/bert-tiny`, not DistilBERT.

## Fit interpretation

The current checkpoint is evaluated on both train and validation data. Test results are never used to select a fit label or best epoch. The default screening policy is explicit and configurable:

- **Overfitting indication:** training macro-F1 is at least 0.80 and exceeds validation macro-F1 by at least 0.05.
- **Underfitting indication:** both training and validation macro-F1 are below 0.80.
- **Good/Normal Fit indication:** both scores reach 0.80 and their absolute difference is below 0.05.
- Other patterns are **Inconclusive**.

These thresholds are heuristic policy choices, not validated performance guarantees. Adjust them with `--gap-threshold` and `--adequate-f1`. Inspect per-class scores, support, loss and dataset limitations as well. Within-corpus scores and synthetic BEC data do not establish real-world generalization. “Normal Fit” does not mean the model has converged or is the best available model.

Best epoch is the first epoch with maximum recorded validation macro-F1, matching the existing checkpoint selection rule.

## Missing historical measurements

The existing three-epoch models recorded summed weighted batch training loss and validation metrics. They did **not** record training accuracy or validation loss. Summed optimizer loss is not comparable to mean validation log loss. Those past curves cannot be recovered from a single best checkpoint, and this implementation does not backfill them with current predictions.

Future runs of `ml/training/train_deep.py` save JSON/CSV history after each epoch, including training and validation accuracy, macro-F1 and comparable unweighted per-email log loss in eval mode. The original weighted optimizer loss sum remains a separate field. This adds a full training-split evaluation pass per epoch and therefore increases training time. Training uses the same optimizer, chunk sampling and validation-based checkpoint selection as before. Current trained artifacts are not overwritten by the evaluator.

## Regularized candidate training

The trainer exposes dropout, word dropout, weight decay, label smoothing, vocabulary size, architecture size and sequence length as explicit recorded settings. Validation macro-F1 controls early stopping (`--patience`). Use `--skip-test` while tuning; after locking a candidate, `ml/evaluation/finalize_artifact.py --artifact PATH` measures its held-out test performance without changing its weights. Candidate runs should use separate output directories. A smaller train/validation gap alone does not justify deploying a model whose validation performance has deteriorated.

Ensemble weight fitting uses in-sample predictions of already-trained base models, not out-of-fold stacking. Its training score can therefore be optimistic. Validation selects the mixing checkpoint and the frozen test split is used only for final reporting. Current test data has already been used for prior project evaluation; it is held out from training, not a newly collected external benchmark.
