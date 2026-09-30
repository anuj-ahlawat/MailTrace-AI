"""Render PPT-ready metrics and a confusion matrix from computed JSON only."""
import csv
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from backend.config import EXPORT_DIR
OUT = EXPORT_DIR / 'model-validation'


def main():
    result = json.loads((OUT / 'validation-results.json').read_text())
    assert result.get('completed_at_utc'), 'Evaluation is not complete'
    selected = result['models'][result['selected_model_key']]
    test = selected['test']; macro = test['report']['macro avg']
    count = result['splits']['test']['count']
    labels = result['labels']; display = ['BENIGN', 'SPAM', 'PHISHING', 'BEC']
    indices = [labels.index(label) for label in display]
    matrix = np.asarray(test['confusion_matrix'])[np.ix_(indices, indices)]
    assert int(matrix.sum()) == count
    assert np.isclose(np.trace(matrix) / count, test['accuracy'])
    names = ['Benign', 'Spam', 'Phishing', 'BEC']
    normalized = matrix / matrix.sum(axis=1, keepdims=True)
    cmap = LinearSegmentedColormap.from_list('mailtrace', ['#f1f6fa', '#9dc5da', '#235d7d', '#12364d'])
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 13, 'svg.fonttype': 'none'})
    fig, ax = plt.subplots(figsize=(9, 7), dpi=300)
    fig.patch.set_facecolor('white')
    fig.subplots_adjust(left=.16, right=.91, bottom=.18, top=.79)
    im = ax.imshow(normalized, vmin=0, vmax=1, cmap=cmap, aspect='equal')
    ax.set_xticks(range(4), names); ax.set_yticks(range(4), names)
    ax.set_xlabel('Predicted class', labelpad=12, fontweight='semibold', color='#17354a')
    ax.set_ylabel('Actual class', labelpad=12, fontweight='semibold', color='#17354a')
    ax.tick_params(axis='both', length=0, pad=10, colors='#17354a')
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xticks(np.arange(-.5, 4, 1), minor=True)
    ax.set_yticks(np.arange(-.5, 4, 1), minor=True)
    ax.grid(which='minor', color='white', linewidth=3)
    ax.tick_params(which='minor', bottom=False, left=False)
    for i in range(4):
        for j in range(4):
            ax.text(j, i, f'{matrix[i,j]:,}', ha='center', va='center', fontsize=22,
                    fontweight='bold' if i == j else 'normal',
                    color='white' if normalized[i,j] >= .55 else '#25485e')
    colorbar = fig.colorbar(im, ax=ax, fraction=.045, pad=.05)
    colorbar.set_ticks([0, .25, .5, .75, 1], labels=['0%', '25%', '50%', '75%', '100%'])
    colorbar.set_label('Share of actual class', labelpad=12, color='#496475', fontsize=11)
    colorbar.outline.set_visible(False); colorbar.ax.tick_params(length=0, labelsize=10)
    fig.text(.5, .93, 'HELD-OUT TEST CONFUSION MATRIX', ha='center', fontsize=19, weight='bold', color='#17354a')
    fig.text(.5, .875, f"{selected['display_name']}  ·  {count:,} test emails", ha='center', fontsize=14, color='#496475')
    fig.text(.5, .055, 'Cells show email counts; colour is normalised within each actual class.\nAll four trained classes are included. No training data is scored here.',
             ha='center', va='center', fontsize=10, color='#496475', linespacing=1.6)
    fig.savefig(OUT / 'confusion-matrix.png', dpi=300, facecolor='white')
    fig.savefig(OUT / 'confusion-matrix.svg', facecolor='white')
    plt.close(fig)
    with (OUT / 'confusion-matrix.csv').open('w', newline='') as stream:
        writer = csv.writer(stream); writer.writerow(['Actual / Predicted', *names])
        writer.writerows([name, *row] for name, row in zip(names, matrix.tolist()))
    ppt = (f"MODEL VALIDATION\nTest Set: {count:,} Emails\nAccuracy: {test['accuracy']*100:.2f}%\n"
           f"Precision (Macro): {macro['precision']*100:.2f}%\nRecall (Macro): {macro['recall']*100:.2f}%\n"
           f"F1-Score (Macro): {macro['f1-score']*100:.2f}%\nBest Model: {selected['display_name']}\n")
    (OUT / 'PPT_READY.txt').write_text(ppt)
    split_table = '\n'.join(f"| {name.title()} | {split['count']:,} | {split['percentage']:.2f}% |" for name, split in result['splits'].items())
    comparison = '\n'.join(f"| {model['display_name']} | {model['test']['accuracy']*100:.2f}% | {model['test']['report']['macro avg']['f1-score']*100:.2f}% |" for model in result['models'].values())
    per_class = '\n'.join(f"| {name.title()} | {test['report'][name]['f1-score']*100:.2f}% | {int(test['report'][name]['support']):,} |" for name in display)
    support_summary = ', '.join(f"{int(test['report'][name]['support']):,} {name.title()}" for name in display)
    cm_table = '\n'.join('| ' + ' | '.join([name, *map(str, row)]) + ' |' for name, row in zip(names, matrix.tolist()))
    match = all(m['matches_recorded_test_confusion_matrix'] for m in result['models'].values())
    timing = selected['inference']
    report = f'''# MailTrace AI — real held-out model validation

Generated {result['completed_at_utc']}. Predictions were recomputed from existing trained artifacts on unchanged test data. No training or threshold tuning was performed. All recomputed confusion matrices match saved test matrices: **{match}**.

## Dataset

Total prepared, deduplicated dataset: **{result['dataset_size']:,} emails**. This is the data actually split for training/evaluation, not the larger raw source archive.

| Split | Emails | Actual proportion |
|---|---:|---:|
{split_table}

Target split: 70% / 15% / 15%; group-preserving allocation produces the exact counts above. Content fingerprints, manifest counts, dataset SHA-256 and cross-split group/hash disjointness were verified.

## Selected model test results

**{selected['display_name']}** was selected using highest **validation macro-F1**, not training or test accuracy. Its validation macro-F1 was freshly reproduced at **{selected['validation_macro_f1']*100:.2f}%**. It also has the highest test accuracy and macro-F1 among the four evaluated artifacts.

| Metric | Test result |
|---|---:|
| Accuracy | {test['accuracy']*100:.2f}% |
| Precision (macro) | {macro['precision']*100:.2f}% |
| Recall (macro) | {macro['recall']*100:.2f}% |
| F1-score (macro) | {macro['f1-score']*100:.2f}% |

Macro averages give each of the **four** classes equal weight. Support-weighted scores, full class precision/recall and unrounded values remain in `validation-results.json`.

| Class | Test F1 | Test emails |
|---|---:|---:|
{per_class}

The project is a four-class classifier. BEC is included in aggregate metrics and the matrix; it is not silently removed to make a three-class result.

## Actual trained-model comparison

| Model | Test accuracy | Test macro-F1 |
|---|---:|---:|
{comparison}

**No trained DistilBERT artifact was found.** The transformer artifact is fine-tuned `prajjwal1/bert-tiny` (`BertForSequenceClassification`, two layers), so its result must be labelled BERT-tiny. Training-script support for DistilBERT does not establish that it was trained.

## Small confusion matrix

Rows are actual labels; columns are predictions. All {count:,} test emails are represented.

| Actual / Predicted | Benign | Spam | Phishing | BEC |
|---|---:|---:|---:|---:|
{cm_table}

![Confusion matrix](confusion-matrix.png)

`confusion-matrix.png` is a 300-DPI, 2700×2100 image with a white background; `confusion-matrix.svg` is the scalable alternative. Cell values are raw counts; shading is row-normalised so minority-class errors remain visible.

## Average inference time

Selected model: **{timing['mean_ms_per_email']:.2f} ms/email** mean, {timing['median_ms_per_email']:.2f} ms median, {timing['p95_ms_per_email']:.2f} ms p95. Measured across all **{timing['sample_count']:,} held-out emails** after {timing['warmup_count']} discarded warm-up predictions.

Scope: {result['inference_timing_scope']}

Environment: {result['environment']['platform']}, {result['environment']['logical_cpu_count']} logical CPUs, four compute threads; Python {result['environment']['python']}, scikit-learn {result['environment']['sklearn']}. Timing is local-machine performance, not an end-to-end application SLA.

## PPT-ready block

```text
{ppt.rstrip()}
```

## Evidence and limitations

- `validation-results.json` contains all fresh results, timings, artifact fingerprints, split fingerprints and the original validation-selection record.
- `*-test-predictions.csv` contains one prediction per held-out row, identified by content hash, with measured latency. Email contents are not exported.
- Test data are imbalanced: {support_summary} messages. The small BEC subset is synthetic, human-reviewed data; its test score does not establish real-world BEC detection performance.
- Dataset grouping/deduplication was checked, but semantic leakage and source artifacts cannot be ruled out. These are held-out results within the supplied historical corpus, not an independent contemporary deployment benchmark.

Reproduce evaluation with `backend/venv/bin/python ml/evaluation/evaluate.py`. Render with `ml/evaluation/confusion_matrix.py` in an environment containing NumPy and Matplotlib. The scripts do not retrain models or change the stored splits.
'''
    (OUT / 'MODEL_VALIDATION.md').write_text(report)
    print(ppt)
    print('Saved:', OUT / 'confusion-matrix.png')


if __name__ == '__main__':
    main()
