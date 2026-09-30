"""Evaluate saved checkpoints and render reproducible, evidence-backed fit plots.

Run from any directory: python /path/to/ml/evaluation/model_graphs.py
No training, provider calls, database access, or model selection is performed.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('HF_HUB_OFFLINE', '1')
os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')
os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')

import numpy as np
import torch
from backend.config import DATASETS_DIR, MODEL_DIR
from backend.detection.inference import MLService, LABELS
from ml.evaluation.fit_metrics import probability_metrics, fit_assessment, history_rows
from ml.evaluation.predict_batch import predict_many

NAMES = {'transformer': 'Transformer', 'bilstm': 'BiLSTM', 'cnn': 'CNN', 'ensemble': 'Ensemble'}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save_json(path, value):
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    temp.replace(path)


def save_csv(path, rows, fields):
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def load_data(directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    combined = hashlib.sha256()
    splits, hashes = {}, {}
    for split in ('train', 'validation', 'test'):
        path = directory / (split + '.jsonl')
        rows = []
        with path.open('rb') as stream:
            for line in stream:
                combined.update(line)
                row = json.loads(line)
                if row['split'] != split or LABELS[row['label_id']] != row['label']:
                    raise ValueError('Invalid split or label mapping')
                rows.append(row)
        splits[split] = rows
        hashes[split] = digest(path)
        counts = {label: sum(r['label'] == label for r in rows) for label in LABELS}
        if counts != manifest['class_distribution'][split]:
            raise ValueError('Dataset counts differ from manifest')
    if combined.hexdigest() != manifest['dataset_version']:
        raise ValueError('Frozen dataset fingerprint mismatch')
    for a, b in (('train', 'validation'), ('train', 'test'), ('validation', 'test')):
        for field in ('content_hash', 'group_id'):
            if {r[field] for r in splits[a]} & {r[field] for r in splits[b]}:
                raise ValueError('Cross-split overlap: ' + field)
    return manifest, splits, hashes


def evaluate_split(service, rows, path, provenance):
    """Reuse only a cache matching all artifact/data fingerprints and record IDs."""
    sidecar = path.with_suffix('.provenance.json')
    if path.exists() and sidecar.exists():
        cached = json.loads(sidecar.read_text())
        if cached.get('inputs') == provenance and cached.get('csv_sha256') == digest(path):
            with path.open(newline='') as stream:
                records = list(csv.DictReader(stream))
            if len(records) == len(rows) and all(record['content_id'] == row['id'] and
                    record['true_label'] == LABELS[row['label_id']] for record, row in zip(records, rows)):
                print('Verified cached predictions:', path.parent.name, path.stem, flush=True)
                return np.array([[float(r['p_' + label]) for label in LABELS] for r in records])
    probabilities = []
    temporary = path.with_suffix('.csv.tmp')
    with temporary.open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['content_id', 'true_label', 'predicted_label', *['p_' + label for label in LABELS]])
        for start in range(0,len(rows),256):
            batch=rows[start:start+256]
            values=predict_many(service,[row['model_text'] for row in batch])
            for row,p in zip(batch,values):
                probabilities.append(p)
                writer.writerow([row['id'],LABELS[row['label_id']],LABELS[int(np.argmax(p))],*map(float,p)])
            if start//256%4==0:
                print(f'{path.parent.name} {path.stem}: {start+len(batch)}/{len(rows)}',flush=True)
    values = np.asarray(probabilities)
    probability_metrics([r['label_id'] for r in rows], values)  # Validate before accepting cache.
    temporary.replace(path)
    save_json(sidecar, {'inputs': provenance, 'csv_sha256': digest(path)})
    return values


def render_model(out, name, history, results, predictions, splits, assessment):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 10})

    def finish(fig, filename, title, note=''):
        fig.suptitle(name + ' · ' + title, fontsize=15, fontweight='bold')
        if note:
            fig.text(.5, .02, note, ha='center', fontsize=8, color='#475569')
        fig.tight_layout(rect=(0, .07, 1, .94))
        fig.savefig(out / filename, dpi=180, facecolor='white')
        plt.close(fig)

    epochs = [r['epoch'] for r in history]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.7))
    for ax, key, title, color in zip(axes, ('training_log_loss', 'validation_log_loss'),
                                   ('Training loss', 'Validation loss'), ('#2563eb', '#dc6b19')):
        values = [r[key] for r in history]
        ax.set_title(title)
        if values and all(v is not None for v in values):
            ax.plot(epochs, values, 'o-', color=color)
            ax.set_ylabel('Mean per-email log loss (eval mode)')
        elif key == 'training_log_loss' and history and all(r['training_loss_sum'] is not None for r in history):
            ax.plot(epochs, [r['training_loss_sum'] for r in history], 'o-', color=color)
            ax.set_ylabel('Recorded sum of weighted batch losses')
            ax.set_title('Training loss · legacy summed objective')
        else:
            ax.text(.5, .5, 'Not recorded during training\nCannot reconstruct missing epoch losses',
                    ha='center', va='center', transform=ax.transAxes)
        ax.set_xlabel('Epoch')
        ax.set_xticks(epochs)
        ax.grid(alpha=.2)
    complete_loss = bool(history) and all(r['training_log_loss'] is not None and r['validation_log_loss'] is not None for r in history)
    finish(fig, 'loss_curves.png', 'Training / validation loss',
           'Comparable per-email losses measured after each epoch.' if complete_loss else
           'Incomplete history: summed optimizer loss is not comparable to mean validation log loss. No values imputed.')

    fig, ax = plt.subplots(figsize=(8, 4.8))
    missing = []
    for key, label, color in (('training_accuracy', 'Train', '#2563eb'), ('validation_accuracy', 'Validation', '#dc6b19')):
        values = [r[key] for r in history]
        if values and all(v is not None for v in values):
            ax.plot(epochs, values, 'o-', label=label, color=color)
        else:
            missing.append(label + ' accuracy not recorded')
    ax.set(xlabel='Epoch', ylabel='Accuracy', ylim=(0, 1.03), xticks=epochs)
    if ax.lines:
        ax.legend()
    ax.grid(alpha=.2)
    finish(fig, 'accuracy_curves.png', 'Training / validation accuracy', '; '.join(missing) or 'Measured after each epoch in eval mode.')

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for ax, split in zip(axes, ('validation', 'test')):
        matrix = np.asarray(results[split]['confusion_matrix'])
        ax.imshow(matrix, cmap='Blues')
        ax.set(xticks=range(4), yticks=range(4), xticklabels=LABELS, yticklabels=LABELS,
               xlabel='Predicted label', ylabel='True label', title=f'{split.title()} · {matrix.sum():,} emails')
        for i in range(4):
            for j in range(4):
                ax.text(j, i, str(matrix[i, j]), ha='center', va='center',
                        color='white' if matrix[i, j] > matrix.max() / 2 else '#172b4d')
    finish(fig, 'confusion_matrix.png', 'Held-out confusion matrices')

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(4)
    for i, (key, label, color) in enumerate((('precision', 'Precision', '#2563eb'), ('recall', 'Recall', '#14a38b'), ('f1-score', 'F1', '#dc6b19'))):
        values = [results['test']['report'][label_name][key] for label_name in LABELS]
        ax.bar(x + (i - 1) * .25, values, .25, label=label, color=color)
    ax.set(xticks=x, xticklabels=LABELS, ylim=(0, 1.08), ylabel='Score')
    ax.legend(loc='lower left')
    ax.grid(axis='y', alpha=.2)
    finish(fig, 'precision_recall_f1.png', 'Test precision / recall / F1', 'All four trained classes are retained, including BEC.')

    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    curve_rows = []
    for ax, split in zip(axes, ('validation', 'test')):
        y = np.asarray([r['label_id'] for r in splits[split]])
        for i, label in enumerate(LABELS):
            auc = results[split]['auc_per_class_ovr'][label]
            if auc is None:
                continue
            fpr, tpr, thresholds = roc_curve(y == i, predictions[split][:, i])
            ax.plot(fpr, tpr, label=f'{label}: {auc:.4f}')
            curve_rows.extend({'split': split, 'class': label, 'fpr': float(f), 'tpr': float(t),
                               'threshold': float(v) if np.isfinite(v) else None}
                              for f, t, v in zip(fpr, tpr, thresholds))
        ax.plot([0, 1], [0, 1], '--', color='#94a3b8')
        ax.set(title=split.title(), xlabel='False positive rate', ylabel='True positive rate', xlim=(0, 1), ylim=(0, 1.02))
        ax.legend(fontsize=8, loc='lower right')
    finish(fig, 'roc_auc.png', 'One-vs-rest ROC curves', 'AUC uses continuous class probabilities, not predicted class labels.')
    save_csv(out / 'roc_points.csv', curve_rows, ['split', 'class', 'fpr', 'tpr', 'threshold'])

    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    split_names = ['train', 'validation', 'test']
    for key, label, offset in [('accuracy', 'Accuracy', -.16), ('f1_macro', 'Macro-F1', .16)]:
        axes[0].bar(np.arange(3) + offset, [results[s][key] for s in split_names], .32, label=label)
    axes[0].set(xticks=range(3), xticklabels=split_names, ylim=(0, 1.08), ylabel='Score')
    axes[0].legend(loc='lower left')
    axes[1].bar(split_names, [results[s]['log_loss'] for s in split_names], color=['#2563eb', '#dc6b19', '#14a38b'])
    axes[1].set(ylabel='Mean per-email log loss')
    finish(fig, 'checkpoint_fit.png', assessment['status'],
           'Current saved checkpoint only; this is not an epoch history. Fit diagnosis uses train/validation macro-F1.')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--data', type=Path, default=DATASETS_DIR / 'splits')
    ap.add_argument('--artifacts', type=Path, default=MODEL_DIR.parent)
    ap.add_argument('--out', type=Path, default=Path(__file__).resolve().parent / 'plots')
    ap.add_argument('--gap-threshold', type=float, default=.05)
    ap.add_argument('--adequate-f1', type=float, default=.80)
    args = ap.parse_args()
    if not 0 < args.gap_threshold <= 1 or not 0 < args.adequate_f1 <= 1:
        ap.error('Fit thresholds must be in (0, 1]')
    args.out.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault('MPLCONFIGDIR', str(ROOT / 'storage/temp/matplotlib'))
    os.environ.setdefault('XDG_CACHE_HOME', str(ROOT / 'storage/temp/cache'))
    torch.set_num_threads(4)
    manifest, splits, hashes = load_data(args.data)
    print('Verified frozen splits:', {k: len(v) for k, v in splits.items()}, flush=True)
    comparison = []
    for key, display in NAMES.items():
        out = args.out / key
        out.mkdir(parents=True, exist_ok=True)
        directory = args.artifacts / key
        if not (directory / 'metadata.json').exists():
            reason = 'No trained artifact or training history exists in the project.'
            save_json(out / 'status.json', {'model': display, 'status': 'Not trained', 'reason': reason})
            (out / 'README.md').write_text(f'# {display}\n\nNot trained: {reason}\nNo fabricated metrics or curves were generated.\n')
            comparison.append({'model': display, 'accuracy': None, 'precision': None, 'recall': None,
                               'f1': None, 'auc': None, 'best_epoch': None, 'fit_status': 'Not trained'})
            continue
        metadata = json.loads((directory / 'metadata.json').read_text())
        save_json(out/'status.json',{'model':display,'status':'Trained','model_type':metadata['model_type']})
        (out/'README.md').write_text(f'# {display}\n\nActual trained checkpoint evaluation. See `metrics.json` for provenance and fit limitations.\n\n'
            'Plots: `loss_curves.png`, `accuracy_curves.png`, `confusion_matrix.png`, `precision_recall_f1.png`, `roc_auc.png`, `checkpoint_fit.png`.\n')
        if metadata['dataset_version'] != manifest['dataset_version'] or [metadata['label_mapping'][str(i)] for i in range(4)] != LABELS:
            raise ValueError('Artifact dataset/label mapping mismatch: ' + key)
        if key == 'transformer':
            display += ' (' + metadata.get('configuration', {}).get('pretrained', metadata['model_type']) + ')'
        fingerprints = {p.name: digest(p) for p in sorted(directory.iterdir()) if p.is_file()}
        service = MLService(directory)
        if service.status != 'Available':
            raise RuntimeError('Cannot load trained artifact: ' + key)
        history = history_rows(metadata.get('history', []))
        save_json(out / 'training_history.json', {'source': str(directory / 'metadata.json'),
                  'raw_history': metadata.get('history', []), 'epochs': history,
                  'missing_values': 'null means not recorded; never zero or estimated'})
        save_csv(out / 'training_history.csv', history, list(history[0]) if history else ['epoch'])
        results, predictions = {}, {}
        for split, rows in splits.items():
            provenance = {'split_sha256': hashes[split], 'artifact_sha256': fingerprints,
                          'inference_source_sha256': digest(ROOT / 'backend/detection/inference.py'),
                          'batch_inference_sha256': digest(Path(__file__).resolve().parent/'predict_batch.py'),
                          'network_source_sha256': digest(ROOT / 'backend/detection/networks.py'), 'labels': LABELS}
            predictions[split] = evaluate_split(service, rows, out / (split + '_predictions.csv'), provenance)
            results[split] = probability_metrics([r['label_id'] for r in rows], predictions[split])
            print(key, split, 'accuracy', results[split]['accuracy'], 'F1', results[split]['f1_macro'], flush=True)
        assessment = fit_assessment(results['train'], results['validation'], args.gap_threshold, args.adequate_f1)
        epochs = [r for r in history if r['validation_macro_f1'] is not None]
        best = max(epochs, key=lambda r: r['validation_macro_f1'])['epoch'] if epochs else None
        summary = {'model': display, 'dataset_version': manifest['dataset_version'], 'labels': LABELS,
                   'evaluated_at_utc': datetime.now(timezone.utc).isoformat(), 'split_sha256': hashes,
                   'artifact_sha256': fingerprints, 'metrics': results, 'best_epoch': best,
                   'best_epoch_basis': 'First maximum saved validation macro-F1, matching training checkpoint selection',
                   'fit': assessment, 'dataset_limitations': manifest['limitations'],
                   'matches_recorded_test_confusion_matrix': results['test']['confusion_matrix'] == metadata['test']['confusion_matrix'] if metadata.get('test') else None,
                   'history_complete': bool(history) and all(r['training_accuracy'] is not None and r['validation_log_loss'] is not None for r in history)}
        save_json(out / 'metrics.json', summary)
        scalar_keys = ['count', 'accuracy', 'precision_macro', 'recall_macro', 'f1_macro', 'log_loss', 'auc_macro_ovr']
        save_csv(out / 'metrics.csv', [{'split': split, **{k: result[k] for k in scalar_keys}} for split, result in results.items()], ['split', *scalar_keys])
        per_class = [{'split': split, 'class': label, **{k: result['report'][label][k] for k in ('precision', 'recall', 'f1-score', 'support')},
                      'auc_ovr': result['auc_per_class_ovr'][label]} for split, result in results.items() for label in LABELS]
        save_csv(out / 'per_class_metrics.csv', per_class, ['split', 'class', 'precision', 'recall', 'f1-score', 'support', 'auc_ovr'])
        render_model(out, display, history, results, predictions, splits, assessment)
        test = results['test']
        comparison.append({'model': display, 'accuracy': test['accuracy'], 'precision': test['precision_macro'],
                           'recall': test['recall_macro'], 'f1': test['f1_macro'], 'auc': test['auc_macro_ovr'],
                           'best_epoch': best, 'fit_status': assessment['status']})
        del service
    save_json(args.out / 'model_comparison.json', {'metric_split': 'test', 'averaging': 'macro across four classes; AUC one-vs-rest',
              'fit_split': 'train versus validation only', 'models': comparison})
    save_csv(args.out / 'model_comparison.csv', comparison, list(comparison[0]))
    header = '| Model | Accuracy | Precision | Recall | F1 | AUC | Best Epoch | Fit Status |\n|---|---|---|---|---|---|---|---|\n'
    def fmt(value):
        return 'N/A' if value is None else f'{value:.4f}'
    table = header + ''.join('| ' + ' | '.join([row['model'], *[fmt(row[k]) for k in ('accuracy', 'precision', 'recall', 'f1', 'auc')],
                           str(row['best_epoch']) if row['best_epoch'] is not None else 'N/A', row['fit_status']]) + ' |\n' for row in comparison)
    (args.out / 'README.md').write_text('# Actual model evaluation\n\n' + table + '\nMetrics are test-set fractions. Precision, recall and F1 use macro averaging over BENIGN, PHISHING, BEC and SPAM. AUC is macro one-vs-rest.\n\n'
        'Fit labels are configurable checkpoint heuristics based only on train/validation macro-F1; they do not prove generalization or convergence. '
        f'Gap threshold: {args.gap_threshold}; adequate F1 threshold: {args.adequate_f1}. '
        'Any missing legacy history curves are explicitly labelled; current checkpoint scores are never presented as historical epoch scores.\n\n'
        'Predictions contain content hashes and probabilities, never original email bodies. Artifact and split fingerprints accompany the outputs. '
        'Run `backend/venv/bin/python ml/evaluation/model_graphs.py` to reproduce; matching prediction caches are verified before reuse.\n')
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(16, 3.8))
    ax.axis('off')
    cells = [[r['model'].replace(' (', '\n('), *[fmt(r[k]) for k in ('accuracy', 'precision', 'recall', 'f1', 'auc')],
              str(r['best_epoch']) if r['best_epoch'] else 'N/A', r['fit_status'].replace(' indication', '\nindication')] for r in comparison]
    table_plot = ax.table(cellText=cells, colLabels=['Model', 'Accuracy', 'Precision', 'Recall', 'F1', 'AUC', 'Best epoch', 'Fit status'],
                          cellLoc='center', loc='center', colWidths=[.24,.08,.08,.08,.08,.08,.07,.25])
    table_plot.auto_set_font_size(False)
    table_plot.set_fontsize(9)
    table_plot.scale(1, 3)
    ax.set_title('Saved model comparison · test metrics / validation-based fit screening', pad=15)
    fig.text(.5, .03, 'Macro averages over four classes. Fit labels are validation-based heuristics, not proof of generalization.', ha='center', fontsize=9)
    fig.savefig(args.out / 'model_comparison.png', dpi=180, bbox_inches='tight', facecolor='white')
    plt.close(fig)
    print('Complete:', args.out, flush=True)


if __name__ == '__main__':
    main()
