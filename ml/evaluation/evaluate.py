"""Re-evaluate existing local artifacts on unchanged held-out data; never train.

Run with backend/venv/bin/python ml/evaluation/evaluate.py.
Results contain hashes and predictions, never original email text.
"""
import csv
import hashlib
import json
import os
import platform
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
os.environ['HF_HUB_OFFLINE'] = '1'
os.environ['TRANSFORMERS_OFFLINE'] = '1'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
sys.path.insert(0, str(ROOT))

import numpy as np
import sklearn
import torch
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from threadpoolctl import threadpool_limits
from backend.detection.inference import MLService, LABELS
from backend.config import DATASETS_DIR, EXPORT_DIR, MODEL_DIR

OUT = EXPORT_DIR / 'model-validation'
ARTIFACTS = MODEL_DIR.parent
DATA = DATASETS_DIR / 'splits'
THREADS = 4
torch.set_num_threads(THREADS)
threadpool_limits(limits=THREADS)


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def metrics(actual, predicted):
    return {'accuracy': float(accuracy_score(actual, predicted)),
            'report': classification_report(actual, predicted, labels=list(range(len(LABELS))),
                                           target_names=LABELS, output_dict=True, zero_division=0),
            'confusion_matrix': confusion_matrix(actual, predicted, labels=list(range(len(LABELS)))).tolist()}


def write_results(result):
    (OUT / 'validation-results.json').write_text(json.dumps(result, indent=2) + '\n')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((DATA / 'manifest.json').read_text())
    combined = hashlib.sha256()
    splits, group_sets, hash_sets, texts, labels, test_ids = {}, {}, {}, {}, {}, []
    for split in ('train', 'validation', 'test'):
        distribution = Counter(); groups = set(); hashes = set(); texts[split] = []; labels[split] = []
        with (DATA / (split + '.jsonl')).open('rb') as stream:
            for line in stream:
                combined.update(line)
                row = json.loads(line)
                assert row['split'] == split, 'Unexpected split assignment'
                assert LABELS[row['label_id']] == row['label'], 'Label mapping mismatch'
                digest = hashlib.sha256(re.sub(r'\s+', ' ', row['model_text']).casefold().encode()).hexdigest()
                assert digest == row['content_hash'], 'Dataset content fingerprint mismatch'
                assert digest not in hashes, 'Duplicate content within split'
                hashes.add(digest); groups.add(row['group_id']); distribution[row['label']] += 1
                if split != 'train':
                    texts[split].append(row['model_text']); labels[split].append(row['label_id'])
                if split == 'test':
                    test_ids.append(row['id'])
        assert dict(distribution) == manifest['class_distribution'][split], 'Manifest class count mismatch'
        group_sets[split] = groups; hash_sets[split] = hashes
        splits[split] = {'count': sum(distribution.values()), 'class_counts': dict(distribution),
                         'sha256': sha256(DATA / (split + '.jsonl'))}
    for a, b in (('train', 'validation'), ('train', 'test'), ('validation', 'test')):
        assert not group_sets[a] & group_sets[b], 'Cross-split group overlap'
        assert not hash_sets[a] & hash_sets[b], 'Cross-split exact-content overlap'
    assert combined.hexdigest() == manifest['dataset_version'], 'Dataset version mismatch'
    total = sum(s['count'] for s in splits.values())
    assert total == manifest['accepted'], 'Prepared dataset size mismatch'
    for split in splits.values():
        split['percentage'] = 100 * split['count'] / total
    selection = json.loads((ARTIFACTS / 'production/selection.json').read_text())
    chosen = Path(selection['selected']).name
    assert chosen == Path(max(selection['candidates'], key=lambda c: c['validation_macro_f1'])['path']).name
    selected_meta=json.loads((ARTIFACTS/chosen/'metadata.json').read_text())
    artifact_names={'tfidf_logistic':['model.joblib'],'cnn':['weights.pt','vocab.json'],
                    'bilstm':['weights.pt','vocab.json'],'transformer':['model.safetensors','config.json'],
                    'ensemble':[]}[selected_meta['model_type']]
    for filename in artifact_names:
        assert sha256(ARTIFACTS/'production'/filename)==sha256(ARTIFACTS/chosen/filename),'Production differs from selected artifact'
    if selected_meta['model_type']=='ensemble':
        deployed=json.loads((ARTIFACTS/'production/metadata.json').read_text())
        assert deployed['members']==selected_meta['members'],'Production ensemble differs from selection'
        assert MLService(ARTIFACTS/'production').status=='Available','Production ensemble failed integrity validation'
    result = {'started_at_utc': datetime.now(timezone.utc).isoformat(), 'dataset_size': total,
              'dataset_version': combined.hexdigest(), 'splits': splits,
              'split_validation': 'Exact content hashes, group disjointness, manifest counts and concatenated split SHA-256 verified',
              'labels': LABELS, 'primary_average': 'macro (all four classes, including BEC)',
              'selection': selection, 'selected_model_key': chosen, 'models': {},
              'environment': {'platform': platform.platform(), 'architecture': platform.machine(),
                              'logical_cpu_count': os.cpu_count(), 'torch_cpu_threads': torch.get_num_threads(),
                              'python': platform.python_version(), 'sklearn': sklearn.__version__, 'torch': torch.__version__},
              'limitations': manifest['limitations'],
              'inference_timing_scope': 'Warm CPU, sequential batch-size-one calls to the existing MLService.predict; includes text vectorization/tokenization, model inference, chunk aggregation, and baseline term explanations. Excludes model load, MIME parsing, database, network intelligence and API latency.'}
    print(json.dumps({'event': 'dataset_verified', 'total': total, 'splits': {k: v['count'] for k, v in splits.items()}}), flush=True)
    write_results(result)
    names = {'baseline': 'TF-IDF + Logistic Regression', 'cnn': 'CNN', 'bilstm': 'BiLSTM', 'transformer': 'BERT-tiny','ensemble':'Learned Ensemble'}
    for name in names:
        directory = ARTIFACTS / name
        if not (directory/'metadata.json').exists():continue
        metadata = json.loads((directory / 'metadata.json').read_text())
        assert metadata['dataset_version'] == result['dataset_version'], 'Artifact trained on another dataset version'
        assert [metadata['label_mapping'][str(i)] for i in range(len(LABELS))] == LABELS
        if name == 'transformer':
            architecture = json.loads((directory / 'config.json').read_text())
            assert metadata['configuration']['pretrained'] == 'prajjwal1/bert-tiny'
            assert architecture['model_type'] == 'bert', 'Unexpected transformer architecture; do not mislabel it'
        service = MLService(directory)
        assert service.status == 'Available', f'Artifact could not be loaded: {name}'
        fingerprints = {p.name: sha256(p) for p in sorted(directory.iterdir()) if p.is_file()}
        # These warm-up predictions are discarded, not counted as test results.
        for text in texts['test'][:20]:
            service.predict(text)
        predicted, timings = [], []
        print(json.dumps({'event': 'model_started', 'model': name}), flush=True)
        for i, text in enumerate(texts['test']):
            start = time.perf_counter_ns()
            output = service.predict(text)
            elapsed = (time.perf_counter_ns() - start) / 1e6
            assert output['status'] == 'Available' and output['label_id'] in range(len(LABELS))
            assert abs(sum(output['probabilities'].values()) - 1) < 1e-5
            predicted.append(output['label_id']); timings.append(elapsed)
            if (i + 1) % 500 == 0:
                print(json.dumps({'event': 'progress', 'model': name, 'done': i + 1, 'total': len(texts['test'])}), flush=True)
        fresh = metrics(labels['test'], predicted)
        recorded = metadata['test']
        same = fresh['confusion_matrix'] == recorded['confusion_matrix']
        val_score = metadata.get('validation_macro_f1')
        if val_score is None:
            val_score = max(c['validation']['report']['macro avg']['f1-score'] for c in metadata['validation_candidates'])
        candidate = next((c for c in selection['candidates'] if Path(c['path']).name == name),None)
        if candidate is not None:assert abs(val_score - candidate['validation_macro_f1']) < 1e-12
        row = {'display_name': names[name], 'model_type': metadata['model_type'],
               'pretrained': metadata.get('configuration', {}).get('pretrained'),
               'test': fresh, 'recorded_test': recorded, 'matches_recorded_test_confusion_matrix': same,
               'validation_macro_f1': val_score, 'artifact_sha256': fingerprints,
               'inference': {'sample_count': len(timings), 'warmup_count': 20,
                             'mean_ms_per_email': float(np.mean(timings)), 'median_ms_per_email': float(np.median(timings)),
                             'p95_ms_per_email': float(np.percentile(timings, 95)), 'total_seconds': sum(timings) / 1000}}
        if name == chosen:
            # Independently verify that the deployed model's stored selection
            # score is a validation score, never a mislabeled training metric.
            from ml.evaluation.predict_batch import predict_many
            validation_predicted = predict_many(service,texts['validation']).argmax(axis=1)
            row['fresh_validation'] = metrics(labels['validation'], validation_predicted)
            assert abs(row['fresh_validation']['report']['macro avg']['f1-score'] - val_score) < 1e-12
        result['models'][name] = row
        with (OUT / f'{name}-test-predictions.csv').open('w', newline='') as stream:
            writer = csv.writer(stream); writer.writerow(['content_id', 'true_label', 'predicted_label', 'elapsed_ms'])
            writer.writerows((identifier, LABELS[actual], LABELS[prediction], elapsed)
                             for identifier, actual, prediction, elapsed in zip(test_ids, labels['test'], predicted, timings))
        write_results(result)
        print(json.dumps({'event': 'model_completed', 'model': name, 'accuracy': fresh['accuracy'],
                          'macro_f1': fresh['report']['macro avg']['f1-score'], 'matches_recorded': same,
                          'mean_ms': row['inference']['mean_ms_per_email']}), flush=True)
        del service
    result['completed_at_utc'] = datetime.now(timezone.utc).isoformat()
    result['best_test_macro_f1_model'] = max(result['models'], key=lambda n: result['models'][n]['test']['report']['macro avg']['f1-score'])
    write_results(result)
    print('Completed. Results: ' + str(OUT / 'validation-results.json'), flush=True)


if __name__ == '__main__':
    main()
