"""Learn a convex probability mixture on train; select its epoch on validation.

Frozen members are bundled so selecting this artifact never loads newer weights
silently. Test data is never read during fitting or checkpoint selection.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import numpy as np
import torch
from backend.config import DATASETS_DIR
from backend.detection.inference import MLService, LABELS
from ml.evaluation.fit_metrics import probability_metrics, history_rows, fit_assessment
from ml.evaluation.predict_batch import predict_many


def artifact_hashes(directory):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()
            if p.is_file() and p.suffix in ('.json', '.joblib', '.pt', '.safetensors', '.txt')
            and not p.name.startswith('training_history')}


def measured_member_predictions(source, split, rows, metadata):
    """Reuse audited predictions only when IDs, labels and artifact provenance agree."""
    local = source / (split + '_predictions.csv')
    previous = ROOT / 'ml/evaluation/plots' / source.name
    path = local if local.exists() else previous / (split + '_predictions.csv')
    if not path.exists():
        return None
    if path == local:
        recorded = metadata.get(split)
        if not recorded:
            return None
    else:
        provenance_path = path.with_suffix('.provenance.json')
        if not provenance_path.exists():
            return None
        provenance = json.loads(provenance_path.read_text())
        if provenance['csv_sha256'] != hashlib.sha256(path.read_bytes()).hexdigest():
            return None
        for name, digest in provenance['inputs']['artifact_sha256'].items():
            if not (source/name).exists() or hashlib.sha256((source/name).read_bytes()).hexdigest()!=digest:
                return None
        recorded = json.loads((previous/'metrics.json').read_text())['metrics'][split]
    with path.open() as stream:
        cached = list(csv.DictReader(stream))
    if len(cached)!=len(rows) or any(c['content_id']!=r['id'] or c['true_label']!=r['label'] for c,r in zip(cached,rows)):
        return None
    values = np.array([[float(row['p_'+label]) for label in LABELS] for row in cached])
    measured = probability_metrics([row['label_id'] for row in rows],values)
    if measured['confusion_matrix']!=recorded['confusion_matrix']:
        return None
    print('Using verified existing probabilities:',source.name,split,flush=True)
    return values


def fit_weights(probabilities, actual, validation_probabilities, validation_actual, epochs=200, patience=25):
    torch.manual_seed(42)
    p = torch.as_tensor(probabilities, dtype=torch.float64)
    y = torch.as_tensor(actual, dtype=torch.long)
    counts = np.bincount(actual, minlength=4)
    class_weights = len(actual) / (4 * counts)
    sample_weights = torch.as_tensor(class_weights[np.asarray(actual)], dtype=torch.float64)
    logits = torch.nn.Parameter(torch.zeros(p.shape[1], dtype=torch.float64))
    optimizer = torch.optim.Adam([logits], lr=.05)
    best_score = -1; best_weights = None; best_epoch = None; history = []; stale = 0
    for epoch in range(1, epochs + 1):
        weights = logits.softmax(0)
        mixture = (p * weights[None, :, None]).sum(1)
        loss = (-mixture[torch.arange(len(y)), y].clamp_min(1e-15).log() * sample_weights).mean()
        # Penalize extreme concentration; validation decides whether it helps.
        loss = loss + .02 * ((weights - 1 / len(weights)) ** 2).sum()
        optimizer.zero_grad(); loss.backward(); optimizer.step()
        weights = logits.detach().softmax(0).numpy()
        train = probability_metrics(actual, np.einsum('nmc,m->nc', probabilities, weights))
        validation = probability_metrics(validation_actual, np.einsum('nmc,m->nc', validation_probabilities, weights))
        history.append({'epoch': epoch, 'training_loss_sum': None, 'optimization_loss': float(loss.detach()),
                        'training': train, 'validation': validation, 'weights': weights.tolist()})
        score = validation['f1_macro']
        if score > best_score:
            best_score = score; best_weights = weights.copy(); best_epoch = epoch; stale = 0
        else:
            stale += 1
        if stale >= patience:
            break
    return best_weights, best_epoch, history


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--members', nargs='+', required=True, type=Path)
    ap.add_argument('--data', type=Path, default=DATASETS_DIR / 'splits')
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    if len(args.members) < 2:
        ap.error('At least two trained members are required')
    if (args.out / 'metadata.json').exists():
        ap.error('Output already has a trained artifact; use a new output directory')
    args.out.mkdir(parents=True, exist_ok=True)
    torch.set_num_threads(2)
    manifest = json.loads((args.data / 'manifest.json').read_text())
    rows = {s: [json.loads(line) for line in (args.data / (s + '.jsonl')).open()] for s in ('train', 'validation')}
    for key in ('content_hash', 'group_id'):
        assert not {r[key] for r in rows['train']} & {r[key] for r in rows['validation']}
    arrays = {s: [] for s in rows}; members = []
    for index, source in enumerate(args.members):
        service = MLService(source)
        if service.status != 'Available' or service.metadata['dataset_version'] != manifest['dataset_version']:
            raise ValueError('Unavailable or incompatible member: ' + str(source))
        destination = args.out / 'members' / f'{index}-{source.name}'
        destination.mkdir(parents=True, exist_ok=True)
        hashes = artifact_hashes(source)
        for name in hashes:
            shutil.copy2(source / name, destination / name)
        members.append({'path': str(destination.relative_to(args.out)), 'source': str(source),
                        'artifact_sha256': hashes, 'weight': None})
        for split in rows:
            print('Predicting ensemble member', source.name, split, flush=True)
            values = measured_member_predictions(source, split, rows[split], service.metadata)
            if values is None:
                values = predict_many(service, [r['model_text'] for r in rows[split]])
            arrays[split].append(values)
            np.save(args.out / f'member-{index}-{split}.npy', values)
    arrays = {s: np.stack(v, axis=1) for s, v in arrays.items()}
    labels = {s: [r['label_id'] for r in v] for s, v in rows.items()}
    weights, best_epoch, history = fit_weights(arrays['train'], labels['train'], arrays['validation'], labels['validation'])
    for member, weight in zip(members, weights):
        member['weight'] = float(weight)
    measured = {}
    for split in rows:
        probabilities = np.einsum('nmc,m->nc', arrays[split], weights)
        measured[split] = probability_metrics(labels[split], probabilities)
        with (args.out / (split + '_predictions.csv')).open('w', newline='') as stream:
            writer = csv.writer(stream); writer.writerow(['content_id', 'true_label', 'predicted_label', *['p_' + label for label in LABELS]])
            for row, p in zip(rows[split], probabilities):
                writer.writerow([row['id'], row['label'], LABELS[int(p.argmax())], *map(float, p)])
    metadata = {'model_type': 'ensemble', 'dataset_version': manifest['dataset_version'], 'label_mapping': dict(enumerate(LABELS)),
                'members': members, 'configuration': {'method': 'Convex probability mixture', 'seed': 42,
                    'objective': 'Class-balanced training log loss + 0.02 squared distance from uniform weights',
                    'selection': 'Highest validation macro-F1; test data never read', 'learning_rate': .05, 'patience': 25},
                'history': history, 'history_schema_version': 2, 'best_epoch': best_epoch,
                'validation_macro_f1': measured['validation']['f1_macro'], **measured, 'test': None,
                'fit': fit_assessment(measured['train'], measured['validation']),
                'dataset_manifest': manifest, 'limitations': manifest['limitations'] + [
                    'Ensemble weights are learned from in-sample training predictions of frozen members, not out-of-fold predictions. '
                    'Validation selects the mixture checkpoint; generalization must be assessed separately on held-out data.']}
    (args.out / 'metadata.json').write_text(json.dumps(metadata, indent=2))
    (args.out / 'training_history.json').write_text(json.dumps({'epochs': history}, indent=2))
    flat = history_rows(history)
    with (args.out / 'training_history.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(flat[0])); writer.writeheader(); writer.writerows(flat)
    print('Ensemble trained:', {'best_epoch': best_epoch, 'weights': weights.tolist(),
          'validation_macro_f1': measured['validation']['f1_macro'], 'fit': metadata['fit']}, flush=True)


if __name__ == '__main__':
    main()
