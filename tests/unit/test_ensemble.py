"""Ensemble integrity and batch equivalence with isolated synthetic artifacts."""
import hashlib
import json

import numpy as np
import pytest

torch = pytest.importorskip('torch')
from backend.detection.inference import MLService, LABELS
from backend.detection.networks import CNN, BiLSTM
from ml.evaluation.predict_batch import predict_many
from ml.training.train_ensemble import fit_weights


def make_member(directory, kind):
    directory.mkdir(parents=True)
    vocab = {'hello': 2, 'world': 3}
    architecture = {'embedding_dim': 8, 'hidden': 4, 'dropout': .5}
    model = (CNN if kind == 'cnn' else BiLSTM)(4, **architecture)
    torch.save(model.state_dict(), directory / 'weights.pt')
    (directory / 'vocab.json').write_text(json.dumps(vocab))
    (directory / 'metadata.json').write_text(json.dumps({'model_type': kind,
        'dataset_version': 'unit-test-only', 'label_mapping': dict(enumerate(LABELS)),
        'configuration': {'architecture': architecture}}))
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()}


@pytest.mark.parametrize('kind', ['cnn', 'bilstm'])
def test_batch_probabilities_match_production_chunking(tmp_path, kind):
    torch.set_num_threads(1)
    make_member(tmp_path / kind, kind)
    model = MLService(tmp_path / kind)
    texts = ['', 'hello world', 'hello ' * 1100, 'unknown world']
    actual = predict_many(model, texts, batch_size=3)
    expected = np.array([[model.predict(text)['probabilities'][label] for label in LABELS] for text in texts])
    np.testing.assert_allclose(actual, expected, atol=1e-6)


def test_self_contained_ensemble_checks_members_and_computes_weighted_probabilities(tmp_path):
    members = []
    for kind, weight in [('cnn', .4), ('bilstm', .6)]:
        hashes = make_member(tmp_path / 'members' / kind, kind)
        members.append({'path': 'members/' + kind, 'weight': weight, 'artifact_sha256': hashes})
    metadata = {'model_type': 'ensemble', 'dataset_version': 'unit-test-only',
                'label_mapping': dict(enumerate(LABELS)), 'members': members}
    (tmp_path / 'metadata.json').write_text(json.dumps(metadata))
    service = MLService(tmp_path)
    assert service.status == 'Available'
    output = service.predict('hello world')
    expected = sum(m['weight'] * np.array(list(MLService(tmp_path / m['path']).predict('hello world')['probabilities'].values())) for m in members)
    np.testing.assert_allclose(list(output['probabilities'].values()), expected, atol=1e-7)
    np.testing.assert_allclose(predict_many(service, ['hello world'])[0], expected, atol=1e-6)
    (tmp_path / 'members/cnn/vocab.json').write_text('{}')
    assert MLService(tmp_path).status == 'Model unavailable'


def test_mixture_training_selects_on_validation_and_records_actual_history():
    y = [0, 1, 2, 3] * 2
    first = np.full((8, 4), .1); first[np.arange(8), y] = .7
    second = np.full((8, 4), .2); second[np.arange(8), y] = .4
    p = np.stack([first, second], axis=1)
    weights, epoch, history = fit_weights(p, y, p, y, epochs=5, patience=2)
    assert np.all(weights >= 0)
    assert weights.sum() == pytest.approx(1)
    assert epoch == max(history, key=lambda r: r['validation']['f1_macro'])['epoch']
    assert all(row['training']['count'] == 8 and row['validation']['count'] == 8 for row in history)
