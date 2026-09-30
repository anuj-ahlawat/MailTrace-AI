"""Tiny synthetic smoke runs test instrumentation, not model performance."""
import csv
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

pytest.importorskip('torch', reason='Optional neural training dependency')


@pytest.mark.parametrize('model', ['cnn', 'bilstm'])
def test_training_saves_real_epoch_measurements_and_loadable_artifact(tmp_path, model):
    from backend.detection.inference import MLService, LABELS
    root = Path(__file__).resolve().parents[2]
    data = tmp_path / 'data'
    data.mkdir()
    for split in ('train', 'validation', 'test'):
        rows = [{'model_text': f'{label} synthetic unit test message {split}', 'label_id': i,
                 'group_id': f'{split}-{i}'} for i, label in enumerate(LABELS)]
        (data / (split + '.jsonl')).write_text(''.join(json.dumps(row) + '\n' for row in rows))
    (data / 'manifest.json').write_text(json.dumps({'dataset_version': 'synthetic-unit-test-only', 'limitations': ['Unit test fixture']}))
    out = tmp_path / model
    result = subprocess.run([sys.executable, str(root / 'ml/training/train_deep.py'), '--model', model,
                             '--epochs', '1', '--batch-size', '4', '--data', str(data), '--out', str(out)],
                            cwd=root, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    metadata = json.loads((out / 'metadata.json').read_text())
    assert metadata['best_epoch'] == 1
    assert metadata['history_schema_version'] == 2
    row = metadata['history'][0]
    assert row['training_loss_sum'] >= 0
    for split in ('training', 'validation'):
        assert row[split]['count'] == 4
        assert row[split]['log_loss'] >= 0
        assert 0 <= row[split]['accuracy'] <= 1
    with (out / 'training_history.csv').open() as stream:
        flat = list(csv.DictReader(stream))
    assert len(flat) == 1
    for key in ('training_log_loss', 'validation_log_loss', 'training_accuracy', 'validation_accuracy'):
        assert flat[0][key] != ''
    assert json.loads((out / 'training_history.json').read_text())['epochs'] == metadata['history']
    service = MLService(out)
    assert service.status == 'Available'
    assert service.predict('synthetic smoke test')['status'] == 'Available'
