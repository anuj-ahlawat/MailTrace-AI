"""Import and validate the route registry without a running database."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from backend.main import app


def test_route_registry_loads_all_existing_feature_groups():
    schema = app.openapi()
    for path in (
        '/health', '/api/auth/login', '/api/emails/upload', '/api/cases',
        '/api/evidence', '/api/reports', '/api/campaigns', '/api/alerts',
        '/api/dashboard/summary', '/api/search', '/api/settings', '/api/gmail/status',
    ):
        assert path in schema['paths']
    operations = [operation['operationId'] for methods in schema['paths'].values()
                  for operation in methods.values() if 'operationId' in operation]
    assert len(operations) == len(set(operations))


@pytest.mark.parametrize(('directory', 'target'), [('.', 'backend.main:app'), ('backend', 'main:app')])
def test_uvicorn_loads_from_both_launch_directories(directory, target):
    root = Path(__file__).resolve().parents[2]
    expected = hashlib.sha256(json.dumps(app.openapi(), sort_keys=True).encode()).hexdigest()
    env = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
    # A fresh interpreter catches import-path failures hidden by pytest's
    # configured pythonpath, including the import performed by a reload child.
    result = subprocess.run(
        [sys.executable, '-c', '''
import hashlib, json, sys
from uvicorn import Config
config = Config(sys.argv[1], reload=True)
config.load()
from uvicorn.importer import import_from_string
app = import_from_string(sys.argv[1])
print(hashlib.sha256(json.dumps(app.openapi(), sort_keys=True).encode()).hexdigest())
''', target],
        cwd=root / directory, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected
