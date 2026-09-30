"""Storage migration must preserve access without widening file access."""
from pathlib import Path

import pytest

from backend import config


def test_relative_paths_resolve_from_repository_not_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('TEST_MAILTRACE_PATH', 'storage/reports')
    assert config.configured_path('TEST_MAILTRACE_PATH', '') == config.ROOT / 'storage/reports'


def test_geoip_discovery_preserves_explicit_disable(tmp_path, monkeypatch):
    city = tmp_path / 'GeoLite2-City_20260918' / 'GeoLite2-City.mmdb'
    city.parent.mkdir()
    city.write_bytes(b'path discovery fixture')
    monkeypatch.setattr(config, 'GEOIP_DIR', tmp_path)
    monkeypatch.delenv('GEOIP_CITY_DB', raising=False)
    assert config.geoip_path('city') == city
    monkeypatch.setenv('GEOIP_CITY_DB', '')
    assert config.geoip_path('city') is None


@pytest.mark.parametrize('scope', ['', 'local-stack-validation'])
def test_existing_evidence_paths_translate_without_modifying_files(tmp_path, monkeypatch, scope):
    monkeypatch.setattr(config, 'ROOT', tmp_path)
    root = tmp_path / 'storage' / scope
    original = root / 'evidence' / 'original.enc'
    original.parent.mkdir(parents=True)
    original.write_bytes(b'immutable ciphertext')
    legacy = tmp_path / 'data' / scope / 'evidence' / original.name
    assert config.resolve_runtime_file(legacy, 'evidence', root) == original
    assert config.resolve_runtime_file(original, 'evidence', root) == original
    assert original.read_bytes() == b'immutable ciphertext'


def test_runtime_paths_reject_escape_and_unrelated_locations(tmp_path, monkeypatch):
    monkeypatch.setattr(config, 'ROOT', tmp_path)
    root = tmp_path / 'storage'
    (root / 'evidence').mkdir(parents=True)
    outside = tmp_path / 'outside.enc'
    outside.write_bytes(b'outside')
    (root / 'evidence' / 'link.enc').symlink_to(outside)
    for path in (outside, root / 'evidence/../../outside.enc',
                 root / 'evidence/link.enc', tmp_path / 'data/reports/outside.enc'):
        with pytest.raises(ValueError):
            config.resolve_runtime_file(path, 'evidence', root)
