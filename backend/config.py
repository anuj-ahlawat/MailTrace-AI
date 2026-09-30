"""Repository-relative paths shared by API, workers and local inference."""
import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')


def configured_path(name, default):
    value = Path(os.getenv(name) or default).expanduser()
    return (value if value.is_absolute() else ROOT / value).resolve()


STORAGE_DIR = configured_path('STORAGE_DIR', os.getenv('DATA_DIR') or 'storage')
MODEL_DIR = configured_path('MODEL_DIR', 'ml/artifacts/production')
DATASETS_DIR = configured_path('DATASETS_DIR', 'data/datasets')
GEOIP_DIR = configured_path('GEOIP_DIR', 'data/geoip')
EXPORT_DIR = configured_path('EXPORT_DIR', str(STORAGE_DIR / 'exports'))


def geoip_path(kind):
    name = 'GEOIP_' + kind.upper() + '_DB'
    if name in os.environ and not os.environ[name]:
        return None  # An explicit empty value disables this database.
    if os.getenv(name):
        return configured_path(name, '')
    filename = 'GeoLite2-' + ('City' if kind.lower() == 'city' else 'ASN') + '.mmdb'
    candidates = sorted(GEOIP_DIR.rglob(filename)) if GEOIP_DIR.is_dir() else []
    return candidates[-1] if candidates else GEOIP_DIR / filename


def resolve_runtime_file(value, kind, root=None):
    """Translate only the known old data/ prefix, without changing DB records."""
    root = Path(root or STORAGE_DIR).resolve()
    path = Path(value).resolve()
    allowed = (root / kind).resolve()
    if path.is_relative_to(allowed):
        return path
    modern = (ROOT / 'storage').resolve()
    if root.is_relative_to(modern):
        legacy = ROOT / 'data' / root.relative_to(modern) / kind
        if path.is_relative_to(legacy):
            translated = (allowed / path.relative_to(legacy)).resolve()
            if translated.is_relative_to(allowed):
                return translated
    raise ValueError('Invalid ' + kind + ' storage path')
