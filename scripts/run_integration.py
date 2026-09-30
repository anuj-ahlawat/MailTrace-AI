"""Exercise the real worker/API workflow against an isolated local test stack.

Requires local MongoDB, redis-server on PATH, and backend/test dependencies.
Production settings, records and evidence are never used by these tests.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from redis import Redis

ROOT = Path(__file__).resolve().parents[1]


def main():
    env = {
        **os.environ,
        'MAILTRACE_INTEGRATION': '1',
        'MONGODB_DB_NAME': 'mailtrace_local_stack_validation',
        'STORAGE_DIR': str(ROOT / 'storage/local-stack-validation'),
        'REDIS_URL': 'redis://127.0.0.1:16379/0',
        'WORKER_MODE': 'celery',
        'PYTHONPATH': str(ROOT),
        'PYTHONDONTWRITEBYTECODE': '1',
    }
    log_dir = ROOT / 'storage/temp/integration'
    log_dir.mkdir(parents=True, exist_ok=True)
    redis = Redis.from_url(env['REDIS_URL'], socket_connect_timeout=1)
    processes, logs = [], []
    try:
        try:
            redis.ping()
        except Exception:
            executable = shutil.which('redis-server')
            if executable is None:
                raise RuntimeError('Install redis-server and add it to PATH')
            log = (log_dir / 'redis.log').open('w')
            logs.append(log)
            processes.append(subprocess.Popen(
                [executable, '--port', '16379', '--bind', '127.0.0.1',
                 '--save', '', '--appendonly', 'no'], stdout=log, stderr=subprocess.STDOUT))
            for _ in range(30):
                try:
                    redis.ping()
                    break
                except Exception:
                    time.sleep(.1)
            else:
                raise RuntimeError('Isolated Redis failed to start; see ' + str(log_dir))
        log = (log_dir / 'celery.log').open('w')
        logs.append(log)
        processes.append(subprocess.Popen(
            [sys.executable, '-m', 'celery', '-A', 'backend.workers.celery_app:celery',
             'worker', '--pool=solo', '--concurrency=1', '--loglevel=WARNING',
             '--hostname=mailtrace-validation@%h'],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT))
        with (log_dir / 'integration.log').open('w') as log:
            result = subprocess.run(
                [sys.executable, '-m', 'pytest', 'tests/integration/test_pipeline_integration.py',
                 '-q', '-s', '-p', 'no:cacheprovider'],
                cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        print('Integration exit status:', result.returncode, '| Logs:', log_dir)
        return result.returncode
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()
        redis.close()


if __name__ == '__main__':
    raise SystemExit(main())
