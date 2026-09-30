"""Shared local/Celery maintenance scheduling with durable leases."""
import logging
from datetime import timedelta
from pymongo import ReturnDocument
from backend.database.store import db, now, uid

logger = logging.getLogger('mailtrace.maintenance')


def tick():
    from backend.integrations.mailbox_monitor import monitor_tick
    monitor_tick()
    # Initialize with a one-hour grace period; existing explicit policy governs
    # deletion. Concurrent processes share the same database scheduler record.
    db.scheduler_state.update_one({'_id': 'retention'}, {'$setOnInsert': {'next_run': now() + timedelta(hours=1)}}, upsert=True)
    lease = uid()
    claimed = db.scheduler_state.find_one_and_update({'_id': 'retention', 'next_run': {'$lte': now()}},
        {'$set': {'next_run': now() + timedelta(hours=1), 'lease': lease}}, return_document=ReturnDocument.AFTER)
    if claimed:
        from backend.core.retention import apply_retention
        result = apply_retention()
        db.scheduler_state.update_one({'_id': 'retention', 'lease': lease}, {'$set': {'last_run': now(), 'result': result}})


def maintenance_loop(stop):
    while not stop.wait(5):
        try:
            tick()
        except Exception:
            logger.warning('maintenance_unavailable; retry scheduled')
