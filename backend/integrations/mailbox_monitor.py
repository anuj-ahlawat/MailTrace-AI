"""Opt-in Gmail history polling. Read-only API; no sending, deletion or quarantine."""
import base64
import hashlib
import re
import time
from datetime import timedelta
import httpx
from fastapi import HTTPException
from pymongo import ReturnDocument
from backend.database.store import db, now, uid, settings, event

API = 'https://gmail.googleapis.com/gmail/v1/users/me'
INTERVAL_SECONDS = 60


def gmail_get(user, suffix, params=None):
    from backend.api.routes.gmail import token
    try:
        response = httpx.get(API + suffix, params=params, headers={'Authorization': 'Bearer ' + token(user)}, timeout=15)
    except httpx.HTTPError:
        raise HTTPException(502, 'Gmail request unavailable')
    if response.status_code != 200:
        raise HTTPException(response.status_code if response.status_code in (401, 403, 404, 429) else 502, 'Gmail request failed')
    return response.json()


def import_message(user, message_id):
    """Durable message deduplication shared by manual and monitored imports."""
    from backend.core.pipeline import acquire
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,100}', message_id):
        raise HTTPException(422, 'Invalid Gmail message ID')
    key = hashlib.sha256((user['_id'] + ':' + message_id).encode()).hexdigest()
    db.gmail_imports.update_one({'_id': key}, {'$setOnInsert': {'status': 'Pending', 'created_at': now()}}, upsert=True)
    existing = db.gmail_imports.find_one({'_id': key})
    if existing.get('status') == 'Completed':
        if not db.emails.find_one({'_id': existing['result']['email_id']}, {'_id': 1}):
            raise HTTPException(410, 'This previously imported analysis has expired under the retention policy')
        return {**existing['result'], 'already_imported': True}
    lease = uid()
    claim = db.gmail_imports.find_one_and_update({'_id': key, 'status': {'$ne': 'Completed'},
        '$or': [{'lease_until': {'$exists': False}}, {'lease_until': {'$lt': now()}}]},
        {'$set': {'lease_until': now() + timedelta(minutes=5), 'lease': lease}}, return_document=ReturnDocument.AFTER)
    if not claim:
        raise HTTPException(409, 'This message is already being imported')
    try:
        # Recover a process that preserved the email but failed before marking
        # the import complete. Do not create duplicate evidence on every poll.
        reference = {'kind': 'gmail', 'user_id': user['_id'], 'message_id': message_id}
        email = db.emails.find_one({'source_reference': reference})
        if email:
            job = db.jobs.find_one({'email_id': email['_id']})
            if not job:
                job = {'_id': uid(), 'email_id': email['_id'], 'evidence_id': email['evidence_id'], 'user_id': user['_id'],
                       'status': 'Uploaded', 'created_at': now(), 'updated_at': now(), 'attempts': 0, 'history': []}
                db.jobs.insert_one(job)
            result = {'email_id': email['_id'], 'evidence_id': email['evidence_id'], 'job_id': job['_id'], 'status': job['status']}
        else:
            data = gmail_get(user, '/messages/' + message_id, {'format': 'raw'})
            content = data.get('raw') or ''
            maximum = settings()['max_upload_mb'] * 1024 * 1024
            if len(content) > (maximum + 2) * 4 // 3 + 4:
                raise HTTPException(413, 'Gmail message exceeds configured size limit')
            try:
                raw = base64.b64decode(content + '=' * (-len(content) % 4), altchars=b'-_', validate=True)
            except (ValueError, TypeError):
                raise HTTPException(502, 'Invalid Gmail raw message')
            if not raw:
                raise HTTPException(502, 'Gmail returned an empty message')
            if len(raw) > maximum:
                raise HTTPException(413, 'Gmail message exceeds configured size limit')
            result = acquire(raw, 'gmail-' + message_id + '.eml', user['_id'], 'Gmail', source_reference=reference)
        db.gmail_imports.update_one({'_id': key, 'lease': lease}, {'$set': {'status': 'Completed', 'result': result}, '$unset': {'lease': '', 'lease_until': ''}})
        event('Gmail email imported', user, 'email', result['email_id'], {'message_id': message_id})
        return result
    except Exception:
        db.gmail_imports.update_one({'_id': key, 'lease': lease}, {'$unset': {'lease': '', 'lease_until': ''}})
        raise


def set_monitor(user, enabled):
    if not db.gmail_connections.find_one({'_id': user['_id']}):
        raise HTTPException(409, 'Connect Gmail first')
    if enabled:
        # Begin at current mailbox history, never silently import the old inbox.
        profile = gmail_get(user, '/profile')
        history_id = str(profile.get('historyId') or '')
        if not history_id.isdigit():
            raise HTTPException(502, 'Gmail did not supply a history cursor')
        monitor = {'enabled': True, 'history_id': history_id, 'status': 'Waiting for new inbox messages',
                   'next_poll_at': now(), 'started_at': now(), 'pending': [], 'imported_count': 0, 'skipped_count': 0}
    else:
        monitor = {'enabled': False, 'status': 'Stopped'}
    db.gmail_connections.update_one({'_id': user['_id']}, {'$set': {'monitor': monitor}})
    event('Gmail monitoring enabled' if enabled else 'Gmail monitoring disabled', user)
    return {'enabled': enabled, 'status': monitor['status'], 'interval_seconds': INTERVAL_SECONDS}


def poll_connection(connection, user):
    started = time.monotonic()
    state = dict(connection['monitor'])
    state['pending'] = list(state.get('pending') or [])
    if not state.get('pending'):
        params = {'startHistoryId': state['history_id'], 'historyTypes': 'messageAdded', 'labelId': 'INBOX', 'maxResults': 20}
        if state.get('page_token'):
            params['pageToken'] = state['page_token']
        try:
            data = gmail_get(user, '/history', params)
        except HTTPException as exc:
            if exc.status_code == 404:
                # Explicit recovery is required; advancing to a fresh cursor
                # here would silently miss evidence during the gap.
                return {**state, 'enabled': False, 'status': 'History expired: review missed mail manually, then restart monitoring'}
            raise
        state['pending'] = list(dict.fromkeys(m['message']['id'] for h in data.get('history') or [] for m in h.get('messagesAdded') or [] if (m.get('message') or {}).get('id')))
        state['next_page_token'] = data.get('nextPageToken')
        state['page_history_id'] = str(data.get('historyId') or state['history_id'])
    remaining = list(state.get('pending') or [])
    for message_id in remaining[:20]:
        if time.monotonic() - started >= 30:
            break  # Persist remaining IDs so a slow provider cannot monopolize the scheduler.
        if not db.gmail_connections.find_one({'_id': user['_id'], 'monitor.enabled': True}):
            return {**state, 'enabled': False, 'status': 'Stopped'}
        try:
            result = import_message(user, message_id)
            if not result.get('already_imported'):
                state['imported_count'] = state.get('imported_count', 0) + 1
        except HTTPException as exc:
            if exc.status_code not in (404, 410, 413):
                raise
            # A deleted or oversized message cannot block every later email.
            # Preserve an audit record and a visible coverage count.
            state['skipped_count'] = state.get('skipped_count', 0) + 1
            event('Gmail monitored message skipped', user, 'gmail', message_id, {'status_code': exc.status_code})
        state['pending'].remove(message_id)
    if not state['pending']:
        state['page_token'] = state.pop('next_page_token', None)
        if not state['page_token']:
            state['history_id'] = state.pop('page_history_id', state['history_id'])
    state.update(status='Monitoring', last_checked_at=now(), next_poll_at=now() + timedelta(seconds=INTERVAL_SECONDS))
    return state


def monitor_tick():
    """One bounded scheduler tick; a Mongo lease prevents duplicate workers."""
    for candidate in db.gmail_connections.find({'monitor.enabled': True, 'monitor.next_poll_at': {'$lte': now()}}).sort('monitor.next_poll_at', 1).limit(1):
        lease = uid()
        connection = db.gmail_connections.find_one_and_update({'_id': candidate['_id'], 'monitor.enabled': True,
            '$or': [{'monitor.lease_until': {'$exists': False}}, {'monitor.lease_until': {'$lt': now()}}]},
            {'$set': {'monitor.lease': lease, 'monitor.lease_until': now() + timedelta(minutes=10)}}, return_document=ReturnDocument.AFTER)
        if not connection:
            continue
        user = db.users.find_one({'_id': connection['_id'], 'status': 'active'})
        try:
            state = poll_connection(connection, user) if user else {'enabled': False, 'status': 'Account inactive'}
        except Exception as exc:
            state = {**connection['monitor'], 'status': 'Lookup unavailable; retry pending', 'next_poll_at': now() + timedelta(minutes=5)}
            event('Gmail monitoring lookup failed', user, 'gmail', connection['_id'], {'error_type': type(exc).__name__})
        state.pop('lease', None)
        state.pop('lease_until', None)
        # A concurrent stop/disconnect/reconnect invalidates this lease.
        db.gmail_connections.update_one({'_id': connection['_id'], 'monitor.enabled': True, 'monitor.lease': lease}, {'$set': {'monitor': state}})
