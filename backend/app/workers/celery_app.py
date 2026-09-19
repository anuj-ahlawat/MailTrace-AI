"""Redis-backed worker; MongoDB job documents are the durable source of status."""
import os
from celery import Celery
from app.platform.store import db
from app.platform.pipeline import process

celery=Celery('mailtrace',broker=os.getenv('REDIS_URL','redis://localhost:6379/0'))
celery.conf.update(task_serializer='json',accept_content=['json'],task_acks_late=True,
    worker_prefetch_multiplier=1,broker_connection_retry_on_startup=True,
    beat_schedule={'dispatch-pending':{'task':'mailtrace.dispatch','schedule':5.0},
                   'retention':{'task':'mailtrace.retention','schedule':3600.0}})

@celery.task(name='mailtrace.analyze',soft_time_limit=1500,time_limit=1800)
def analyze(job_id):process(job_id)

@celery.task(name='mailtrace.dispatch')
def dispatch():
    from app.platform.store import now
    db.jobs.update_many({'lease_until':{'$lt':now()},'status':{'$nin':['Completed','Failed','Uploaded']}},
        {'$set':{'status':'Failed','error':'Worker lease expired; retry explicitly'}})
    for job in db.jobs.find({'status':'Uploaded'}).sort('created_at',1).limit(20):analyze.delay(job['_id'])

@celery.task(name='mailtrace.retention')
def retention():
    from app.platform.retention import apply_retention
    return apply_retention()
