import celery

from celery import Celery
import requests
from redis import StrictRedis
import argparse
from avclass2.avclass2_labeler import main
celery_broker = 'redis://127.0.0.1:6379/5'
celery_backend = 'redis://127.0.0.1:6379/5'

celery = Celery('labels', broker=celery_broker, backend= celery_backend)
redis_client = StrictRedis()

@celery.task
def process(path_of_file):
    args = argparse.ArgumentParser()
    args.vt = path_of_file
    main(args)