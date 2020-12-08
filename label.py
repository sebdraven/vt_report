from configparser import ConfigParser

import celery

from celery import Celery
import requests
from redis import StrictRedis
import argparse
from avclass2.avclass2_labeler import main, default_exp_file,default_tag_file,default_tax_file
celery_broker = 'redis://127.0.0.1:6379/5'
celery_backend = 'redis://127.0.0.1:6379/5'

celery = Celery('labels', broker=celery_broker, backend= celery_backend)
redis_client = StrictRedis()

@celery.task
def process(path_of_file):
    args = ConfigParser()
    args.read('vt_report.conf')
    args.set('vt_report', 'vt', path_of_file)
    args.set('vt_report', 'tax', default_tax_file)
    args.set('vt_report', 'exp', default_exp_file)
    args.set('vt_report', 'tag', default_tag_file)
    main(args)