import json
import os

from celery import Celery
import requests
from redis import StrictRedis

celery_broker = 'redis://127.0.0.1:6379/5'
celery_backend = 'redis://127.0.0.1:6379/5'

celery = Celery('tasks', broker=celery_broker, backend= celery_backend)
redis_client = StrictRedis()
@celery.task

def push(name):

    redis_client.rpush('files', name)


if redis_client.llen('files') % 10000 == 0:
    print('number file to record %s' % redis_client.llen('files'))

@celery.task
def vt_report(hash_file, api_key):
    params = {'resource': hash_file,
              'apikey': api_key}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                            params=params)

    if response.status_code == 200:
        r = response.json()
        directory = 'jsons/%s/%s/%s/%s/%s' % (hash_file[0:2], hash_file[3:5], hash_file[6:8], hash_file[9:11], hash_file[12:14])
        os.makedirs(directory, exist_ok=True)
        json.dump(r, open(os.path.join(directory, '%s.json' % hash_file), 'w'))
        print('records %s.json' % hash_file)