import json
import os

from celery import Celery
import requests
from redis import StrictRedis
import ZODB, ZODB.FileStorage

import capa.main
import capa.rules
import capa.engine
import capa.features
import capa.render
from capa.engine import *
import logging



celery_broker = 'redis://127.0.0.1:6379/5'
celery_backend = 'redis://127.0.0.1:6379/5'

celery = Celery('tasks', broker=celery_broker, backend= celery_backend)

@celery.task

def push(name):
    redis_client = StrictRedis()
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

@celery.task
def capa_extraction(db_rules, path_rules, path_file):
    storage = ZODB.FileStorage.FileStorage(db_rules)
    db = ZODB.DB(storage)

    con = db.open()

    rules = con.root.rules

    extractor = capa.main.get_extractor(path_file, 'auto', disable_progress=True)
    capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
    meta = capa.main.collect_metadata('', path_file, path_rules, 'auto', extractor)
    capa_json = capa.render.render_json(meta, rules, capabilities)
    db.close()

    if capa_json:
        name_file = os.path.basename(path_file)
        path_dir = 'jsons/%s/%s/%s/%s' % (name_file[0:2], name_file[2:4], name_file[4:6], name_file[6:8])
        try:
            os.makedirs(path_dir)
        except:
            pass
        path_file = os.path.join(path_dir, name_file)
        try:
            fw = open(path_file, 'w')
            if fw:
                fw.write(capa_json)
                logging.info('jsons results %s' % path_file)
                fw.close()
        except:
            logging.error('Bad recording %s' % path_file)
            pass