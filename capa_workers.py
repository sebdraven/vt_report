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
        path_dir = 'jsons_capa/%s/%s/%s/%s' % (name_file[0:2], name_file[2:4], name_file[4:6], name_file[6:8])
        try:
            os.makedirs(path_dir)
        except:
            pass
        path_file_json = '%s.capa' % os.path.join(path_dir, name_file)
        try:
            fw = open(path_file_json, 'w')
            if fw:
                fw.write(capa_json)
                logging.info('jsons results %s' % path_file_json)
                fw.close()
        except:
            logging.error('Bad recording %s' % path_file)
            pass