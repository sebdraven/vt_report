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


@celery.task(ignore_result=True, max_retries=3, time_limite=70)
def capa_extraction(path_rules, path_file):
    client_redis = StrictRedis(db=6, decode_responses=True)
    rules = capa.main.get_rules(path_rules, disable_progress=True)
    rules = capa.rules.RuleSet(rules)
    capa_json = None
    try:
        extractor = capa.main.get_extractor(path_file, 'auto', disable_progress=True)
        capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
        meta = capa.main.collect_metadata('', path_file, path_rules, 'auto', extractor)
        capa_json = capa.render.render_json(meta, rules, capabilities)
    except:
        client_redis.hset('file failed', key=path_file, value=1)

    if capa_json:
        name_file = os.path.basename(path_file)
        path_dir = '/mnt/pst/jsons_capa'
        path_file_json = '%s.capa' % os.path.join(path_dir, name_file)
        try:
            fw = open(path_file_json, 'w')
            if fw:
                fw.write(capa_json)
                logging.info('jsons results %s' % path_file_json)
                fw.close()
                client_redis.incr('nb_capa')
                path_file_viv = '%s.viv' % path_file
                try:
                    if os.path.isfile(path_file_viv):
                        os.remove(path_file_viv)
                except:
                    logging.error('Can\'t delete %s' % path_file_viv)
        except:
            logging.error('Bad recording %s' % path_file_json)
            pass

@celery.task
def clean_viv(path_file):

    if os.path.isfile(path_file):
        try:
            os.remove(path_file)
            logging.warning('the file %s has been deleted' % path_file)
        except:
            logging.error('delete has failed %s' % path_file)