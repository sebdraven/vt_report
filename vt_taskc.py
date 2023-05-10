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
import zlib
import boto3
import pefile


celery_broker = 'redis://127.0.0.1:6379/5'
celery_backend = 'redis://127.0.0.1:6379/5'

celery = Celery('tasks', broker=celery_broker, backend= celery_backend)

@celery.task

def push(name):
    redis_client = StrictRedis(db=6 , decode_responses=True)
    redis_client.rpush('files', name)

    if redis_client.llen('files') % 10000 == 0:
        print('number file to record %s' % redis_client.llen('files'))
    return True
@celery.task
def unzip_file(path_file,dir_unzip='/mnt/pst/dataset/sorel_unzip/'):
    name_file = os.path.basename(path_file)
    path_dir = os.path.join(dir_unzip, name_file)
    data = zlib.decompress(open(path_file, 'rb').read())
    fw = open(path_dir, 'wb')
    fw.write(data)
    fw.close()
    return True

@celery.task
def download_malware(access_key,secret_key,name_bucket,path_binarie, name_file,dir_download='/mnt/pst/soreldataset/'):
    redis_client = StrictRedis()
    try:
        session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
        s3 = session.client('s3')
        path_zip = f"{dir_download}/{name_file}.zip"
        path_file= f"{path_binarie}/{name_file}"
        logging.info(f"download {name_file}")
        s3.download_file(name_bucket, path_file, path_zip)
        data = zlib.decompress(open(path_zip, 'rb').read())
        path_mwl = f"{dir_download}/{name_file}"
        fw = open(path_mwl, 'wb')
        fw.write(data)
        fw.close()
        os.remove(path_zip)
    except:
        redis_client.rpush('filesdl', name_file)
        logging.error(f"error download {name_file}")
        return False

   
    return True
    
    
    
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


@celery.task(ignore_result=True, max_retries=3, time_limite=70)
def capa_extraction(path_rules, path_file,path_signatures):
    client_redis = StrictRedis(db=6, decode_responses=True)
    sigs = capa.main.get_signatures(path_signatures)
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
    else:
        return False

@celery.task
def rewrite_header_file(path_file):
    try:
        data = open(path_file, 'rb').read()

        pe = pefile.PE(data=data)
        if pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE:
            pe.FILE_HEADER.Machine = 0x14c
            pe.write(filename=path_file)
            pe.close()
    except:
        logging.error('error reformat %s' % path_file)
        pass

@celery.task
def clean_viv(path_file):

    if os.path.isfile(path_file):
        try:
            os.remove(path_file)
            logging.warning('the file %s has been deleted' % path_file)
        except:
            logging.error('delete has failed %s' % path_file)