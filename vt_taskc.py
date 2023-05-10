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
    
    session = boto3.Session(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key
)
    s3 = session.client('s3')
    path_zip = f"{dir_download}/{name_file}.zip"
    s3.download_file(name_bucket, path_binarie, path_zip)
    data = zlib.decompress(open(path_zip, 'rb').read())
    path_mwl = f"{dir_download}/{name_file}"
    fw = open(path_mwl, 'wb')
    fw.write(data)
    fw.close()

   
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
