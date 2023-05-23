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
from capa.main import compute_layout
from capa.engine import *
import logging
import zlib
import boto3
import pefile
import shutil


celery_broker = 'redis://127.0.0.1:6379/5'
celery_backend = 'redis://127.0.0.1:6379/5'

celery = Celery('tasks', broker=celery_broker, backend= celery_backend)

@celery.task(ignore_result=True)

def push(name):
    redis_client = StrictRedis(db=6 , decode_responses=True)
    redis_client.rpush('files', name)

    if redis_client.llen('files') % 10000 == 0:
        print('number file to record %s' % redis_client.llen('files'))
    return True
@celery.task(ignore_result=True)
def unzip_file(path_file,dir_unzip='/mnt/pst/dataset/sorel_unzip/', malware_dataset='/mnt/data/soreldataset'):
    name_file = os.path.basename(path_file)
    
    hash_file = name_file.split('.')[0]
    path_unzip_file = os.path.join(dir_unzip,hash_file)
    data = zlib.decompress(open(path_file, 'rb').read())
    pe = pefile.PE(data=data)
    if pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE:
        pe.FILE_HEADER.Machine = 0x014c
    else:
        pe.FILE_HEADER.Machine = 0x8664
    pe.write(filename=path_unzip_file)
    shutil.move(path_unzip_file, os.path.join(malware_dataset,hash_file))
    return True

@celery.task(ignore_result=True)
def download_malware(access_key,secret_key,name_bucket,path_file, name_file,dir_download='/mnt/data/soreldataset'):
    client_redis = StrictRedis(db=6, decode_responses=True)
    try:
        session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
        s3 = session.client('s3')
        path_zip = f"{dir_download}/{name_file}.zip"
       
        logging.info(f"download {name_file}")
        s3.download_file(name_bucket, path_file, path_zip)
        data = zlib.decompress(open(path_zip, 'rb').read())
        path_mwl = f"{dir_download}/{name_file}"
        pe = pefile.PE(data=data)
        if pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE:
            pe.FILE_HEADER.Machine = 0x014c
        else:
            pe.FILE_HEADER.Machine = 0x8664
        pe.write(filename=path_mwl)
        os.remove(path_zip)
        client_redis.incr('files_success')
    except Exception as e:
        if e.response['Error']['Code'] == '404':
            print("Le fichier n'existe pas sur S3.")
            client_redis.rpush('files_not_found', path_file)
            return False
        if e.response['Error']['Code'] == '403':
            client_redis.rpush('files_forbidden', path_file) 
            return False
        else:
            # Gérer d'autres exceptions ici si nécessaire
            print("Une erreur s'est produite :", e)
            return False
   
    return True
    
    
    
@celery.task(ignore_result=True)
def check_file_exists(bucket_name, file_key, access_key, secret_key):
    client_redis = StrictRedis(db=6, decode_responses=True)
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    s3 = session.client('s3')
    try:
        s3.head_object(Bucket=bucket_name, Key=file_key)
        print("Le fichier existe sur S3.")
        client_redis.rpush('filesdl', file_key)
        return True
    except Exception as e:
        if e.response['Error']['Code'] == '404':
            print("Le fichier n'existe pas sur S3.")
            client_redis.rpush('files_not_found', file_key)
            return False
        if e.response['Error']['Code'] == '403':
            client_redis.rpush('files_forbidden', file_key) 
            return False
        else:
            # Gérer d'autres exceptions ici si nécessaire
            print("Une erreur s'est produite :", e)
            return False



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
def capa_extraction(path_file,path_rules='/mnt/data/capa-rules-5.1.0/',path_signatures='/mnt/data/capa-5.1.0/sigs'):
    client_redis = StrictRedis(db=6, decode_responses=True)
    sigs = capa.main.get_signatures(path_signatures)
    rules = capa.main.get_rules([path_rules])
  
    capa_json = None
    try:
        extractor = capa.main.get_extractor(path_file, 'auto','windows','vivisect', sigs,disable_progress=True)
        capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
        meta = capa.main.collect_metadata(['lib'], path_file,'pe','windows', [path_rules], extractor)
        meta["analysis"].update(counts)
        meta["analysis"]["layout"] = compute_layout(rules, extractor, capabilities)
        capa_json=capa.render.json.render(meta, rules, capabilities)

    except:
        client_redis.hset('file failed', key=path_file, value=1)

    if capa_json:
        name_file = os.path.basename(path_file)
        path_dir = '/mnt/data/jsons_capa'
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

@celery.task(ignore_result=True)
def rewrite_header_file(path_file):
    
    try:
        data = open(path_file, 'rb').read()

        pe = pefile.PE(data=data)
        if pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE:
            pe.FILE_HEADER.Machine = 0x14c
            pe.write(filename=path_file)
            pe.close()
        else:
            pe.FILE_HEADER.Machine = 0x8664
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