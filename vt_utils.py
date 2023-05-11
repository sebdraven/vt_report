import argparse
import glob
import json
import logging
import os
import sys
import time
import shutil
import os.path
from redis import StrictRedis

from vt_taskc import vt_report, push,unzip_file,rewrite_header_file
from label import process

try:
    from vt_taskc import capa_extraction,clean_viv
    import ZODB, ZODB.FileStorage
    import capa.rules
    import capa.main
    import lief

except:
    pass


def all_files(path):
    return [json.load(open(json_file))['sha256'] for json_file in glob.glob(path)
            if os.path.isfile(json_file) and 'sha256' in json.load(open(json_file))]


def vt_report_launcher(api_key):
    redis_client = StrictRedis()
    while True:
        h = redis_client.lpop('files')
        vt_report.delay(h.decode(), api_key)
        time.sleep(1)


def record_file(max,malware_data='/data/malware_samples/DATASET'):
    number_file = 0
    print('start record file')
    for root, dirs, files in os.walk(malware_data):
        for name in files:
            print('name file %s' % name)
            path_file = os.path.join(root, name)
            push.delay(path_file)
            number_file += 1
            if number_file == max:
                break
            if number_file % 10000 == 0:
                print('number file to record %s' % number_file)

def label(json_dir='jsons', debug=True):
    json_path = os.path.join(os.path.dirname(__file__), json_dir)
    number_file = 0
    for root, dir, files in os.walk(json_path):
        for name in files:
            path = os.path.join(root, name)
            process.delay(path)
            if debug:
                number_file += 1
        if number_file == 1:
            break


def createobjectrules(path='mydata.fs', rules=''):
    storage = ZODB.FileStorage.FileStorage(path)
    db = ZODB.DB(storage)

    con = db.open()
    if con:
        with db.transaction() as connection:
            connection.root.rules = rules
        db.close()
    return path


def filter_dataset(malware_dataset):
    redis_client = StrictRedis(db=6, decode_responses=True)
    for root, dir, files in os.walk(malware_dataset):
        for name in files:
            path_file = os.path.join(root, name)
            capa_record = False

            path_dir = 'jsons_capa/%s/%s/%s/%s' % (name[0:2], name[2:4], name[4:6], name[6:8])
            file_capa = os.path.join(path_dir, '%s.capa' % name)

            if not os.path.isfile(file_capa) and not path_file.endswith('viv') \
                    and lief.is_pe(path_file):
                redis_client.rpush('files', path_file)


def record_clean(malware_data='/data/malware_samples/DATASET'):
    client_redis = StrictRedis(db=6, decode_responses=True)
    for root, dirs, files in os.walk(malware_data):
        for name in files:
            if 'viv' in name:
                path_file = os.path.join(root, name)
                client_redis.rpush('clean', path_file)
                logging.info('file %s is recorded' % path_file)


def clean():
    client_redis = StrictRedis(db=6, decode_responses=True)
    path_file = client_redis.lpop('clean')
    while path_file:
        if type(path_file) == bytes:
            path_file = path_file.decode()
        clean_viv.delay(path_file)
        path_file = client_redis.lpop('clean')


def launch_capa(path_rule):
    redis_client = StrictRedis(db=6, decode_responses=True)
    path_file = redis_client.lpop('files')

    while path_file:
        if not redis_client.hexists('files failed', path_file):
            capa_extraction.delay(path_rule, path_file)
            path_file = redis_client.lpop('files')


def stats(jsons_capa='jsons_capa', jsons_report='jsons'):
    stats_jsons_capa = 0
    stats_jsons_vt = 0
    for root, dir, files in os.walk(jsons_capa):
        stats_jsons_capa += len(files)
    print('jsons capa: %s \n' % stats_jsons_capa)
    for root, dir, files in os.walk(jsons_report):
        stats_jsons_vt += len(files)
    print('jsons vt: %s' % stats_jsons_vt)

def load_zip(malwaredataset='/mnt/pst/soreldataset/'):
    redis_client = StrictRedis(db=6, decode_responses=True)
    for root, dirs, files in os.walk(malwaredataset):
        for name in files:
            path_file = os.path.join(root, name)
            print("path file %s" % path_file)
            if path_file.endswith('.zip'):
                redis_client.rpush('files', path_file)

def unzip_launcher():
    redis_client = StrictRedis(db=6, decode_responses=True)
    path_file = redis_client.lpop('files')
    while path_file:
        unzip_file.delay(path_file)
        path_file = redis_client.lpop('files')

def move_unzip_file(directory_unzip='/mnt/pst/dataset/sorel_unzip/',malwaredataset='/mnt/pst/soreldataset/'):
    for root,dirs, files in os.walk(directory_unzip):
        for name in files:
            path_file = os.path.join(root, name)
            hash_file = name.split('.')[0]
            path_to_move = os.path.join(malwaredataset,hash_file)
            print('path to move %s' % path_to_move)
        

def rewrite_header():
    redis_client = StrictRedis(db=6, decode_responses=True)
    path_file = redis_client.lpop('files')
    while path_file:
        rewrite_header_file.delay(path_file)
        path_file = redis_client.lpop('files')

def parse_command_line():
    parser = argparse.ArgumentParser(description='VT Labelling')
    parser.add_argument('--record', dest='record',action='store_true' ,help='Command to record all files name in redis')
    parser.add_argument('--max', dest='max', help='max number of file to record',default=10)
    parser.add_argument('--vt_report', dest='vt_report', help='Launch report catcher of VT')
    parser.add_argument('--label', dest='label', help='labelling vt report')
    parser.add_argument('--capa', dest='capa', help='rules')
    parser.add_argument('--malwaredataset', dest='mlwdataset', help='malwaredataset')
    parser.add_argument('--filter', action='store_true', dest='filter')
    parser.add_argument('--stats', action='store_true', dest='stats')
    parser.add_argument('--clean', action='store_true', dest='clean')
    parser.add_argument('--filter_clean', action='store_true', dest='flc')
    parser.add_argument('--unzip', action='store_true', dest='unzip')
    parser.add_argument('--rw', action='store_true', dest='rewrite_header')
    parser.add_argument('--lz', action='store_true', dest='load_zip')
    parser.add_argument('--mv', action='store_true', dest='move_unzip')
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_command_line()
    if args.record:
        if not args.mlwdataset:
            record_file(args.max)
        else:
            record_file(args.max,malware_data=args.mlwdataset)
    if args.vt_report:
        vt_report_launcher(args.vt_report)
    if args.label:
        label(debug=False)
    if args.filter and args.mlwdataset:
        filter_dataset(args.mlwdataset)
    if args.capa:
        launch_capa(args.capa)
    if args.stats:
        stats()
    if args.flc:
        record_clean()
    if args.clean:
        clean()
    if args.unzip:
        unzip_launcher()
    if args.rewrite_header:
        rewrite_header()
    if args.load_zip:
        load_zip()
    if args.move_unzip:
        move_unzip_file()