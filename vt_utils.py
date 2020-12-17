import argparse
import glob
import json
import os
import sys
import time
import os.path
from redis import StrictRedis

from vt_taskc import vt_report, push
from label import process
from capa_workers import capa_extraction
import ZODB, ZODB.FileStorage
import capa.rules
import capa.main




def all_files(path):
    return [json.load(open(json_file))['sha256'] for json_file in glob.glob(path)
             if os.path.isfile(json_file) and 'sha256' in json.load(open(json_file))]


def vt_report_launcher(api_key):
    redis_client = StrictRedis()
    while True:
        h = redis_client.lpop('files')
        vt_report.delay(h.decode(), api_key)
        time.sleep(1)


def record_file(malware_data='/data/malware_samples/DATASET'):

    number_file = 0
    for root, dirs, files in os.walk(malware_data):
        for name in files:
            push.delay(name)


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

def createobjectrules(path='mydata.fs',rules=''):
    rules = capa.main.get_rules(rules, disable_progress=True)
    rules = capa.rules.RuleSet(rules)

    storage = ZODB.FileStorage.FileStorage(path)
    db = ZODB.DB(storage)

    con = db.open()
    if con:
        with db.transaction() as connection:
            connection.root.rules = rules
        db.close()
    return path


def launch_capa(db_rules,path_rules, malware_dataset):
    for root, dir, files in os.walk(malware_dataset):
            for name in files:
                path_file = os.path.join(root, name)
                capa_extraction.delay(db_rules,path_rules, path_file)

def parse_command_line():
    parser = argparse.ArgumentParser(description='VT Labelling')
    parser.add_argument('--record', dest='record', help='Command to record all files name in redis')
    parser.add_argument('--vt_report', dest='vt_report', help='Launch report catcher of VT')
    parser.add_argument('--label', dest='label', help='labelling vt report')
    parser.add_argument('--capa', dest='capa', help='rules')
    parser.add_argument('--malwaredataset', dest='mlwdataset', help='malwaredataset')
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_command_line()
    if args.record:
        record_file()
    if args.vt_report:
        vt_report_launcher(args.vt_report)
    if args.label:
        label(debug=False)
    if args.capa and args.mlwdataset:
        path = createobjectrules(rules=args.capa)
        print('record rules %s' % path)
        launch_capa(path, args.capa, args.mlwdataset)