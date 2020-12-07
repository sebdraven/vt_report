import argparse
import glob
import json
import os
import sys
import time

from redis import StrictRedis

from vt_taskc import vt_report, push
from label import label

redis_client = StrictRedis()


def all_files(path):
    return [json.load(open(json_file))['sha256'] for json_file in glob.glob(path)
             if os.path.isfile(json_file) and 'sha256' in json.load(open(json_file))]


def vt_report_launcher(api_key):
    while True:
        h = redis_client.lpop('files')
        vt_report.delay(h.decode(), api_key)
        time.sleep(1)


def record_file(malware_data='/data/malware_samples/DATASET'):

    number_file = 0
    for root, dirs, files in os.walk(malware_data):
        for name in files:
            push.delay(name)


def label(json_dir='jsons'):
    json_path = os.path.join(os.path.dirname(__file__), json_dir)
    for root, dir, files in os.walk(json_path):
        for name in files:
            label.delay(name)


def parse_command_line():
    parser = argparse.ArgumentParser(description='VT Labelling')
    parser.add_argument('--record', dest='record', help='Command to record all files name in redis')
    parser.add_argument('--vt_report', dest='vt_report', help='Launch report catcher of VT')
    parser.add_argument('--label', dest='label', help='labelling vt report')
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_command_line()
    if args.record:
        record_file()
    if args.vt_report:
        vt_report_launcher(args.vt_report)