#!/usr/bin/env python3

import argparse
import datetime
import fcntl
import hashlib
import json
import logging
import os
import re
import socket
import time
import traceback
import sys


_LOG_LEVELS = dict(
  DEBUG=logging.DEBUG,
  INFO=logging.INFO,
  WARNING=logging.WARNING,
  ERROR=logging.ERROR,
)

_DB_FILE_NAME = 'glst_db.json'
_CFG_FILE_NAME = 'glst.conf.json'

_DEFAULT_CONFIG = dict(
  reject_msg='451 Please try again later',
  reject_error=19,
  timeout=300,
  expire_timeout=604800,
  lame_timeout=7200,
  cleanup_interval=3600,
  error_return=0,
  whitelist_address=[
    '127.0.0.1',
  ],
  whitelist_domains=[
    'google.com',
    'yahoo.com',
    'outlook.com',
  ],
  blacklist_domains = [],
)


class FileLock(object):

  def __init__(self, path):
    self._fd = open(path, mode='wb')

  def __enter__(self):
    fcntl.lockf(self._fd, fcntl.LOCK_EX)
    return self

  def __exit__(self, ex_type, ex_value, traceback):
    fcntl.lockf(self._fd, fcntl.LOCK_UN)
    return False



def make_object(d):
  class Obj:
    pass

  obj = Obj()
  for k, v in d.items():
    if isinstance(v, dict):
      v = make_object(v)
    setattr(obj, k, v)

  return obj


def log(lev, msg):
  for l in msg.split('\n'):
    logging.log(lev, l)


def setup_logging(args):
  log_level = _LOG_LEVELS[args.log_level]
  formatter = logging.Formatter(
    fmt='%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')
  handlers = []

  h = logging.StreamHandler()
  h.setLevel(log_level)
  h.setFormatter(formatter)
  handlers.append(h)

  if args.log_file:
    h = logging.FileHandler(args.log_file)
    h.setLevel(log_level)
    h.setFormatter(formatter)
    handlers.append(h)

  logging.basicConfig(level=log_level, handlers=handlers)


def unverp(a):
  m = re.match(r'([^+@]+)\+[^@]+(@.*)', a)

  return m.group(1) + m.group(2) if m else a


def ensure(data, name, vtype):
  v = data.get(name, None)
  if v is None:
    v = vtype()
    data[name] = v

  return v


def get_time(data, name):
  return datetime.datetime.fromisoformat(data[name])


def time_diff(lhs, rhs):
  return (lhs - rhs).total_seconds()


def load_json(path):
  with open(path, mode='r') as f:
    return json.load(f)


def save_json(path, data, indent=2):
  with open(path, mode='w') as fp:
    json.dump(data, fp, indent=indent)


def script_path():
  return os.path.dirname(os.path.realpath(__file__))


def load_config(path):
  cfg = dict(**_DEFAULT_CONFIG)
  if path is None:
    lpath = os.path.join(script_path(), _CFG_FILE_NAME)
    if os.path.exists(lpath):
      path = lpath
  if path is not None:
    log(logging.DEBUG, f'Loading config from {path}')
    cfg.update(load_json(path))

  return make_object(cfg)


def load_db(path):
  return load_json(path) if os.path.exists(path) else dict()


def get_db_path(path):
  if path is None:
    path = os.path.join(script_path(), _DB_FILE_NAME)

  return path


def get_host_name(addr):
  try:
    return socket.gethostbyaddr(addr)[0]
  except:
    log(logging.INFO, f'Unable to resolve address: {addr}')


def get_domain(addr):
  parts = addr.split('.')
  return '.'.join(parts[-2:]) if len(parts) > 1 else addr


def split_address(addr):
  m = re.match(r'\[([^\]]+)\]:(\d+)', addr)

  return (m.group(1), int(m.group(2))) if m else (addr, None)


def key_hash(d):
  h = hashlib.sha1()
  h.update(d.encode())

  return h.hexdigest()


def process_addresses(cfg, db, args, remote_host, remote_domain):
  sender = args.sender.lower()

  waits = 0
  now = datetime.datetime.now()
  iso_now = datetime.datetime.isoformat(now)
  act_db = ensure(db, 'active', dict)
  for rcpt in args.rcpt:
    rcpt = unverp(rcpt.lower())
    key = key_hash(';'.join([sender, rcpt, remote_domain]))
    dbe = act_db.get(key, None)
    if dbe is None:
      dbe = dict(ctime=iso_now, ltime=iso_now, count=1, host=remote_host,
                 sender=sender, rcpt=rcpt)
      act_db[key] = dbe
      waits += 1
    else:
      dbe['count'] += 1
      dbe['ltime'] = iso_now
      ctime = get_time(dbe, 'ctime')
      if time_diff(now, ctime) < cfg.timeout:
        waits += 1

  if waits and args.reject_file and cfg.reject_msg:
    with open(args.reject_file, mode='w') as f:
      f.write(cfg.reject_msg + '\n')

  return cfg.reject_error if waits else 0


def cleanup(cfg, db):
  now = datetime.datetime.now()
  last_cleanup = datetime.datetime.fromisoformat(
    ensure(db, 'last_cleanup',
           lambda: datetime.datetime.isoformat(now)))
  if time_diff(now, last_cleanup) > cfg.cleanup_interval:
    act_db = ensure(db, 'active', dict)
    xkeys = []
    for key, dbe in act_db.items():
      elapsed = time_diff(now, get_time(dbe, 'ltime'))
      if ((elapsed > cfg.expire_timeout) or
          (dbe['count'] == 1 and elapsed > cfg.lame_timeout)):
        xkeys.append(key)

    log(logging.DEBUG, f'Dropping {len(xkeys)} keys')
    for key in xkeys:
      act_db.pop(key, None)

    db['last_cleanup'] = datetime.datetime.isoformat(now)


def run(cfg, args):
  remote_address, remote_port = split_address(args.remote_address)
  if remote_address in cfg.whitelist_address:
    log(logging.DEBUG, f'Whitelisted address: {remote_address}')
    return 0
  remote_host = get_host_name(remote_address)
  if remote_host is None:
    return cfg.reject_error
  remote_domain = get_domain(remote_host)
  if remote_domain in cfg.whitelist_domains:
    log(logging.DEBUG, f'Whitelisted domain: {remote_domain}')
    return 0
  if remote_domain in cfg.blacklist_domains:
    log(logging.DEBUG, f'Blacklisted domain: {remote_domain}')
    return cfg.reject_error

  db_path = get_db_path(args.db_file)
  log(logging.DEBUG, f'Using DB file {db_path}')

  with FileLock(db_path + '.__lock__') as lock:
    db = load_db(db_path)
    code = process_addresses(cfg, db, args, remote_host, remote_domain)
    cleanup(cfg, db)
    save_json(db_path, db)

  return code


def main(args):
  cfg = load_config(args.config_file)
  try:
    code = run(cfg, args)
  except Exception as ex:
    fex = traceback.format_exc()
    log(logging.ERROR, f'{fex}\n{ex}')
    code = cfg.error_return

  sys.exit(code)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Mail greylisting utility',
                                   formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('--config_file', type=str,
                      help='The path to the configuration file')
  parser.add_argument('--sender', type=str, required=True,
                      help='The sender email adddres')
  parser.add_argument('--remote_address', type=str, required=True,
                      help='The sender network adddres')
  parser.add_argument('--rcpt', action='append',
                      help='The recipient email adddres')
  parser.add_argument('--db_file', type=str,
                      help='The path to the DB file')
  parser.add_argument('--reject_file', type=str,
                      help='The path to the file which will receive the error message')
  parser.add_argument('--log_level', type=str, default='DEBUG',
                      help='The logging level (DEBUG, INFO, WARNING, ERROR)')
  parser.add_argument('--log_file', type=str,
                      help='The log file path')

  args = parser.parse_args()
  setup_logging(args)
  main(args)
