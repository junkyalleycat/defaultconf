#!/usr/bin/env python3

import socket
from collections import namedtuple
import subprocess
import argparse
import ipaddress
import yaml
import json
from pathlib import Path
import hashlib

import lockfile 

default_run_path = Path('/var/run/defaultconf')
default_runcfg_path = Path('/var/db/defaultconf.json')

default_protocols = {'static', 'dhcp', 'ppp', 'ra'}
def validate_protocol(protocol):
    protocols = default_protocols
    if protocol in protocols:
        return True
    raise Exception(f'unknown protocol: {protocol}')

def calc_hash(s):
    m = hashlib.sha256()
    m.update(s.encode())
    return m.hexdigest()

def read_config(runcfg_path):
    if runcfg_path.exists():
        config = json.loads(runcfg_path.read_text())
    else:
        config = {}
    config['_original_hash'] = calc_hash(json.dumps(config, sort_keys=True))
    return config

def write_config(runcfg_path, config):
    current = dict(filter(lambda i: i[0] != '_original_hash', config.items()))
    current_text = json.dumps(current, sort_keys=True)
    if calc_hash(current_text) == config['_original_hash']:
        return
    lock = lockfile.LockFile(runcfg_path.with_suffix(f'{runcfg_path.suffix}.lock'))
    with lock:
        fresh_config = read_config(runcfg_path)
        # TODO just lock between the read and write and remove this failure scenario
        if config['_original_hash'] != fresh_config['_original_hash']:
            raise Exception('concurrent config modification')
        runcfg_path.write_text(current_text)

Gateway = namedtuple('Gateway', ['af', 'iface', 'protocol', 'addr', 'ts'])

def load_defaults(run_path):
    defaults = set()
    for entry in run_path.iterdir():
        if not entry.suffix == '.gateway':
            continue
        pretty_af, iface, protocol, _ = entry.name.split('.')
        af = parse_af(pretty_af)
        addr = ipaddress.ip_address(entry.read_text().strip())
        defaults.add(Gateway(af, iface, protocol, addr, entry.lstat().st_mtime))
    return defaults

def get_default_path(run_path, af, iface, protocol):
    pretty_af = to_pretty_af(af)
    return run_path.joinpath(f'{pretty_af}.{iface}.{protocol}.gateway')

# per address family, sorted by
# iface priority
# - protocol priority

def parse_af(af):
    if af == 'ip':
        return socket.AF_INET
    elif af == 'ip6':
        return socket.AF_INET6
    raise Exception(f'unknown af: {af}')

def to_pretty_af(af):
    if af == socket.AF_INET:
        return 'ip'
    elif af == socket.AF_INET6:
        return 'ip6'
    raise Exception(f'unknown af: {af}')

def default_sort_strategy(e):
    return e.ts

class GatewaySelect(namedtuple('GatewaySelect', ['af', 'iface', 'protocol'])):

    def matches(self, o):
        if self.af is not None:
            if self.af != o.af:
                return False
        if self.iface is not None:
            if self.iface != o.iface:
                return False
        if self.protocol is not None:
            if self.protocol != o.protocol:
                return False
        return True

    def to_data(self):
        return self._asdict()

    @staticmethod
    def from_data(data):
        return GatewaySelect(**data)

# af[ip,ip6] -> iface[] -> protocol[] -> addr[]
class DefaultConf:

    def __init__(self, config):
        self.config = config
        self.run_path = default_run_path
        self.sort_strategy = default_sort_strategy

    def add_default(self, af, iface, protocol, addr):
        entry = get_default_path(self.run_path, af, iface, protocol)
        entry.write_text(str(addr))

    def remove_default(self, af, iface, protocol, addr):
        entry = get_default_path(self.run_path, af, iface, protocol)
        entry.unlink()

    def get_default_iface(self):
        return self.config.get('default-iface', None)

    def set_default_iface(self, iface):
        if iface is None:
            if 'default-iface' in self.config:
                del self.config['default-iface']
        else:
            self.config['default-iface'] = iface

    def enable(self, af, iface, protocol):
        disabled = self.get_disabled()
        disabled -= { GatewaySelect(af, iface, protocol) }
        self.set_disabled(disabled)

    def disable(self, af, iface, protocol):
        disabled = self.get_disabled()
        disabled |= { GatewaySelect(af, iface, protocol) }
        self.set_disabled(disabled)

    def get_disabled(self):
        disabled = self.config.get('disabled', [])
        disabled = { GatewaySelect.from_data(e) for e in disabled }
        return disabled

    def set_disabled(self, disabled):
        self.config['disabled'] = [ e.to_data() for e in disabled ]

    def get_default(self, af, iface, protocol):
        defaults = load_defaults(self.run_path)

        if iface is None:
            iface = self.get_default_iface()
        select = GatewaySelect(af, iface, protocol)
        defaults = filter(select.matches, defaults)

        def enabled_filter(e):
            for disabled in self.get_disabled():
                if disabled.matches(e):
                    return False
            return True
        defaults = filter(enabled_filter, defaults)
        
        # run the defaults through the priority list
        # one at a time until a bucket matches

        sorted_defaults = sorted(defaults, key=self.sort_strategy, reverse=True) 
        return next(iter(sorted_defaults), None)

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='action')
    subparser = subparsers.add_parser('add')
    subparser.add_argument('-f', metavar='address-family')
    subparser.add_argument('-i', metavar='iface', required=True)
    subparser.add_argument('-p', metavar='protocol', required=True)
    subparser.add_argument('addr', metavar='address')
    subparser = subparsers.add_parser('remove')
    subparser.add_argument('-f', metavar='address-family')
    subparser.add_argument('-i', metavar='iface', required=True)
    subparser.add_argument('-p', metavar='protocol', required=True)
    subparser = subparsers.add_parser('set-default-iface')
    subparser.add_argument('iface', metavar='iface')
    subparser = subparsers.add_parser('get-default-iface')
    subparser = subparsers.add_parser('get')
    subparser.add_argument('-f', metavar='address-family', required=True)
    subparser.add_argument('-i', metavar='iface')
    subparser.add_argument('-p', metavar='protocol')
    subparser = subparsers.add_parser('disable')
    subparser.add_argument('-f', metavar='address-family')
    subparser.add_argument('-i', metavar='iface')
    subparser.add_argument('-p', metavar='protocol')
    subparser = subparsers.add_parser('enable')
    subparser.add_argument('-f', metavar='address-family')
    subparser.add_argument('-i', metavar='iface')
    subparser.add_argument('-p', metavar='protocol')
    args = parser.parse_args()

    run_path = default_run_path
    runcfg_path = default_runcfg_path

    run_path.mkdir(parents=True, exist_ok=True)

    config = read_config(runcfg_path)
    default_conf = DefaultConf(config)

    if args.action is None:
        raise Exception('action not specified')
    elif args.action == 'add':
        validate_protocol(args.p)
        af = parse_af(args.f)    
        addr = ipaddress.ip_address(args.addr)
        default_conf.add_default(af, args.i, args.p, addr)
    elif args.action == 'remove':
        af = parse_af(args.f)
        default_conf.remove_default(af, args.i, args.p)
    elif args.action == 'get':
        af = parse_af(args.f)
        default = default_conf.get_default(af, args.i, args.p)
        if default is not None:
            print(default.addr)
    elif args.action == 'set-default-iface':
        iface = None if args.iface == 'delete' else args.iface
        default_conf.set_default_iface(iface)
    elif args.action == 'get-default-iface':
        iface = default_conf.get_default_iface()
        if iface is not None:
            print(iface)
    elif args.action == 'enable':
        af = None if args.f is None else parse_af(args.f)
        default_conf.enable(af, args.i, args.p)
    elif args.action == 'disable':
        af = None if args.f is None else parse_af(args.f)
        default_conf.disable(af, args.i, args.p)
    else:
        raise Exception(f'unknown action: {args.action}')

    write_config(runcfg_path, config)

