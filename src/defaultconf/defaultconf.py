#!/usr/bin/env python3

import contextlib
import time
import logging
import socket
from collections import namedtuple
import argparse
import ipaddress
import yaml
import json
from pathlib import Path
import filelock 

from . import daemon
from . import bsdnetlink

default_config_path = Path('/usr/local/etc/defaultconf.yaml')
default_state_path = Path('/var/db/defaultconf.state')
default_pid_path = Path('/var/run/defaultconf.pid')

default_protocols = {'static', 'dhcp', 'ppp', 'ra'}
def validate_protocol(protocol):
    protocols = default_protocols
    if protocol not in protocols:
        raise Exception(f'unknown protocol: {protocol}')

def default_sort_strategy(e):
    return e.ts

class Gateway(namedtuple('Gateway', ['af', 'iface', 'protocol', 'addr', 'ts'])):

    @staticmethod
    def from_data(data):
        kwargs = dict(data)
        kwargs['addr'] = ipaddress.ip_address(data['addr'])
        return Gateway(**kwargs)

    def to_data(self):
        data = self._asdict()
        data['addr'] = str(self.addr)
        return data

class GatewaySelect(namedtuple('GatewaySelect', ['af', 'iface', 'protocol'],
            defaults=[None, None, None])):

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

class Config(namedtuple('Config', ['state_path', 'priority', 'pid_path'],
            defaults=[default_state_path, [], default_pid_path])):
    
    @staticmethod
    def from_data(data):
        kwargs = dict(data)
        kwargs['priority'] = [ GatewaySelect.from_data(e) for e in data.get('priority', []) ]
        return Config(**kwargs)

    @staticmethod
    def from_path(path):
        if path.exists():
            return Config.from_data(yaml.load(path.read_text(), Loader=yaml.SafeLoader))
        return Config()

class State(namedtuple('State', ['gateways', 'disabled'],
            defaults=[set(), set()])):

    def add(self, af, iface, protocol, addr):
        # remove any other gateways that look like me
        self.remove(GatewaySelect(af, iface, protocol))
        self.gateways.update({Gateway(af, iface, protocol, addr, time.time())})

    def remove(self, select):
        matches = set(filter(select.matches, self.gateways))
        self.gateways.difference_update(matches)

    def disable(self, select):
        self.disabled.update({select})

    def enable(self, select):
        matches = set(filter(select.matches, self.disabled))
        self.disabled.difference_update(matches)

    def deepcopy(self):
        return State.from_data(json.loads(json.dumps(self.to_data())))

    @staticmethod
    def from_data(data):
        kwargs = dict(data)
        kwargs['gateways'] = { Gateway.from_data(e) for e in data.get('gateways', []) }
        kwargs['disabled'] = { GatewaySelect.from_data(e) for e in data.get('disabled', []) }
        return State(**kwargs)

    def to_data(self):
        data = self._asdict()
        data['gateways'] = [ e.to_data() for e in self.gateways ]
        data['disabled'] = [ e.to_data() for e in self.disabled ]
        return data

    @staticmethod
    def from_path(path):
        if path.exists():
            return State.from_data(json.loads(path.read_text()))
        return State()

    def to_path(self, path):
        path.write_text(json.dumps(self.to_data()))

    @staticmethod
    @contextlib.contextmanager
    def update(config):
        state_path = config.state_path
        state_lock_path = Path(f'{state_path}.lock')
        with filelock.FileLock(state_lock_path):
            state = State.from_path(state_path)
            pre = json.dumps(state.to_data(), sort_keys=True)
            yield state
            post = json.dumps(state.to_data(), sort_keys=True)
            if pre != post:
                state.to_path(state_path)
                daemon.try_signal_daemon(config)

class DefaultConf:

    def __init__(self, config):
        self.config = config
        self.sort_strategy = default_sort_strategy
        self.reload_state()

    def reload_state(self):
        self.state = State.from_path(self.config.state_path)

    def get_defaults(self, select):
        # save state instance incase we reload
        state = self.state
        defaults = filter(select.matches, state.gateways)

        def enabled_filter(e):
            for disabled in state.disabled:
                if disabled.matches(e):
                    return False
            return True
        defaults = filter(enabled_filter, defaults)
        
        # run the defaults through the priority list
        # one at a time until a bucket matches
        # 1) for every priority, find ifaces that match it
        by_priority = [ [] for i in range(len(self.config.priority)+1) ]
        for default in defaults:
            match_found = False
            for i in range(len(self.config.priority)):
                if self.config.priority[i].matches(default):
                    by_priority[i].append(default)
                    match_found = True
                    break
            if not match_found:
                by_priority[-1].append(default)
        # 2) for all priority buckets, sort them and append the output
        defaults = []
        for bucket in by_priority:
            defaults.extend(list(sorted(bucket, key=self.sort_strategy, reverse=True)))

        return defaults

def parse_af(af):
    if af == 'ip':
        return int(socket.AF_INET)
    elif af == 'ip6':
        return int(socket.AF_INET6)
    raise Exception(f'unknown af: {af}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', metavar='config-path', type=Path, default=default_config_path)
    subparsers = parser.add_subparsers(dest='action')
    subparser = subparsers.add_parser('add')
    subparser.add_argument('-f', metavar='address-family', required=True)
    subparser.add_argument('-i', metavar='iface', required=True)
    subparser.add_argument('-p', metavar='protocol', required=True)
    subparser.add_argument('addr', metavar='address')
    subparser = subparsers.add_parser('remove')
    subparser.add_argument('-f', metavar='address-family')
    subparser.add_argument('-i', metavar='iface')
    subparser.add_argument('-p', metavar='protocol')
    subparser = subparsers.add_parser('get-default')
    subparser.add_argument('-f', metavar='address-family')
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
    subparser = subparsers.add_parser('daemon')
    subparser = subparsers.add_parser('signal-daemon')
    args = parser.parse_args()

    config = Config.from_path(args.c)

    if args.action is None:
        raise Exception('action not specified')
    elif args.action == 'daemon':
        daemon.daemon(config)
    elif args.action == 'signal-daemon':
        daemon.try_signal_daemon(config, ignore_failure=False)
    elif args.action == 'add':
        validate_protocol(args.p)
        af = parse_af(args.f)    
        addr = ipaddress.ip_address(args.addr)
        with State.update(config) as state:
            state.add(af, args.i, args.p, addr)
    elif args.action == 'remove':
        af = parse_af(args.f)
        with State.update(config) as state:
            state.remove(GatewaySelect(af, args.i, args.p))
    elif args.action == 'get-default':
        af = None if args.f is None else parse_af(args.f)
        default_conf = DefaultConf(config)
        select = GatewaySelect(af, args.i, args.p)
        default = next(iter(default_conf.get_defaults(select)), None)
        if default is not None:
            print(json.dumps(default.to_data()))
    elif args.action == 'enable':
        af = None if args.f is None else parse_af(args.f)
        with State.update(config) as state:
            state.enable(GatewaySelect(af, args.i, args.p))
    elif args.action == 'disable':
        af = None if args.f is None else parse_af(args.f)
        with State.update(config) as state:
            state.disable(GatewaySelect(af, args.i, args.p))
    else:
        raise Exception(f'unknown action: {args.action}')

