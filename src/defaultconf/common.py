#!/usr/bin/env python3

import logging
import signal
import os
import contextlib
import time
import socket
from collections import namedtuple
import ipaddress
import yaml
import json
from pathlib import Path
import filelock 

default_config_path = Path('/usr/local/etc/defaultconf.yaml')
default_state_path = Path('/var/db/defaultconf.state')
default_pid_path = Path('/var/run/defaultconf.pid')

def default_sort_strategy(e):
    return e.ts

class Gateway(namedtuple('Gateway', ['af', 'link', 'protocol', 'addr', 'ts'])):

    @staticmethod
    def from_data(data):
        kwargs = dict(data)
        kwargs['af'] = socket.AddressFamily[data['af']]
        kwargs['addr'] = ipaddress.ip_address(data['addr'])
        return Gateway(**kwargs)

    def to_data(self):
        data = self._asdict()
        data['af'] = self.af.name
        data['addr'] = str(self.addr)
        return data

class GatewaySelect(namedtuple('GatewaySelect', ['af', 'link', 'protocol'],
            defaults=[None, None, None])):

    def matches(self, o):
        if self.af is not None:
            if self.af != o.af:
                return False
        if self.link is not None:
            if self.link != o.link:
                return False
        if self.protocol is not None:
            if self.protocol != o.protocol:
                return False
        return True

    @staticmethod
    def from_data(data):
        kwargs = dict(data)
        if data.get('af') is not None:
            kwargs['af'] = socket.AddressFamily[data['af']]
        return GatewaySelect(**kwargs)

    def to_data(self):
        data = self._asdict()
        if self.af is not None:
            data['af'] = self.af.name
        return data

class Config(namedtuple('Config', ['state_path', 'priority', 'pid_path', 'fib'],
            defaults=[default_state_path, [], default_pid_path, 0])):
    
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

    def add(self, af, link, protocol, addr):
        # remove any other gateways that look like me
        self.remove(GatewaySelect(af, link, protocol))
        self.gateways.update({Gateway(af, link, protocol, addr, time.time())})

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
                try_signal_daemon(config)

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

def try_signal_daemon(config, *, ignore_failure=None):
    ignore_failure = True if ignore_failure is None else ignore_failure
    try:
        pid = int(config.pid_path.read_text())
        os.kill(pid, signal.SIGUSR1)
    except Exception as e:
        if ignore_failure:
            logging.error(e)
        else:
            raise

