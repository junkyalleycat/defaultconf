#!/usr/bin/env python3

import socket
import argparse
import ipaddress
import json
from pathlib import Path

from .common import *

default_protocols = {'static', 'dhcp', 'ppp', 'ra'}
def validate_protocol(protocol):
    protocols = default_protocols
    if protocol not in protocols:
        raise Exception(f'unknown protocol: {protocol}')

def parse_af(af):
    if af == 'inet':
        return socket.AF_INET
    elif af == 'inet6':
        return socket.AF_INET6
    raise Exception(f'unknown af: {af}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', metavar='config-path', type=Path, default=default_config_path)
    parser.add_argument('-d', action='store_true')
    subparsers = parser.add_subparsers(dest='action')
    subparser = subparsers.add_parser('add')
    subparser.add_argument('-f', metavar='address-family', required=True)
    subparser.add_argument('-l', metavar='link', required=True)
    subparser.add_argument('-p', metavar='protocol', required=True)
    subparser.add_argument('addr', metavar='address')
    subparser = subparsers.add_parser('remove')
    subparser.add_argument('-f', metavar='address-family')
    subparser.add_argument('-l', metavar='link')
    subparser.add_argument('-p', metavar='protocol')
    subparser = subparsers.add_parser('get-default')
    subparser.add_argument('-f', metavar='address-family')
    subparser.add_argument('-l', metavar='link')
    subparser.add_argument('-p', metavar='protocol')
    subparser = subparsers.add_parser('disable')
    subparser.add_argument('-f', metavar='address-family')
    subparser.add_argument('-l', metavar='link')
    subparser.add_argument('-p', metavar='protocol')
    subparser = subparsers.add_parser('enable')
    subparser.add_argument('-f', metavar='address-family')
    subparser.add_argument('-l', metavar='link')
    subparser.add_argument('-p', metavar='protocol')
    subparser = subparsers.add_parser('daemon')
    subparser = subparsers.add_parser('signal-daemon')
    args = parser.parse_args()

    if args.d:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    config = Config.from_path(args.c)

    if args.action is None:
        raise Exception('action not specified')
    elif args.action == 'daemon':
        from . import daemon
        daemon.daemon(config)
    elif args.action == 'signal-daemon':
        try_signal_daemon(config, ignore_failure=False)
    elif args.action == 'add':
        validate_protocol(args.p)
        af = parse_af(args.f)    
        addr = ipaddress.ip_address(args.addr)
        with State.update(config) as state:
            state.add(af, args.l, args.p, addr)
    elif args.action == 'remove':
        af = parse_af(args.f)
        with State.update(config) as state:
            state.remove(GatewaySelect(af, args.l, args.p))
    elif args.action == 'get-default':
        af = None if args.f is None else parse_af(args.f)
        default_conf = DefaultConf(config)
        select = GatewaySelect(af, args.l, args.p)
        default = next(iter(default_conf.get_defaults(select)), None)
        if default is not None:
            print(json.dumps(default.to_data()))
    elif args.action == 'enable':
        af = None if args.f is None else parse_af(args.f)
        with State.update(config) as state:
            state.enable(GatewaySelect(af, args.l, args.p))
    elif args.action == 'disable':
        af = None if args.f is None else parse_af(args.f)
        with State.update(config) as state:
            state.disable(GatewaySelect(af, args.l, args.p))
    else:
        raise Exception(f'unknown action: {args.action}')

