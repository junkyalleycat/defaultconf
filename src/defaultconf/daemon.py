#!/usr/bin/env python3

import functools
import os
import logging
import signal
import threading
import concurrent.futures
import socket
import ipaddress

from . import bsdnetlink
from .common import *

class Trigger:

    def __init__(self):
        self.s = threading.BoundedSemaphore(1)
        self.acquire()

    def release(self):
        try:
            self.s.release()
        except ValueError:
            pass

    def acquire(self, blocking=True, timeout=None):
        return self.s.acquire(blocking=blocking, timeout=timeout)

def default_test(nettables, default):
    # filter links to link name
    try:
        link, = nettables.get_links(lambda e: e.name == default.link)
    except ValueError:
        # catch too few and too many,
        # TODO too many should never happen, consider throwing
        return False

    # skip if link isn't up
    if not link.up:
        return False

    # filter until you find an addr that works
    linkaddrs = nettables.get_addrs(lambda e: e.link_index == link.index)
    for addr in linkaddrs:
        if default.addr in addr.address.network:
            return True

    # filter all routes as next hops that support our case
    # TODO the hops could be across ifs right?
    linkroutes = nettables.get_routes(lambda e: e.link_index == link.index)
    for route in linkroutes:
        if default.addr in route.dst.network:
            return True

    return False

def normalize_default(defaultconf, nettables, snl, fib, af, af_default_dst):
    defaults = defaultconf.get_defaults(GatewaySelect(af=af))
    pdefault_test = functools.partial(default_test, nettables)
    default = next(iter(filter(pdefault_test, defaults)), None)
    link_index = None if default is None else bsdnetlink.if_nametoindex(snl, default.link)
    current_default = None
    try:
        current_default, = nettables.get_routes(lambda r: r.dst == af_default_dst)
    except ValueError:
        # too few or too many
        # TODO throw on too many?
        pass
    if default is None:
        if current_default is None:
            logging.debug("default==null, current_default==null, NOOP")
        else:
            logging.debug("default==null, current_default!=null, DELETE")
            bsdnetlink.delete_route(snl, fib, current_default.dst, current_default.gw, current_default.link_index)
    else:
        if current_default is None:
            logging.debug("default!=null, current_default!=null, SET")
            bsdnetlink.new_route(snl, fib, af_default_dst, default.addr, link_index)
        else:
            if current_default.gw == default.addr:
                logging.debug("default!=null, current_default!=null, default==current_default, NOOP")
            else:
                logging.debug("default!=null, current_default!=null, default!=current_default, UPDATE")
                bsdnetlink.delete_route(snl, fib, current_default.dst, current_default.gw, current_default.link_index)
                bsdnetlink.add_route(snl, fib, af_default_dst, default.addr, link_index)

def daemon(config):
    logging.basicConfig(level=logging.DEBUG)
    config.pid_path.write_text(str(os.getpid()))
    defaultconf = DefaultConf(config)

    # triggered to quit daemon
    finish_ev = threading.Event()

    # triggered whenever we want to reconsider the defaults
    trigger_ev = Trigger()

    executor = concurrent.futures.ThreadPoolExecutor()
    tasks = []
    tasks.append(executor.submit(finish_ev.wait))

    # handler for signals that terminate the daemon
    def sigterm_handler(*_):
        finish_ev.set()
    signal.signal(signal.SIGTERM, sigterm_handler)
    signal.signal(signal.SIGINT, sigterm_handler)

    # handler for signals that trigger state reload
    state_reload_ev = Trigger()
    def sigusr1_handler(*_):
        state_reload_ev.release()
    signal.signal(signal.SIGUSR1, sigusr1_handler)

    # wait for a signal to reload the state file
    def state_reload_handler():
        while not finish_ev.is_set():
            if not state_reload_ev.acquire(timeout=1):
                continue
            defaultconf.reload_state()
            trigger_ev.release()
    tasks.append(executor.submit(state_reload_handler))

    nettables = bsdnetlink.NetTables()
    tasks.append(executor.submit(bsdnetlink.maintain_nettables, finish_ev, trigger_ev, nettables))

    # wait for update events, evaulate the tables, possibly act
    inet4_default_dst = ipaddress.ip_network('0.0.0.0/0')
    inet6_default_dst = ipaddress.ip_network('::/0')
    def monitor():
        snl = bsdnetlink.SNL(bsdnetlink.NETLINK_ROUTE, read_timeout=1)
        while not finish_ev.is_set():
            if not trigger_ev.acquire(timeout=1):
                continue
            logging.debug("triggered")
            fib = config.fib
            try:
                normalize_default(defaultconf, nettables, snl, fib, socket.AF_INET, inet4_default_dst)
            except Exception as e:
                logging.error(e)
            try:
                normalize_default(defaultconf, nettables, snl, fib, socket.AF_INET6, inet6_default_dst)
            except Exception as e:
                logging.error(e)

    tasks.append(executor.submit(monitor))

    try:
        done, pending = concurrent.futures.wait(tasks, return_when=concurrent.futures.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        finish_ev.set()

