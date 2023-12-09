#!/usr/bin/env python3

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

def daemon(config):
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
        while not finish_ev.is_set():
            if not trigger_ev.acquire(timeout=1):
                continue
            print("TRIGGERED!")

            def filter_defaults(af):
                defaults = defaultconf.get_defaults(GatewaySelect(af=af))
                found_default = None
                for default in defaults:
                    # filter links to link name
                    try:
                        linkaddrs, = nettables.get_links(lambda l: l.link.name == default.link)
                    except ValueError:
                        # catch too few and too many,
                        # TODO too many should never happen, consider throwing
                        continue
                    # skip if link isn't up
                    if not linkaddrs.link.up:
                        continue
                    # filter until you find an addr that works
                    for addr in linkaddrs.addrs:
                        if default.addr not in addr.address.network:
                            continue
                        found_default = default
                        break
                    if found_default:
                        break
                return found_default

            inet4_default = filter_defaults(socket.AF_INET)
            current_inet4_default = None
            try:
                current_inet4_default, = nettables.get_routes(lambda r: r.dst == inet4_default_dst)
            except ValueError:
                # too few or too many
                # TODO throw on too many?
                pass
            if inet4_default is None:
                if current_inet4_default is None:
                    print("default==null, current_default==null, NOOP")
                else:
                    print("default==null, current_default!=null, DELETE")
            else:
                if current_inet4_default is None:
                    print("default!=null, current_default!=null, SET")
                else:
                    print(current_inet4_default.gw)
                    print(inet4_default.addr)
                    if current_inet4_default.gw == inet4_default.addr:
                        print("default!=null, current_default!=null, default==current_default, NOOP")
                    else:
                        print("default!=null, current_default!=null, default!=current_default, UPDATE")
#            print(current_inet4_default)

#            print(filter_defaults(socket.AF_INET))
#            print(filter_defaults(socket.AF_INET6))

    tasks.append(executor.submit(monitor))

    try:
        done, pending = concurrent.futures.wait(tasks, return_when=concurrent.futures.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        finish_ev.set()

