#!/usr/bin/env python3

from hashlib import sha256
import ctypes
import logging
import os
from pathlib import *
import concurrent.futures
import signal
import queue
import threading
from ipaddress import *
from collections import namedtuple
import socket
import json
import argparse

from .bsdnet import *

# TODO fib shit for all of this stuff

def parse_addr(addr):
    if addr.sa_family == socket.AF_INET:
        addr_in = sockaddr_in.from_sockaddr(addr)
        return ip_address(bytes(addr_in.sin_addr))
    elif addr.sa_family == socket.AF_INET6:
        addr6_in = sockaddr_in6.from_sockaddr(addr)
        return ip_address(bytes(addr6_in.sin6_addr))
    else:
        raise Exception(f'unsupported sa_family: {addr.sa_family}')
   
def dump_links(snl):
    nw = snl.new_writer()
    hdr = nw.create_msg_request(RTM_GETLINK)
    hdr.nlmsg_flags |= NLM_F_DUMP
    hdr = nw.finalize_msg()

    snl.send_message(hdr)
    while hdr := snl.read_reply_multi(hdr.nlmsg_seq):
        yield parse_nlmsg_link(snl, hdr)

def dump_addrs(snl):
    nw = snl.new_writer()
    hdr = nw.create_msg_request(RTM_GETADDR)
    hdr.nlmsg_flags |= NLM_F_DUMP
    hdr = nw.finalize_msg()

    snl.send_message(hdr)
    while hdr := snl.read_reply_multi(hdr.nlmsg_seq):
        yield parse_nlmsg_addr(snl, hdr)

def dump_routes(snl, *, fib=None):
    fib = 0 if fib is None else fib
    nw = snl.new_writer()
    hdr = nw.create_msg_request(RTM_GETROUTE)
    hdr.nlmsg_flags |= NLM_F_DUMP
    rtm = nw.reserve_msg_object(rtmsg)
    nw.add_msg_attr(RTA_TABLE, c_uint32(fib))
    hdr = nw.finalize_msg()

    snl.send_message(hdr)
    while hdr := snl.read_reply_multi(hdr.nlmsg_seq):
        yield parse_nlmsg_route(snl, hdr)

def parse_nlmsg_link(snl, hdr):
    return snl.parse_nlmsg(hdr, snl_rtm_link_parser_simple)

def parse_nlmsg_addr(snl, hdr):
    return snl.parse_nlmsg(hdr, snl_rtm_addr_parser)

def parse_nlmsg_route(snl, hdr):
    return snl.parse_nlmsg(hdr, snl_rtm_route_parser)

def parse_nlmsg(snl, hdr):
    if hdr.nlmsg_type in (RTM_NEWLINK, RTM_DELLINK):
        nlmsg = parse_nlmsg_link(snl, hdr)
    elif hdr.nlmsg_type in (RTM_NEWADDR, RTM_DELADDR):
        nlmsg = parse_nlmsg_addr(snl, hdr)
    elif hdr.nlmsg_type in (RTM_NEWROUTE, RTM_DELROUTE):
        nlmsg = parse_nlmsg_route(snl, hdr)
    else:
        raise Exception(f'unsupported nlmsg_type: {hdr.nlmsg_type}')
    return nlmsg

def monitor_nl(ev, handler):
    snl_event = SNL(NETLINK_ROUTE, read_timeout=1)
# TODO is a helper necessary?
    snl_helper = SNL(NETLINK_ROUTE, read_timeout=1)

    groups = [
        RTNLGRP_LINK,
        RTNLGRP_IPV4_IFADDR,
        RTNLGRP_IPV4_ROUTE,
        RTNLGRP_IPV6_IFADDR,
        RTNLGRP_IPV6_ROUTE
    ]

    snl_event.get_socket().setsockopt(SOL_NETLINK, NETLINK_MSG_INFO, 1)
    for group in groups:
        snl_event.get_socket().setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)

    while not ev.is_set():
        try:
            hdr = snl_event.read_message()
        except BlockingIOError:
            continue
        if hdr:
            nlmsg = parse_nlmsg(snl_helper, hdr)
            handler(hdr.nlmsg_type, nlmsg)

def addr_to_af(addr):
    if type(addr) is IPv4Address:
        return socket.AF_INET
    elif type(addr) is IPv6Address:
        return socket.AF_INET6
    elif type(addr) is IPv4Network:
        return socket.AF_INET
    elif type(addr) is IPv6Network:
        return socket.AF_INET6
    else:
        raise Exception(f'unknown address type: {type(dst)}')

def do_route(snl, fib, cmd, flags, dst, gw, if_idx):
    nw = snl.new_writer()
    hdr = nw.create_msg_request(cmd)
    hdr.nlmsg_flags |= flags
    rtm = nw.reserve_msg_object(rtmsg)
    rtm.rtm_family = addr_to_af(dst)
    rtm.rtm_protocol = RTPROT_STATIC 
    rtm.rtm_type = RTN_UNICAST
    rtm.rtm_dst_len = dst.prefixlen

    dst_packed = dst.network_address.packed
    dst_data = (c_byte*len(dst_packed)).from_buffer_copy(dst_packed)
    nw.add_msg_attr(RTA_DST, dst_data) 
    nw.add_msg_attr(RTA_TABLE, c_uint32(fib))

    # the netlink rtm.rtm_protocol seems to be ignored
    rtm_flags = RTF_STATIC 
    nw.add_msg_attr(NL_RTA_RTFLAGS, c_uint32(rtm_flags))

    if gw:
        assert addr_to_af(dst) == addr_to_af(gw)
        gw_data = (c_byte*len(gw.packed)).from_buffer_copy(gw.packed)
        nw.add_msg_attr(RTA_GATEWAY, gw_data)

    # this is optional, but i should provide to be explicit
    if if_idx:
        nw.add_msg_attr(RTA_OIF, c_uint32(if_idx))

    hdr = nw.finalize_msg()
    snl.send_message(hdr)
    snl.read_reply_code(hdr.nlmsg_seq)

def if_nametoindex(snl, ifname):
    nw = snl.new_writer()
    hdr = nw.create_msg_request(RTM_GETLINK)
    nw.reserve_msg_object(ifinfomsg)
    data = create_string_buffer(ifname.encode())
    nw.add_msg_attr(IFLA_IFNAME, data)
    hdr = nw.finalize_msg()

    snl.send_message(hdr)
    hdr = snl.read_reply_multi(hdr.nlmsg_seq)
    snl.read_reply_multi(hdr.nlmsg_seq)
    return snl.parse_nlmsg(hdr, snl_rtm_link_parser_simple).ifi_index

def new_route(snl, fib, dst, gw, if_idx):
    nl_cmd = RTM_NEWROUTE
    nl_flags = NLM_F_CREATE | NLM_F_EXCL
    do_route(snl, fib, nl_cmd, nl_flags, dst, gw, if_idx)

def delete_route(snl, fib, dst, gw, if_idx):
    nl_cmd = RTM_DELROUTE
    nl_flags = 0
    do_route(snl, fib, nl_cmd, nl_flags, dst, gw, if_idx)

# nettables
class JSONEncoder(json.JSONEncoder):

    def default(self, o):
        if type(o) in [IPv4Address, IPv4Network, IPv4Interface]:
            return str(o)
        elif type(o) in [IPv6Address, IPv6Network, IPv6Interface]:
            return str(o)
        elif type(o) is NetTables:
            return { 'links': o.links, 'routes': o.routes, 'addrs': o.addrs }
        elif type(o) is set:
            return list(o)
        return json.JSONEncoder.default(self, o)

class Link(namedtuple('Link', ['name', 'index', 'up'])):

    @staticmethod
    def from_snl_parsed_link_simple(s):
        name = string_at(s.ifla_ifname).decode()
        up_flag = bool(s.ifi_flags & IFF_UP)
        return Link(name, s.ifi_index, up_flag) 

class LinkAddress(namedtuple('LinkAddress', ['link_index', 'address'])):

    @staticmethod
    def from_snl_parsed_addr(s):
        local = parse_addr(s.ifa_local.contents) if s.ifa_local else None
        # NOTE, this project doesn't need the peer address
        addr = parse_addr(s.ifa_address.contents) if local is None else local
        ifaceaddr = ip_interface((addr, s.ifa_prefixlen,))
        return LinkAddress(s.ifa_index, ifaceaddr)

class Route(namedtuple('Route', ['dst', 'gw', 'link_index'])):

    @staticmethod
    def from_snl_parsed_route(s):
        if s.rta_multipath.num_nhops != 0:
            raise Exception()
        dst = ip_network((parse_addr(s.rta_dst.contents), s.rtm_dst_len))
        if s.rta_rtflags & RTF_GATEWAY:
            gw = parse_addr(s.rta_gw.contents)
        else:
            gw = None
        return Route(dst, gw, s.rta_oif)

class NetTables:

    LinkAddresses = namedtuple('LinkAddresses', ['link', 'addrs'])

    def __init__(self):
        self.lock = threading.RLock()
        self.links = set()
        self.routes = set()
        self.addrs = set()

    def new_link(self, link):
        with self.lock:
            self.del_link(link)
            self.links.update({link})

    def del_link(self, link):
        with self.lock:
            to_remove = set(filter(lambda e: e.index == link.index, self.links))
            self.links.difference_update(to_remove)

    def get_links(self, p):
        with self.lock:
            return set(filter(p, self.links))

    def new_addr(self, addr):
        with self.lock:
            self.addrs.update({addr})

    def del_addr(self, addr):
        with self.lock:
            self.addrs.difference_update({addr})

    def get_addrs(self, p):
        with self.lock:
            return set(filter(p, self.addrs))

    def new_route(self, route):
        with self.lock:
            self.routes.update({route})

    def del_route(self, route):
        with self.lock:
            self.routes.difference_update({route})

    def get_routes(self, p):
        with self.lock:
            return set(filter(p, self.routes))

def maintain_nettables(finish, trigger_ev, nettables):
    executor = concurrent.futures.ThreadPoolExecutor()
    tasks = []
    tasks.append(executor.submit(finish.wait))

    nlmsg_q = queue.Queue()
    def handler(nlmsg_type, nlmsg):
        nlmsg_q.put((nlmsg_type, nlmsg,))
    tasks.append(executor.submit(monitor_nl, finish, handler))

    # TODO close the gap
    with SNL(NETLINK_ROUTE, read_timeout=1) as snl:
        for link in dump_links(snl):
            nettables.new_link(Link.from_snl_parsed_link_simple(link))
        for addr in dump_addrs(snl):
            nettables.new_addr(LinkAddress.from_snl_parsed_addr(addr))
        for route in dump_routes(snl):
            nettables.new_route(Route.from_snl_parsed_route(route))
    trigger_ev.release()

    def nlmsg_handler():
        while not finish.is_set():
            try:
                nlmsg_type, nlmsg = nlmsg_q.get(timeout=1)
            except queue.Empty:
                continue
            if nlmsg_type == RTM_NEWLINK:
                nettables.new_link(Link.from_snl_parsed_link_simple(nlmsg))
            elif nlmsg_type == RTM_DELLINK:
                nettables.del_link(Link.from_snl_parsed_link_simple(nlmsg))
            elif nlmsg_type == RTM_NEWADDR:
                nettables.new_addr(LinkAddress.from_snl_parsed_addr(nlmsg))
            elif nlmsg_type == RTM_DELADDR:
                nettables.del_addr(LinkAddress.from_snl_parsed_addr(nlmsg))
            elif nlmsg_type == RTM_NEWROUTE:
                nettables.new_route(Route.from_snl_parsed_route(nlmsg))
            elif nlmsg_type == RTM_DELROUTE:
                nettables.del_route(Route.from_snl_parsed_route(nlmsg))
            else:
                logging.error(f'unknown nlmsg_type: {nlmsg_type}')
            trigger_ev.release()
    tasks.append(executor.submit(nlmsg_handler))

    try:
        done, pending = concurrent.futures.wait(tasks, return_when=concurrent.futures.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        finish.set()

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='action')
    subparser = subparsers.add_parser('new-route')
    subparser.add_argument('-d', metavar='destination', type=ip_network, required=True)
    subparser.add_argument('-g', metavar='gateway', type=ip_address)
    subparser.add_argument('-i', metavar='iface')
    subparser.add_argument('-f', metavar='fib', type=int, default=0)
    subparser = subparsers.add_parser('delete-route')
    subparser.add_argument('-d', metavar='destination', type=ip_network, required=True)
    subparser.add_argument('-g', metavar='gateway', type=ip_address)
    subparser.add_argument('-i', metavar='iface')
    subparser.add_argument('-f', metavar='fib', type=int, default=0)
    subparsers.add_parser('dump-links')
    subparsers.add_parser('dump-addrs')
    subparser = subparsers.add_parser('dump-routes')
    subparser.add_argument('-f', metavar='fib', type=int, default=0)
    subparsers.add_parser('monitor-nl')
    subparser = subparsers.add_parser('if_nametoindex')
    subparser.add_argument('link')
    subparsers.add_parser('nettables')
    args = parser.parse_args()

    snl = SNL(NETLINK_ROUTE, read_timeout=1)
    if args.action is None:
        raise Exception('action not specified')
    elif args.action == 'new-route':
        if_idx = None if args.i is None else if_nametoindex(snl, args.i)
        new_route(snl, args.f, args.d, args.g, if_idx)
    elif args.action == 'delete-route':
        if_idx = None if args.i is None else if_nametoindex(snl, args.i)
        delete_route(snl, args.f, args.d, args.g, if_idx)
    elif args.action == 'dump-links':
        for link in dump_links(snl):
            l = Link.from_snl_parsed_link_simple(link)
            print(l)
    elif args.action == 'dump-addrs':
        for addr in dump_addrs(snl):
            a = LinkAddress.from_snl_parsed_addr(addr)
            print(a)
    elif args.action == 'dump-routes':
        for route in dump_routes(snl, fib=args.f):
            r = Route.from_snl_parsed_route(route)
            print(r)
    elif args.action == 'monitor-nl':
        ev = threading.Event()
        def handler(nlmsg_type, nlmsg):
            print(nlmsg)
        monitor_nl(ev, handler)
    elif args.action == 'if_nametoindex':
        print(if_nametoindex(snl, args.link))
    elif args.action == 'nettables':
        finish = threading.Event()
        class BLAH:
            def release(self): pass
        nettables = NetTables()
        maintain_nettables(finish, BLAH(), nettables)
        print(if_nametoindex(snl, args.link))
    else:
        raise Exception(f'unknown action: {args.action}')

