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
import ipaddress
from ipaddress import *
from collections import namedtuple
import socket
import json
import argparse

from .bsdnet import *

def digest(b):
    return sha256(b).hexdigest()

def parse_addr(addr):
    if addr.sa_family == socket.AF_INET:
        addr_in = sockaddr_in.from_sockaddr(addr)
        return ipaddress.ip_address(bytes(addr_in.sin_addr))
    elif addr.sa_family == socket.AF_INET6:
        addr6_in = sockaddr_in6.from_sockaddr(addr)
        return ipaddress.ip_address(bytes(addr6_in.sin6_addr))
    else:
        raise Exception(f'unsupported sa_family: {addr.sa_family}')
   
def dump_links():
    snl = SNL(NETLINK_ROUTE, read_timeout=1)
    nw = snl.new_writer()
    hdr = nw.create_msg_request(RTM_GETLINK)
    hdr.nlmsg_flags |= NLM_F_DUMP
    nw.finalize_msg()

    snl.send_message(hdr)
    while hdr := snl.read_reply_multi(hdr.nlmsg_seq):
        yield parse_nlmsg_link(snl, hdr)

def dump_addrs():
    snl = SNL(NETLINK_ROUTE, read_timeout=1)
    nw = snl.new_writer()
    hdr = nw.create_msg_request(RTM_GETADDR)
    hdr.nlmsg_flags |= NLM_F_DUMP
    nw.finalize_msg()

    snl.send_message(hdr)
    while hdr := snl.read_reply_multi(hdr.nlmsg_seq):
        yield parse_nlmsg_addr(snl, hdr)

def dump_routes():
    snl = SNL(NETLINK_ROUTE, read_timeout=1)
    nw = snl.new_writer()
    hdr = nw.create_msg_request(RTM_GETROUTE)
    hdr.nlmsg_flags |= NLM_F_DUMP
# TODO fib
# nw.reserve_msg_object(rtmsg)
# nw.reserve_msg_object(nlattr)
# nw.reserve_msg_object(c_uint32)
    nw.finalize_msg()

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
#    snl_helper = SNL(NETLINK_ROUTE, read_timeout=1)
    snl_helper = snl_event

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

class Link(namedtuple('Link', ['name', 'index', 'up'])):

    @staticmethod
    def from_snl_parsed_link_simple(s):
        name = string_at(s.ifla_ifname).decode()
        up_flag = bool(s.ifi_flags & IFF_UP)
        return Link(name, s.ifi_index, up_flag) 

class LinkAddress(namedtuple('LinkAddress', ['link_index', 'local', 'address', 'prefixlen'])):

    @staticmethod
    def from_snl_parsed_addr(s):
        local = parse_addr(s.ifa_local.contents) if s.ifa_local else None
        addr = parse_addr(s.ifa_address.contents)
        ifaceaddr = ipaddress.ip_interface((addr, s.ifa_prefixlen,))
        return LinkAddress(s.ifa_index, local, ifaceaddr, s.ifa_prefixlen)

class Route(namedtuple('Route', ['dst', 'gw', 'prefixlen', 'link_index', 'host'])):

    @staticmethod
    def from_snl_parsed_route(s):
        if s.rta_multipath.num_nhops != 0:
            raise Exception()
        host_flag = bool(s.rta_rtflags & RTF_HOST)
        dst = parse_addr(s.rta_dst.contents)
        if not host_flag:
            dst = ipaddress.ip_network((dst, s.rtm_dst_len,))
        if s.rta_rtflags & RTF_GATEWAY:
            gw = parse_addr(s.rta_gw.contents)
        else:
            gw = None
        return Route(dst, gw, s.rtm_dst_len, s.rta_oif, host_flag)

class NetTables:

    LinkAddresses = namedtuple('LinkAddresses', ['link', 'addrs'])

    def __init__(self):
        self.lock = threading.RLock()
        self.links = {}
        self.routes = set()

    def new_link(self, link):
        with self.lock:
            if link.index in self.links:
                addrs = self.links[link.index].addrs
                self.links[link.index] = NetTables.LinkAddresses(link, addrs)
            else:
                self.links[link.index] = NetTables.LinkAddresses(link, set())

    def del_link(self, link):
        with self.lock:
            if link.index in self.links:
                del self.links[link.index]
            self.routes.difference_update(set(filter(lambda e: e.link_index == link.index, self.routes)))

    def new_addr(self, a):
        with self.lock:
            link = self.links[a.link_index]
            link.addrs.update({a})

    def del_addr(self, a):
        with self.lock:
            link = self.links[a.link_index]
            link.addrs.difference_update({a})

    def get_links(self, p):
        with self.lock:
            return list(filter(p, self.links.values()))

    # TODO filter out pinned routes, we can't control them anyways
    def new_route(self, r):
        with self.lock:
            self.routes |= {r}

    def del_route(self, r):
        with self.lock:
            self.routes -= {r}

    def get_routes(self, p):
        with self.lock:
            return set(filter(p, self.routes))

    def get_link_addrs(self):
        return dict(self.links)

class JSONEncoder(json.JSONEncoder):

    def default(self, o):
        if type(o) is ipaddress.IPv4Address:
            return str(o)
        elif type(o) is ipaddress.IPv6Address:
            return str(o)
        elif type(o) is NetTables:
            return { 'links': o.links, 'routes': o.routes }
        elif type(o) is set:
            return list(o)
        return json.JSONEncoder.default(self, o)

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

def do_route(snl, cmd, flags, dst, gw, def_gw, if_idx):
    nw = snl.new_writer()
    n = nw.create_msg_request(cmd)
    r = nw.reserve_msg_object(rtmsg)
    nl_request = namedtuple('nl_request', ['n', 'r'])(n, r)
    nl_request.n.nlmsg_flags |= flags # | NLM_F_ACK
    nl_request.r.rtm_family = addr_to_af(dst)
    nl_request.r.rtm_table = RT_TABLE_MAIN
    nl_request.r.rtm_scope = RT_SCOPE_NOWHERE

    if cmd != RTM_DELROUTE:
        nl_request.r.rtm_protocol = RTPROT_BOOT
        nl_request.r.rtm_type = RTN_UNICAST

    nl_request.r.rtm_family = addr_to_af(dst)
    nl_request.r.rtm_dst_len = dst.prefixlen

    if nl_request.r.rtm_family == socket.AF_INET6:
        nl_request.r.rtm_scope = RT_SCOPE_UNIVERSE
    else:
        nl_request.r.rtm_scope = RT_SCOPE_LINK

    if gw:
        gw_data = (c_char*len(gw.packed)).from_buffer_copy(gw.packed)
        nw.add_msg_attr(RTA_GATEWAY, sizeof(gw_data), gw_data)
        nl_request.r.rtm_scope = 0
        nl_request.r.rtm_family = addr_to_af(gw)

    if not def_gw:
        dst_packed = dst.network_address.packed
        dst_data = (c_char*len(dst_packed)).from_buffer_copy(dst_packed)
        nw.add_msg_attr(RTA_DST, sizeof(dst_data), dst_data) 
# NOTE this is optional
        if if_idx:
            nw.add_msg_attr(RTA_OIF, sizeof(c_int), c_int(if_idx))

    nw.finalize_msg()
    snl.send_message(nl_request.n)
    snl.read_reply_code(nl_request.n.nlmsg_seq)

def if_nametoindex_nl(ifname):
    snl = SNL(NETLINK_ROUTE, read_timeout=1)

    nw = snl.new_writer()
    hdr = nw.create_msg_request(RTM_GETLINK)
    nw.reserve_msg_object(ifinfomsg)
    data = create_string_buffer(ifname.encode())
    nw.add_msg_attr(IFLA_IFNAME, sizeof(data), data)
    nw.finalize_msg()

    snl.send_message(hdr)
    hdr = snl.read_reply_multi(hdr.nlmsg_seq)
    return snl.parse_nlmsg(hdr, snl_rtm_link_parser_simple).ifi_index

def new_route(dst, gw, iface):
    nl_cmd = RTM_NEWROUTE
    nl_flags = NLM_F_CREATE | NLM_F_EXCL

    snl = SNL(NETLINK_ROUTE, read_timeout=1)
    to_addr = ipaddress.ip_network(dst) #'8.8.4.4')
    gw_addr = ipaddress.ip_address(gw) #'192.168.12.1')    
    default_gw = None
    if_idx = None if iface is None else if_nametoindex_nl(iface) #'lo0')

    do_route(snl, nl_cmd, nl_flags, to_addr, gw_addr, default_gw, if_idx)

def delete_route(dst, gw, iface):
    nl_cmd = RTM_DELROUTE
    nl_flags = 0

    snl = SNL(NETLINK_ROUTE, read_timeout=1)
    to_addr = ipaddress.ip_network(dst) #'8.8.4.4')
    gw_addr = ipaddress.ip_address(gw) #'192.168.12.1')    
    default_gw = None
    if_idx = None if iface is None else if_nametoindex_nl(iface)

    do_route(snl, nl_cmd, nl_flags, to_addr, gw_addr, default_gw, if_idx)

def maintain_nettables(finish, trigger_ev, nettables):
    executor = concurrent.futures.ThreadPoolExecutor()
    tasks = []
    tasks.append(executor.submit(finish.wait))

    nlmsg_q = queue.Queue()
    def handler(nlmsg_type, nlmsg):
        nlmsg_q.put((nlmsg_type, nlmsg,))
    tasks.append(executor.submit(monitor_nl, finish, handler))

    # TODO close the gap
    for link in dump_links():
        nettables.new_link(Link.from_snl_parsed_link_simple(link))
    for addr in dump_addrs():
        nettables.new_addr(LinkAddress.from_snl_parsed_addr(addr))
    for route in dump_routes():
        nettables.new_route(Route.from_snl_parsed_route(route))
    trigger_ev.release()

    def nlmsg_handler():
        while not finish.is_set():
            try:
                nlmsg_type, nlmsg = nlmsg_q.get(read_timeout=1)
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
    subparser.add_argument('-d', metavar='destination')
    subparser.add_argument('-g', metavar='gateway')
    subparser.add_argument('-i', metavar='iface')
    subparser = subparsers.add_parser('delete-route')
    subparser.add_argument('-d', metavar='destination')
    subparser.add_argument('-g', metavar='gateway')
    subparser.add_argument('-i', metavar='iface')
    subparsers.add_parser('dump-links')
    subparsers.add_parser('dump-addrs')
    subparsers.add_parser('dump-routes')
    subparsers.add_parser('monitor-nl')
    subparser = subparsers.add_parser('if_nametoindex_nl')
    subparser.add_argument('link')
    args = parser.parse_args()

    if args.action is None:
        raise Exception('action not specified')
    elif args.action == 'new-route':
        new_route(args.d, args.g, args.i)
    elif args.action == 'delete-route':
        delete_route(args.d, args.g, args.i)
    elif args.action == 'dump-links':
        for link in dump_links():
            l = Link.from_snl_parsed_link_simple(link)
            print(l)
    elif args.action == 'dump-addrs':
        for addr in dump_addrs():
            a = LinkAddress.from_snl_parsed_addr(addr)
            print(a)
    elif args.action == 'dump-routes':
        for route in dump_routes():
            r = Route.from_snl_parsed_route(route)
            print(r)
    elif args.action == 'monitor-nl':
        ev = threading.Event()
        def handler(nlmsg_type, nlmsg):
            print(nlmsg)
        monitor_nl(ev, handler)
    elif args.action == 'if_nametoindex_nl':
        print(if_nametoindex_nl(args.link))
    else:
        raise Exception(f'unknown action: {args.action}')

