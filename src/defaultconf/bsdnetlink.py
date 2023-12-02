#!/usr/bin/env python3

import logging
import os
from pathlib import *
import concurrent.futures
import signal
import queue
import threading
import ipaddress
from collections import namedtuple
import socket
import json

from .bsdnet import *

def parse_addr(addr):
    if addr.sa_family == socket.AF_INET:
        addr_in = sockaddr_in.from_address(addressof(addr))
        return ipaddress.ip_address(bytes(addr_in.sin_addr))
    elif addr.sa_family == socket.AF_INET6:
        addr6_in = sockaddr_in6.from_address(addressof(addr))
        return ipaddress.ip_address(bytes(addr6_in.sin6_addr))
    else:
        raise Exception(f'unsupported sa_family: {addr.sa_family}')
    
def dump_links():
    snl = SNL(NETLINK_ROUTE)

    class _msg(Structure):
        _fields_ = [
            ('hdr', nlmsghdr),
            ('ifmsg', ifinfomsg)
        ]
    msg = _msg()
    msg.hdr.nlmsg_type = RTM_GETLINK
    msg.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
    msg.hdr.nlmsg_seq = snl.get_seq()
    msg.hdr.nlmsg_len = sizeof(msg)

    snl.send_message(msg.hdr)
    while _hdr := snl.read_reply_multi(msg.hdr.nlmsg_seq):
        yield parse_nlmsg_link(snl, _hdr)
        snl.clear_lb()

def dump_addrs():
    snl = SNL(NETLINK_ROUTE)

    class _msg(Structure):
        _fields_ = [
            ('hdr', nlmsghdr),
            ('ifaddrmsg', ifaddrmsg)
        ]
    msg = _msg()
    msg.hdr.nlmsg_type = RTM_GETADDR
    msg.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
    msg.hdr.nlmsg_seq = snl.get_seq()
    msg.hdr.nlmsg_len = sizeof(msg)

    snl.send_message(msg.hdr)
    while _hdr := snl.read_reply_multi(msg.hdr.nlmsg_seq):
        yield parse_nlmsg_addr(snl, _hdr)
        snl.clear_lb()

def dump_routes():
    snl = SNL(NETLINK_ROUTE)

    class _msg(Structure):
        _fields_ = [
            ('hdr', nlmsghdr),
            ('rtmsg', rtmsg),
            ('nla_fibnum', nlattr),
            ('fibnum', c_uint32)
        ]

    msg = _msg()
    msg.hdr.nlmsg_type = RTM_GETROUTE
    msg.hdr.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
    msg.hdr.nlmsg_seq = snl.get_seq()
    msg.nla_fibnum.nla_len = sizeof(nlattr)+sizeof(c_uint32)
    msg.nla_fibnum.nla_type = RTA_TABLE
    msg.fibnum = 0
    msg.hdr.nlmsg_len = sizeof(msg)

    snl.send_message(msg.hdr)
    while _hdr := snl.read_reply_multi(msg.hdr.nlmsg_seq):
        yield parse_nlmsg_route(snl, _hdr)
        snl.clear_lb()

def parse_nlmsg_link(snl, _hdr):
    link = snl_parsed_link_simple()
    snl.parse_nlmsg(_hdr, snl_rtm_link_parser_simple, link)
    return link.deepcopy()

def parse_nlmsg_addr(snl, _hdr):
    addr = snl_parsed_addr()
    snl.parse_nlmsg(_hdr, snl_rtm_addr_parser, addr)
    return addr.deepcopy()

def parse_nlmsg_route(snl, _hdr):
    route = snl_parsed_route()
    snl.parse_nlmsg(_hdr, snl_rtm_route_parser, route)
    return route.deepcopy()

def parse_nlmsg(snl, nlmsg_type, _hdr):
    if nlmsg_type in (RTM_NEWLINK, RTM_DELLINK):
        nlmsg = parse_nlmsg_link(snl, _hdr)
    elif nlmsg_type in (RTM_NEWADDR, RTM_DELADDR):
        nlmsg = parse_nlmsg_addr(snl, _hdr)
    elif nlmsg_type in (RTM_NEWROUTE, RTM_DELROUTE):
        nlmsg = parse_nlmsg_route(snl, _hdr)
    else:
        raise Exception(f'unsupported nlmsg_type: {nlmsg_type}')
    return nlmsg

def monitor_nl(ev, handler):
    snl_event = SNL(NETLINK_ROUTE, read_timeout=1)
    snl_helper = SNL(NETLINK_ROUTE)

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
        _hdr = None
        try:
            _hdr = snl_event.read_message()
        except BlockingIOError:
            pass
        if _hdr: # is not None:
            hdr = nlmsghdr.from_address(_hdr.value)
            nlmsg = parse_nlmsg(snl_helper, hdr.nlmsg_type, _hdr)
            handler(hdr.nlmsg_type, nlmsg)
            snl_helper.clear_lb()
            snl_event.clear_lb()

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
        print(LinkAddress(s.ifa_index, local, ifaceaddr, s.ifa_prefixlen))
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

