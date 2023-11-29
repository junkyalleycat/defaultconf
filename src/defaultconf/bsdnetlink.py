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

def flat_print(i):
    for field_name, field_type in i._fields_:
        value = getattr(i, field_name)
        if value and (field_type == POINTER(sockaddr)):
            value = parse_addr(value.contents)
        print(f'{field_name} = {value}')

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

    e = snl_errmsg_data()
    while rmsg := snl.read_reply_multi(msg.hdr.nlmsg_seq, e):
        yield parse_nlmsg_link(snl, rmsg)
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

    e = snl_errmsg_data()
    while rmsg := snl.read_reply_multi(msg.hdr.nlmsg_seq, e):
        yield parse_nlmsg_addr(snl, rmsg)
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

    e = snl_errmsg_data()
    while rmsg := snl.read_reply_multi(msg.hdr.nlmsg_seq, e):
        yield parse_nlmsg_route(snl, rmsg)
        snl.clear_lb()

def parse_nlmsg_link(snl_helper, rmsg):
    link = snl_parsed_link_simple()

    if not snl_helper.parse_nlmsg(rmsg, snl_rtm_link_parser_simple, link):
        raise Exception()

    return link.deepcopy()

def parse_nlmsg_addr(snl_helper, rmsg):
    addr = snl_parsed_addr()

    if not snl_helper.parse_nlmsg(rmsg, snl_rtm_addr_parser, addr):
        raise Exception()

    return addr.deepcopy()

def parse_nlmsg_route(snl_helper, rmsg):
    route = snl_parsed_route()

    if not snl_helper.parse_nlmsg(rmsg, snl_rtm_route_parser, route):
        raise Exception()

    return route.deepcopy()

def parse_nlmsg(h_ss_cmd, nlmsg_type, rmsg):
    if nlmsg_type in (RTM_NEWLINK, RTM_DELLINK):
        nlmsg = parse_nlmsg_link(h_ss_cmd, rmsg)
    elif nlmsg_type in (RTM_NEWADDR, RTM_DELADDR):
        nlmsg = parse_nlmsg_addr(h_ss_cmd, rmsg)
    elif nlmsg_type in (RTM_NEWROUTE, RTM_DELROUTE):
        nlmsg = parse_nlmsg_route(h_ss_cmd, rmsg)
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
        rmsg = None
        try:
            rmsg = snl_event.read_message()
        except BlockingIOError:
            pass
        if rmsg: # is not None:
            hdr = nlmsghdr.from_address(rmsg.value)
            nlmsg = parse_nlmsg(snl_helper, hdr.nlmsg_type, rmsg)
            handler(hdr.nlmsg_type, nlmsg)
            snl_helper.clear_lb()
            snl_event.clear_lb()

class Link(namedtuple('Link', ['ifname', 'index', 'up'])):

    @staticmethod
    def from_snl_parsed_link_simple(s):
        ifname = string_at(s.ifla_ifname).decode()
        up_flag = bool(s.ifi_flags & IFF_UP)
        return Link(ifname, s.ifi_index, up_flag) 

class LinkAddress(namedtuple('IfAddress', ['if_index', 'local', 'address', 'prefixlen'])):

    @staticmethod
    def from_snl_parsed_addr(s):
        local = parse_addr(s.ifa_local.contents) if s.ifa_local else None
        address = parse_addr(s.ifa_address.contents)
        return LinkAddress(s.ifa_index, local, address, s.ifa_prefixlen)

class Route(namedtuple('Route', ['dst', 'gw', 'prefixlen', 'if_index', 'host'])):

    @staticmethod
    def from_snl_parsed_route(s):
        if s.rta_multipath.num_nhops != 0:
            raise Exception()
        dst = parse_addr(s.rta_dst.contents)
        if s.rta_rtflags & RTF_GATEWAY:
            gw = parse_addr(s.rta_gw.contents)
        else:
            gw = None
        host_flag = bool(s.rta_rtflags & RTF_HOST)
        return Route(dst, gw, s.rtm_dst_len, s.rta_oif, host_flag)

class NetTables:

    LinkAddresses = namedtuple('LinkAddresses', ['link', 'addrs'])

    def __init__(self):
        self.links = {}
        self.routes = set()

    def new_link(self, link):
        if link.index in self.links:
            addrs = self.links[link.index].addrs
            self.links[link.index] = NetTables.LinkAddresses(link, addrs)
        else:
            self.links[link.index] = NetTables.LinkAddresses(link, [])

    def del_link(self, link):
        if link.index in self.links:
            del self.links[link.index]
        if_routes = set(filter(lambda e: e.if_index == link.index, self.routes))
        self.routes -= if_routes

    def new_addr(self, a):
        link = self.links[a.if_index]
        link.addrs.append(a)

    def del_addr(self, a):
        link = self.links[a.if_index]
        if a in link.addrs:
            link.addrs.remove(a)

    def new_route(self, r):
        self.routes |= {r}

    def del_route(self, r):
        self.routes -= {r}

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

def main():
    print(f'pid: {os.getpid()}')
    finish = threading.Event()

    def sig_handler(*_):
        finish.set()
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    def sigusr1_handler(*_):
        try:
            Path('/tmp/rtable').write_text(json.dumps(nt, cls=JSONEncoder))
        except Exception as e:
            logging.exception(e)
    signal.signal(signal.SIGUSR1, sigusr1_handler)

    executor = concurrent.futures.ThreadPoolExecutor()
    tasks = []
    tasks.append(executor.submit(finish.wait))

    nlmsg_q = queue.Queue()
    def handler(nlmsg_type, nlmsg):
        nlmsg_q.put((nlmsg_type, nlmsg,))
    tasks.append(executor.submit(monitor_nl, finish, handler))

    # close the gap
    nt = NetTables()
    for link in dump_links():
        nt.new_link(Link.from_snl_parsed_link_simple(link))
    for addr in dump_addrs():
        nt.new_addr(LinkAddress.from_snl_parsed_addr(addr))
    for route in dump_routes():
        nt.new_route(Route.from_snl_parsed_route(route))

    def nlmsg_handler():
        while not finish.is_set():
            try:
                nlmsg_type, nlmsg = nlmsg_q.get(timeout=1)
            except queue.Empty:
                continue
            if nlmsg_type == RTM_NEWLINK:
                nt.new_link(Link.from_snl_parsed_link_simple(nlmsg))
            elif nlmsg_type == RTM_DELLINK:
                nt.del_link(Link.from_snl_parsed_link_simple(nlmsg))
            elif nlmsg_type == RTM_NEWADDR:
                nt.new_addr(LinkAddress.from_snl_parsed_addr(nlmsg))
            elif nlmsg_type == RTM_DELADDR:
                nt.del_addr(LinkAddress.from_snl_parsed_addr(nlmsg))
            elif nlmsg_type == RTM_NEWROUTE:
                nt.new_route(Route.from_snl_parsed_route(nlmsg))
            elif nlmsg_type == RTM_DELROUTE:
                nt.del_route(Route.from_snl_parsed_route(nlmsg))
    tasks.append(executor.submit(nlmsg_handler))

    try:
        done, pending = concurrent.futures.wait(tasks, return_when=concurrent.futures.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        finish.set()

