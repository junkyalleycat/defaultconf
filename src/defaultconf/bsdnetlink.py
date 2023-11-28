#!/usr/bin/env python3

import ipaddress
from collections import namedtuple
import socket

from .bsdnet import *

Iface = namedtuple('Iface', ['name', 'index', 'up'])
Route = namedtuple('Route', ['dst', 'gw', 'prefixlen', 'if_index', 'host'])
IfaceAddress = namedtuple('IfAddress', ['if_index', 'local', 'address', 'prefixlen'])

def parse_addr(addr):
    if addr.sa_family == socket.AF_INET:
        addr_in = sockaddr_in.from_address(addressof(addr))
        return ipaddress.ip_address(bytes(addr_in.sin_addr))
    elif addr.sa_family == socket.AF_INET6:
        addr6_in = sockaddr_in6.from_address(addressof(addr))
        return ipaddress.ip_address(bytes(addr6_in.sin6_addr))
    else:
        raise Exception(f'unknown sa_family: {addr.sa_family}')
    
def flat_print(i):
    for field_name, field_type in i._fields_:
        value = getattr(i, field_name)
        if value and (field_type == POINTER(sockaddr)):
            value = parse_addr(value.contents)
        print(f'{field_name} = {value}')

def main():

    def create_iface(l):
        ifname = string_at(l.ifla_ifname).decode()
        up_flag = bool(l.ifi_flags & IFF_UP)
        return Iface(ifname, l.ifi_index, up_flag)

    def create_addr(a):
        local = parse_addr(a.ifa_local.contents) if a.ifa_local else None
        address = parse_addr(a.ifa_address.contents)
        return IfaceAddress(a.ifa_index, local, address, a.ifa_prefixlen)

    def create_route(r):
        if r.rta_multipath.num_nhops != 0:
            raise Exception()
        dst = parse_addr(r.rta_dst.contents)
        if r.rta_rtflags & RTF_GATEWAY:
            gw = parse_addr(r.rta_gw.contents)
        else:
            gw = None
        host_flag = bool(r.rta_rtflags & RTF_HOST)
        return Route(dst, gw, r.rtm_dst_len, r.rta_oif, host_flag)

    def dump_ifaces():
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
            link = snl_parsed_link_simple()
            if not snl.parse_nlmsg(rmsg, snl_rtm_link_parser_simple, link):
                raise Exception()
            print(create_iface(link))
            snl.clear_lb()

    dump_ifaces()

    def dump_addrs():
        snl = SNL(NETLINK_ROUTE)

#        NL_RTM_GETADDR
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
            attrs = snl_parsed_addr()
            if not snl.parse_nlmsg(rmsg, snl_rtm_addr_parser, attrs):
                raise Exception()
            print(create_addr(attrs))

    dump_addrs()

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
            rt = snl_parsed_route()
            if not snl.parse_nlmsg(rmsg, snl_rtm_route_parser, rt):
                raise Exception()
            print(create_route(rt))
            snl.clear_lb()

    dump_routes()

    def handle_nlmsg_link(hdr, h_ss_cmd, rmsg):
        l = snl_parsed_link_simple()
        ss = h_ss_cmd

        if not ss.parse_nlmsg(rmsg, snl_rtm_link_parser_simple, l):
            raise Exception()

        print(create_iface(l))

    def handle_nlmsg_addr(hdr, h_ss_cmd, rmsg):
        attrs = snl_parsed_addr()
        ss = h_ss_cmd

        if not ss.parse_nlmsg(rmsg, snl_rtm_addr_parser, attrs):
            raise Exception()

        print(create_addr(attrs))

    def handle_nlmsg_route(hdr, h_ss_cmd, rmsg):
        r = snl_parsed_route()
        ss = h_ss_cmd

        if not ss.parse_nlmsg(rmsg, snl_rtm_route_parser, r):
            raise Exception()

        print(create_route(r))

    def handle_nlmsg(h_ss_cmd, rmsg):
        hdr = nlmsghdr.from_buffer(rmsg)
        nlmsg_type = hdr.nlmsg_type
        if nlmsg_type in (RTM_NEWLINK, RTM_DELLINK):
            handle_nlmsg_link(hdr, h_ss_cmd, rmsg)
        elif nlmsg_type in (RTM_NEWADDR, RTM_DELADDR):
            handle_nlmsg_addr(hdr, h_ss_cmd, rmsg)
        elif nlmsg_type in (RTM_NEWROUTE, RTM_DELROUTE):
            handle_nlmsg_route(hdr, h_ss_cmd, rmsg)
        else:
            raise Exception(f'unexpected type: {nlmsg_type}')

    def monitor_nl():
        ss_event = SNL(NETLINK_ROUTE, read_timeout=1)
        h_ss_cmd = SNL(NETLINK_ROUTE)

        groups = [
            RTNLGRP_LINK,
            RTNLGRP_IPV4_IFADDR,
            RTNLGRP_IPV4_ROUTE,
            RTNLGRP_IPV6_IFADDR,
            RTNLGRP_IPV6_ROUTE
        ]

        ss_event.get_socket().setsockopt(SOL_NETLINK, NETLINK_MSG_INFO, 1)
        for group in groups:
            ss_event.get_socket().setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)

        while True:
            rmsg = None
            try:
                rmsg = ss_event.read_message()
            except BlockingIOError:
                pass
            if rmsg is not None:
                handle_nlmsg(h_ss_cmd, rmsg)
                h_ss_cmd.clear_lb()
                ss_event.clear_lb()

    monitor_nl()
