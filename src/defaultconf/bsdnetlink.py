#!/usr/bin/env python3

import socket
from ctypes import *

from ._bsdnetlink import *
from .bsdcommon import *

# netlink/netlink.h
class nlmsghdr(Structure):

    _fields_ = [
        ('nlmsg_len', c_uint32),
        ('nlmsg_type', c_uint16),
        ('nlmsg_flags', c_uint16),
        ('nlmsg_seq', c_uint32),
        ('nlmsg_pid', c_uint32)
    ]

# netlink/netlink.h
class nlattr(Structure):

    _fields_ = [
        ('nla_len', c_uint16),
        ('nla_type', c_uint16)
    ]

# netlink/route/route.h
class rtmsg(Structure):

    _fields_ = [
        ('rtm_family', u_char),
        ('rtm_dst_len', u_char),
        ('rtm_src_len', u_char),
        ('rtm_tos', u_char),
        ('rtm_table', u_char),
        ('rtm_protocol', u_char),
        ('rtm_scope', u_char),
        ('rtm_type', u_char),
        ('rtm_flags', unsigned)
    ]

# netlink/route/interface.h
class ifinfomsg(Structure):

    _fields_ = [
        ('ifi_family', u_char),
        ('__ifi_pad', u_char),
        ('ifi_type', c_ushort),
        ('ifi_index', c_int),
        ('ifi_flags', unsigned),
        ('ifi_change', unsigned)
    ]

class snl_errmsg_data(Structure):

    _fields_ = [
        ('orig_hdr', POINTER(nlmsghdr)),
        ('error', c_int),
        ('error_offs', c_uint32),
        ('error_str', c_char_p),
        ('cookie', POINTER(nlattr))
    ]

class snl_parsed_link_simple(Structure):

    _fields_ = [
        ('ifi_index', c_uint32),
        ('ifla_mtu', c_uint32),
        ('ifi_type', c_uint16),
        ('ifi_flags', c_uint32),
        ('ifla_ifname', POINTER(c_char))
    ]

class SNL:

    def __init__(self, netlink_family):
        self.ss = bsdsnl.snl_init(netlink_family)

    def clear_lb(self):
        bsdsnl.snl_clear_lb(self.ss)

    def get_seq(self):
        return bsdsnl.snl_get_seq(self.ss)

    def send_message(self, hdr):
        bsdsnl.snl_send_message(self.ss, addressof(hdr))

    def read_reply_multi(self, nlmsg_seq, e):
        _hdr = bsdsnl.snl_read_reply_multi(self.ss, nlmsg_seq, addressof(e))
        if not _hdr:
            return None
        hdr = nlmsghdr.from_address(_hdr)
        msg = (c_char*hdr.nlmsg_len).from_address(_hdr)
        return msg

    def parse_nlmsg(self, hdr, parser, target):
        bsdsnl.snl_parse_nlmsg(self.ss, addressof(hdr), parser, addressof(target))

    def __del__(self):
        bsdsnl.snl_free(self.ss)

def main():
    snl = SNL(bsdsnl.NETLINK_ROUTE)

    def prepare_ifmap_netlink():
        class _msg(Structure):
            _fields_ = [
                ('hdr', nlmsghdr),
                ('ifmsg', ifinfomsg)
            ]
        msg = _msg()
        msg.hdr.nlmsg_type = bsdsnl.RTM_GETLINK
        msg.hdr.nlmsg_flags = bsdsnl.NLM_F_DUMP | bsdsnl.NLM_F_REQUEST
        msg.hdr.nlmsg_seq = snl.get_seq()
        msg.hdr.nlmsg_len = sizeof(msg)

        snl.send_message(msg.hdr)

        e = snl_errmsg_data()
        while rmsg := snl.read_reply_multi(msg.hdr.nlmsg_seq, e):
            link = snl_parsed_link_simple()
            snl.parse_nlmsg(rmsg, bsdsnl.snl_rtm_link_parser_simple, link)
            ifname = string_at(link.ifla_ifname).decode()
            print(ifname)

    prepare_ifmap_netlink()

    class _rqmsg(Structure):
        
        _fields_ = [
            ('hdr', nlmsghdr),
            ('rtmsg', rtmsg),
            ('nla_fibnum', nlattr),
            ('fibnum', c_uint32)
        ]

    rqmsg = _rqmsg()
    rqmsg.hdr.nlmsg_type = bsdsnl.RTM_GETROUTE
    rqmsg.hdr.nlmsg_flags = bsdsnl.NLM_F_DUMP | bsdsnl.NLM_F_REQUEST
    rqmsg.hdr.nlmsg_seq = snl.get_seq()
    # NOTE remove family to get all routes
    rqmsg.rtmsg.rtm_family = socket.AF_INET
    rqmsg.nla_fibnum.nla_len = sizeof(nlattr)+sizeof(c_uint32)
    rqmsg.nla_fibnum.nla_type = bsdsnl.RTA_TABLE
    rqmsg.fibnum = 0
    rqmsg.hdr.nlmsg_len = sizeof(rqmsg)
    snl.send_message(rqmsg.hdr)

    e = snl_errmsg_data()

    while rmsg := snl.read_reply_multi(rqmsg.hdr.nlmsg_seq, e):
        print(sizeof(rmsg))
        snl.clear_lb()

