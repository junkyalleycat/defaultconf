#!/usr/bin/env python3

import os
import functools
import time
from collections import namedtuple
import socket
from ctypes import *

from ._bsdnet import *
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

    def deepcopy(self):
        return nlattr.from_buffer_copy(self)

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

# netlink/route/ifaddrs.h
class ifaddrmsg(Structure):

    _fields_ = [
        ('ifa_family', c_uint8),
        ('ifa_prefixlen', c_uint8),
        ('ifa_flags', c_uint8),
        ('ifa_scope', c_uint8),
        ('ifa_index', c_uint32)
    ]

# netlink/netlink_snl.h
class snl_errmsg_data(Structure):

    _fields_ = [
        ('orig_hdr', POINTER(nlmsghdr)),
        ('error', c_int),
        ('error_offs', c_uint32),
        ('error_str', POINTER(c_char)),
        ('cookie', POINTER(nlattr))
    ]

# netlink/netlink_snl_route_parsers.h
class snl_parsed_link_simple(Structure):

    _fields_ = [
        ('ifi_index', c_uint32),
        ('ifla_mtu', c_uint32),
        ('ifi_type', c_uint16),
        ('ifi_flags', c_uint32),
        ('ifla_ifname', POINTER(c_char))
    ]

    def deepcopy(self):
        copy = snl_parsed_link_simple.from_buffer_copy(self)
        copy.ifla_ifname = create_string_buffer(string_at(self.ifla_ifname))
        return copy

# netlink/netlink_snl_route_parsers.h
class rta_mpath(Structure):

    _fields_ = [
        ('num_nhops', c_uint32),
        ('nhops', c_void_p) # TODO POINTER(POINTER(rta_mpath_nh)))
    ]

    def deepcopy(self):
        copy = rta_mpath.from_buffer_copy(self)
        copy.nhops = c_void_p() # TODO
        return copy

# netlink/netlink_snl.h
class snl_state(Structure):

    _fields_ = [
        ('fd', c_int),
        ('buf', POINTER(c_char)),
        ('off', size_t),
        ('bufsize', size_t),
        ('datalen', size_t),
        ('seq', c_uint32),
        ('init_done', c_bool),
        ('lb', c_void_p) # TODO POINTER(linear_buffer))
    ]

# netlink/netlink_snl_route_parsers.h
class snl_parsed_route(Structure):

    _fields_ = [
        ('rta_dst', POINTER(sockaddr)),
        ('rta_gw', POINTER(sockaddr)),
        ('rta_metrics', POINTER(nlattr)),
        ('rta_multipath', rta_mpath),
        ('rta_expires', c_uint32),
        ('rta_oif', c_uint32),
        ('rta_expire', c_uint32),
        ('rta_table', c_uint32),
        ('rta_knh_id', c_uint32),
        ('rta_nh_id', c_uint32),
        ('rta_rtflags', c_uint32),
        ('rtax_mtu', c_uint32),
        ('rtax_weight', c_uint32),
        ('rtm_family', c_int8),
        ('rtm_type', c_int8),
        ('rtm_protocol', c_uint8),
        ('rtm_dst_len', c_uint8)
    ]

    def deepcopy(self):
        copy = snl_parsed_route.from_buffer_copy(self)
        if self.rta_dst:
            copy.rta_dst = pointer(self.rta_dst.contents.deepcopy())
        if self.rta_gw:
            copy.rta_gw = pointer(self.rta_gw.contents.deepcopy())
        if self.rta_metrics:
            copy.rta_metrics = pointer(self.rta_metrics.contents.deepcopy())
        self.rta_multipath = self.rta_multipath.deepcopy()
        return copy

# netlink/netlink_snl_route_parsers.h
class snl_parsed_addr(Structure):

    _fields_ = [
        ('ifa_family', c_uint8),
        ('ifa_prefixlen', c_uint8),
        ('ifa_index', c_uint32),
        ('ifa_local', POINTER(sockaddr)),
        ('ifa_address', POINTER(sockaddr)),
        ('ifa_broadcast', POINTER(sockaddr)),
        ('ifa_label', POINTER(c_char)),
        ('ifa_cacheinfo', c_void_p), # TODO POINTER(ifa_cacheinfo)),
        ('ifaf_vhid', c_uint32),
        ('ifaf_flags', c_uint32)
    ]

    def deepcopy(self):
        copy = snl_parsed_addr.from_buffer_copy(self)
        if self.ifa_local:
            copy.ifa_local = pointer(self.ifa_local.contents.deepcopy())
        if self.ifa_address:
            copy.ifa_address = pointer(self.ifa_address.contents.deepcopy())
        if self.ifa_broadcast:
            copy.ifa_broadcast = pointer(self.ifa_broadcast.contents.deepcopy())
        copy.ifa_label = create_string_buffer(string_at(self.ifa_label))
        self.ifa_cacheinfo = c_void_p() # TODO
        return copy

# netlink/route/route.h
class rtattr(Structure):

    _fields_ = [
        ('rta_len', c_short),
        ('rta_type', c_ushort)
    ]

# netlink/netlink_snl.h
class snl_writer(Structure):

    _fields_ = [
        ('base', POINTER(c_char)),
        ('offset', c_uint32),
        ('size', c_uint32),
        ('hdr', POINTER(nlmsghdr)),
        ('ss', POINTER(snl_state)),
        ('error', c_bool)
    ]

# NOTE everything is copied coming out of here, it's a perf hit but makes things predictable
# NOTE what is NOT performed though is the modification of memory addresses in the copies,
#   see examples of deepcopy for how this can be handled
# NOTE one of the goals of SNL is to remove error ambiguity and allow callers to simply call
#   this is handled in part by the c code, which aggresively checks for errno and throws,
#   and is also handled by asserts here, as well as validation of the error struct when present
class SNL:

    def __init__(self, netlink_family, *, read_timeout=None):
        ss = snl_state()
        snl_init(addressof(ss), netlink_family)
        self.ss = ss
        self.ss_s = socket.socket(AF_NETLINK, socket.SOCK_RAW, 0, self.ss.fd)
        # not using python settimeout because it works very differently
        # (puts socket into non-blocking and uses select, which means the timeout is near 0)
        c_read_timeout = timeval(tv_sec=1, tv_usec=0)
        self.ss_s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, c_read_timeout)
        self.read_timeout = read_timeout
        self.deleted = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__() 

    def get_socket(self):
        return self.ss_s

    def get_seq(self):
        return snl_get_seq(addressof(self.ss))

    def send_message(self, hdr):
        rc = snl_send_message(addressof(self.ss), addressof(hdr))
        assert rc

    def _read_with_timeout(self, read_op, timeout):
        timeout = self.read_timeout if timeout is None else timeout
        endtime = None if timeout is None else time.time() + timeout
        while True:
            try:
                return read_op()
            except BlockingIOError:
                if endtime is None:
                    continue
                if time.time() >= endtime:
                    raise

    @staticmethod
    def _copy_hdr(_hdr):
        hdr = nlmsghdr.from_address(_hdr)
        buf = (c_byte*hdr.nlmsg_len)()
        memmove(buf, _hdr, hdr.nlmsg_len)
        return nlmsghdr.from_buffer(buf)

    def read_message(self, *, timeout=None):
        read_op = lambda:snl_read_message(addressof(self.ss))
        _hdr = self._read_with_timeout(read_op, timeout)
        assert _hdr
        return SNL._copy_hdr(_hdr)

    def read_reply(self, nlmsg_seq, *, timeout=None):
        read_op = lambda:snl_read_reply(addressof(self.ss), nlmsg_seq)
        _hdr = self._read_with_timeout(read_op, timeout)
        assert _hdr
        return SNL._copy_hdr(_hdr)

    @staticmethod
    def _handle_error(e):
        if e.error_str:
            error_msg = string_at(e.error_str).decode()
        else:
            error_msg = os.strerror(e.error)
        raise OSError(e.error, error_msg)

    def read_reply_multi(self, nlmsg_seq, *, timeout=None):
        e = snl_errmsg_data()
        read_op = lambda:snl_read_reply_multi(addressof(self.ss), nlmsg_seq, addressof(e))
        _hdr = self._read_with_timeout(read_op, timeout)
        if e.error:
            SNL._handle_error(e)
        return SNL._copy_hdr(_hdr) if _hdr else None

    def read_reply_code(self, nlmsg_seq, *, timeout=None):
        e = snl_errmsg_data()
        read_op = lambda:snl_read_reply_code(addressof(self.ss), nlmsg_seq, addressof(e))
        rc = self._read_with_timeout(read_op, timeout)
        if e.error:
            SNL._handle_error(e)
        assert rc

    def parse_nlmsg(self, hdr, parser):
        target = parser.t()
        try:
            if not snl_parse_nlmsg(addressof(self.ss), addressof(hdr), parser.c_fn_p, addressof(target)):
                raise Exception()
            # deepcopy the known result to normalize the memory addresses (in reality python refs)
            copy = target.deepcopy()
        finally:
            self._clear_lb()
        return copy

    def new_writer(self):
        return SNLWriter(self)

    def _clear_lb(self):
        snl_clear_lb(addressof(self.ss))

    def __del__(self):
        # for safety we don't assume that ss was set
        ss = getattr(self, 'ss', None)
        if ss:
            delattr(self, 'ss')
            snl_free(addressof(ss))

# NOTE
#   This odd class records a series of operations on an SNLWriter, but doesn't
#   actually execute them until we finalize.  This way we don't have to worry about
#   bad memory references from reallocations and clear_lb.  This is still less code
#   than porting everything to python, or writing my own snl
class SNLWriter:

    def __init__(self, snl):
        self.snl = snl
        self.nw = snl_writer()
        snl_init_writer(addressof(snl.ss), addressof(self.nw))
        assert not self.nw.error
        self.ops = []
        self.finalized = False

    def reserve_msg_data_raw(self, sz):
        buf = (c_byte*sz)()
        def op():
            p = c_void_p(snl_reserve_msg_data_raw(addressof(self.nw), sz))
            assert not self.nw.error
            assert p
            memmove(p, buf, sz)
        self.ops.append(op)
        return cast(buf, c_void_p)
       
    def reserve_msg_object(self, t):
        p = self.reserve_msg_data_raw(sizeof(t))
        return t.from_address(p.value)

    def add_msg_attr(self, attr_type, data):
        attr_len = sizeof(data)
        data_copy = (c_byte*attr_len).from_buffer_copy(data)
        def op():
            rc = snl_add_msg_attr(addressof(self.nw), attr_type, attr_len, addressof(data_copy))
            assert not self.nw.error
            assert rc
        self.ops.append(op)

    def create_msg_request(self, nlmsg_type):
        hdr = nlmsghdr()
        # TODO special cases are gross
        hdr.nlmsg_type = nlmsg_type
        hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK
        def op():
            _hdr = snl_create_msg_request(addressof(self.nw), nlmsg_type)
            assert not self.nw.error
            assert _hdr
            h = nlmsghdr.from_address(_hdr)
            # TODO certain fields are created already, this overwrites them
            #   this is currently handled by special casing above, eww
            memmove(_hdr, addressof(hdr), sizeof(hdr))
        self.ops.append(op)
        return hdr

    def finalize_msg(self):
        if self.finalized:
            raise Exception()
        self.finalized = True
        try:
            for op in self.ops:
                op()
            _hdr = snl_finalize_msg(addressof(self.nw))
            assert not self.nw.error
            assert _hdr
            hdr = nlmsghdr.from_address(_hdr)
            buf = (c_byte*hdr.nlmsg_len)()
            memmove(buf, addressof(hdr), hdr.nlmsg_len)
            return nlmsghdr.from_buffer(buf)
        finally:
            self.snl._clear_lb()

Parser = namedtuple('Parser', ['c_fn_p', 't'])
snl_rtm_link_parser_simple = Parser(snl_rtm_link_parser_simple, snl_parsed_link_simple)
snl_rtm_addr_parser = Parser(snl_rtm_addr_parser, snl_parsed_addr)
snl_rtm_route_parser = Parser(snl_rtm_route_parser, snl_parsed_route)

