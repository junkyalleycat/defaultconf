#!/usr/bin/env python3

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

class SNL:

    def __init__(self, netlink_family, *, read_timeout=None):
        self.ss = snl_state()
        snl_init(addressof(self.ss), netlink_family)
        self.ss_s = socket.fromfd(self.ss.fd, AF_NETLINK, socket.SOCK_RAW)
        # not using python settimeout because it works very differently
        # (puts socket into non-blocking and uses select, which means the timeout is near 0)
        if read_timeout is not None:
            timeout = timeval(tv_sec=read_timeout, tv_usec=0)
            self.ss_s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)

    def get_socket(self):
        return self.ss_s

    def clear_lb(self):
        snl_clear_lb(addressof(self.ss))

    def get_seq(self):
        return snl_get_seq(addressof(self.ss))

    def send_message(self, hdr):
        snl_send_message(addressof(self.ss), addressof(hdr))

    def read_message(self):
        _hdr = c_void_p(snl_read_message(addressof(self.ss)))
        return _hdr if _hdr else None

    def read_reply_multi(self, nlmsg_seq):
        e = snl_errmsg_data()
        _hdr = c_void_p(snl_read_reply_multi(addressof(self.ss), nlmsg_seq, addressof(e)))
        if e.error != 0:
            if e.error_str:
                error_msg = string_at(e.error_str)
                raise Exception(f'error[{e.error}]: {error_msg}')
            else:
                raise Exception(f'error[{e.error}]')
        return _hdr if _hdr else None

    def parse_nlmsg(self, hdr, parser, target):
        if not snl_parse_nlmsg(addressof(self.ss), hdr.value, parser, addressof(target)):
            raise Exception()

    def __del__(self):
        snl_free(addressof(self.ss))

