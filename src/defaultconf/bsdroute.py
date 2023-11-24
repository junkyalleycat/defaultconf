#!/usr/bin/env python3

import logging
import sys
import ipaddress
import os
from collections import namedtuple
import socket
from ctypes import *
from textwrap import wrap

PF_ROUTE = 17          # sys/socket.h
SO_RERROR = 0x00020000 # sys/socket.h

IF_NAMESIZE = 16       # net/if.h
IFNAMSIZ = IF_NAMESIZE # net/if.h

pid_t = c_int32        # sys/_types.h
suseconds_t = c_long   # sys/_types.h
time_t = c_int64       # x86/_types.h
sa_family_t = c_uint8  # sys/_types.h
in_port_t = c_uint16   # sys/types.h
in_addr_t = c_uint32   # sys/types.h
u_char = c_ubyte       # sys/types.h

# sys/_timeval.h
class timeval(Structure):

    _fields_ = [
        ('tv_sec', time_t),
        ('tv_usec', suseconds_t)
    ]

# net/if_dl.h
class sockaddr_dl(Structure):

    _fields_ = [
        ('sdl_len', u_char),
        ('sdl_family', u_char),
        ('sdl_index', c_ushort),
        ('sdl_type', u_char),
        ('sdl_nlen', u_char),
        ('sdl_alen', u_char),
        ('sdl_slen', u_char),
        ('sdl_data', c_char*46)
    ]

# sys/socket.h
class sockaddr(Structure):

    _fields_ = [
        ('sa_len', u_char),
        ('sa_family', sa_family_t),
        ('sa_data', c_char*14)
    ]

# netinet/in.h
class in_addr(Structure):

    _fields_ = [
        ('s_addr', in_addr_t)
    ]

# netinet/in.h
class sockaddr_in(Structure):

    _fields_ = [
        ('sin_len', c_uint8),
        ('sin_family', sa_family_t),
        ('sin_port', in_port_t),
        ('sin_addr', in_addr),
        ('sin_zero', c_char*8)
    ]

# netinet6/in6.h
class in6_addr(Structure):

    class __u6_addr(Union):

        _fields_ = [
            ('__u6_addr8', c_uint8*16),
            ('__u6_addr16', c_uint16*8),
            ('__u6_addr32', c_uint32*4)
        ]

    _anonymous_ = ('__u6_addr',)
    _fields_ = [
        ('__u6_addr', __u6_addr)
    ]

# netinet6/in6.h
class sockaddr_in6(Structure):

    _fields_ = [
        ('sin6_len', c_uint8),
        ('sin6_family', sa_family_t),
        ('sin6_port', in_port_t),
        ('sin6_flowinfo', c_uint32),
        ('sin6_addr', in6_addr),
        ('sin6_scope_id', c_uint32)
    ]

# net/route.h
class rt_metrics(Structure):

    _fields_ = [
        ('rmx_locks', c_ulong),
        ('rmx_mtu', c_ulong),
        ('rmx_hopcount', c_ulong),
        ('rmx_expire', c_ulong),
        ('rmx_recvpipe', c_ulong),
        ('rmx_sendpipe', c_ulong),
        ('rmx_ssthresh', c_ulong),
        ('rmx_rtt', c_ulong),
        ('rmx_rttvar', c_ulong),
        ('rmx_pksent', c_ulong),
        ('rmx_weight', c_ulong),
        ('rmx_nhidx', c_ulong),
        ('rmx_filler', c_ulong*2)
    ]

# net/route.h
class rt_msghdr(Structure):

    _fields_ = [
        ('rtm_msglen', c_ushort),
        ('rtm_version', u_char),
        ('rtm_type', u_char),
        ('rtm_index', c_ushort),
        ('_rtm_spare1', c_ushort),
        ('rtm_flags', c_int),
        ('rtm_addrs', c_int),
        ('rtm_pid', pid_t),
        ('rtm_seq', c_int),
        ('rtm_errno', c_int),
        ('rtm_fmask', c_int),
        ('rtm_inits', c_ulong),
        ('rtm_rmx', rt_metrics)
    ]

# net/if.h
class ifa_msghdr(Structure):

    _fields_ = [
        ('ifam_msglen', c_ushort),
        ('ifam_version', u_char),
        ('ifam_type', u_char),
        ('ifam_addrs', c_int),
        ('ifam_flags', c_int),
        ('ifam_index', c_ushort),
        ('_ifam_spare1', c_ushort),
        ('ifam_metrics', c_int)
    ]

# net/if.h
class if_data(Structure):

    class __ifi_epoch(Union):

        _fields_ = [
            ('tt', time_t),
            ('ph', c_uint64)
        ]

    class __ifi_lastchange(Union):

        class ph(Structure):

            _fields_ = [
                ('ph1', c_uint64),
                ('ph2', c_uint64)
            ]

        _anonymous_ = ('ph',)
        _fields_ = [
            ('tv', timeval),
            ('ph', ph)
        ]

    _anonymous_ = ('__ifi_epoch', '__ifi_lastchange',)
    _fields_ = [
        ('ifi_type', c_uint8),
        ('ifi_physical', c_uint8),
        ('ifi_addrlen', c_uint8),
        ('ifi_hdrlen', c_uint8),
        ('ifi_link_state', c_uint8),
        ('ifi_vhid', c_uint8),
        ('ifi_datalen', c_uint16),
        ('ifi_mtu', c_uint32),
        ('ifi_metric', c_uint32),
        ('ifi_baudrate', c_uint64),
        ('ifi_ipackets', c_uint64),
        ('ifi_ierrors', c_uint64),
        ('ifi_opackets', c_uint64),
        ('ifi_oerrors', c_uint64),
        ('ifi_collisions', c_uint64),
        ('ifi_ibytes', c_uint64),
        ('ifi_obytes', c_uint64),
        ('ifi_imcasts', c_uint64),
        ('ifi_omcasts', c_uint64),
        ('ifi_iqdrops', c_uint64),
        ('ifi_oqdrops', c_uint64),
        ('ifi_noproto', c_uint64),
        ('ifi_hwassist', c_uint64),
        ('__ifi_epoch', __ifi_epoch),
        ('__ifi_lastchange', __ifi_lastchange)
    ]

# net/if.h
class if_msghdr(Structure):

    _fields_ = [
        ('ifm_msglen', c_ushort),
        ('ifm_version', u_char),
        ('ifm_type', u_char),
        ('ifm_addrs', c_int),
        ('ifm_flags', c_int),
        ('ifm_index', c_ushort),
        ('_ifm_spare1', c_ushort),
        ('ifm_data', if_data)
    ]

# net/if.h
class ifma_msghdr(Structure):

    _fields_ = [
        ('ifmam_msglen', c_ushort),
        ('ifmam_version', u_char),
        ('ifmam_type', u_char),
        ('ifmam_addrs', c_int),
        ('ifmam_flags', c_int),
        ('ifmam_index', c_ushort),
        ('_ifmam_spare1', c_ushort)
    ]

# net/if.h
class if_announcemsghdr(Structure):

    _fields_ = [
        ('ifan_msglen', c_ushort),
        ('ifan_version', u_char),
        ('ifan_type', u_char),
        ('ifan_index', c_ushort),
        ('ifan_name', c_char*IFNAMSIZ),
        ('ifan_what', c_ushort)
    ]

# net/route.h
RTM_VERSION = 5

# net/route.h
RTA_DST = 0x1
RTA_GATEWAY = 0x2
RTA_NETMASK = 0x4
RTA_GENMASK = 0x8
RTA_IFP = 0x10
RTA_IFA = 0x20
RTA_AUTHOR = 0x40
RTA_BRD = 0x80

# net/route.h
RTAX_DST = 0
RTAX_GATEWAY = 1
RTAX_NETMASK = 2
RTAX_GENMASK = 3
RTAX_IFP = 4
RTAX_IFA = 5
RTAX_AUTHOR = 6
RTAX_BRD = 7
RTAX_MAX = 8

# net/route.h
RTF_UP = 0x1
RTF_GATEWAY = 0x2
RTF_HOST = 0x4
RTF_REJECT = 0x8
RTF_DYNAMIC = 0x10
RTF_MODIFIED = 0x20
RTF_DONE = 0x40
RTF_XRESOLVE = 0x200
RTF_LLINFO = 0x400
RTF_LLDATA = 0x400
RTF_STATIC = 0x800
RTF_BLACKHOLE = 0x1000
RTF_PROTO2 = 0x4000
RTF_PROTO1 = 0x8000
RTF_PROTO3 = 0x40000
RTF_FIXEDMTU = 0x80000
RTF_PINNED = 0x100000
RTF_LOCAL = 0x200000
RTF_BROADCAST = 0x400000
RTF_MULTICAST = 0x800000
RTF_STICKY = 0x10000000
RTF_GWFLAG_COMPAT = 0x80000000

# net/route.h
RTM_Type = namedtuple('RTM_Type', ['pretty', 'n', 'hdr_type'])
RTM_ADD = RTM_Type('RTM_ADD', 0x1, rt_msghdr)
RTM_DELETE = RTM_Type('RTM_DELETE', 0x2, rt_msghdr)
RTM_CHANGE = RTM_Type('RTM_CHANGE', 0x3, rt_msghdr)
RTM_GET = RTM_Type('RTM_GET', 0x4, rt_msghdr)
RTM_LOSING = RTM_Type('RTM_LOSING', 0x5, rt_msghdr)
RTM_REDIRECT = RTM_Type('RTM_REDIRECT', 0x6, rt_msghdr)
RTM_MISS = RTM_Type('RTM_MISS', 0x7, rt_msghdr)
RTM_LOCK = RTM_Type('RTM_LOCK', 0x8, rt_msghdr)
RTM_RESOLVE = RTM_Type('RTM_RESOLVE', 0xb, rt_msghdr)
RTM_NEWADDR = RTM_Type('RTM_NEWADDR', 0xc, ifa_msghdr)
RTM_DELADDR = RTM_Type('RTM_DELADDR', 0xd, ifa_msghdr)
RTM_IFINFO = RTM_Type('RTM_IFINFO', 0xe, if_msghdr)
RTM_NEWMADDR = RTM_Type('RTM_NEWMADDR', 0xf, ifma_msghdr)
RTM_DELMADDR = RTM_Type('RTM_DELMADDR', 0x10, ifma_msghdr)
RTM_IFANNOUNCE = RTM_Type('RTM_IFANNOUNCE', 0x11, if_announcemsghdr)
RTM_IEEE80211 = RTM_Type('RTM_IEEE80211', 0x12, if_announcemsghdr)

rtm_types = {
    RTM_ADD,
    RTM_DELETE,
    RTM_CHANGE,
    RTM_GET,
    RTM_LOSING,
    RTM_REDIRECT,
    RTM_MISS,
    RTM_LOCK,
    RTM_RESOLVE,
    RTM_NEWADDR,
    RTM_DELADDR,
    RTM_IFINFO,
    RTM_NEWMADDR,
    RTM_DELMADDR,
    RTM_IFANNOUNCE,
    RTM_IEEE80211
}

rtm_types_n = { e.n: e for e in rtm_types }

# net/route.h
def SA_SIZE(sa):
#    sa_len = int_cfield(bytes(sa), 0, sockaddr.sa_len)
    sa_len = sa.sa_len
    if sa_len == 0:
        return sizeof(c_long)
    return 1+((sa_len-1) | (sizeof(c_long)-1))

def ensure_buffer(source, offset, sz):
    if (len(source)-offset) >= sz:
        return source, offset
    buf = bytearray(sz)
    buf[:len(source)] = source
    return buf, 0

def get_rtm_addrs(buf, p, rtm_hdr_addrs):
    rtm_addrs = [None]*RTAX_MAX
    for i in range(RTAX_MAX):
        if (rtm_hdr_addrs & (1<<i)) == 0:
            continue
        # TODO avoid creating sockaddr (because buf might be smaller?)
        sa = sockaddr.from_buffer(buf, p)
        if sa.sa_len == 0:
            # TODO sbin/route/route.c just treats this like a default gateway
            # gonna fail on it until I have an example
            raise Exception('sa.sa_len == 0')
        else:
            if sa.sa_family == socket.AF_INET6:
                rta = sockaddr_in6.from_buffer(buf, p)
            elif sa.sa_family == socket.AF_INET:
                rta = sockaddr_in.from_buffer(buf, p)
            elif sa.sa_family == socket.AF_LINK:
                ebuf, ep = ensure_buffer(buf, p, sizeof(sockaddr_dl))
                rta = sockaddr_dl.from_buffer(ebuf, ep)
            else:
                raise Exception(f'unknown sa.sa_family: {sa.sa_family}')
            if sizeof(rta) < sa.sa_len:
                # NOTE
                # I think it's ok that we truncate, the reason is beause
                # if an attempt to read data beyond the end is made, the
                # code will loudly fail (index out of bounds)
                # also, all examples collected so far are for a long aligned sockaddr_dl
                logging.warning(f'sizeof(rta)[{sizeof(rta)}] < sa.sa_len[{sa.sa_len}]')
            rtm_addrs[i] = rta
        p += SA_SIZE(sa)
    return p, rtm_addrs

def int_cfield(buf, offset, cfield):
    p = offset+cfield.offset
    return int.from_bytes(buf[p:p+cfield.size], byteorder='little')

def pf_route_process(handler):
    s = socket.socket(PF_ROUTE, socket.SOCK_RAW, 0)
    # catch recv overrun errors
    # TODO do the error fields need to be checked in the headers?
    s.setsockopt(socket.SOL_SOCKET, SO_RERROR, 1)

    while True:
        buf = bytearray(os.read(s.fileno(), 2048))
        p = 0
        rtm_msglen = int_cfield(buf, p, rt_msghdr.rtm_msglen)
        assert rtm_msglen == len(buf)
        rtm_version = int_cfield(buf, p, rt_msghdr.rtm_version)
        assert rtm_version == RTM_VERSION
        rtm_type_n = int_cfield(buf, p, rt_msghdr.rtm_type)
        rtm_type = rtm_types_n.get(rtm_type_n)
        if rtm_type is None:
            logging.warning(f'unknown rtm_type: {rtm_type_n}')
            continue
        rtm_hdr = rtm_type.hdr_type.from_buffer(buf, p)
        p += sizeof(rtm_hdr)
        if type(rtm_hdr) is rt_msghdr:
            p, rtm_addrs = get_rtm_addrs(buf, p, rtm_hdr.rtm_addrs)
        elif type(rtm_hdr) is ifa_msghdr:
            p, rtm_addrs = get_rtm_addrs(buf, p, rtm_hdr.ifam_addrs)
        elif type(rtm_hdr) is if_msghdr:
            p, rtm_addrs = get_rtm_addrs(buf, p, rtm_hdr.ifm_addrs)
        elif type(rtm_hdr) is ifma_msghdr:
            p, rtm_addrs = get_rtm_addrs(buf, p, rtm_hdr.ifmam_addrs)
        elif type(rtm_hdr) is if_announcemsghdr:
            rtm_addrs = [None]*RTAX_MAX
        else:
            raise Exception(f'unknown rtm_hdr: {(type(rtm_hdr))}')
        assert p == rtm_msglen
        handler(rtm_type, rtm_hdr, rtm_addrs)

def str_sockaddr(sa):
    if sa is None:
        return None
    elif type(sa) is sockaddr_dl:
        if sa.sdl_alen == 0:
            return f'link#{sa.sdl_index}'
        else:
            return ':'.join(wrap(sa.sdl_data[:sa.sdl_alen].hex(), 2))
    elif type(sa) is sockaddr_in:
        return str(ipaddress.ip_address(bytes(sa.sin_addr)))
    elif type(sa) is sockaddr_in6:
        return str(ipaddress.ip_address(bytes(sa.sin6_addr)))
    raise Exception(f'unknown sa type: {type(sa)}')

def main():
    def handler(rtm_type, rtm_hdr, rtm_addrs):
        str_rtm_addrs = [str_sockaddr(e) for e in rtm_addrs]
        print(f'{rtm_type.pretty} {str_rtm_addrs}')
        print()
        sys.stdout.flush()

    pf_route_process(handler)

if __name__ == '__main__':
    main()
    
