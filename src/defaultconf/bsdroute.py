#!/usr/bin/env python3

from enum import Enum
import sys
import logging
import ipaddress
import os
from collections import namedtuple
import socket
from ctypes import *
from textwrap import wrap

from .bsdcommon import *

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

# net/route.h
RTM_VERSION = 5

# net/route.h
class RTM_ADDR(Enum):
    RTA_DST = 0x1
    RTA_GATEWAY = 0x2
    RTA_NETMASK = 0x4
    RTA_GENMASK = 0x8
    RTA_IFP = 0x10
    RTA_IFA = 0x20
    RTA_AUTHOR = 0x40
    RTA_BRD = 0x80

# net/route.h
class RTM_FLAG(Enum):
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
class RTM_TYPE(Enum):
    RTM_ADD = 0x1
    RTM_DELETE = 0x2
    RTM_CHANGE = 0x3
    RTM_GET = 0x4
    RTM_LOSING = 0x5
    RTM_REDIRECT = 0x6
    RTM_MISS = 0x7
    RTM_LOCK = 0x8
    RTM_RESOLVE = 0xb
    RTM_NEWADDR = 0xc
    RTM_DELADDR = 0xd
    RTM_IFINFO = 0xe
    RTM_NEWMADDR = 0xf
    RTM_DELMADDR = 0x10
    RTM_IFANNOUNCE = 0x11
    RTM_IEEE80211 = 0x12

# net/route.h
def SA_SIZE(sa):
    sa_len = sa.sa_len
    if sa_len == 0:
        return sizeof(c_long)
    return 1+((sa_len-1) | (sizeof(c_long)-1))

rtm_hdr_types = {}
rtm_hdr_types[RTM_TYPE.RTM_ADD] = rt_msghdr
rtm_hdr_types[RTM_TYPE.RTM_DELETE] = rt_msghdr
rtm_hdr_types[RTM_TYPE.RTM_CHANGE] = rt_msghdr
rtm_hdr_types[RTM_TYPE.RTM_GET] = rt_msghdr
rtm_hdr_types[RTM_TYPE.RTM_LOSING] = rt_msghdr
rtm_hdr_types[RTM_TYPE.RTM_REDIRECT] = rt_msghdr
rtm_hdr_types[RTM_TYPE.RTM_MISS] = rt_msghdr
rtm_hdr_types[RTM_TYPE.RTM_LOCK] = rt_msghdr
rtm_hdr_types[RTM_TYPE.RTM_RESOLVE] = rt_msghdr
rtm_hdr_types[RTM_TYPE.RTM_NEWADDR] = ifa_msghdr
rtm_hdr_types[RTM_TYPE.RTM_DELADDR] = ifa_msghdr
rtm_hdr_types[RTM_TYPE.RTM_IFINFO] = if_msghdr
rtm_hdr_types[RTM_TYPE.RTM_NEWMADDR] = ifma_msghdr
rtm_hdr_types[RTM_TYPE.RTM_DELMADDR] = ifma_msghdr
rtm_hdr_types[RTM_TYPE.RTM_IFANNOUNCE] = if_announcemsghdr
rtm_hdr_types[RTM_TYPE.RTM_IEEE80211] = if_announcemsghdr

def ensure_buffer(source, offset, sz):
    if (len(source)-offset) >= sz:
        return source, offset
    buf = bytearray(sz)
    buf[:len(source)] = source
    return buf, 0

def get_rtm_addrs(buf, p, rtm_hdr_addrs):
    rtm_addrs = {}
    for rtm_addr in RTM_ADDR:
        if (rtm_hdr_addrs & rtm_addr.value) == 0:
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
            rtm_addrs[rtm_addr] = rta
        p += SA_SIZE(sa)
    return p, rtm_addrs

# extract field as int without creating struct
def int_cfield(buf, offset, cfield):
    p = offset+cfield.offset
    return int.from_bytes(buf[p:p+cfield.size], byteorder=sys.byteorder)

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
        rtm_type = RTM_TYPE(int_cfield(buf, p, rt_msghdr.rtm_type))
        rtm_hdr_type = rtm_hdr_types[rtm_type]
        rtm_hdr = rtm_hdr_type.from_buffer(buf, p)
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
            rtm_addrs = {}
        else:
            raise Exception(f'unknown rtm_hdr: {(type(rtm_hdr))}')
        assert p == rtm_msglen
        handler(rtm_type, rtm_hdr, rtm_addrs)

def str_sockaddr(sa):
    if sa is None:
        return None
    elif type(sa) is sockaddr_dl:
        if sa.sdl_nlen != 0:
            return sa.sdl_data[:sa.sdl_nlen].decode()
        elif sa.sdl_alen != 0:
            return ':'.join(wrap(sa.sdl_data[:sa.sdl_alen].hex(), 2))
        elif sa.sdl_index != 0:
            return f'link#{sa.sdl_index}'
        raise Exception()
    elif type(sa) is sockaddr_in:
        return str(ipaddress.ip_address(bytes(sa.sin_addr)))
    elif type(sa) is sockaddr_in6:
        return str(ipaddress.ip_address(bytes(sa.sin6_addr)))
    raise Exception(f'unknown sa type: {type(sa)}')

def str_flags(flags, n):
    flag_names = []
    for flag in flags:
        if n & flag.value:
            flag_names.append(flag.name)
    return '|'.join(flag_names)

def main():
    def handler(rtm_type, rtm_hdr, rtm_addrs):
        str_rtm_addrs = {i[0].name: str_sockaddr(i[1]) for i in rtm_addrs.items()}
        print(rtm_type.name)
        print(f'  rtm_addrs={str_rtm_addrs}')
        if type(rtm_hdr) is rt_msghdr:
            str_rtm_flags = str_flags(RTM_FLAG, rtm_hdr.rtm_flags)
            print(f'  rtm_flags={str_rtm_flags}')
        elif type(rtm_hdr) is if_msghdr:
            str_ifm_flags = str_flags(IFM_FLAG, rtm_hdr.ifm_flags)
            print(f'  ifm_flags={str_ifm_flags}')
            print(f'  ifm_index={rtm_hdr.ifm_index}')
        elif type(rtm_hdr) is ifa_msghdr:
            str_ifam_flags = str_flags(IFM_FLAG, rtm_hdr.ifam_flags)
            print(f'  ifam_flags={str_ifam_flags}')
            print(f'  ifam_index={rtm_hdr.ifam_index}')
        print()
        sys.stdout.flush()

    pf_route_process(handler)

if __name__ == '__main__':
    main()
    
