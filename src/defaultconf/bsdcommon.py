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

AF_NETLINK = 38            # sys/socket.h
PF_NETLINK = AF_NETLINK    # sys/socket.h
PF_ROUTE = socket.AF_ROUTE # sys/socket.h
SO_RERROR = 0x00020000     # sys/socket.h

IF_NAMESIZE = 16       # net/if.h
IFNAMSIZ = IF_NAMESIZE # net/if.h

pid_t = c_int32        # sys/_types.h
suseconds_t = c_long   # sys/_types.h
time_t = c_int64       # x86/_types.h
sa_family_t = c_uint8  # sys/_types.h
in_port_t = c_uint16   # sys/types.h
in_addr_t = c_uint32   # sys/types.h
u_char = c_ubyte       # sys/types.h
size_t = c_uint64      # sys/_types.h
ssize_t = c_int64      # sys/_types.h
unsigned = c_uint      # c-spec
socklen_t = c_uint32   # sys/_types.h

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

# sys/_iovec.h
class iovec(Structure):

    _fields_ = [
        ('iov_base', c_void_p),
        ('iov_len', size_t)
    ]

# sys/socket.h
class msghdr(Structure):

    _fields_ = [
        ('msg_name', c_void_p),
        ('msg_namelen', socklen_t),
        ('msg_iov', POINTER(iovec)),
        ('msg_iovlen', c_int),
        ('msg_control', c_void_p),
        ('msg_controllen', socklen_t),
        ('msg_flags', c_int)
    ]

# net/if.h
class IFM_FLAG(Enum):
    IFF_UP = 0x1
    IFF_BROADCAST = 0x2
    IFF_DEBUG = 0x4
    IFF_LOOPBACK = 0x8
    IFF_POINTOPOINT = 0x10
    IFF_NEEDSEPOCH = 0x20
    IFF_DRV_RUNNING = 0x40
    IFF_NOARP = 0x80
    IFF_PROMISC = 0x100
    IFF_ALLMULTI = 0x200
    IFF_DRV_OACTIVE = 0x400
    IFF_SIMPLEX = 0x800
    IFF_LINK0 = 0x1000
    IFF_LINK1 = 0x2000
    IFF_LINK2 = 0x4000
    IFF_ALTPHYS = IFF_LINK2
    IFF_MULTICAST = 0x8000
    IFF_CANTCONFIG = 0x10000
    IFF_PPROMISC = 0x20000
    IFF_MONITOR = 0x40000
    IFF_STATICARP = 0x80000
    IFF_STICKYARP = 0x100000
    IFF_DYING = 0x200000
    IFF_RENAMING = 0x400000
    IFF_SPARE = 0x800000
    IFF_NETLINK_1 = 0x1000000
    IFF_RUNNING = IFF_DRV_RUNNING
    IFF_OACTIVE = IFF_DRV_OACTIVE

