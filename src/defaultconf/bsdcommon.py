#!/usr/bin/env python3

from ctypes import *

suseconds_t = c_long   # sys/_types.h
time_t = c_int64       # x86/_types.h
sa_family_t = c_uint8  # sys/_types.h
in_port_t = c_uint16   # sys/types.h
in_addr_t = c_uint32   # sys/types.h
u_char = c_ubyte       # sys/types.h
size_t = c_uint64      # sys/_types.h
unsigned = c_uint      # c-spec

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

