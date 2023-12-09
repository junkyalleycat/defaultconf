#include <Python.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netlink/netlink.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route_parsers.h>

#define THROW_ON_ERRNO(_v) if (_v) { PyErr_SetFromErrno(PyExc_OSError); return NULL; }

static PyObject* bsdnet_snl_init(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    int netlink_family;
    if (!PyArg_ParseTuple(args, "Li", &ss, &netlink_family)) {
        return NULL;
    }
    errno = 0;
    bool rc = snl_init(ss, netlink_family);
    THROW_ON_ERRNO(errno);
    return PyBool_FromLong(rc);
}

static PyObject* bsdnet_snl_free(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    errno = 0;
    /* void */ snl_free(ss);
    THROW_ON_ERRNO(errno);
    Py_RETURN_NONE;
}

static PyObject* bsdnet_snl_clear_lb(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    errno = 0;
    /* void */ snl_clear_lb(ss);
    THROW_ON_ERRNO(errno);
    Py_RETURN_NONE;
}

static PyObject* bsdnet_snl_get_seq(PyObject* self, PyObject* args) {
    struct snl_state *ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    return PyLong_FromLong(snl_get_seq(ss));
}

static PyObject* bsdnet_snl_send_message(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    struct nlmsghdr* hdr;
    if (!PyArg_ParseTuple(args, "LL", &ss, &hdr)) {
        return NULL;
    }
    errno = 0;
    bool rc = snl_send_message(ss, hdr);
    THROW_ON_ERRNO(errno);
    return PyBool_FromLong(rc);
}

static PyObject *bsdnet_snl_read_reply_code(PyObject *self, PyObject *args) {
    struct snl_state *ss;
    uint32_t nlmsg_seq;
    struct snl_errmsg_data *e;
    if (!PyArg_ParseTuple(args, "LiL", &ss, &nlmsg_seq, &e)) {
        return NULL;
    }
    bool rc;
    int my_errno;
    Py_BEGIN_ALLOW_THREADS;
    errno = 0;
    rc = snl_read_reply_code(ss, nlmsg_seq, e);
    my_errno = errno;
    Py_END_ALLOW_THREADS;
    THROW_ON_ERRNO(my_errno);
    return PyBool_FromLong(rc);
}

static PyObject *bsdnet_snl_read_reply_multi(PyObject *self, PyObject *args) {
    struct snl_state *ss;
    uint32_t nlmsg_seq;
    struct snl_errmsg_data *e;
    if (!PyArg_ParseTuple(args, "LiL", &ss, &nlmsg_seq, &e)) {
        return NULL;
    }
    void *hdr;
    int my_errno;
    Py_BEGIN_ALLOW_THREADS;
    errno = 0;
    hdr = snl_read_reply_multi(ss, nlmsg_seq, e);
    my_errno = errno;
    Py_END_ALLOW_THREADS;
    THROW_ON_ERRNO(my_errno);
    return PyLong_FromVoidPtr(hdr);
}

static PyObject *bsdnet_snl_read_reply(PyObject *self, PyObject *args) {
    struct snl_state *ss;
    uint32_t nlmsg_seq;
    if (!PyArg_ParseTuple(args, "Li", &ss, &nlmsg_seq)) {
        return NULL;
    }
    void *hdr;
    int my_errno;
    Py_BEGIN_ALLOW_THREADS;
    errno = 0;
    hdr = snl_read_reply(ss, nlmsg_seq);
    my_errno = errno;
    Py_END_ALLOW_THREADS;
    THROW_ON_ERRNO(my_errno);
    return PyLong_FromVoidPtr(hdr);
}

static PyObject* bsdnet_snl_parse_nlmsg(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    struct nlmsghdr* hdr;
    struct snl_hdr_parser* parser;
    void* target;
    if (!PyArg_ParseTuple(args, "LLLL", &ss, &hdr, &parser, &target)) {
        return NULL;
    }
    errno = 0;
    bool rc = PyBool_FromLong(snl_parse_nlmsg(ss, hdr, parser, target));
    THROW_ON_ERRNO(errno);
    return PyBool_FromLong(rc);
}

static PyObject *bsdnet_snl_read_message(PyObject *self, PyObject *args) {
    struct snl_state *ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    void *hdr;
    int my_errno;
    Py_BEGIN_ALLOW_THREADS;
    errno = 0;
    hdr = snl_read_message(ss);
    my_errno = errno;
    Py_END_ALLOW_THREADS;
    THROW_ON_ERRNO(my_errno);
    return PyLong_FromVoidPtr(hdr); 
}

static PyObject* bsdnet_snl_init_writer(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    struct snl_writer* nw;
    if (!PyArg_ParseTuple(args, "LL", &ss, &nw)) {
        return NULL;
    }
    errno = 0;
    /* void */ snl_init_writer(ss, nw);
    THROW_ON_ERRNO(errno);
    Py_RETURN_NONE;
}

static PyObject *bsdnet_snl_create_msg_request(PyObject *self, PyObject *args) {
    struct snl_writer *nw;
    int nlmsg_type;
    if (!PyArg_ParseTuple(args, "Li", &nw, &nlmsg_type)) {
        return NULL;
    }
    errno = 0;
    struct nlmsghdr *hdr = snl_create_msg_request(nw, nlmsg_type);
    THROW_ON_ERRNO(errno);
    return PyLong_FromVoidPtr(hdr);
}

static PyObject *bsdnet_snl_reserve_msg_data_raw(PyObject *self, PyObject *args) {
    struct snl_writer *nw;
    size_t sz;
    if (!PyArg_ParseTuple(args, "LL", &nw, &sz)) {
        return NULL;
    }
    errno = 0;
    void *p = snl_reserve_msg_data_raw(nw, sz);
    THROW_ON_ERRNO(errno);
    return PyLong_FromVoidPtr(p);
}


static PyObject *bsdnet_snl_add_msg_attr(PyObject *self, PyObject *args) {
    struct snl_writer *nw;
    int attr_type;
    int attr_len;
    void *data;
    if (!PyArg_ParseTuple(args, "LiiL", &nw, &attr_type, &attr_len, &data)) {
        return NULL;
    }
    errno = 0;
    bool rc = snl_add_msg_attr(nw, attr_type, attr_len, data);
    THROW_ON_ERRNO(errno);
    return PyBool_FromLong(rc);
}

static PyObject *bsdnet_snl_finalize_msg(PyObject *self, PyObject *args) {
    struct snl_writer *nw;
    if (!PyArg_ParseTuple(args, "L", &nw)) {
        return NULL;
    }
    errno = 0;
    struct nlmsghdr *hdr = snl_finalize_msg(nw);
    THROW_ON_ERRNO(errno);
    return PyLong_FromVoidPtr(hdr);
}

static PyMethodDef bsdnet_methods[] = {
    {"snl_init", bsdnet_snl_init, METH_VARARGS, NULL},
    {"snl_free", bsdnet_snl_free, METH_VARARGS, NULL},
    {"snl_clear_lb", bsdnet_snl_clear_lb, METH_VARARGS, NULL},
    {"snl_get_seq", bsdnet_snl_get_seq, METH_VARARGS, NULL},
    {"snl_send_message", bsdnet_snl_send_message, METH_VARARGS, NULL},
    {"snl_read_reply_multi", bsdnet_snl_read_reply_multi, METH_VARARGS, NULL},
    {"snl_read_reply_code", bsdnet_snl_read_reply_code, METH_VARARGS, NULL},
    {"snl_read_reply", bsdnet_snl_read_reply, METH_VARARGS, NULL},
    {"snl_parse_nlmsg", bsdnet_snl_parse_nlmsg, METH_VARARGS, NULL},
    {"snl_read_message", bsdnet_snl_read_message, METH_VARARGS, NULL},
    {"snl_init_writer", bsdnet_snl_init_writer, METH_VARARGS, NULL},
    {"snl_create_msg_request", bsdnet_snl_create_msg_request, METH_VARARGS, NULL},
    {"snl_reserve_msg_data_raw", bsdnet_snl_reserve_msg_data_raw, METH_VARARGS, NULL},
    {"snl_add_msg_attr", bsdnet_snl_add_msg_attr, METH_VARARGS, NULL},
    {"snl_finalize_msg", bsdnet_snl_finalize_msg, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef bsdnet_module = {
    PyModuleDef_HEAD_INIT,
    "_bsdnet",
    NULL,
    -1,
    bsdnet_methods
};

PyMODINIT_FUNC PyInit__bsdnet() {
    PyObject* module = PyModule_Create(&bsdnet_module);
    PyModule_AddIntConstant(module, "snl_rtm_link_parser_simple", (long) &snl_rtm_link_parser_simple);
    PyModule_AddIntConstant(module, "snl_rtm_route_parser", (long) &snl_rtm_route_parser);
    PyModule_AddIntConstant(module, "snl_rtm_addr_parser", (long) &snl_rtm_addr_parser);
    PyModule_AddIntConstant(module, "snl_rtm_link_parser", (long) &snl_rtm_link_parser);

    PyModule_AddIntConstant(module, "AF_NETLINK", AF_NETLINK);
    PyModule_AddIntConstant(module, "NETLINK_ROUTE", NETLINK_ROUTE);
    PyModule_AddIntConstant(module, "NLM_F_DUMP", NLM_F_DUMP);
    PyModule_AddIntConstant(module, "NLM_F_REQUEST", NLM_F_REQUEST);
    PyModule_AddIntConstant(module, "NLM_F_CREATE", NLM_F_CREATE);
    PyModule_AddIntConstant(module, "NLM_F_EXCL", NLM_F_EXCL);
    PyModule_AddIntConstant(module, "NLM_F_ACK", NLM_F_ACK);
    PyModule_AddIntConstant(module, "RTM_GETROUTE", RTM_GETROUTE);
    PyModule_AddIntConstant(module, "RTM_GETLINK", RTM_GETLINK);
    PyModule_AddIntConstant(module, "RTM_GETADDR", RTM_GETADDR);
    PyModule_AddIntConstant(module, "RTA_TABLE", RTA_TABLE);
    PyModule_AddIntConstant(module, "RTNLGRP_LINK", RTNLGRP_LINK);
    PyModule_AddIntConstant(module, "RTNLGRP_NEIGH", RTNLGRP_NEIGH);
    PyModule_AddIntConstant(module, "RTNLGRP_NEXTHOP", RTNLGRP_NEXTHOP);
    PyModule_AddIntConstant(module, "RTNLGRP_IPV4_IFADDR", RTNLGRP_IPV4_IFADDR);
    PyModule_AddIntConstant(module, "RTNLGRP_IPV4_ROUTE", RTNLGRP_IPV4_ROUTE);
    PyModule_AddIntConstant(module, "RTNLGRP_IPV6_IFADDR", RTNLGRP_IPV6_IFADDR);
    PyModule_AddIntConstant(module, "RTNLGRP_IPV6_ROUTE", RTNLGRP_IPV6_ROUTE);
    PyModule_AddIntConstant(module, "RTN_UNICAST", RTN_UNICAST);
    PyModule_AddIntConstant(module, "RT_SCOPE_LINK", RT_SCOPE_LINK);
    PyModule_AddIntConstant(module, "NETLINK_MSG_INFO", NETLINK_MSG_INFO);
    PyModule_AddIntConstant(module, "NETLINK_ADD_MEMBERSHIP", NETLINK_ADD_MEMBERSHIP);
    PyModule_AddIntConstant(module, "SOL_NETLINK", SOL_NETLINK);
    PyModule_AddIntConstant(module, "RTM_NEWLINK", RTM_NEWLINK);
    PyModule_AddIntConstant(module, "RTM_DELLINK", RTM_DELLINK);
    PyModule_AddIntConstant(module, "RTM_NEWADDR", RTM_NEWADDR);
    PyModule_AddIntConstant(module, "RTM_DELADDR", RTM_DELADDR);
    PyModule_AddIntConstant(module, "RTM_NEWROUTE", RTM_NEWROUTE);
    PyModule_AddIntConstant(module, "RTM_DELROUTE", RTM_DELROUTE);
    PyModule_AddIntConstant(module, "RTM_NEWNEIGH", RTM_NEWNEIGH);
    PyModule_AddIntConstant(module, "RTM_DELNEIGH", RTM_DELNEIGH);
    PyModule_AddIntConstant(module, "RT_TABLE_MAIN", RT_TABLE_MAIN);
    PyModule_AddIntConstant(module, "RT_SCOPE_NOWHERE", RT_SCOPE_NOWHERE);
    PyModule_AddIntConstant(module, "RTPROT_BOOT", RTPROT_BOOT);
    PyModule_AddIntConstant(module, "RTN_UNICAST", RTN_UNICAST);
    PyModule_AddIntConstant(module, "RT_SCOPE_UNIVERSE", RT_SCOPE_UNIVERSE);
    PyModule_AddIntConstant(module, "RTA_GATEWAY", RTA_GATEWAY);
    PyModule_AddIntConstant(module, "RTA_DST", RTA_DST);
    PyModule_AddIntConstant(module, "RTA_OIF", RTA_OIF);
    PyModule_AddIntConstant(module, "IFLA_IFNAME", IFLA_IFNAME);

    PyModule_AddIntConstant(module, "IFF_UP", IFF_UP);
    PyModule_AddIntConstant(module, "IF_NAMESIZE", IF_NAMESIZE);
    
    PyModule_AddIntConstant(module, "RTF_GATEWAY", RTF_GATEWAY);
    PyModule_AddIntConstant(module, "RTF_HOST", RTF_HOST);
    
    return module;
}

