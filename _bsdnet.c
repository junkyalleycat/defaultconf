#include <Python.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netlink/netlink.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route_parsers.h>

static PyObject* bsdnet_snl_init(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    int netlink_family;
    if (!PyArg_ParseTuple(args, "Li", &ss, &netlink_family)) {
        return NULL;
    }
    if (!snl_init(ss, netlink_family)) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* bsdnet_snl_free(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    snl_free(ss);
    Py_RETURN_NONE;
}

static PyObject* bsdnet_snl_clear_lb(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    snl_clear_lb(ss);
    Py_RETURN_NONE;
}

static PyObject* bsdnet_snl_get_seq(PyObject* self, PyObject* args) {
    struct snl_state *ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    return PyLong_FromLongLong(snl_get_seq(ss));
}

static PyObject* bsdnet_snl_send_message(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    struct nlmsghdr* hdr;
    if (!PyArg_ParseTuple(args, "LL", &ss, &hdr)) {
        return NULL;
    }
    if (!snl_send_message(ss, hdr)) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* bsdnet_snl_read_reply_multi(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    uint32_t nlmsg_seq;
    struct snl_errmsg_data* e;
    if (!PyArg_ParseTuple(args, "LiL", &ss, &nlmsg_seq, &e)) {
        return NULL;
    }
    return PyLong_FromVoidPtr(snl_read_reply_multi(ss, nlmsg_seq, e));
}

static PyObject* bsdnet_snl_parse_nlmsg(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    struct nlmsghdr* hdr;
    struct snl_hdr_parser* parser;
    void* target;
    if (!PyArg_ParseTuple(args, "LLLL", &ss, &hdr, &parser, &target)) {
        return NULL;
    }
    return PyBool_FromLong(snl_parse_nlmsg(ss, hdr, parser, target));
}

static PyObject* bsdnet_snl_read_message(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    struct nlmsghdr* hdr;
    if (!(hdr = snl_read_message(ss))) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    return PyLong_FromVoidPtr(hdr); 
}

static PyMethodDef bsdnet_methods[] = {
    {"snl_init", bsdnet_snl_init, METH_VARARGS, NULL},
    {"snl_free", bsdnet_snl_free, METH_VARARGS, NULL},
    {"snl_clear_lb", bsdnet_snl_clear_lb, METH_VARARGS, NULL},
    {"snl_get_seq", bsdnet_snl_get_seq, METH_VARARGS, NULL},
    {"snl_send_message", bsdnet_snl_send_message, METH_VARARGS, NULL},
    {"snl_read_reply_multi", bsdnet_snl_read_reply_multi, METH_VARARGS, NULL},
    {"snl_parse_nlmsg", bsdnet_snl_parse_nlmsg, METH_VARARGS, NULL},
    {"snl_read_message", bsdnet_snl_read_message, METH_VARARGS, NULL},
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

    PyModule_AddIntConstant(module, "IFF_UP", IFF_UP);
    PyModule_AddIntConstant(module, "IF_NAMESIZE", IF_NAMESIZE);
    
    PyModule_AddIntConstant(module, "RTF_GATEWAY", RTF_GATEWAY);
    PyModule_AddIntConstant(module, "RTF_HOST", RTF_HOST);
    
    return module;
}

