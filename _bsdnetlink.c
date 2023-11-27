#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route_parsers.h>

static PyObject* bsdnetlink_snl_init(PyObject* self, PyObject* args) {
    int netlink_family;
    if (!PyArg_ParseTuple(args, "i", &netlink_family)) {
        return NULL;
    }
    struct snl_state *ss = malloc(sizeof(struct snl_state));
    if (ss == NULL) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    if (!snl_init(ss, netlink_family)) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    return PyLong_FromVoidPtr(ss);
}

static PyObject* bsdnetlink_snl_free(PyObject* self, PyObject* args) {
    struct snl_state *ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    snl_free(ss);
    Py_RETURN_NONE;
}

static PyObject* bsdnetlink_snl_clear_lb(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    snl_clear_lb(ss);
    Py_RETURN_NONE;
}

static PyObject* bsdnetlink_snl_get_seq(PyObject* self, PyObject* args) {
    struct snl_state *ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    return PyLong_FromLongLong(snl_get_seq(ss));
}

static PyObject* bsdnetlink_snl_send_message(PyObject* self, PyObject* args) {
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

static PyObject* bsdnetlink_snl_read_reply_multi(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    uint32_t nlmsg_seq;
    struct snl_errmsg_data* e;
    if (!PyArg_ParseTuple(args, "LiL", &ss, &nlmsg_seq, &e)) {
        return NULL;
    }
    return PyLong_FromVoidPtr(snl_read_reply_multi(ss, nlmsg_seq, e));
}

static PyObject* bsdnetlink_snl_parse_nlmsg(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    struct nlmsghdr* hdr;
    struct snl_hdr_parser* parser;
    void* target;
    if (!PyArg_ParseTuple(args, "LLLL", &ss, &hdr, &parser, &target)) {
        return NULL;
    }
    if (!snl_parse_nlmsg(ss, hdr, parser, target)) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyMethodDef bsdnetlink_snl_methods[] = {
    {"snl_init", bsdnetlink_snl_init, METH_VARARGS, NULL},
    {"snl_free", bsdnetlink_snl_free, METH_VARARGS, NULL},
    {"snl_clear_lb", bsdnetlink_snl_clear_lb, METH_VARARGS, NULL},
    {"snl_get_seq", bsdnetlink_snl_get_seq, METH_VARARGS, NULL},
    {"snl_send_message", bsdnetlink_snl_send_message, METH_VARARGS, NULL},
    {"snl_read_reply_multi", bsdnetlink_snl_read_reply_multi, METH_VARARGS, NULL},
    {"snl_parse_nlmsg", bsdnetlink_snl_parse_nlmsg, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef bsdnetlink_snl_module = {
    PyModuleDef_HEAD_INIT,
    "bsdnetlink_snl",
    NULL,
    -1,
    bsdnetlink_snl_methods
};

PyMODINIT_FUNC PyInit_bsdnetlink_snl() {
    PyObject* module = PyModule_Create(&bsdnetlink_snl_module);
    PyModule_AddIntConstant(module, "snl_rtm_link_parser_simple", (long) &snl_rtm_link_parser_simple);
    PyModule_AddIntConstant(module, "snl_rtm_route_parser", (long) &snl_rtm_route_parser);

    PyModule_AddIntConstant(module, "NETLINK_ROUTE", NETLINK_ROUTE);
    PyModule_AddIntConstant(module, "NLM_F_DUMP", NLM_F_DUMP);
    PyModule_AddIntConstant(module, "NLM_F_REQUEST", NLM_F_REQUEST);
    PyModule_AddIntConstant(module, "RTM_GETROUTE", RTM_GETROUTE);
    PyModule_AddIntConstant(module, "RTM_GETLINK", RTM_GETLINK);
    PyModule_AddIntConstant(module, "RTA_TABLE", RTA_TABLE);

    return module;
}

