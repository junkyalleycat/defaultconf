#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route_parsers.h>

static PyObject* bsdsnl_init(PyObject* self, PyObject* args) {
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

static PyObject* bsdsnl_free(PyObject* self, PyObject* args) {
    struct snl_state *ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    snl_free(ss);
    Py_RETURN_NONE;
}

static PyObject* bsdsnl_clear_lb(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    snl_clear_lb(ss);
    Py_RETURN_NONE;
}

static PyObject* bsdsnl_get_seq(PyObject* self, PyObject* args) {
    struct snl_state *ss;
    if (!PyArg_ParseTuple(args, "L", &ss)) {
        return NULL;
    }
    return PyLong_FromLongLong(snl_get_seq(ss));
}

static PyObject* bsdsnl_send_message(PyObject* self, PyObject* args) {
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

static PyObject* bsdsnl_read_reply_multi(PyObject* self, PyObject* args) {
    struct snl_state* ss;
    uint32_t nlmsg_seq;
    struct snl_errmsg_data* e;
    if (!PyArg_ParseTuple(args, "LiL", &ss, &nlmsg_seq, &e)) {
        return NULL;
    }
    return PyLong_FromVoidPtr(snl_read_reply_multi(ss, nlmsg_seq, e));
}

static PyObject* bsdsnl_parse_nlmsg(PyObject* self, PyObject* args) {
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

static PyMethodDef bsdsnl_methods[] = {
    {"snl_init", bsdsnl_init, METH_VARARGS, NULL},
    {"snl_free", bsdsnl_free, METH_VARARGS, NULL},
    {"snl_clear_lb", bsdsnl_clear_lb, METH_VARARGS, NULL},
    {"snl_get_seq", bsdsnl_get_seq, METH_VARARGS, NULL},
    {"snl_send_message", bsdsnl_send_message, METH_VARARGS, NULL},
    {"snl_read_reply_multi", bsdsnl_read_reply_multi, METH_VARARGS, NULL},
    {"snl_parse_nlmsg", bsdsnl_parse_nlmsg, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef bsdsnl_module = {
    PyModuleDef_HEAD_INIT,
    "bsdsnl",
    NULL,
    -1,
    bsdsnl_methods
};

PyMODINIT_FUNC PyInit_bsdsnl() {
    PyObject* module = PyModule_Create(&bsdsnl_module);
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

