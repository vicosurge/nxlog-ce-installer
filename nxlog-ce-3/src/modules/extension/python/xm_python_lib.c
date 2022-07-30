#include <Python.h>

#ifdef gid_t
# undef gid_t
#endif

#ifdef uid_t
# undef uid_t
#endif

#include "../../../common/module.h"
#include "../../../common/date.h"
#include "../../../common/error_debug.h"
#include "libnxpython.h"
#include "xm_python.h"


#define NX_LOGMODULE NX_LOGMODULE_MODULE

//#define DEBUG_REFCNT_BUILD

#ifdef DEBUG_REFCNT_BUILD

#define _LOG_PYREF(x,s) log_info("LIB %s:%d %s, %s: %ld", __FILE__, __LINE__, (s), #x, Py_REFCNT(x))
#define LOG_Py_DECREF(x) _LOG_PYREF(x, "V"); Py_DECREF(x)
#define LOG_Py_INCREF(x) _LOG_PYREF(x, "^"); Py_INCREF(x)
#define LOG_Py_XDECREF(x) _LOG_PYREF(x, "V"); Py_XDECREF(x)

#else

#define LOG_Py_DECREF(x) Py_DECREF(x)
#define LOG_Py_INCREF(x) Py_INCREF(x)
#define LOG_Py_XDECREF(x) Py_XDECREF(x)

#endif


static PyObject *_object_from_value(nx_value_t *value)
{
    char date_iso[20];
    PyObject * obj = NULL;

    if (value == NULL || !value->defined)
    {
        Py_RETURN_NONE;
    }

    switch (value->type)
    {
	case NX_VALUE_TYPE_INTEGER:
        obj = PyLong_FromLong(value->integer);
        break;
    case NX_VALUE_TYPE_STRING:
        obj = PyUnicode_FromString(value->string->buf);
        break;
    case NX_VALUE_TYPE_DATETIME:
        nx_date_to_iso(date_iso, sizeof(date_iso), value->datetime);
        obj = PyUnicode_FromString(date_iso);
        break;
    case NX_VALUE_TYPE_BOOLEAN:
        obj = PyBool_FromLong(value->boolean);
        break;
    case NX_VALUE_TYPE_IP4ADDR:
    case NX_VALUE_TYPE_IP6ADDR:
        obj = PyUnicode_FromString(nx_value_to_string(value));
        break;
    case NX_VALUE_TYPE_BINARY:
//        obj = PyBuffer_FromReadWriteMemory(value->binary.value, value->binary.len);
	obj = PyMemoryView_FromMemory(value->binary.value, value->binary.len, PyBUF_READ | PyBUF_WRITE);
        break;
    case NX_VALUE_TYPE_UNKNOWN:
    default:
        break;
    }

    if (!obj) {
        Py_RETURN_NONE;
    }
    return obj;
}

static boolean _lookup_value(nx_logdata_t *logdata, const char *field_name, nx_value_t **value)
{
    nx_logdata_field_t *i_field;
    nx_logdata_field_list_t *fields = &(logdata->fields);

    for (i_field = NX_DLIST_FIRST(fields);
         i_field;
         i_field = NX_DLIST_NEXT(i_field, link))
    {
        if (strcmp(i_field->key, field_name) == 0)
        {
            *value = i_field->value;
            return TRUE;
        }
    }
    return FALSE;
}

static int _converter_module(PyObject *obj, void *result)
{
    nx_module_t **mod = (nx_module_t **)result;
    *mod = (nx_module_t *)PyCapsule_GetPointer(obj, "module");
    return (*mod) == NULL ? 0 : 1;
}
static int _converter_logdata(PyObject *obj, void *result)
{
    nx_logdata_t **data = (nx_logdata_t **)result;
    *data = (nx_logdata_t *)PyCapsule_GetPointer(obj, "logdata");
    return (*data) == NULL ? 0 : 1;
}

/**
 * Python call: libpynxlog.get_logdata_field(c_module, c_logdata, name)
 * @brief get_logdata_field find logdata filed by name and return its value
 * @param self
 * @param args: ( module: PyCapsule(nx_module_t*),
 *                logdata: PyCapsule(nx_logdata_t),
 *                name: PyString)
 * @return Field value if field exists, else None
 */
static PyObject *get_logdata_field(PyObject *self UNUSED, PyObject *args)
{
    nx_module_t *module;
    nx_logdata_t *logdata;
    nx_value_t *value;
    PyObject *py_value;
    PyObject *py_tuple;
    const char *field_name;
    PyArg_ParseTuple(args, "O&O&s",
                     _converter_module,
                     &module,
                     _converter_logdata,
                     &logdata,
                     &field_name);

    if (!_lookup_value(logdata, field_name, &value))
    {
        Py_RETURN_NONE;
    }
    py_value = _object_from_value(value);
    py_tuple = Py_BuildValue("O", py_value);
    LOG_Py_DECREF(py_value);
    return py_tuple;
}

/**
 * Python call: libpynxlog.set_field(c_module, c_logdata, name, value)
 * @brief set_field
 * @param self
 * @param args
 * @return
 */
static PyObject *set_logdata_field(PyObject *self UNUSED, PyObject *args)
{
    PyObject *py_value;
    nx_module_t *module;
    nx_logdata_t *logdata;
    const char *field_name;

    PyArg_ParseTuple(args, "O&O&sO",
                     _converter_module,
                     &module,
                     _converter_logdata,
                     &logdata,
                     &field_name,
                     &py_value);
    if (PyLong_Check(py_value))
    {
        nx_logdata_set_integer(logdata, field_name, PyLong_AsLong(py_value));
    }
    else if (PyLong_Check(py_value))
    {
        nx_logdata_set_integer(logdata, field_name, PyLong_AsLongLong(py_value));
    }
    else if (PyBytes_Check(py_value))
    {
	PyObject *tmp1 = PyObject_Str(py_value);
	PyObject *tmp2 = PyUnicode_AsEncodedString(tmp1, "utf-8", "replace");
	nx_logdata_set_string(logdata, field_name, PyBytes_AsString(tmp2));
	LOG_Py_DECREF(tmp1);
	LOG_Py_DECREF(tmp2);
    }
    else if (PyBool_Check(py_value))
    {
        nx_logdata_set_boolean(logdata, field_name, py_value == Py_True);
    }
    else
    {
	PyObject *py_str = PyObject_Str(py_value);
	PyObject *py_str2 = PyUnicode_AsEncodedString(py_str, "utf-8", "replace");
        nx_logdata_set_string(logdata, field_name,
                             (py_str ? PyBytes_AsString(py_str2) : ""));
        LOG_Py_DECREF(py_str);
	LOG_Py_DECREF(py_str2);
    }
    Py_RETURN_TRUE;
}

/**
 * @brief delete_field - remove field from logdata
 * @param self
 * @param args
 * @return
 */
static PyObject *delete_logdata_field(PyObject *self UNUSED, PyObject *args)
{
    nx_module_t *module;
    nx_logdata_t *logdata;
    const char *field_name;

    PyArg_ParseTuple(args, "O&O&s",
                     _converter_module,
                     &module,
                     _converter_logdata,
                     &logdata,
                     &field_name);
    if (field_name == NULL)
    {
        Py_RETURN_FALSE;
    }
    if (nx_logdata_delete_field(logdata, field_name) == TRUE)
    {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

/**
 * @brief field_names returns field names array
 * @param self
 * @param args
 * @return
 */
static PyObject *get_logdata_fieldnames(PyObject *self UNUSED, PyObject *args)
{
    nx_module_t *module;
    nx_logdata_t *logdata;
    nx_logdata_field_t *i_field;
    nx_logdata_field_list_t *fields;
    PyObject *result;
    PyObject *array;
    PyObject *item;
    PyArg_ParseTuple(args, "O&O&",
                     _converter_module,
                     &module,
                     _converter_logdata,
                     &logdata);

    fields = &(logdata->fields);

    array = PyList_New(0);

    for (i_field = NX_DLIST_FIRST(fields);
         i_field;
         i_field = NX_DLIST_NEXT(i_field, link))
    {
	item = PyUnicode_FromString(i_field->key);
	PyList_Append(array, item);
	LOG_Py_DECREF(item);
    }

    result = Py_BuildValue("O", array);
    LOG_Py_DECREF(array);
    return result;
}

/**
 * @brief field_type returns one of field type:
 * integer | string | datetime | regext | boolean | ip4addr |
 * ip6addr | binary | unknown
 * @param self
 * @param args
 * @return
 */
static PyObject *get_logdata_fieldtype(PyObject *self UNUSED, PyObject *args)
{
    nx_module_t *module;
    nx_logdata_t *logdata;
    const char *field_name;
    nx_value_t *value;

    PyArg_ParseTuple(args, "O&O&s",
                     _converter_module,
                     &module,
                     _converter_logdata,
                     &logdata,
                     &field_name);
    if (field_name == NULL)
    {
        Py_RETURN_NONE;
    }
    if (!_lookup_value(logdata, field_name, &value))
    {
        Py_RETURN_NONE;
    }
    if (!value->defined)
    {
        Py_RETURN_NONE;
    }
    return Py_BuildValue("s", nx_value_type_to_string(value->type));
}

/**
 * @brief push_logdata - append logdata to module input
 * @param self
 * @param args
 * @return
 */
static PyObject *post_logdata(PyObject * self UNUSED, PyObject * args)
{
    nx_logdata_t *logdata;
    nx_module_t *module;


    PyArg_ParseTuple(args, "O&O&",
                     _converter_module,
                     &module,
                     _converter_logdata,
                     &logdata);

    log_debug("add input data 0x%lx (module %s)", (unsigned long int)logdata,
             module->dsoname);

    PyThreadState *curr_tstate = PyThreadState_Get();
    // Release  GIL
    PyEval_SaveThread();

    nx_module_add_logdata_input(module, NULL, logdata);

    // Acquire GIL
    PyEval_RestoreThread(curr_tstate);

    Py_RETURN_NONE;
}

/**
 * @brief logdata_new Create logdata object
 * @param self
 * @param args
 * @return
 */
static PyObject *logdata_new(PyObject *self UNUSED, PyObject *args UNUSED)
{
    nx_logdata_t *logdata;
    PyObject *py_logdata;
    PyObject *ret;

    logdata = nx_logdata_new();
    py_logdata = PyCapsule_New(logdata, "logdata", NULL);
    ret = Py_BuildValue("O", py_logdata);
    LOG_Py_XDECREF(py_logdata);

    return ret;
}

/* LOGGING FUNCTIONS */
static PyObject *py_log_debug(PyObject *self UNUSED, PyObject *args)
{
    const char *msg;
    PyArg_ParseTuple(args, "s", &msg);
    if (msg)
    {
        log_debug("%s", msg);
    }
    Py_RETURN_NONE;
}

static PyObject *py_log_info(PyObject *self UNUSED, PyObject *args)
{
    const char *msg;
    PyArg_ParseTuple(args, "s", &msg);
    if (msg)
    {
        log_info("%s", msg);
    }
    Py_RETURN_NONE;
}

static PyObject *py_log_warning(PyObject *self UNUSED, PyObject *args)
{
    const char *msg;

    PyArg_ParseTuple(args, "s", &msg);
    if (msg)
    {
        log_warn("%s", msg);
    }
    Py_RETURN_NONE;
}

static PyObject *py_log_error(PyObject *self UNUSED, PyObject *args)
{
    const char *msg;

    PyArg_ParseTuple(args, "s", &msg);
    if (msg)
    {
        log_error("%s", msg);
    }
    Py_RETURN_NONE;
}

/**
 * @brief set_read_timer - add nxlog event
 * @param self
 * @param args
 * @return
 */
static PyObject * set_read_timer(PyObject *self UNUSED, PyObject *args)
{
    nx_module_t *module;
    nx_event_t *read_event;
    float delay;

    PyArg_ParseTuple(args, "O&f",
                     _converter_module,
                     &module,
                     &delay);

    if (module->type != NX_MODULE_TYPE_INPUT)
    {
	// not supported
	Py_RETURN_NONE;
    }

    read_event = nx_module_data_get(module, "read_event");
    ASSERT(read_event == NULL);
    log_debug("Add read event for %lx (%s),  delay=%f",
             (uint64_t)module,
             module->dsoname,
             delay);

    read_event = nx_event_new();
    read_event->module = module;
    read_event->delayed = TRUE;
    read_event->time = apr_time_now() + (apr_time_t)((float)APR_USEC_PER_SEC * delay);
    read_event->type = NX_EVENT_READ;
    read_event->priority = module->priority;
    nx_module_data_set(module, "read_event", nx_event_add(read_event), NULL);
    Py_RETURN_NONE;
}

/* Save context (any Python variable into module data) */
static PyObject * save_context(PyObject * self UNUSED, PyObject * args)
{
    PyObject * ctx_to_save;
    PyObject * old_saved_ctx;
    nx_module_t * module;
    char * key;
    PyArg_ParseTuple(args, "O&sO",
                     _converter_module,
                     &module,
                     &key,
                     &ctx_to_save);
    LOG_Py_INCREF(ctx_to_save);
    old_saved_ctx = nx_module_data_get(module, key);
    LOG_Py_XDECREF(old_saved_ctx);
    nx_module_data_set(module, key, ctx_to_save, NULL);
    Py_RETURN_NONE;
}

/* Load context from module data*/
static PyObject * load_context(PyObject * self UNUSED, PyObject * args)
{
    PyObject * old_saved_ctx;
    nx_module_t * module;
    char * key;
    PyArg_ParseTuple(args, "O&s",
                     _converter_module,
                     &module,
                     &key);

    old_saved_ctx = nx_module_data_get(module, key);
    if (old_saved_ctx == NULL)
    {
        Py_RETURN_NONE;
    }
    return Py_BuildValue("O", old_saved_ctx);
}

static PyMethodDef cnxlog_methods[] = {
    {"get_logdata_field", get_logdata_field, METH_VARARGS, "Get logdata field value"},
    {"set_logdata_field", set_logdata_field, METH_VARARGS, "Set logdata field value"},
    {"delete_logdata_field", delete_logdata_field, METH_VARARGS, "delete logdata field value"},
    {"get_logdata_field_type", get_logdata_fieldtype, METH_VARARGS, "get logdata field type"},
    {"get_logdata_field_names", get_logdata_fieldnames, METH_VARARGS, "get logdata field names"},
    {"logdata_new", logdata_new, METH_NOARGS, "generate new event"},
    {"log_debug", py_log_debug, METH_VARARGS, "output to log"},
    {"log_info", py_log_info, METH_VARARGS, "output to log"},
    {"log_warning", py_log_warning, METH_VARARGS, "output to log"},
    {"log_error", py_log_error, METH_VARARGS, "output to log"},
    {"set_read_timer", set_read_timer, METH_VARARGS, "add read event to nxlog"},
    {"post_logdata", post_logdata, METH_VARARGS, "push logdata to nxlog"},
    {"save_context", save_context, METH_VARARGS, "save context"},
    {"load_context", load_context, METH_VARARGS, "load context"},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef libpynxlog =
{
    PyModuleDef_HEAD_INIT,
    "libpynxlog", /* name of module */
    "",          /* module documentation, may be NULL */
    -1,          /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
    cnxlog_methods,
    NULL,
    NULL,
    NULL,
    NULL
};


PyMODINIT_FUNC PyInit_libpynxlog()
{
    return PyModule_Create(&libpynxlog);
}
