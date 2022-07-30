/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev
 */

#include <Python.h>

#ifdef gid_t
# undef gid_t
#endif

#ifdef uid_t
# undef uid_t
#endif

#include "../../../common/module.h"
#include "../../../common/error_debug.h"
#include "../../../common/value.h"
#include "../../../common/expr.h"
#include "../../../common/logdata.h"
#include "../../../common/date.h"

#include "xm_python.h"


#define NX_LOGMODULE NX_LOGMODULE_MODULE


//#define DEBUG_REFCNT_BUILD

#ifdef DEBUG_REFCNT_BUILD

#define _LOG_PYREF(x,s) log_info("CB %s:%d %s, %s: %ld", __FILE__, __LINE__, (s), #x, Py_REFCNT(x))
#define LOG_Py_DECREF(x) _LOG_PYREF(x, "V");  Py_DECREF(x)
#define LOG_Py_INCREF(x) _LOG_PYREF(x, "^"); Py_INCREF(x)
#define LOG_Py_XDECREF(x) _LOG_PYREF(x, "V"); Py_XDECREF(x)

#else

#define LOG_Py_DECREF(x)  Py_DECREF(x)
#define LOG_Py_INCREF(x) Py_INCREF(x)
#define LOG_Py_XDECREF(x) Py_XDECREF(x)

#endif

PyObject * logdata_new(nx_module_t * module, nx_logdata_t * logdata)
{
    xm_python_config_t *conf;
    PyObject * args;
    PyObject * py_logdata;
    PyObject * py_logdata_type;
    PyObject * py_tmp;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (xm_python_config_t*)module->config;

    py_logdata_type = PyObject_GetAttrString(conf->py_conf->py_module, "LogData");

    if ( (py_logdata_type == NULL) || (PyType_Check(py_logdata_type) != 1) )
    {
        throw_msg("Couldn't get LogData type");
    }

    py_tmp = PyCapsule_New(logdata, "logdata", NULL);
    args = Py_BuildValue("OO", conf->py_conf->py_module_instance, py_tmp);
    LOG_Py_XDECREF(py_tmp);
    if (args == NULL)
    {
        LOG_Py_DECREF(py_logdata_type);
        throw_msg("Couldn't build LogData argument");
    }

    py_logdata = PyType_GenericNew((PyTypeObject *)py_logdata_type, args, NULL);
    int instance_check = PyObject_IsInstance(py_logdata, py_logdata_type);

    if ( (py_logdata == NULL) || (instance_check != 1) )
    {
        throw_msg("Couldn't instantiate LogData object");
    }
    ASSERT(0 == Py_TYPE(py_logdata)->tp_init(py_logdata, args, NULL));

    LOG_Py_DECREF(args);
    LOG_Py_DECREF(py_logdata_type);

    return py_logdata;
}

static void call_obj(nx_module_t * module, const char * name, PyObject * arg)
{
    PyObject * py_func;
    xm_python_config_t *modconf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);
    ASSERT(name != NULL);
    ASSERT(arg != NULL);

    modconf = (xm_python_config_t *)module->config;

    py_func = PyObject_GetAttrString(modconf->py_conf->py_code, name);
    if (py_func == NULL || !PyCallable_Check(py_func))
    {
        nx_python_log_err();
        throw_msg("Not callable!");
    }
    else
    {
        PyObject_CallObject(py_func, arg);
        nx_python_log_err();
    }

     LOG_Py_DECREF(py_func);

}

void nx_expr_proc__xm_python_call(nx_expr_eval_ctx_t *eval_ctx,
                                         nx_module_t *module,
                                         nx_expr_list_t *args)
{
    nx_expr_list_elem_t *arg;
    nx_value_t value;
    nx_logdata_t * logdata;
    PyObject * py_logdata;
    xm_python_config_t *conf;
    nx_exception_t e;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);
    conf = (xm_python_config_t*)module->config;

    if (eval_ctx->logdata == NULL)
    {
        throw_msg("no logdata available to xm_python->call(), possibly dropped");
    }

    logdata = eval_ctx->logdata;
    ASSERT(module != NULL);

    arg = NX_DLIST_FIRST(args);
    ASSERT(arg != NULL);
    ASSERT(arg->expr != NULL);
    nx_expr_evaluate(eval_ctx, &value, arg->expr);


    if (value.defined != TRUE)
    {
        throw_msg("'subroutine' string is undef");
    }

    if (value.type != NX_VALUE_TYPE_STRING)
    {
        nx_value_kill(&value);
        throw_msg("string type required for 'subroutine'");
    }

    log_debug("calling python subroutine: %s", value.string->buf);

    nx_python_begin_section(conf->py_conf);
    try
            {
                py_logdata= logdata_new(module, logdata);

                if (py_logdata == NULL)
                {
                    nx_python_log_err();
                    throw_msg("Couldn't create LogData object");
                }

                PyObject * py_args = Py_BuildValue("(O)", py_logdata);
                if (py_args == NULL)
                {
                    nx_python_log_err();
                    throw_msg("Couldn't prepare arg list");
                }
                call_obj(module, value.string->buf, py_args);
                LOG_Py_XDECREF(py_args);
                LOG_Py_XDECREF(py_logdata);
                nx_value_kill(&value);
            }
    catch(e)
    {
        nx_python_log_err();
        nx_python_end_section(conf->py_conf);
        rethrow(e);
    }
    nx_python_end_section(conf->py_conf);
}


void nx_expr_proc__xm_python_python_call(nx_expr_eval_ctx_t *eval_ctx,
                                         nx_module_t *module,
                                         nx_expr_list_t *args)
{
    nx_expr_list_elem_t *arg;
    nx_value_t value;
    nx_logdata_t * logdata;
    PyObject * py_logdata;
    xm_python_config_t *conf;
    nx_exception_t e;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);
    conf = (xm_python_config_t*)module->config;

    if (eval_ctx->logdata == NULL)
    {
        throw_msg("no logdata available to xm_python->call(), possibly dropped");
    }

    logdata = eval_ctx->logdata;
    ASSERT(module != NULL);

    arg = NX_DLIST_FIRST(args);
    ASSERT(arg != NULL);
    ASSERT(arg->expr != NULL);
    nx_expr_evaluate(eval_ctx, &value, arg->expr);


    if (value.defined != TRUE)
    {
        throw_msg("'subroutine' string is undef");
    }

    if (value.type != NX_VALUE_TYPE_STRING)
    {
        nx_value_kill(&value);
        throw_msg("string type required for 'subroutine'");
    }

    log_debug("calling python subroutine: %s", value.string->buf);

    nx_python_begin_section(conf->py_conf);
    try
    {
        py_logdata= logdata_new(module, logdata);

        if (py_logdata == NULL)
        {
            nx_python_log_err();
            throw_msg("Couldn't create LogData object");
        }

        PyObject * py_args = Py_BuildValue("(O)", py_logdata);
        if (py_args == NULL)
        {
            nx_python_log_err();
            throw_msg("Couldn't prepare arg list");
        }
        call_obj(module, value.string->buf, py_args);
        LOG_Py_XDECREF(py_args);
        LOG_Py_XDECREF(py_logdata);
        nx_value_kill(&value);
    }
    catch(e)
    {
        nx_python_log_err();
        nx_python_end_section(conf->py_conf);
        rethrow(e);
    }
    nx_python_end_section(conf->py_conf);
}

