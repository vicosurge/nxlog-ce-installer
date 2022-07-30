/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev
 */

#include "../../../common/module.h"
#include "../../../common/error_debug.h"

#include "om_python.h"

#define NX_LOGMODULE NX_LOGMODULE_MODULE

#define NX_OM_PY_CALLABLE_NAME "write_data"

//#define DEBUG_REFCNT_BUILD

#ifdef DEBUG_REFCNT_BUILD

#define _LOG_PYREF(x,s) log_info("OUT %s:%d %s, %s: %ld", __FILE__, __LINE__, (s), #x, Py_REFCNT(x))
#define LOG_Py_DECREF(x) _LOG_PYREF(x, "V"); Py_DECREF(x)
#define LOG_Py_INCREF(x) _LOG_PYREF(x, "^"); Py_INCREF(x)
#define LOG_Py_XDECREF(x) _LOG_PYREF(x, "V"); Py_XDECREF(x)

#else

#define LOG_Py_DECREF(x) Py_DECREF(x)
#define LOG_Py_INCREF(x) Py_INCREF(x)
#define LOG_Py_XDECREF(x) Py_XDECREF(x)

#endif

/* Instantiate new nxlog.LogData object */
static PyObject * nx_om_python_logdata_new(nx_module_t * module, nx_logdata_t * logdata)
{
    nx_om_python_config_t *conf;
    PyObject * args;
    PyObject * py_logdata;
    PyObject * py_logdata_type;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (nx_om_python_config_t*)module->config;

    py_logdata_type = PyObject_GetAttrString(conf->py_conf->py_module, "LogData");

    if (py_logdata_type == NULL)
    {
        throw_msg("Couldn't get LogData type");
    }

    args = Py_BuildValue("OO", conf->py_conf->py_module_instance,
                         PyCapsule_New(logdata, "logdata", NULL));
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

static void om_python_write(nx_module_t *module)
{
    nx_om_python_config_t *conf;
    PyObject * py_args;
    PyObject * py_logdata;
    nx_logdata_t * logdata;
    nx_exception_t e;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (nx_om_python_config_t*)module->config;

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
        log_debug("module %s not running, not writing any more data", module->name);
        return;
    }

    if ( (logdata = nx_module_logqueue_peek(module)) == NULL )
    {
        log_debug("no log data available for %s", module->name);
        return;
    }


    nx_python_begin_section(conf->py_conf);

    try
    {
        py_logdata = nx_om_python_logdata_new(module, logdata);
        py_args = Py_BuildValue("(O)", py_logdata);
        if (py_args == NULL)
        {
            throw_msg("Couldn't prepare arg list");
        }
    }
    catch (e)
    {
        nx_python_log_err();
        nx_python_end_section(conf->py_conf);
        rethrow(e);
    }

    PyObject_Call(conf->py_callable, py_args, NULL);

    LOG_Py_DECREF(py_args);
    LOG_Py_DECREF(py_logdata);
    nx_python_log_err();
    nx_python_end_section(conf->py_conf);
    nx_module_logqueue_pop(module, logdata);
}

static void om_python_config(nx_module_t *module)
{
    nx_om_python_config_t *modconf;
    const nx_directive_t *curr;

    ASSERT(module != NULL);

    modconf = apr_pcalloc(module->pool, sizeof(nx_om_python_config_t));
    modconf->py_conf = nx_python_conf_new(module->pool);
    module->config = modconf;

    curr = module->directives;

    while (curr != NULL)
    {
        if (nx_module_common_keyword(curr->directive) == TRUE)
        {
        }
        else if (strcasecmp(curr->directive, "pythoncode") == 0)
        {
            if (modconf->pythoncode != NULL)
            {
                nx_conf_error(curr, "PythonCode is already defined");
            }
	    modconf->pythoncode = nx_cfg_unquote_string(curr, module->pool);
        }
        else if ( strcasecmp(curr->directive, "call") == 0 )
        {
            if ( modconf->call != NULL )
            {
                nx_conf_error(curr, "Call is already defined");
            }
            modconf->call = apr_pstrdup(module->pool, curr->args);
            ASSERT(modconf->call);
        }
        else
        {
            nx_conf_error(curr, "invalid keyword: %s", curr->directive);
        }
        curr = curr->next;
    }

    if (modconf->pythoncode == NULL)
    {
        nx_conf_error(module->directives, "'PythonCode' is required");
    }
}



static void om_python_event(nx_module_t *module, nx_event_t *event)
{
    ASSERT(event != NULL);
    ASSERT(module != NULL);

    switch ( event->type )
    {
	case NX_EVENT_DATA_AVAILABLE:
	    om_python_write(module);
	    break;
	default:
	    nx_panic("invalid event type: %d", event->type);
    }
}



static void om_python_init(nx_module_t *module)
{
    nx_om_python_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (nx_om_python_config_t*)module->config;

    ASSERT(conf->pythoncode != NULL);

    nx_python_init(module, conf->py_conf, conf->pythoncode);
    nx_python_init_iomodule(conf->py_conf,
                            conf->pythoncode,
                            (conf->call == NULL ? NX_OM_PY_CALLABLE_NAME : conf->call),
                            &conf->py_callable);
}




static void om_python_shutdown(nx_module_t *module)
{
    nx_om_python_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (nx_om_python_config_t*)module->config;

    nx_python_begin_section(conf->py_conf);
    LOG_Py_XDECREF(conf->py_callable);
    nx_python_end_section(conf->py_conf);

    nx_python_finalize(conf->py_conf);
}



NX_MODULE_DECLARATION nx_om_python_module =
{
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_OUTPUT,
    NULL,			// capabilities
    om_python_config,		// config
    NULL,			// start
    NULL,	 		// stop
    NULL,			// pause
    NULL,			// resume
    om_python_init,		// init
    om_python_shutdown,		// shutdown
    om_python_event,		// event
    NULL,			// info
    NULL,			// exports
};
