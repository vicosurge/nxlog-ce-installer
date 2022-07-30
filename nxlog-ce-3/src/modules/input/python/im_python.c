/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev
 */

#include <apr_env.h>
#include <apr_lib.h>
#include <libgen.h>
#include <Python.h>

#include "../../../common/module.h"
#include "../../../common/error_debug.h"

#include "im_python.h"


#define NX_IM_PY_CALLABLE_NAME "read_data"

#define NX_LOGMODULE NX_LOGMODULE_MODULE

//#define DEBUG_REFCNT_BUILD

#ifdef DEBUG_REFCNT_BUILD

#define _LOG_PYREF(x,s) log_info("IN %s:%d %s, %s: %ld", __FILE__, __LINE__, (s), #x, Py_REFCNT(x))
#define LOG_Py_DECREF(x) _LOG_PYREF(x, "V"); Py_DECREF(x)
#define LOG_Py_INCREF(x) _LOG_PYREF(x, "^"); Py_INCREF(x)
#define LOG_Py_XDECREF(x) _LOG_PYREF(x, "V"); Py_XDECREF(x)

#else

#define LOG_Py_DECREF(x) Py_DECREF(x)
#define LOG_Py_INCREF(x) Py_INCREF(x)
#define LOG_Py_XDECREF(x) Py_XDECREF(x)

#endif

void im_python_config(nx_module_t *module)
{
    nx_im_python_config_t *modconf;
    const nx_directive_t *curr;

    ASSERT(module != NULL);

    modconf = apr_pcalloc(module->pool, sizeof(nx_im_python_config_t));
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

static nx_im_python_config_t *get_conf(nx_module_t *module)
{
    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    return (nx_im_python_config_t *) module->config;
}

static void im_python_init(nx_module_t *module)
{
    nx_im_python_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (nx_im_python_config_t *) module->config;

    ASSERT(conf->pythoncode != NULL);

    nx_python_init(module, conf->py_conf, conf->pythoncode);

    nx_python_init_iomodule(conf->py_conf,
                            conf->pythoncode,
                            (conf->call == NULL ? NX_IM_PY_CALLABLE_NAME : conf->call),
                            &conf->py_callable);
}

static void im_python_shutdown(nx_module_t *module)
{
    nx_im_python_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (nx_im_python_config_t *) module->config;

    nx_python_begin_section(conf->py_conf);

    LOG_Py_XDECREF(conf->py_callable);

    nx_python_end_section(conf->py_conf);
    nx_python_finalize(conf->py_conf);
}

static void im_python_set_read_timer(nx_module_t *module)
{
    nx_event_t *event;

    event = nx_module_data_get(module, "read_event");

    ASSERT(event == NULL);

    event = nx_event_new();
    event->module = module;
    event->delayed = FALSE;
    event->type = NX_EVENT_READ;
    event->priority = module->priority;
    nx_module_data_set(module, "read_event", nx_event_add(event), NULL);
}

static void im_python_remove_read_event(nx_module_t * module)
{
    nx_event_t * read_event;

    ASSERT(module != NULL);

    read_event = nx_module_data_get(module, "read_event");

    if ( read_event != NULL )
    {
	nx_event_remove(read_event);
	nx_event_free(read_event);
	nx_module_data_set(module, "read_event", NULL, NULL);
    }
}

static void im_python_read_data(nx_module_t *module)
{
    nx_im_python_config_t *conf;
    PyObject * args;
    nx_exception_t e;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (nx_im_python_config_t *) module->config;

    nx_module_data_set(module, "read_event", NULL, NULL);

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
	log_debug("module %s not running, not reading any more data", module->name);
	return;
    }

    nx_python_begin_section(conf->py_conf);
    try
    {
        args = Py_BuildValue("(O)", conf->py_conf->py_module_instance);
        if (args == NULL)
        {
            throw_msg("Couldn't build func arguments");
        }
        PyObject_Call(conf->py_callable, args,  NULL);
        nx_python_log_err();
        LOG_Py_XDECREF(args);
    }
    catch(e)
    {
        nx_python_log_err();
        nx_python_end_section(conf->py_conf);
        rethrow(e);
    }
    nx_python_end_section(conf->py_conf);
}


static void im_python_start(nx_module_t * module)
{
    nx_module_data_set(module, "read_event", NULL, NULL);
    im_python_set_read_timer(module);
}

static void im_python_event(nx_module_t *module, nx_event_t *event)
{
    nx_exception_t e;

    ASSERT(event != NULL);

    switch ( event->type )
    {
    case NX_EVENT_READ:
	try
	{
	    im_python_read_data(module);
	}
	catch(e)
	{
	    log_exception(e);
	}
	break;
    default:
        nx_panic("invalid event type: %d", event->type);
    }
}



static void im_python_pause(nx_module_t *module)
{
    im_python_remove_read_event(module);
}

static void im_python_resume(nx_module_t *module)
{

    im_python_remove_read_event(module);
    if ( nx_module_get_status(module) != NX_MODULE_STATUS_STOPPED )
    {
	im_python_set_read_timer(module);
    }
}


NX_MODULE_DECLARATION nx_im_python_module = {
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_INPUT,
    NULL,               // capabilities
    im_python_config,   // config
    im_python_start,    // start
    NULL,               // stop
    im_python_pause,    // pause
    im_python_resume,   // resume
    im_python_init,     // init
    im_python_shutdown, // shutdown
    im_python_event,    // event
    NULL,               // info
    NULL                // exports
};
