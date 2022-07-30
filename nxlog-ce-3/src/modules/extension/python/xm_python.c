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

#include <apr_env.h>
#include <apr_lib.h>
#include <libgen.h>

#include "../../../common/module.h"
#include "../../../common/error_debug.h"

#include "xm_python.h"
#include "libnxpython.h"

#define NX_LOGMODULE NX_LOGMODULE_CORE

void xm_python_config(nx_module_t *module)
{
    xm_python_config_t *modconf;
    const nx_directive_t *curr;

    ASSERT(module != NULL);

    modconf = apr_pcalloc(module->pool, sizeof(xm_python_config_t));
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

void xm_python_init(nx_module_t *module)
{
    xm_python_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (xm_python_config_t *)module->config;

    nx_python_init(module, conf->py_conf, conf->pythoncode);
}
void xm_python_shutdown(nx_module_t *module)
{
    xm_python_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (xm_python_config_t *)module->config;

    nx_python_finalize(conf->py_conf);
}

extern nx_module_exports_t nx_module_exports_xm_python;

NX_MODULE_DECLARATION nx_xm_python_module = {
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_EXTENSION,
    NULL,                        // capabilities
    xm_python_config,            // config
    NULL,                        // start
    NULL,                        // stop
    NULL,                        // pause
    NULL,                        // resume
    xm_python_init,              // init
    xm_python_shutdown,          // shutdown
    NULL,                        // event
    NULL,                        // info
    &nx_module_exports_xm_python // exports
};

