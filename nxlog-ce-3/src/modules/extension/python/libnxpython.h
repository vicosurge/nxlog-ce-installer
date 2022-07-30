/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev
 */

#ifndef LIBNXPYTHON_H
#define LIBNXPYTHON_H

#include <apr_portable.h>
#include <Python.h>

#include "../../../common/event.h"

/* Common python config struct */
typedef struct nx_python_conf_t
{
    PyObject *py_code;                   ///< Loaded user script (as python module)
    PyObject *py_module;                 ///< Our nxlog python module
    PyObject *py_module_instance;        ///< nxlog.Module class instance
    PyInterpreterState *py_interpreter;  ///< Sub-interpreter state
    apr_threadkey_t *thread_state_key;   ///< Holds the PyThreadState for each worker thread
} nx_python_conf_t ;


nx_python_conf_t * nx_python_conf_new(apr_pool_t * mp);

// Fetch and log python error
void nx_python_log_err(void);

// Python interpreter init
void nx_python_init(nx_module_t * module, nx_python_conf_t * conf, const char *pythoncode);
void nx_python_finalize(nx_python_conf_t * conf);

// Each python statements must be wrapped into 'begin_section' and 'end_section'
void nx_python_begin_section(nx_python_conf_t * conf);
void nx_python_end_section(nx_python_conf_t * conf);

//used by im_python and om_python
void nx_python_init_iomodule (nx_python_conf_t * conf,
                                     const char * pythoncode,
                                     const char * func,
                                     PyObject **callable);

#endif // LIBNXPYTHON_H
