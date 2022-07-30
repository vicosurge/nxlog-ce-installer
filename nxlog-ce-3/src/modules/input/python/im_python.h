/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev
 */

#include <Python.h>
#include "../../extension/python/libnxpython.h"

typedef struct nx_im_python_config_t
{
    char *pythoncode;
    nx_python_conf_t * py_conf;
    PyObject *py_callable;
    nx_event_t *event;
    char * call;

} nx_im_python_config_t;

