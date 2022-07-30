/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev
 */

#ifndef __NX_OM_PYTHON_H
#define __NX_OM_PYTHON_H

#include "../../../common/types.h"
#include "../../../common/module.h"
#include "../../extension/python/libnxpython.h"

typedef struct nx_om_python_config_t
{
    char *pythoncode;
    nx_python_conf_t * py_conf;
    PyObject *py_callable;
    char *call;
} nx_om_python_config_t;

#endif	/* __NX_OM_PYTHON_H */
