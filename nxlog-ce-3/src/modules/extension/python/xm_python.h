/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev
 */

#include "libnxpython.h"

typedef struct xm_python_config_t
{
    char *pythoncode;
    nx_python_conf_t * py_conf;
} xm_python_config_t;


