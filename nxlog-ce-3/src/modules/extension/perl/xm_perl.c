/*
 * This file is part of the nxlog log collector tool.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 * License:
 * Copyright (C) 2012 by Botond Botyanszki
 * This library is free software; you can redistribute it and/or modify
 * it under the same terms as Perl itself, either Perl version 5.8.5 or,
 * at your option, any later version of Perl 5 you may have available.
 */

#include "../../../common/module.h"
#include "../../../common/error_debug.h"
#include "xm_perl.h"
#include "nx_perl_ss.h"

// mingw hack (experimental)
#if defined(PERL_IMPLICIT_SYS) && defined(__MINGW32__)
# undef setjmp
# undef longjmp
#endif

#define NX_LOGMODULE NX_LOGMODULE_MODULE

EXTERN_C void xs_init(pTHX);

static void xm_perl_config(nx_module_t *module)
{
    nx_perl_config(module, NULL);
}



static void xm_perl_init(nx_module_t *module)
{
    nx_perl_global_init();
    nx_perl_module_init(module);
}



static void xm_perl_shutdown(nx_module_t *module)
{
    nx_perl_module_shutdown(module);
    nx_perl_global_shutdown();
}



extern nx_module_exports_t nx_module_exports_xm_perl;

NX_MODULE_DECLARATION nx_xm_perl_module =
{
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_EXTENSION,
    NULL,			// capabilities
    xm_perl_config,		// config
    NULL,			// start
    NULL,	 		// stop
    NULL,			// pause
    NULL,			// resume
    xm_perl_init,		// init
    xm_perl_shutdown,		// shutdown
    NULL,			// event
    NULL,			// info
    &nx_module_exports_xm_perl, //exports
};
