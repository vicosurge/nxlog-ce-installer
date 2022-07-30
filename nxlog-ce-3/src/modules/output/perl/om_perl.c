/*
 * This file is part of the nxlog log collector tool.
 * Website: http://nxlog.org
 * Author: Ivan Baidakou <the.dmol@gmail.com>
 * License:
 * Copyright (C) 2015 by Botond Botyanszki
 * This library is free software; you can redistribute it and/or modify
 * it under the same terms as Perl itself, either Perl version 5.8.5 or,
 * at your option, any later version of Perl 5 you may have available.
 */

#include "../../../common/module.h"
#include "../../../common/error_debug.h"
#include "om_perl.h"
#include "../../extension/perl/nx_perl_ss.h"

// mingw hack (experimental)
#if defined(PERL_IMPLICIT_SYS) && defined(__MINGW32__)
# undef longjmp
# undef setjmp
#  ifdef _WIN64
#   define setjmp(BUF) _setjmp((BUF), __builtin_frame_address (0))
#  else
#   define setjmp(BUF) _setjmp3((BUF), NULL)
#  endif
#endif

#define NX_LOGMODULE NX_LOGMODULE_MODULE
#define OM_PERL_DEFAULT_SUBROUTINE_NAME "write_data"
EXTERN_C void xs_init(pTHX);



static void om_perl_write(nx_module_t *module)
{
    nx_perl_config_t *modconf;
    nx_exception_t e;
    nx_logdata_t *logdata;

    ASSERT(module != NULL);

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
	log_debug("module %s not running, not writing any more data", module->name);
	return;
    }

    modconf = (nx_perl_config_t *) module->config;

    if ( (logdata = nx_module_logqueue_peek(module)) == NULL )
    {
	log_debug("no log data available for %s", module->name);
	return;
    }
    nx_perl_ss_begin();
    nx_module_logqueue_pop(module, logdata);
    PERL_SET_CONTEXT(modconf->perl_interpreter);
    dTHXa(modconf->perl_interpreter);
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);

    XPUSHs(sv_2mortal(newSViv(PTR2IV(logdata))));
    PUTBACK;

    call_pv(modconf->run, G_EVAL | G_DISCARD);

    SPAGAIN;

    try
    {
	/* check $@ */
	if ( SvTRUE(ERRSV) )
	{
	    log_error("perl subroutine %s failed with an error: \'%s\'",
		      modconf->run, SvPV_nolen(ERRSV));
	}
    }
    catch(e)
    {
	PUTBACK;
	FREETMPS;
	LEAVE;
	nx_perl_ss_end();
	rethrow(e);
    }
    PUTBACK;
    FREETMPS;
    LEAVE;
    nx_perl_ss_end();
    nx_logdata_free(logdata);
    log_debug("perl subroutine %s finished", modconf->run);
}



static void om_perl_config(nx_module_t *module)
{
    nx_perl_config(module, OM_PERL_DEFAULT_SUBROUTINE_NAME);
}



static void om_perl_event(nx_module_t *module, nx_event_t *event)
{
    ASSERT(event != NULL);

    switch ( event->type )
    {
	case NX_EVENT_DATA_AVAILABLE:
	    om_perl_write(module);
	    break;
	default:
	    nx_panic("invalid event type: %d", event->type);
    }
}



static void om_perl_init(nx_module_t *module)
{
    nx_perl_global_init();
    nx_perl_module_init(module);
}



static void om_perl_shutdown(nx_module_t *module)
{
    nx_perl_module_shutdown(module);
    nx_perl_global_shutdown();
}



NX_MODULE_DECLARATION nx_om_perl_module =
{
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_OUTPUT,
    NULL,			// capabilities
    om_perl_config,		// config
    NULL,			// start
    NULL,	 		// stop
    NULL,			// pause
    NULL,			// resume
    om_perl_init,		// init
    om_perl_shutdown,		// shutdown
    om_perl_event,		// event
    NULL,			// info
    NULL,			// exports
};
