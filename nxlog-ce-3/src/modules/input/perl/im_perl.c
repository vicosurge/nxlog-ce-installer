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
#include "im_perl.h"
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
#define IM_PERL_DEFAULT_SUBROUTINE_NAME "read_data"

EXTERN_C void xs_init(pTHX);

static void im_perl_set_read_timer_cb(nx_module_t *module, int delay)
{
    nx_event_t *event;
    nx_perl_config_t *imconf;

    imconf = (nx_perl_config_t *) module->config;
    ASSERT(imconf->event == NULL);

    log_debug("im_perl_set_read_timer_cb with delay %d", delay);

    event = nx_event_new();
    event->module = module;
    event->delayed = TRUE;
    event->time = apr_time_now() + (APR_USEC_PER_SEC * delay);
    event->type = NX_EVENT_READ;
    event->priority = module->priority;

    imconf->event = nx_event_add(event);
}



static void im_perl_add_read_event(nx_module_t *module)
{
    nx_event_t *event;
    nx_perl_config_t *modconf;

    modconf = (nx_perl_config_t *) module->config;
    ASSERT(modconf->event == NULL);

    event = nx_event_new();
    event->module = module;
    event->delayed = FALSE;
    event->type = NX_EVENT_READ;
    event->priority = module->priority;

    modconf->event = nx_event_add(event);
}



static void im_perl_read_data(nx_module_t *module)
{
    nx_perl_config_t *modconf;
    nx_exception_t e;


    ASSERT(module != NULL);
    modconf = (nx_perl_config_t *) module->config;

    modconf->event = NULL;

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
	log_debug("module %s not running, not reading any more data", module->name);
	return;
    }

    nx_perl_ss_begin();
    PERL_SET_CONTEXT(modconf->perl_interpreter);
    dTHXa(modconf->perl_interpreter);
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);

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
    log_debug("perl subroutine %s finished", modconf->run);
}



static void im_perl_config(nx_module_t *module)
{
    nx_perl_config(module, IM_PERL_DEFAULT_SUBROUTINE_NAME);
    nx_module_data_set(module, "set_read_timer_cb", &im_perl_set_read_timer_cb, NULL);
}



static void im_perl_init(nx_module_t *module)
{
    nx_perl_global_init();
    nx_perl_module_init(module);
}



static void im_perl_start(nx_module_t *module)
{
    ASSERT(module->config != NULL);

    log_debug("im_perl_start");

    im_perl_add_read_event(module);
}



static void im_perl_shutdown(nx_module_t *module)
{
    nx_perl_module_shutdown(module);
    nx_perl_global_shutdown();
}



static void im_perl_event(nx_module_t *module, nx_event_t *event)
{
    nx_exception_t e;

    ASSERT(event != NULL);

    switch ( event->type )
    {
	case NX_EVENT_READ:
	    try
	    {
		im_perl_read_data(module);
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



static void im_perl_pause(nx_module_t *module)
{
    nx_perl_config_t *imconf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    imconf = (nx_perl_config_t *) module->config;

    if ( imconf->event != NULL )
    {
	nx_event_remove(imconf->event);
	nx_event_free(imconf->event);
	imconf->event = NULL;
    }
}



static void im_perl_resume(nx_module_t *module)
{
    nx_perl_config_t *imconf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    imconf = (nx_perl_config_t *) module->config;

    if ( imconf->event != NULL )
    {
	nx_event_remove(imconf->event);
	nx_event_free(imconf->event);
	imconf->event = NULL;
    }

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_STOPPED )
    {
	im_perl_add_read_event(module);
    }
}


extern nx_module_exports_t nx_module_exports_im_perl;

NX_MODULE_DECLARATION nx_im_perl_module =
{
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_INPUT,
    NULL,			// capabilities
    im_perl_config,		// config
    im_perl_start,		// start
    im_perl_pause,	 	// stop
    im_perl_pause,		// pause
    im_perl_resume,		// resume
    im_perl_init,		// init
    im_perl_shutdown,		// shutdown
    im_perl_event,		// event
    NULL,			// info
    NULL, 			// exports
};
