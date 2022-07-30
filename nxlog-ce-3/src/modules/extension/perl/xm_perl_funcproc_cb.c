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
#include "xm_perl.h"
#include "nx_perl_ss.h"

#define NX_LOGMODULE NX_LOGMODULE_CORE

static void xm_perl_call(nx_expr_eval_ctx_t *eval_ctx,
			 nx_module_t *module,
			 nx_expr_list_t *args)
{
    nx_expr_list_elem_t *arg;
    nx_value_t value;
    nx_value_t param;
    nx_perl_config_t *modconf;
    int argc;
    nx_exception_t e;
    PerlInterpreter * old_context;

    char * str_val;

    if ( eval_ctx->logdata == NULL )
    {
	throw_msg("no logdata available to xm_perl->call(), possibly dropped");
    }

    ASSERT(module != NULL);
    modconf = (nx_perl_config_t *) module->config;

    arg = NX_DLIST_FIRST(args);
    ASSERT(arg != NULL);
    ASSERT(arg->expr != NULL);
    nx_expr_evaluate(eval_ctx, &value, arg->expr);

    if ( value.defined != TRUE )
    {
	throw_msg("'subroutine' string is undef");
    }
    if ( value.type != NX_VALUE_TYPE_STRING )
    {
	nx_value_kill(&value);
	throw_msg("string type required for 'subroutine'");
    }

    log_debug("calling perl subroutine: %s", value.string->buf);
    nx_perl_ss_begin();
    old_context = PERL_GET_CONTEXT;
    PERL_SET_CONTEXT(modconf->perl_interpreter);
    dTHXa(modconf->perl_interpreter);
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);

    XPUSHs(sv_2mortal(newSViv(PTR2IV(eval_ctx->logdata))));

// from here we forget Perl's own define which interfere with nxlog's list macros
#undef link

    for (arg = NX_DLIST_NEXT(arg, link), argc = 1;
         arg;
         arg = NX_DLIST_NEXT(arg, link), argc ++)
    {
	nx_expr_evaluate(eval_ctx, &param, arg->expr);
	if ( ! param.defined )
	{
	    XPUSHs(&PL_sv_undef);
	}
	else
	{
	    switch (param.type) {
	    case NX_VALUE_TYPE_INTEGER:
		XPUSHs(sv_2mortal(newSViv(param.integer)));
		break;
	    case NX_VALUE_TYPE_BOOLEAN:
		XPUSHs(value.boolean ? &PL_sv_yes : &PL_sv_no);
		break;
	    default:
		str_val = nx_value_to_string(&param);
		XPUSHs(sv_2mortal(newSVpv(str_val, 0)));
		free(str_val);
		break;
	    }
	}
	nx_value_kill(&param);
    }

    PUTBACK;
    call_pv(value.string->buf, G_EVAL | G_DISCARD);

    SPAGAIN;

    try
    {
	/* check $@ */
	if ( SvTRUE(ERRSV) )
	{
	    log_error("perl subroutine %s failed with an error: \'%s\'",
		      value.string->buf, SvPV_nolen(ERRSV));
	}
/*
    else
    {
	if ( cnt != 0 )
	{
	    log_warn("perl subroutine %s should not return anything, got %d items",
		     value.string->buf, cnt);
	}
    }
*/
    }
    catch(e)
    {
	PUTBACK;
	FREETMPS;
	LEAVE;
	nx_value_kill(&value);
	PERL_SET_CONTEXT(old_context);
	nx_perl_ss_end();
	rethrow(e);
    }
    PUTBACK;
    FREETMPS;
    LEAVE;

    log_debug("perl subroutine %s finished", value.string->buf);

    nx_value_kill(&value);
    PERL_SET_CONTEXT(old_context);
    nx_perl_ss_end();
}




void nx_expr_proc__xm_perl_perl_call(nx_expr_eval_ctx_t *eval_ctx,
				nx_module_t *module,
				nx_expr_list_t *args)
{
    xm_perl_call(eval_ctx, module, args);
}



void nx_expr_proc__xm_perl_call(nx_expr_eval_ctx_t *eval_ctx,
				nx_module_t *module,
				nx_expr_list_t *args)
{
    xm_perl_call(eval_ctx, module, args);
}
