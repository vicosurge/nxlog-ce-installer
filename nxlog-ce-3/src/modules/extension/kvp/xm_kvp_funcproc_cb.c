/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#include <apr_lib.h>

#include "../../../common/module.h"
#include "xm_kvp.h"

#define NX_LOGMODULE NX_LOGMODULE_CORE

void nx_expr_proc__parse_kvp(nx_expr_eval_ctx_t *eval_ctx,
			     nx_module_t *module,
			     nx_expr_list_t *args)
{
    nx_expr_list_elem_t *source = NULL, *prefix = NULL;
    nx_value_t source_value;
    nx_value_t prefix_value;
    nx_kvp_ctx_t *ctx;
    nx_xm_kvp_conf_t *modconf;
    nx_exception_t e;

    ASSERT(module != NULL);
    if ( eval_ctx->logdata == NULL )
    {
	throw_msg("no logdata available to parse_kvp(), possibly dropped");
    }

    modconf = (nx_xm_kvp_conf_t *) module->config;
    ASSERT(modconf != NULL);
    ctx = &(modconf->ctx);

    if ( args == NULL )
    {
	//  parse_kvp() ; no parameter

	if ( nx_logdata_get_field_value(eval_ctx->logdata, "raw_event", &source_value) == FALSE )
	{
	    throw_msg("raw_event field missing");
	}
	if ( source_value.defined != TRUE )
	{
	    throw_msg("raw_event field is undef");
	}
	if ( source_value.type != NX_VALUE_TYPE_STRING )
	{
	    throw_msg("string type required for field 'raw_event'");
	}
	nx_kvp_parse(eval_ctx->logdata, ctx, source_value.string->buf, source_value.string->len, NULL);

	return;
    }

    //  parse_kvp(...) ; one or two parameter(s)

    // first parameter
    source = NX_DLIST_FIRST(args);
    ASSERT(source != NULL);

    // second parameter
    prefix = NX_DLIST_NEXT(source, link);

    ASSERT(source->expr != NULL);
    nx_expr_evaluate(eval_ctx, &source_value, source->expr);

    if ( source_value.defined != TRUE )
    {
	throw_msg("source string is undef");
    }
    if ( source_value.type != NX_VALUE_TYPE_STRING )
    {
	nx_value_kill(&source_value);
	throw_msg("string type required for source string");
    }

    if ( prefix != NULL )
    {
	nx_expr_evaluate(eval_ctx, &prefix_value, prefix->expr);
	// this will tolerate undef as prefix
	if ( prefix_value.defined == TRUE )
	{
	    if ( prefix_value.type != NX_VALUE_TYPE_STRING )
	    {
		nx_value_kill(&prefix_value);
		throw_msg("string type required for prefix string");
	    }
	}
    }

    try
    {
	if ( (prefix == NULL) || ((prefix != NULL) && (prefix_value.defined == FALSE)) )
	{
	    // no prefix OR prefix is undef
	    nx_kvp_parse(eval_ctx->logdata, ctx, source_value.string->buf, source_value.string->len, NULL);
	}
	else
	{
	    nx_kvp_parse(eval_ctx->logdata, ctx, source_value.string->buf, source_value.string->len, prefix_value.string->buf);
	}
    }
    catch(e)
    {
	nx_value_kill(&source_value);
	if ( prefix != NULL )
	{
	    nx_value_kill(&prefix_value);
	}
	rethrow(e);
    }
    if ( prefix != NULL )
    {
	nx_value_kill(&prefix_value);
    }
    nx_value_kill(&source_value);
}



void nx_expr_func__to_kvp(nx_expr_eval_ctx_t *eval_ctx,
			  nx_module_t *module,
			  nx_value_t *retval,
			  int32_t num_arg,
			  nx_value_t *args UNUSED)
{
    nx_xm_kvp_conf_t *modconf;

    ASSERT(retval != NULL);
    ASSERT(num_arg == 0);
    ASSERT(module != NULL);
    if ( eval_ctx->logdata == NULL )
    {
	throw_msg("no logdata available to to_kvp(), possibly dropped");
    }

    modconf = (nx_xm_kvp_conf_t *) module->config;
    ASSERT(modconf != NULL);

    retval->string = nx_logdata_to_kvp(&(modconf->ctx), eval_ctx->logdata);
    retval->type = NX_VALUE_TYPE_STRING;
    retval->defined = TRUE;
}



void nx_expr_proc__to_kvp(nx_expr_eval_ctx_t *eval_ctx,
			  nx_module_t *module,
			  nx_expr_list_t *args UNUSED)
{
    nx_xm_kvp_conf_t *modconf;
    nx_value_t *val;
    nx_string_t *kvpstr;

    ASSERT(module != NULL);
    if ( eval_ctx->logdata == NULL )
    {
	throw_msg("no logdata available to to_kvp(), possibly dropped");
    }

    modconf = (nx_xm_kvp_conf_t *) module->config;
    ASSERT(modconf != NULL);

    kvpstr = nx_logdata_to_kvp(&(modconf->ctx), eval_ctx->logdata);

    val = nx_value_new(NX_VALUE_TYPE_STRING);
    val->string = kvpstr;
    nx_logdata_set_field_value(eval_ctx->logdata, "raw_event", val);
}


void nx_expr_proc__reset_kvp(nx_expr_eval_ctx_t *eval_ctx UNUSED,
			     nx_module_t *module,
			     nx_expr_list_t *args UNUSED)
{
    nx_xm_kvp_conf_t *modconf;

    ASSERT(module != NULL);

    modconf = (nx_xm_kvp_conf_t *) module->config;
    ASSERT(modconf != NULL);

    modconf->ctx.keyquotechar = '\0';
    modconf->ctx.valquotechar = '\0';
    modconf->ctx.kvpdelimiter = '\0';
    modconf->ctx.kvdelimiter = '\0';
}
