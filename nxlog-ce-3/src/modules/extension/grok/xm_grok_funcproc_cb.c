/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev
 */

#include <apr_lib.h>

#include "../../../common/module.h"

#include "grok.h"
#include "xm_grok.h"


#define NX_LOGMODULE NX_LOGMODULE_MODULE


boolean check_string_param(nx_expr_eval_ctx_t *eval_ctx,
			   nx_value_t *value,
			   nx_expr_list_elem_t *arg)
{
    if ( arg == NULL || arg->expr == NULL)
    {
	return (FALSE);
    }

    nx_expr_evaluate(eval_ctx, value, arg->expr);

    if ( (value->defined != TRUE) || (value->type != NX_VALUE_TYPE_STRING) )
    {
	nx_value_kill(value);
	return (FALSE);
    }
    return (TRUE);
}


#define nx_string_zfree(x) if (x) nx_string_free(x);


void nx_expr_proc__match_grok(nx_expr_eval_ctx_t *eval_ctx,
			      nx_module_t *module,
			      nx_expr_list_t *args)
{
    xm_grok_pattern_t *db;
    nx_expr_list_elem_t *arg;
    nx_expr_list_elem_t *next_arg;
    nx_grok_t *grok;
    nx_string_t *match_value;
    nx_module_t *caller_module;
    xm_grok_conf_t *conf;
    size_t idx;

    nx_value_t value;
    nx_value_t pat_value;
    nx_string_t *field = NULL;
    nx_string_t *pattern = NULL;

    caller_module = eval_ctx->module;

    ASSERT(caller_module != NULL);
    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (xm_grok_conf_t *) module->config;

    db = xm_grok_get_db_checked(module);

    if ( eval_ctx->logdata == NULL )
    {
	throw_msg("no logdata available to match_grok([field],pattern), possibly dropped");
    }

    if ( args == NULL )
    {
	throw_msg("a match_grok([field],pattern) requires arguments");
    }

    arg = NX_DLIST_FIRST(args);

    pat_value.defined = FALSE;
    value.defined = FALSE;

    if ( check_string_param(eval_ctx, &value, arg) != TRUE )
    {
	throw_msg("a match_grok([field],pattern) requires string argument");
    }
    // allocated: value
    if ( (next_arg = NX_DLIST_NEXT(arg, link)) == NULL )
    {
	// Second argument not defined
	field = nx_string_clone(eval_ctx->logdata->raw_event);
	pattern = nx_string_clone(value.string);
    }
    else if ( check_string_param(eval_ctx, &pat_value, next_arg) == TRUE )
    {

	field = nx_string_clone(value.string);
	pattern = nx_string_clone(pat_value.string);
    }
    else
    {
	nx_value_kill(&value);
	nx_value_kill(&pat_value);
	throw_msg("The second argument of match_grok([field],pattern) must be string");
    }
    nx_value_kill(&value);
    nx_value_kill(&pat_value);

    grok = grok_pattern_match_global(db->pool, field->buf, db->patterns, grok_get_module_storage(caller_module),
				     conf->in_use, pattern->buf);

    if ( grok != NULL )
    {
	for ( idx = 0; idx < grok->maches_num; idx++ )
	{
	    if ( nx_grok_match_has_name(grok, idx))
	    {
		match_value = nx_grok_get_match_value(grok, idx);
		nx_logdata_set_string(eval_ctx->logdata,
				      nx_grok_match_get_name(grok, idx),
				      match_value->buf);
	    }
	}
    }

    nx_string_zfree(field);
    nx_string_zfree(pattern);
}


void nx_expr_func__match_grok(nx_expr_eval_ctx_t *eval_ctx,
			      nx_module_t *module,
			      nx_value_t *retval,
			      int32_t num_arg,
			      nx_value_t *args)
{
    xm_grok_pattern_t *db;
    nx_string_t *field = NULL;
    nx_string_t *pattern = NULL;
    nx_grok_t *grok;
    xm_grok_conf_t *conf;
    nx_string_t *match_value;
    nx_module_t *caller_module;
    size_t idx;

    ASSERT(retval != NULL);
    ASSERT(args != NULL);
    ASSERT(num_arg != 0);
    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (xm_grok_conf_t *) module->config;
    caller_module = eval_ctx->module;


    db = xm_grok_get_db_checked(module);

    if ( eval_ctx->logdata == NULL )
    {
	throw_msg("no logdata available to match_grok([field],pattern), possibly dropped");
    }

    if ( args[0].defined != TRUE )
    {
	retval->defined = FALSE;
	return;
    }
    if ( args[0].type != NX_VALUE_TYPE_STRING )
    {
	throw_msg("invalid '%s' type of first argument for function "
		  "'match_grok([field],pattern)'",
		  nx_value_type_to_string(args[0].type));
    }
    if ( num_arg == 1 )
    {
	field = nx_string_clone(eval_ctx->logdata->raw_event);
	pattern = nx_string_clone(args[0].string);
    }
    else if ( num_arg == 2 )
    {
	if ( args[1].defined != TRUE)
	{
	    retval->defined = FALSE;
	    return;
	}

	if ( args[1].type != NX_VALUE_TYPE_STRING )
	{
	    throw_msg("invalid '%s' type of second argument for function "
		      "'match_grok([field],pattern)''",
		      nx_value_type_to_string(args[1].type));
	}
	field = nx_string_clone(args[0].string);
	pattern = nx_string_clone(args[1].string);
    }

    grok = grok_pattern_match_global(db->pool, field->buf, db->patterns, grok_get_module_storage(caller_module),
				     conf->in_use, pattern->buf);

    retval->defined = TRUE;
    retval->type = NX_VALUE_TYPE_BOOLEAN;
    retval->boolean = (grok != NULL);

    if ( grok != NULL )
    {
	for ( idx = 0; idx < grok->maches_num; idx++ )
	{
	    if ( nx_grok_match_has_name(grok, idx))
	    {
		match_value = nx_grok_get_match_value(grok, idx);
		nx_logdata_set_string(eval_ctx->logdata, nx_grok_match_get_name(grok, idx), match_value->buf);
	    }
	}
    }

    nx_string_zfree(field);
    nx_string_zfree(pattern);
}

