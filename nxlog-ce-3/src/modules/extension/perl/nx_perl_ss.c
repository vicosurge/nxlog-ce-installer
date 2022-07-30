#include "../../../core/ctx.h"
#include "../../../core/nxlog.h"
#include "../../../common/error_debug.h"

#include "xm_perl.h"
#include "nx_perl_ss.h"

#include "libnxperl.h"


// mingw hack (experimental)
#if defined(PERL_IMPLICIT_SYS) && defined(__MINGW32__)
# undef setjmp
# undef longjmp
#endif

#define NX_LOGMODULE NX_LOGMODULE_MODULE

EXTERN_C void xs_init(pTHX);

#define NX_PERL_CTX_DATA_NAME "ctx.perl.ext"

/* perl locking */
struct _perl_ctx
{
    int ref_cnt;
    apr_thread_mutex_t *ss_mutex;
};


void nx_perl_ss_begin()
{
    apr_status_t rv;
    nx_ctx_t *nx_ctx;
    struct _perl_ctx *ctx;

    nx_ctx = nx_ctx_get();

    ASSERT(nx_ctx != NULL);

    ctx = nx_ctx_data_get(nx_ctx, NX_PERL_CTX_DATA_NAME);

    ASSERT(ctx != NULL);

    rv = apr_thread_mutex_lock(ctx->ss_mutex);
    if ( rv != APR_SUCCESS )
    {
	log_aprerror(rv, "Lock perl mutex (0x%lx)", (uint64_t) ctx->ss_mutex);
	ASSERT(rv == APR_SUCCESS);
    }
}


void nx_perl_ss_end()
{
    apr_status_t rv;
    nx_ctx_t *nx_ctx;
    struct _perl_ctx *ctx;

    nx_ctx = nx_ctx_get();

    ASSERT(nx_ctx != NULL);

    ctx = nx_ctx_data_get(nx_ctx, NX_PERL_CTX_DATA_NAME);

    ASSERT(ctx != NULL);

    rv = apr_thread_mutex_unlock(ctx->ss_mutex);
    if ( rv != APR_SUCCESS )
    {
	log_aprerror(rv, "Unlock perl mutex (0x%lx)", (uint64_t) ctx->ss_mutex);
	ASSERT(rv == APR_SUCCESS);
    }
}


void nx_perl_global_init()
{
    nx_ctx_t *nx_ctx;
    struct _perl_ctx *ctx;

    nx_ctx = nx_ctx_get();

    ASSERT(nx_ctx != NULL);

    ctx = nx_ctx_data_get(nx_ctx, NX_PERL_CTX_DATA_NAME);

    if ( ctx == NULL )
    {
	ctx = apr_pcalloc(nx_ctx->pool, sizeof(struct _perl_ctx));
	CHECKERR(apr_thread_mutex_create(&ctx->ss_mutex, APR_THREAD_MUTEX_DEFAULT, nx_ctx->pool));

	nx_ctx_data_set(nx_ctx, NX_PERL_CTX_DATA_NAME, ctx);

	if ( nxlog_get()->reload_request == FALSE )
	{
	    PERL_SYS_INIT3(NULL, NULL, NULL);
	}

    }
    ctx->ref_cnt++;
}


void nx_perl_global_shutdown()
{
    nx_ctx_t *nx_ctx;
    struct _perl_ctx *ctx;

    nx_ctx = nx_ctx_get();

    ASSERT(nx_ctx != NULL);
    ctx = nx_ctx_data_get(nx_ctx, NX_PERL_CTX_DATA_NAME);

    if ( ctx != NULL )
    {
	ctx->ref_cnt--;
	if ( ctx->ref_cnt <= 0 )
	{
	    if ( nxlog_get()->reload_request == FALSE )
	    {
		PERL_SYS_TERM();
	    }
	    nx_ctx_data_set(nx_ctx, NX_PERL_CTX_DATA_NAME, NULL);
	}
    }
}


void nx_perl_config(nx_module_t *module, const char *default_fun_name)
{
    nx_perl_config_t *modconf;
    const nx_directive_t *curr;

    modconf = apr_pcalloc(module->pool, sizeof(nx_perl_config_t));
    module->config = modconf;

    curr = module->directives;

    while ( curr != NULL )
    {
	if ( nx_module_common_keyword(curr->directive) )
	{
	}
	else if ( strcasecmp(curr->directive, "perlcode") == 0 )
	{
	    if ( modconf->perlcode != NULL )
	    {
		nx_conf_error(curr, "PerlCode is already defined");
	    }
	    modconf->perlcode = apr_pstrdup(module->pool, curr->args);
	}
	else if ( strcasecmp(curr->directive, "config") == 0 )
	{
	    if ( nx_module_data_get(module, "perl_conf") != NULL )
	    {
		nx_conf_error(curr, "Config is already defined");
	    }
	    nx_module_data_set(module, "perl_conf", curr->args, NULL);
	}
	else if ( strcasecmp(curr->directive, "call") == 0 )
	{
	    if ( default_fun_name == NULL )
	    {
	        nx_conf_error(curr, "Call directive not supported");
	    }
	    if ( modconf->run != NULL )
	    {
		nx_conf_error(curr, "Call is already defined");
	    }
	    modconf->run = apr_pstrdup(module->pool, curr->args);
	    ASSERT(modconf->run);
	}
	else
	{
	    nx_conf_error(curr, "invalid keyword: %s", curr->directive);
	}
	curr = curr->next;
    }

    if ( modconf->perlcode == NULL )
    {
	nx_conf_error(module->directives, "'PerlCode' is required");
    }

    if ( (modconf->run == NULL) && (default_fun_name != NULL) )
    {
        modconf->run = apr_pstrdup(module->pool, default_fun_name);
    }

    log_debug("configured to use %s", modconf->perlcode);
}


void nx_perl_module_init(nx_module_t *module)
{
    nx_perl_config_t *modconf;
    char *args[3];

    ASSERT(module != NULL);

    TRIAL_CHECK();

    modconf = (nx_perl_config_t *)module->config;
    ASSERT(modconf != NULL);
    ASSERT(modconf->perlcode != NULL);

    args[0] = "nxlog";
    args[1] = modconf->perlcode;
    args[2] = NULL;

    if ( modconf->perl_interpreter == NULL )
    {
	dTHX;
	modconf->perl_interpreter = perl_alloc();
	PL_perl_destruct_level = 1;
	perl_construct(modconf->perl_interpreter);
	PERL_SET_CONTEXT(modconf->perl_interpreter);
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    }

    if ( perl_parse(modconf->perl_interpreter, xs_init, 2, args, NULL) )
    {
	if ( modconf->perl_interpreter != NULL )
	{
	    dTHX;
	    PERL_SET_CONTEXT(modconf->perl_interpreter);
	    perl_destruct(modconf->perl_interpreter);
	    perl_free(modconf->perl_interpreter);
	    modconf->perl_interpreter = NULL;
	    log_debug("perl has been destructed");
	}
	nx_perl_ss_end();
	throw_msg("the perl interpreter failed to parse %s", modconf->perlcode);
    }
    PERL_SET_CONTEXT(modconf->perl_interpreter);
    nx_perl_initialize_library(modconf->perl_interpreter, module);
    log_debug("perl has been initialized");
}


void nx_perl_module_shutdown(nx_module_t *module)
{
    nx_perl_config_t *modconf;

    ASSERT(module != NULL);

    modconf = (nx_perl_config_t *) module->config;
    ASSERT(modconf != NULL);

    if ( modconf->perl_interpreter != NULL )
    {
	dTHX;
	PERL_SET_CONTEXT(modconf->perl_interpreter);
	nx_perl_shutdown_library(modconf->perl_interpreter, module);
	PL_perl_destruct_level = 1;
	perl_destruct(modconf->perl_interpreter);
	perl_free(modconf->perl_interpreter);
	modconf->perl_interpreter = NULL;
    }
}
