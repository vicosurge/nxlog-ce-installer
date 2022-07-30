#include "../common/logdata.h"
#include "../../../common/module.h"

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"
#include "apr_thread_mutex.h"
#include "libnxperl.h"

#undef link
#define NX_LOGMODULE NX_LOGMODULE_MODULE

/* key: THX, value *nx_module_t */
static apr_hash_t *_module_map = NULL;
static apr_thread_mutex_t* _module_map_mutex = NULL;
static apr_pool_t *_mm_pool = NULL;

void nx_perl_initialize_library(pTHX_ nx_module_t *module)
{
    if (_module_map_mutex == NULL) {
        log_debug("creating mutex _module_map_mutex");
        ASSERT(apr_thread_mutex_create(&_module_map_mutex, APR_THREAD_MUTEX_UNNESTED, module->pool) == APR_SUCCESS);
    }
    if (_module_map == NULL)
    {
        ASSERT(apr_pool_create_core(&_mm_pool) == APR_SUCCESS);
        _module_map = apr_hash_make(_mm_pool);
        ASSERT(_module_map != NULL);
    }

    PerlInterpreter *perl_interpreter = aTHX;
    ASSERT(apr_thread_mutex_lock(_module_map_mutex) == APR_SUCCESS);
    void *key = apr_pcalloc(_mm_pool, sizeof(void *));
    memcpy(key, &perl_interpreter, sizeof(void *));
    apr_hash_set(_module_map, key, sizeof(void *), module);
    ASSERT(apr_thread_mutex_unlock(_module_map_mutex) == APR_SUCCESS);
    log_debug("perl interpreter (%lx) => module (%lx)", (unsigned long) aTHX, (unsigned long) module);
}



void nx_perl_shutdown_library(pTHX_ nx_module_t *module)
{
    if (_module_map_mutex) {
        log_debug("destroing mutex _module_map_mutex");
        ASSERT(apr_thread_mutex_destroy(_module_map_mutex) == APR_SUCCESS);
        _module_map_mutex = NULL;
        apr_pool_destroy(_mm_pool);
        _module_map = NULL;
    }
}

static nx_module_t* _lookup_module(pTHX)
{
    int protected_access;
    nx_module_t* module = NULL;
    PerlInterpreter *perl_interpreter = aTHX;
    protected_access = _module_map_mutex != NULL;
    if (protected_access) {
        ASSERT(apr_thread_mutex_lock(_module_map_mutex) == APR_SUCCESS);
    } else {
        log_warn("uprotected access to _module_map");
    }
    if (protected_access) {
        ASSERT(apr_thread_mutex_unlock(_module_map_mutex) == APR_SUCCESS);
    }
    module = apr_hash_get(_module_map, &perl_interpreter, sizeof(void *));
    assert(module);
    log_debug("[lookup] perl interpreter (%lx) => module (%lx)", (unsigned long int) aTHX, (unsigned long int) module);
    return module;
}

static void _bootstrap()
{
    dTHX;
    if (_module_map == NULL)
    {
	//_module_map = newHV();
    }
}

MODULE = Log::Nxlog		PACKAGE = Log::Nxlog

BOOT:
    _bootstrap();


void set_field_integer(event, key, value)
    nx_logdata_t *event;
    char         *key;
    SV           *value;

    CODE:

    if ( SvOK(value) )
    {
	if ( SvIOK(value) )
	{
	    nx_logdata_set_integer(event, key, SvIV(value));
	}
	else
	{
	    Perl_croak(aTHX_ "Non-integer argument passed to nxlog::set_field_integer()");
	}
    }
    else
    { // undef
	nx_logdata_delete_field(event, key);
    }



void set_field_string(event, key, value)
    nx_logdata_t *event;
    char         *key;
    SV           *value;

    CODE:

    if ( SvOK(value) )
    {
	if ( SvPOK(value) )
	{
	    nx_logdata_set_string(event, key, SvPV_nolen(value));
	}
	else
	{
	    Perl_croak(aTHX_ "Non-string argument passed to nxlog::set_field_string()");
	}
    }
    else
    { // undef
	nx_logdata_delete_field(event, key);
    }



void set_field_boolean(event, key, value)
    nx_logdata_t *event;
    char         *key;
    SV           *value;

    CODE:

    if ( SvOK(value) )
    {
	if ( SvIOK(value) )
	{
	    if ( SvIV(value) )
	    {
		nx_logdata_set_boolean(event, key, TRUE);
	    }
	    else
	    {
		nx_logdata_set_boolean(event, key, FALSE);
	    }
	}
	else
	{
	    Perl_croak(aTHX_ "Non-integer argument passed to nxlog::set_field_boolean()");
	}
    }
    else
    { // undef
	nx_logdata_delete_field(event, key);
    }



SV *get_field(event, key)
    nx_logdata_t  *event;
    char          *key;

    CODE:

    boolean       rc;
    nx_value_t    nx_value;

    rc = nx_logdata_get_field_value(event, key, &nx_value);

    if ( rc )
    {
	if ( nx_value.defined == FALSE )
	{
	    XSRETURN_UNDEF;
	}

	if ( nx_value.type == NX_VALUE_TYPE_STRING )
	{
	    XSRETURN_PV(nx_value.string->buf);
	}
	else if ( nx_value.type == NX_VALUE_TYPE_INTEGER )
	{
	    XSRETURN_IV(nx_value.integer);
	}
	else if ( nx_value.type == NX_VALUE_TYPE_DATETIME )
	{
	    XSRETURN_IV(nx_value.datetime);
	}
	else if ( nx_value.type == NX_VALUE_TYPE_BOOLEAN )
	{
	    if ( nx_value.boolean == TRUE )
	    {
		XSRETURN_YES;
	    }
	    else
	    {
		XSRETURN_NO;
	    }
	}
	else if ( (nx_value.type == NX_VALUE_TYPE_IP4ADDR) ||
		  (nx_value.type == NX_VALUE_TYPE_IP6ADDR) )
	{
	    char *addr;

	    addr = nx_value_to_string(&nx_value);
	    RETVAL = newSVpv(addr, 0);
	    free(addr);
	}
	else if ( nx_value.type == NX_VALUE_TYPE_BINARY )
	{
	    RETVAL = newSVpv(nx_value.binary.value, nx_value.binary.len);
	}
	else
	{
	    XSRETURN_UNDEF;
	}
    }
    else
    {
	XSRETURN_UNDEF;
    }

    OUTPUT:
      RETVAL



void delete_field(event, key)
    nx_logdata_t *event;
    char         *key;

    CODE:

    nx_logdata_delete_field(event, key);



SV *field_type(event, key)
    nx_logdata_t  *event;
    char          *key;

    CODE:

    boolean       rc;
    nx_value_t    nx_value;

    rc = nx_logdata_get_field_value(event, key, &nx_value);

    if ( rc )
    {
	if ( nx_value.defined == FALSE )
	{
	    XSRETURN_UNDEF;
	}

	XSRETURN_PV(nx_value_type_to_string(nx_value.type));
    }
    else
    {
	XSRETURN_UNDEF;
    }

    OUTPUT:
      RETVAL



AV *field_names(event)
    nx_logdata_t  *event;

    CODE:
    nx_logdata_field_t *field;
    SV *sv;

    RETVAL = newAV();
    sv_2mortal((SV*) RETVAL);
    for ( field = NX_DLIST_FIRST(&(event->fields));
	  field != NULL;
	  field = NX_DLIST_NEXT(field, link) )
    {
	sv = newSVpv(field->key, 0);
	av_push(RETVAL, sv);
    }

    OUTPUT:
      RETVAL

nx_logdata_t* logdata_new()

    CODE:
       nx_logdata_t* event;
       event = nx_logdata_new();
       log_debug("created event %lx", (unsigned long int) event);
       RETVAL = event;
    OUTPUT:
       RETVAL

void add_input_data(event)
    nx_logdata_t *event;

    CODE:
    nx_module_t* module = _lookup_module(aTHX);
    log_debug("add input data %lx", (unsigned long int) event);
    nx_module_add_logdata_input(module, NULL, event);

void set_read_timer(delay)
    int delay

   CODE:
   nx_module_t* module = _lookup_module(aTHX);
   nx_perl_set_read_timer_func_t* callback =
       (nx_perl_set_read_timer_func_t*) nx_module_data_get(module, "set_read_timer_cb");
    if (!callback) {
	log_warn("set_read_timer is not available, ignoring");
    } else {
	callback(module, delay);
    }

SV *get_nxlog_conf()

    CODE:

	char * perl_conf;
        nx_module_t* module = _lookup_module(aTHX);
	perl_conf = (char *)nx_module_data_get(module, "perl_conf");

	if (perl_conf)
	{
	    XSRETURN_PV(strdup(perl_conf));
	}
	else
	{
	    XSRETURN_UNDEF;
	}
    OUTPUT:
      RETVAL



void log_debug(msg)
    char         *msg;

    CODE:

    log_debug("%s", msg);



void log_info(msg)
    char         *msg;

    CODE:

    log_info("%s", msg);



void log_warning(msg)
    char         *msg;

    CODE:

    log_warn("%s", msg);



void log_error(msg)
    char         *msg;

    CODE:

    log_error("%s", msg);
