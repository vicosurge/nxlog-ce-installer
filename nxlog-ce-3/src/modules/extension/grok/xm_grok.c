/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev
 */

#include "../../../common/module.h"
#include "../../../common/error_debug.h"
#include "../../../common/resource.h"
#include "../../../common/serialize.h"
#include "../../../common/date.h"
#include "../../../common/alloc.h"

#include <apr_lib.h>
#include <strings.h>

#include "grok.h"
#include "xm_grok.h"


#define NX_LOGMODULE NX_LOGMODULE_MODULE


typedef struct xm_grok_match_t
{
    size_t start_pos;
    size_t end_pos;
    size_t len;
    char *value;
    char *name;
} xm_grok_match_t;

typedef struct xm_grok_prepared_t
{
    char *arg;
    pcre *re;
    xm_grok_match_t *matches;
    size_t maches_num;
} xm_grok_prepared_t;


static xm_grok_pattern_t *xm_grok_get_db(nx_module_t *module)
{
    ASSERT (module);

    return (xm_grok_pattern_t *) nx_module_data_get(module, "xm_grok_pattern_db");
}


static void xm_grok_save_db(nx_module_t *module, xm_grok_pattern_t *db)
{
    ASSERT(module);
    ASSERT(db);

    return nx_module_data_set(module, "xm_grok_pattern_db", db, NULL);
}


static void dump_table(apr_hash_t *ht)
{
    const char *k;
    char *v;

    ASSERT(ht);

    apr_hash_index_t *hi;

    for ( hi = apr_hash_first(NULL, ht); hi; hi = apr_hash_next(hi) )
    {
	apr_hash_this(hi, (const void **) &k, NULL, (void **) &v);
	log_debug("TABLE: key=%s, val=%s\n", k, v);
    }
}


static xm_grok_pattern_t *xm_grok_reload_db(nx_module_t *module)
{
    int i;
    char *location;
    apr_pool_t *db_pool;
    xm_grok_conf_t *conf;

    ASSERT(module);
    ASSERT(module->config);

    conf = (xm_grok_conf_t *) module->config;

    if ( (conf->pattern_files == NULL) || (conf->pattern_files->nelts == 0) )
    {
	return NULL;
    }

    db_pool = nx_pool_create_core();
    xm_grok_pattern_t *db = apr_pcalloc(db_pool, sizeof(xm_grok_pattern_t));
    db->pool = db_pool;
    db->patterns = apr_hash_make(db_pool);
    db->resolved = apr_hash_make(db_pool);
    db->version = conf->version;


    for ( i = 0; i < conf->pattern_files->nelts; i++ )
    {
	location = APR_ARRAY_IDX(conf->pattern_files, i, char *);
	grok_pattern_load(location, db->patterns, db_pool);
    }

    if ( apr_hash_count(db->patterns) )
    {
	grok_pattern_evaluate_all(db->patterns);
    }

    dump_table(db->patterns);

    return db;
}


static void xm_grok_clear_db(xm_grok_pattern_t *db)
{
    apr_hash_index_t *index;
    void *val;
    nx_grok_t *grok;

    if ( db == NULL)
    {
	return;
    }

    for ( index = apr_hash_first(db->pool, db->resolved);
	  index;
	  index = apr_hash_next(index))
    {

	apr_hash_this(index, NULL, NULL, &val);
	grok = (nx_grok_t *) val;
	log_debug("Delete grok: %s (%s)", grok->arg->buf, grok->subj->buf);
	nx_grok_free(grok);
    }
    apr_pool_destroy(db->pool);
}


static boolean need_reload_db(nx_module_t *module)
{

    xm_grok_conf_t *conf;
    xm_grok_pattern_t *db;

    ASSERT(module);
    ASSERT(module->config);

    conf = (xm_grok_conf_t *) module->config;
    db = xm_grok_get_db(module);

    // db empty, need reload
    if ( db == NULL )
    {
	return TRUE;
    }

    // Check config updated
    if ( db->version < conf->version )
    {
	// case 1: db->version = 0, conf->version = 1
	// This only can be if this function called before
	// xm_grok started
	// don't need
	if ((db->version == 0) && (conf->version == 1))
	{
	    // fix config version
	    db->version = conf->version;
	    return FALSE;
	}
	return TRUE;
    }

    return FALSE;
}


xm_grok_pattern_t *xm_grok_get_db_checked(nx_module_t *module)
{
    xm_grok_conf_t *conf;
    xm_grok_pattern_t *db;

    ASSERT(module);
    ASSERT(module->config);

    conf = (xm_grok_conf_t *) module->config;

    ASSERT (conf->mutex != NULL);

    if ( conf->pattern_files == NULL || conf->pattern_files->nelts == 0 )
    {
	return NULL;
    }


    db = xm_grok_get_db(module);

    if ( need_reload_db(module))
    {
	CHECKERR(apr_thread_mutex_lock(conf->mutex));
	// the second check for concurrent threads
	db = xm_grok_get_db(module);
	if ( need_reload_db(module) )
	{

	    if ( db != NULL)
	    {
		log_debug("Should reload db ver %d (conf.version: %d) into %s", db->version, conf->version,
			  module->name);
		xm_grok_clear_db(db);
	    }
	    db = xm_grok_reload_db(module);
	    xm_grok_save_db(module, db);
	    log_debug("Save reload db ver %d (conf.version: %d) into %s", db->version, conf->version, module->name);
	}
	CHECKERR(apr_thread_mutex_unlock(conf->mutex));
    }
    return db;
}


static void im_grok_start(nx_module_t *module)
{
    xm_grok_conf_t *conf;

    ASSERT(module);
    ASSERT(module->config);
    log_debug("Grok module start");
    conf = (xm_grok_conf_t *) module->config;
    conf->version++;
}


static void xm_grok_config(nx_module_t *module)
{
    // Load files
    xm_grok_conf_t *conf;
    const nx_directive_t *curr;

    ASSERT(module != NULL);

    conf = apr_pcalloc(module->pool, sizeof(xm_grok_conf_t));
    conf->pattern_files = apr_array_make(module->pool, 0, sizeof(char *));
    conf->version = 0;
    conf->in_use = nx_grok_list_new(module->pool);
    CHECKERR_MSG(apr_thread_mutex_create(&(conf->mutex), APR_THREAD_MUTEX_DEFAULT, module->pool),
		 "Couldn't create grok db mutex");


    module->config = conf;

    for ( curr = module->directives;
	  curr != NULL;
	  curr = curr->next )
    {
	if ( nx_module_common_keyword(curr->directive) == TRUE )
	{

	}
	else if ( strcasecmp(curr->directive, "Pattern") == 0 || strcasecmp(curr->directive, "PatternFile") == 0 )
	{

	    *(char **) apr_array_push(conf->pattern_files) = apr_pstrdup(module->pool, curr->args);
	    log_debug("Add pattern files: %s", curr->args);

	}
	else
	{
	    nx_conf_error(curr, "invalid keyword: %s", curr->directive);
	}
    }
}


static void xm_grok_shutdown(nx_module_t *module)
{
    xm_grok_conf_t *conf;
    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    xm_grok_clear_db(xm_grok_get_db(module));

    conf = (xm_grok_conf_t *)module->config;

    nx_grok_list_foreach(conf->in_use, nx_grok_free);
}


extern nx_module_exports_t nx_module_exports_xm_grok;

NX_MODULE_DECLARATION nx_xm_grok_module =
	{
		NX_MODULE_API_VERSION,
		NX_MODULE_TYPE_EXTENSION,
		NULL,                        // capabilities
		xm_grok_config,              // config
		im_grok_start,               // start
		NULL,                        // stop
		NULL,                        // pause
		NULL,                        // resume
		NULL,                        // init
		xm_grok_shutdown,            // shutdown
		NULL,                        // event
		NULL,                        // info
		&nx_module_exports_xm_grok,  // exports
	};
