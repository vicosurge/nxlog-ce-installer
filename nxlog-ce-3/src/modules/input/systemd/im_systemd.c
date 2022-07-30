/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev <avkhadeev@gmail.com>
 */

#include <apr_portable.h>
#include <pwd.h>
#include <grp.h>

#include "../../../common/module.h"
#include "../../../common/event.h"
#include "../../../common/error_debug.h"
#include "../../../common/alloc.h"
#include "../../../common/config_cache.h"

#include <systemd/sd-journal.h>

#define IM_SYSTEMD_CC_KEY "systemd_cursor"

#define NX_LOGMODULE NX_LOGMODULE_MODULE
#define IM_SYSTEMD_READ_THREASHOLD 50


void im_systemd_process_logdata(sd_journal *journal, nx_logdata_t *logdata);


#define CHECKERR_NEG_MSG(code, fmt, args...)                         \
do {								 \
     apr_status_t _rv = code;					 \
     if ( _rv < 0 )						 \
     {					 			 \
	 throw_cause(-_rv, #code, fmt, ##args);			 \
     }					 			 \
} while (0)


typedef struct im_systemd_config_t
{
    boolean read_from_last;
    sd_journal *journal;
    char *cursor;
    apr_file_t *journal_file;
} im_systemd_config_t;


static void im_systemd_config(nx_module_t *module)
{
    im_systemd_config_t *conf;
    const nx_directive_t *curr;

    ASSERT(module != NULL);
    ASSERT (module->directives);

    conf = apr_pcalloc(module->pool, sizeof(im_systemd_config_t));
    module->config = conf;

    for ( curr = module->directives; curr != NULL; curr = curr->next )
    {
	if ( nx_module_common_keyword(curr->directive) == TRUE )
	{
	}
	else if ( strcasecmp(curr->directive, "ReadFromLast") == 0)
	{
	}
	else
	{
	    nx_conf_error(curr, "invalid keyword: %s", curr->directive);
	}
    }

    conf->read_from_last = TRUE;
    nx_cfg_get_boolean(module->directives, "ReadFromLast", &(conf->read_from_last));
}


// Save last readen record position
static void im_systemd_cursor_save(nx_module_t *module)
{
    im_systemd_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (im_systemd_config_t *) module->config;

    if ( conf->cursor == NULL )
    {
	CHECKERR_NEG_MSG(sd_journal_get_cursor(conf->journal, &conf->cursor),
	                 "Couldn't get systemd cursor");
    }
    nx_config_cache_set_string(module->name, IM_SYSTEMD_CC_KEY, conf->cursor);
    //free(conf->cursor);
}


static void im_systemd_cursor_update(nx_module_t *module)
{
    im_systemd_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (im_systemd_config_t *) module->config;

    if ( conf->cursor != NULL )
    {
	free(conf->cursor);
    }
    CHECKERR_NEG_MSG(sd_journal_get_cursor(conf->journal, &conf->cursor),
		     "Get next cursor");
}

static void im_systemd_cursor_free(nx_module_t *module)
{
    im_systemd_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (im_systemd_config_t *) module->config;

    if ( conf->cursor != NULL )
    {
	free(conf->cursor);
    }
}


// Restore last readen record position
static void im_systemd_cursor_restore(nx_module_t *module)
{
    im_systemd_config_t *conf;
    int err;
    char *cur;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (im_systemd_config_t *) module->config;

    if ( conf->read_from_last == FALSE )
    {
	CHECKERR_NEG_MSG(sd_journal_seek_head(conf->journal),
			 "Restore journal position");
	return;
    }

    if ( nx_config_cache_get_string(module->name,
                                    IM_SYSTEMD_CC_KEY,
                                    &cur) == TRUE )
    {
	if ( conf->cursor != NULL )
	{
	    free(conf->cursor);
	}

	conf->cursor = cur;
	err = sd_journal_seek_cursor(conf->journal, conf->cursor);

        if ( err != 0 )
	{
	    log_warn("Couldn't seek at cursor (%s). Read from start", strerror(-err));
	    CHECKERR_NEG_MSG(sd_journal_seek_head(conf->journal),
	                     "Couldn't seek at head record");
	}

	CHECKERR_NEG_MSG(sd_journal_next(conf->journal),
	                 "Skip last message");
    }
}


static void im_systemd_stop(nx_module_t *module)
{
    im_systemd_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (im_systemd_config_t *) module->config;

    ASSERT (conf->journal);

    im_systemd_cursor_save(module);
    im_systemd_cursor_free(module);
    sd_journal_close(conf->journal);
    nx_module_pollset_remove_file(module, conf->journal_file);
    nx_module_remove_events_by_type(module, NX_EVENT_POLL);
    nx_module_remove_events_by_type(module, NX_EVENT_READ);
}


static void im_systemd_pause(nx_module_t *module)
{
    ASSERT(module != NULL);

    nx_module_remove_events_by_type(module, NX_EVENT_POLL);
    nx_module_remove_events_by_type(module, NX_EVENT_READ);
}


static void im_systemd_resume(nx_module_t *module)
{
    if ( nx_module_get_status(module) != NX_MODULE_STATUS_STOPPED )
    {
	nx_module_pollset_poll(module, FALSE);
    }
}


static void im_systemd_init(nx_module_t *module)
{
    nx_module_pollset_init(module);
}


static void im_systemd_poll(nx_module_t *module)
{
    im_systemd_config_t *conf;
    int fd;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (im_systemd_config_t *) module->config;

    ASSERT (conf->journal);

    // Remove old file from pollset
    if ( conf->journal_file != NULL )
    {
	nx_module_pollset_remove_file(module, conf->journal_file);
    }

    fd = sd_journal_get_fd(conf->journal);
    CHECKERR_NEG_MSG(fd, "Conldn't get systemd file descriptor");

#ifndef APR_FOPEN_NONBLOCK
    // this version of APR doesn't have APR_FOPEN_NONBLOCK;
    // NOTE: apr_file_flags_get() will only return APR_FOPEN_READ
    CHECKERR(apr_os_file_put(&conf->journal_file, &fd,
                             APR_FOPEN_READ,
                             module->pool));
#else
    CHECKERR(apr_os_file_put(&conf->journal_file, &fd,
                             APR_FOPEN_READ | APR_FOPEN_NONBLOCK,
                             module->pool));
#endif

    nx_module_pollset_add_file(module, conf->journal_file,
			       (apr_int16_t)sd_journal_get_events(conf->journal));
}


static void im_systemd_start(nx_module_t *module)
{
    im_systemd_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (im_systemd_config_t *) module->config;

    ASSERT (conf->journal == NULL);

    // (1) Load cached cursor
    CHECKERR_NEG_MSG(sd_journal_open(&conf->journal, SD_JOURNAL_LOCAL_ONLY),
                 "Open systemd journal");

    im_systemd_cursor_restore(module);

    im_systemd_poll(module);
    nx_module_pollset_poll(module, FALSE);
}


static void im_systemd_invalidate(nx_module_t *module)
{
    im_systemd_config_t *conf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (im_systemd_config_t *) module->config;

    ASSERT (conf->journal);

    sd_journal_close(conf->journal);
    nx_module_remove_events_by_type(module, NX_EVENT_POLL);
    nx_module_remove_events_by_type(module, NX_EVENT_READ);

    CHECKERR_NEG_MSG(sd_journal_open(&conf->journal, SD_JOURNAL_LOCAL_ONLY),
                     "Open systemd journal");

    CHECKERR_NEG_MSG(sd_journal_seek_cursor(conf->journal, conf->cursor),
                     "Seek cursor after invalidate");

    CHECKERR_NEG_MSG(sd_journal_next(conf->journal),
                     "next record after invalidate");
    sd_journal_process(conf->journal);
//    CHECKERR_NEG_MSG(sd_journal_get_cursor(conf->journal, &conf->cursor),
//                     "Get cursor after invalidate");

    im_systemd_poll(module);
    nx_module_pollset_poll(module, FALSE);
}


/**
 * @brief im_systemd_read_logdata read single systemd record
 * @param module
 * @return FALSE if EOF
 */
static boolean im_systemd_read_logdata(nx_module_t *module)
{
    im_systemd_config_t *conf;
    int rv;
    nx_logdata_t *logdata;
    nx_exception_t e;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (im_systemd_config_t *) module->config;

    CHECKERR_NEG_MSG(rv = sd_journal_next(conf->journal),
                     "systemd journal next record");
    if ( rv == 0 )
    {
	// Reached the end
	return ( FALSE );
    }
    im_systemd_cursor_update(module);
    logdata = nx_logdata_new();
    try
    {
	im_systemd_process_logdata(conf->journal, logdata);
    }
    catch (e)
    {
	nx_logdata_free(logdata);
	rethrow(e);
    }
    nx_module_add_logdata_input(module, &(module->input), logdata);
    return ( TRUE );
}


static void im_systemd_read(nx_module_t *module)
{
    int readen;
    im_systemd_config_t *conf;
    int proc;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
        log_debug("module %s not running, not reading any more data", module->name);
        return;
    }

    conf = (im_systemd_config_t *) module->config;

    ASSERT (conf->journal);

    if ( (proc = sd_journal_process(conf->journal)) < 0 )
    {
	if ( proc == -EBADF )
	{
	    // Probably exiting nxlog
	    log_info("EBADF");
	    return;
	}
	CHECKERR_NEG_MSG(proc, "get process");
    }

    switch ( proc )
    {
    case SD_JOURNAL_NOP:	    //the journal did not change since the last invocation
    case SD_JOURNAL_APPEND:	    //new entries have been appended to the end of the journal
        for ( readen = 0; readen < IM_SYSTEMD_READ_THREASHOLD; readen ++ )
	{
	    if ( im_systemd_read_logdata(module) == FALSE )
	    {
		// no more data
		break;
	    }
	}
	// Wait data
//	im_systemd_poll(module);
	nx_module_pollset_poll(module, FALSE);
	break;
    case SD_JOURNAL_INVALIDATE:	    //journal files were added or removed (possibly due to rotation)
	im_systemd_invalidate(module);
	break;
    default:			    // Error
	throw_msg("Bad process: %d", proc);
    }
}


static void im_systemd_event(nx_module_t *module, nx_event_t *event)
{
    ASSERT(event != NULL);

    switch ( event->type )
    {
        case NX_EVENT_POLL:
        case NX_EVENT_READ:
            im_systemd_read(module);
            break;
        default:
            nx_panic("invalid event type: %d", event->type);
    }
}


NX_MODULE_DECLARATION nx_im_systemd_module =
{
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_INPUT,
    "CAP_NET_BIND_SERVICE",	// capabilities
    im_systemd_config,		// config
    im_systemd_start,		// start
    im_systemd_stop, 		// stop
    im_systemd_pause,		// pause
    im_systemd_resume,		// resume
    im_systemd_init,		// init
    NULL,			// shutdown
    im_systemd_event,		// event
    NULL,			// info
    NULL,			// exports
};
