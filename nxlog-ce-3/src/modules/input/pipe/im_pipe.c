/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev <avkhadeev@gmail.com>
 */

#include <apr_lib.h>
#include <apr_portable.h>
#include <sys/stat.h>
#include "../../../common/fileperms.h"

#ifndef APR_FOPEN_NONBLOCK
#include <fcntl.h>
#endif

#include "../../../common/module.h"
#include "../../../common/alloc.h"


#define NX_LOGMODULE NX_LOGMODULE_MODULE
#define IM_PIPE_MAX_READEN   50

#define IM_PIPE_READ_STATE_WAIT_DATA        1
#define IM_PIPE_READ_STATE_READ                2
#define IM_PIPE_READ_STATE_FULL                3


typedef struct im_pipe_config_t
{
    int read_state;
    char * path;
    nx_module_input_func_decl_t * inputfunc;
    nx_fileperms_conf_t perms_conf;
    boolean	createdir;

} im_pipe_config_t;


typedef enum im_pipe_read_status_t
{
    im_pipe_read_status_ok,
    im_pipe_read_status_no_data,
    im_pipe_read_status_eof,
    im_pipe_read_status_err

} im_pipe_read_status_t;


boolean im_pipe_check_file(apr_pool_t * pool, im_pipe_config_t *conf)
{
    apr_finfo_t info;
    apr_status_t rv;

    if ( conf->createdir == TRUE )
    {
	nx_fileperms_create_dir(pool, &conf->perms_conf, conf->path);
    }
    
    rv = apr_stat(&info, conf->path, APR_FINFO_TYPE, pool);

    if ( APR_STATUS_IS_ENOENT(rv) )
    {
	if ( mkfifo(conf->path, 0660) == -1 )
	{
	    log_errno("Creating pipe '%s' ", conf->path);
	    return ( FALSE);
	}
#ifndef WIN32
	nx_fileperms_setperms(&conf->perms_conf, conf->path);
#endif
	return ( TRUE);
    }

    CHECKERR_MSG(rv, "Get '%s' stat", conf->path);

    return info.filetype == APR_PIPE || info.filetype == APR_CHR;
}


static void im_pipe_config(nx_module_t * module)
{
    im_pipe_config_t * conf;
    const nx_directive_t * volatile curr;

    ASSERT(module != NULL);
    ASSERT(module->directives != NULL);

    conf = apr_pcalloc(module->pool, sizeof(im_pipe_config_t));
    conf->read_state = IM_PIPE_READ_STATE_WAIT_DATA;
    module->config = conf;


    for ( curr = module->directives;
	  curr;
	  curr = curr->next )
    {
	if ( nx_module_common_keyword(curr->directive) == TRUE )
	{
	}
	else if ( strcasecmp(curr->directive, "Pipe") == 0 )
	{
	    conf->path = nx_cfg_unquote_string(curr, module->pool);
	}
	else if ( strcasecmp(curr->directive, "InputType") == 0 )
	{
	    if ( conf->inputfunc != NULL )
	    {
		nx_conf_error(curr, "InputType is already defined");
	    }

	    if ( curr->args != NULL )
	    {
		conf->inputfunc = nx_module_input_func_lookup(curr->args);
	    }
	    if ( conf->inputfunc == NULL )
	    {
		nx_conf_error(curr, "Invalid InputType '%s'", curr->args);
	    }
	}
	else if ( nx_fileperms_config(curr, &conf->perms_conf) == TRUE )
	{
	    // permissions config is set
	}
	else if ( strcasecmp(curr->directive, "CreateDir") == 0 )
	{
	    if ( curr->args == NULL )
	    {
		nx_conf_error(curr, "Invalid CreateDir: empty");
	    }
	    nx_cfg_boolean(curr, &conf->createdir);
	}
	else
	{
	    nx_conf_error(curr, "invalid keyword: %s", curr->directive);
	}

    }

    if ( conf->path == NULL )
    {
	nx_conf_error(module->directives, "'Pipe' should be defined");
    }


    if ( conf->inputfunc == NULL )
    {
	conf->inputfunc = nx_module_input_func_lookup("linebased");
    }
}


static void im_pipe_close(nx_module_t * module)
{
    ASSERT(module != NULL);
    ASSERT(module->input.desc.f != NULL);

    nx_module_pollset_remove_file(module, module->input.desc.f);
    apr_file_close(module->input.desc.f);
    module->input.desc.f = NULL;
}


static void im_pipe_open(nx_module_t * module)
{
    apr_file_t * handler;
    im_pipe_config_t * config;

    ASSERT(module->config != NULL);

    config = (im_pipe_config_t *) module->config;

#ifndef APR_FOPEN_NONBLOCK
    // this version of APR doesn't have APR_FOPEN_NONBLOCK; use native open()
    // and just pass APR_FOPEN_READ to APR (apr_file_flags_get() will return this)
    int fd = open(config->path, O_RDONLY | O_NONBLOCK);

    if ( fd == -1 )
    {
	throw_msg("Couldn't open %s: %s", config->path, strerror(errno));
    }

    CHECKERR_MSG(apr_os_file_put(&handler, &fd, APR_FOPEN_READ, module->pool),
		 "Couldn't open %%s", config->path);

#else

    CHECKERR_MSG(apr_file_open(&handler, config->path, APR_FOPEN_READ | APR_FOPEN_NONBLOCK, APR_FPROT_OS_DEFAULT,
			       module->pool),
		 "Couldn't open %%s", config->path);

#endif

    module->input.desc.f = handler;
    module->input.desc_type = APR_POLL_FILE;
    nx_module_pollset_add_file(module, handler, APR_POLLIN);
}


static void im_pipe_file_reopen(nx_module_t * module)
{
    ASSERT(module != NULL);
    ASSERT(module->input.desc.f != NULL);

    im_pipe_close(module);
    im_pipe_open(module);
}


static void im_pipe_start(nx_module_t * module)
{
    im_pipe_config_t * config;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    config = (im_pipe_config_t *) module->config;

    if ( im_pipe_check_file(module->pool, config) == FALSE )
    {
	throw_msg("Invalid %s file type", config->path);
    }

    im_pipe_open(module);
    nx_module_add_poll_event(module);
}


static void im_pipe_stop(nx_module_t * module)
{
    ASSERT(module != NULL);
    ASSERT(module->input.desc.f != NULL);
    ASSERT(module->input.desc_type == APR_POLL_FILE);

    nx_module_remove_events_by_data(module, module->input.desc.f);
    im_pipe_close(module);
}


static void im_pipe_init(nx_module_t * module)
{
    nx_module_pollset_init(module);
}


static void im_pipe_resume(nx_module_t * module)
{
    ASSERT(module != NULL);

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_STOPPED )
    {
	nx_module_add_poll_event(module);
    }
}


static apr_size_t im_pipe_free_space(nx_module_input_t * input)
{
    ASSERT(input != NULL);
    if (input->buflen == 0)
    {
	input->bufstart = 0;
    }
    return (apr_size_t)(input->bufsize - (input->buflen + input->bufstart));
}


static im_pipe_read_status_t im_pipe_fill_input(nx_module_input_t * input)
{
    apr_status_t rv;
    apr_size_t readen;
    char * buf;
    im_pipe_read_status_t result;

    ASSERT(input != NULL);
    ASSERT(input->desc_type == APR_POLL_FILE);
    ASSERT(input->desc.f != NULL);

    // check space remaining
    readen = im_pipe_free_space(input);

    // Fill input can only be invoked with free space
    ASSERT(readen > 0);

    buf = input->buf + input->bufstart + input->buflen;

    rv = apr_file_read(input->desc.f, buf, &readen);

    switch ( rv )
    {
	case APR_EOF:
	    log_debug("eof");
	    result = im_pipe_read_status_eof;
	    break;
	case APR_SUCCESS:
	case APR_TIMEUP:
	    log_debug("%lu bytes readen (%d)", readen, rv);
	    input->buflen += (int) readen;
	    result = readen > 0 ? im_pipe_read_status_ok : im_pipe_read_status_no_data;
	    break;
	default:
	    log_warn("reading error: %d", rv);
	    result = im_pipe_read_status_err;
	    break;
    }
    return result;
}


static void im_pipe_step_reader(nx_module_input_t * input, nx_event_type_t event_type)
{
    im_pipe_config_t * config;

    ASSERT(input != NULL);
    ASSERT(input->module != NULL);
    ASSERT(input->module->config != NULL);

    config = (im_pipe_config_t *) input->module->config;

    switch ( config->read_state )
    {
	case IM_PIPE_READ_STATE_FULL:
	    if ( im_pipe_free_space(input) > 0 )
	    {
		config->read_state = IM_PIPE_READ_STATE_READ;
	    }
	    break;
	case IM_PIPE_READ_STATE_READ:
	    switch ( im_pipe_fill_input(input) )
	    {
		case im_pipe_read_status_ok:
		    config->read_state =
			    im_pipe_free_space(input) == 0 ? IM_PIPE_READ_STATE_FULL : IM_PIPE_READ_STATE_READ;
		    break;
		case im_pipe_read_status_no_data:
		    config->read_state = IM_PIPE_READ_STATE_WAIT_DATA;
		    break;
		case im_pipe_read_status_eof:
		    im_pipe_file_reopen(input->module);
		    config->read_state = IM_PIPE_READ_STATE_WAIT_DATA;
		    break;
		case im_pipe_read_status_err:
		default:
		    throw_msg("Error reading pipe");
	    }
	    break;
	case IM_PIPE_READ_STATE_WAIT_DATA:
	    if ( event_type == NX_EVENT_READ )
	    {
		config->read_state = IM_PIPE_READ_STATE_READ;
	    }
	    else if ( event_type == NX_EVENT_DISCONNECT )
	    {
		im_pipe_file_reopen(input->module);
	    }
	    break;
	default:
	    throw_msg("Unknown im_pipe state");
    }
}


static void im_pipe_input_swipe(nx_module_input_t * input)
{
    if (input->bufstart > (input->bufsize / 2))
    {
	memcpy(input->buf, input->buf + input->bufstart, (size_t)input->buflen);
	input->bufstart = 0;
    }
}


static void im_pipe_step(nx_module_t * module, nx_event_type_t event_type)
{
    nx_module_input_t * input;
    nx_logdata_t * logdata;
    im_pipe_config_t * config;

    int to_process = IM_PIPE_MAX_READEN;

    input = &(module->input);

    config = (im_pipe_config_t *) module->config;

    do
    {
	im_pipe_step_reader(input, event_type);
	while (( -- to_process > 0) && (logdata = config->inputfunc->func(input, config->inputfunc->data)) != NULL )
	{
	    nx_module_add_logdata_input(module, input, logdata);
	}
	im_pipe_input_swipe(input);
    } while ( config->read_state == IM_PIPE_READ_STATE_READ && to_process > 0 );

}


static void im_pipe_event(nx_module_t * module, nx_event_t * event)
{

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);
    ASSERT(event != NULL);

    switch ( event->type )
    {
	case NX_EVENT_POLL:
	    if ( nx_module_get_status(module) == NX_MODULE_STATUS_RUNNING )
	    {
		nx_module_pollset_poll(module, TRUE);
	    }
	case NX_EVENT_DISCONNECT:
	case NX_EVENT_READ:

	    // This event will process later
	    break;
	default:
	    nx_panic("invalid event type: %d", event->type);
    }
    im_pipe_step(module, event->type);
}


NX_MODULE_DECLARATION nx_im_pipe_module =
{
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_INPUT,
    NULL,		// capabilities
    im_pipe_config,	// config
    im_pipe_start,	// start
    im_pipe_stop,	// stop
    NULL,		// pause
    im_pipe_resume,	// resume
    im_pipe_init,	// init
    NULL,		// shutdown
    im_pipe_event,	// event
    NULL,		// info
    NULL,		// exports
};
