/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */
//#pragma GCC optimize ("0")
#include <stdlib.h>
#include <apr_portable.h>
#include <unistd.h>
#include <apr_file_info.h>
#include <apr_fnmatch.h>

#include "../../../core/nxlog.h"
#include "../../../common/module.h"
#include "../../../common/event.h"
#include "../../../common/error_debug.h"
#include "../../../common/config_cache.h"
#include "../../../common/expr-parser.h"
#include "../../../common/alloc.h"
#include "../../../common/filepath.h"

#include "im_file.h"

#define NX_LOGMODULE NX_LOGMODULE_MODULE

#define IM_FILE_DEFAULT_POLL_INTERVAL 1 /* The number of seconds to check the files for new data */
#define IM_FILE_MAX_READ 50 /* The max number of logs to read in a single iteration */
#define IM_FILE_DEFAULT_ACTIVE_FILES 10 /* The number of files which will be open at a time */
#define IM_FILE_DEFAULT_NOESCAPE  FALSE
#define IM_FILE_DEFAULT_GRACETIMEOUT  1

typedef enum
{
    IM_FILE_EVT_DIRCHECK = 1,
    IM_FILE_EVT_ONEOFEXEC
} im_file_evt_subtype_t;


static void im_file_input_get_filepos(nx_module_t *module,
				      nx_im_file_input_t *file,
				      boolean blacklist);

static nx_event_t* im_file_add_spec_event(nx_module_t *module, im_file_evt_subtype_t subtype, boolean delayed);


static void im_file_input_close(nx_module_t *module, nx_im_file_input_t *file) 
{
    nx_im_file_conf_t *imconf;

    ASSERT(file != NULL);

    imconf = (nx_im_file_conf_t *) module->config;

    if ( imconf->currsrc == file )
    {
	imconf->currsrc = NX_DLIST_NEXT(file, link);
    }


    if ( file->input != NULL )
    {

	// at end of file we process buffer
	if ( file->input->desc.f != NULL && file->num_eof > 0 )
	{
	    nx_logdata_t *logdata;
	    while ( (logdata = file->input->inputfunc->func(file->input, file->input->inputfunc->data)) != NULL )
	    {
		nx_module_add_logdata_input(file->input->module, file->input, logdata);
	    }
	}

	// post processing input
	nx_module_input_flush(file->input);

	if ( file->input->desc.f != NULL )
	{
	    // save file position
	    im_file_input_get_filepos(module, file, FALSE);
	    log_debug("input_close(): module %s buffer: start:%d  len:%d  incomplete:%d",
		     module->name, file->input->bufstart, file->input->buflen, file->input->incomplete_len);

	    // save config cache pos
	    nx_config_cache_set_int(module->name, file->name, (int64_t) file->filepos);
	    log_debug("module %s saved position %ld for %s",
		      module->name, (long int) file->filepos, file->name);

	    if ( APR_SUCCESS == apr_file_close(file->input->desc.f) )
	    {
		file->input->desc.f = NULL;
		log_debug("file %s closed", file->name);
	    }
	    else
	    {
		log_error("File close was unsuccessful (%s)", file->name);
	    }
	}

	if ( (file->input->inputfunc != NULL) && (file->input->inputfunc->clean != NULL) )
	{
	    file->input->inputfunc->clean(file->input, NULL);
	}

	if (file->input->desc.f == NULL)
	{
	    apr_pool_destroy(file->input->pool);
	    file->input = NULL;

	    NX_DLIST_REMOVE(imconf->open_files, file, link);
	    (imconf->num_open_files)--;
	    ASSERT(imconf->num_open_files >= 0);
	}
    }

    if (file->input == NULL)
    {
	file->num_eof = 0;
    }
}


/**
 * If filehash removed then file will be available in next dircheck event as a new file
 * @param module
 * @param file
 */
static void im_file_filehash_remove(nx_module_t* module, nx_im_file_input_t** file)
{
    ASSERT(module != NULL);
    ASSERT(file != NULL);
    ASSERT(*file != NULL);
    nx_im_file_conf_t *imconf;
    imconf = (nx_im_file_conf_t *) module->config;
    ASSERT(imconf != NULL);

    // file must be closed first!
    ASSERT((*file)->input == NULL);

    ASSERT((*file)->name != NULL);
    ASSERT(*((*file)->name) != '\x0');
    apr_hash_set(imconf->files, (*file)->name, APR_HASH_KEY_STRING, NULL);

    if ((*file)->pool != NULL)
    {
	apr_pool_destroy((*file)->pool);
    }
    *file = NULL;
}

static boolean im_file_input_open(nx_module_t *module,
				  nx_im_file_input_t **file,
				  boolean readfromlast,
				  boolean existed);

/**
 *
 * @param module
 * @param file
 * @return  TRUE if processed
 */
static boolean im_file_oneof_exec(nx_module_t* module, nx_im_file_input_t* file)
{
    ASSERT(module != NULL);
    ASSERT(file != NULL);
    nx_im_file_conf_t *imconf;
    imconf = (nx_im_file_conf_t *) module->config;
    ASSERT(imconf != NULL);

    if (imconf->oneof_exec == NULL || file->first_eof_time == 0 || file->oneof_processed == TRUE)
    {
	return FALSE;
    }

    apr_time_t now = apr_time_now();
    apr_time_t elapsed_since_eof = now - file->first_eof_time;
    apr_time_t elapsed_since_read = now - file->last_succesful_readtime;
//    log_info("Elapsed since eof : %"APR_UINT64_T_FMT , elapsed_since_eof);
    if ( imconf->oneof_grace_timeout > 0 &&
	( (!imconf->closewhenidle && elapsed_since_eof < imconf->oneof_grace_timeout) ||
	( imconf->closewhenidle && (file->last_succesful_readtime==0 || elapsed_since_read < imconf->oneof_grace_timeout )))
	)
    {
	return  FALSE;
    }

    log_debug("processing <OnEOF> at file %s", file->name);

    boolean reopen_needed = (file->input == NULL);

    if (reopen_needed)
    {
	boolean open_success = im_file_input_open(module, &file, imconf->readfromlast, TRUE);
	if (open_success == FALSE)
	{
	    return FALSE;
	}
    }

    nx_expr_eval_ctx_t eval_ctx;
    nx_expr_eval_ctx_init(&eval_ctx, NULL, module, file->input);

    nx_module_input_data_set(file->input, NX_MODULE_INPUT_CONTEXT_FILENAME, apr_pstrdup(file->input->pool, file->name));
    nx_expr_statement_list_execute(&eval_ctx, imconf->oneof_exec);

    if (reopen_needed)
    {
	im_file_input_close(module, file);
    }

    file->oneof_processed = TRUE;
    return TRUE;
}



static void im_file_oneofexec_event_cb(nx_module_t* module)
{
    ASSERT(module != NULL);
    nx_im_file_conf_t *imconf = (nx_im_file_conf_t *) module->config;
    ASSERT(imconf != NULL);

    imconf->execoneof_event = NULL;

    if (imconf->oneof_exec == NULL)
    {
	return;
    }

    apr_hash_index_t *idx;
    const char *fname;
    apr_ssize_t keylen;
    nx_im_file_input_t *file;

    apr_pool_t *pool;
    apr_pool_create(&pool, module->pool);
    ASSERT(pool);

    for ( idx = apr_hash_first(pool, imconf->files);
	  idx != NULL;
	  idx = apr_hash_next(idx) )
    {
	apr_hash_this(idx, (const void **) &fname, &keylen, (void **) &file);
	if (file->oneof_processed == FALSE)
	{
	    im_file_oneof_exec(module, file);
	}
    }
    apr_pool_destroy(pool);
    
    ASSERT(imconf->execoneof_event == NULL);
    imconf->execoneof_event = im_file_add_spec_event(module, IM_FILE_EVT_ONEOFEXEC, TRUE);
}



static void im_file_input_blacklist(nx_module_t *module, nx_im_file_input_t *file)
{
    im_file_input_close(module, file);

    if ( file->blacklist_interval == 0 )
    {
	file->blacklist_interval = 1;
    }
    else
    {
	file->blacklist_interval *= 2;
    }
    file->blacklist_until = apr_time_now() + file->blacklist_interval * APR_USEC_PER_SEC;
}



static void im_file_fill_buffer(nx_module_t *module, nx_im_file_input_t *file, boolean *got_eof)
{
    apr_status_t rv;
    apr_size_t len;
    nx_module_input_t *input;

    ASSERT(file != NULL);
    
    input = file->input;
    ASSERT(input != NULL);
    ASSERT(file->input->buf != NULL);
    ASSERT(file->input->module != NULL);
    ASSERT(file->input->desc_type == APR_POLL_FILE);
    ASSERT(file->input->desc.f != NULL);

    //log_info("bufstart: %d, buflen: %d", input->bufstart, input->buflen);

    if ( input->bufstart == input->bufsize )
    {
	input->bufstart = 0;
	input->buflen = 0;
    }
    if ( input->buflen == 0 )
    {
	input->bufstart = 0;
    }

    ASSERT(input->bufstart + input->buflen <= input->bufsize);

    len = (apr_size_t) (input->bufsize - (input->buflen + input->bufstart));

    rv = apr_file_read(input->desc.f, input->buf + input->bufstart + input->buflen, &len);

    if ( rv != APR_SUCCESS )
    {
	if ( APR_STATUS_IS_EOF(rv) )
	{
	    log_debug("Module %s got EOF from %s", input->module->name, file->name);
	    *got_eof = TRUE;
	    file->blacklist_until = 0;
	    file->blacklist_interval = 0;
	}
	else if ( APR_STATUS_IS_EAGAIN(rv) )
	{
	    // Normally this shouldn't happen because file i/o is blocking,
	    // but for some weird reason we get this on windows in some rare cases.
	    // So just wait a little instead of panic()-ing.
	    apr_sleep(APR_USEC_PER_SEC / 10);
	}
	else if ( APR_STATUS_IS_EBADF(rv) )
	{
	    im_file_input_close(module, file);
	    throw(rv, "Module %s couldn't read from file (bug?)", input->module->name);
	}
	else
	{
	    log_aprerror(rv, "Module %s couldn't read from file %s", input->module->name, file->name);
	    im_file_input_blacklist(module, file);
	    *got_eof = TRUE; // needed to skip to next file in im_file_read
	}
    }
    else
    {
	file->blacklist_until = 0;
	file->blacklist_interval = 0;
    }

    if (len > 0)
    {
	file->last_succesful_readtime = apr_time_now();
    }

    input->buflen += (int) len;
    ASSERT(input->buflen <= input->bufsize);
}



static void im_file_eval_expr(nx_module_t *module, nx_expr_t *expr, char *result, uint32_t max_result_size)
{
    nx_expr_eval_ctx_t ctx;
    nx_value_t value;

    ASSERT(expr != NULL);
    ASSERT(expr->type != NX_EXPR_TYPE_VALUE);

    ctx.module = module;
    ctx.logdata = NULL;

    nx_expr_evaluate(&ctx, &value, expr);
    if ( value.defined == FALSE )
    {
	throw_msg("%s expresion at line %d in file '%s' evaluated to undef", module->name, expr->decl.line, expr->decl.file);
    }

    if ( value.type != NX_VALUE_TYPE_STRING )
    {
	throw_msg("%s expression at line %d in file '%s' evaluated to '%', string type required",
		  module->name, expr->decl.line, expr->decl.file, nx_value_type_to_string(value.type));
    }
    
    // update result
    apr_cpystrn(result, value.string->buf, max_result_size);
    nx_value_kill(&value);

    if ( strlen(result) == 0 )
    {
	throw_msg("%s expression at line %d in file '%s' evaluated to an empty string", module->name, expr->decl.line, expr->decl.file);
    }

    return;
}



static void im_file_input_get_filepos(nx_module_t *module,
				      nx_im_file_input_t *file,
				      boolean blacklist)
{
    apr_off_t filepos;
    apr_status_t rv;

    ASSERT(file != NULL);
    ASSERT(file->input != NULL);
    ASSERT(file->input->desc.f != NULL);

    filepos = 0;
    if ( (rv = apr_file_seek(file->input->desc.f, APR_CUR, &filepos)) != APR_SUCCESS )
    {
	if ( blacklist == TRUE )
	{
	    im_file_input_blacklist(module, file);
	}
	log_aprerror(rv, "failed to get file position for %s", file->name);
    }
    else
    {
	ASSERT(filepos >= file->input->buflen);
	filepos -= file->input->buflen;

	ASSERT(filepos >= file->input->incomplete_len);
	file->filepos = filepos - file->input->incomplete_len;
    }
}



/**
 * Return TRUE if a newly opened file was added
 */
static boolean im_file_input_open(nx_module_t *module,
				  nx_im_file_input_t **file,
				  boolean readfromlast,
				  boolean existed)
{
    nx_im_file_conf_t *imconf;
    apr_pool_t *pool;
    apr_finfo_t file_info;
    boolean volatile opened = FALSE;
    nx_exception_t e;

    ASSERT(file != NULL);
    ASSERT(*file != NULL);

    imconf = (nx_im_file_conf_t *) module->config;

    if ( ((*file)->blacklist_until != 0) && ((*file)->blacklist_until > apr_time_now()) )
    {
	log_debug("ignoring blacklisted file %s until blacklisting expires", (*file)->name);

	return ( FALSE );
    }

    if ( (*file)->oneof_processed == TRUE )
    {
	log_debug("ignoring <OnEOF> processed file %s", (*file)->name);
	return ( FALSE );
    }

    log_debug("im_file_input_open: %s", (*file)->name);

    try
    {
	apr_status_t rv = APR_SUCCESS;

	if ( (*file)->input == NULL )
	{
	    log_debug("opening %s", (*file)->name);
	    pool = nx_pool_create_core();
	    (*file)->input = nx_module_input_new(module, pool);
	    NX_DLIST_INSERT_TAIL(imconf->open_files, *file, link);
	    (imconf->num_open_files)++;
	
	    nx_module_input_data_set((*file)->input, NX_MODULE_INPUT_CONTEXT_FILENAME, apr_pstrdup(pool, (*file)->name));
	    CHECKERR_MSG(apr_file_open(&((*file)->input->desc.f), (*file)->name, APR_READ,
				       APR_OS_DEFAULT, pool), "failed to open %s", (*file)->name);
	    (*file)->input->desc_type = APR_POLL_FILE;
	    (*file)->input->inputfunc = imconf->inputfunc;

	    // NOT stream: positioning allowed
	    if ( (*file)->filepos > 0 )
	    {
		CHECKERR_MSG(apr_file_seek((*file)->input->desc.f, APR_SET, &((*file)->filepos)),
			     "failed to seek to file position %lu in file %s",
			     (*file)->filepos, (*file)->name);
	    }
	    else if ( readfromlast == TRUE )
	    {
		apr_off_t fileend = 0;

		CHECKERR_MSG(apr_file_seek((*file)->input->desc.f, APR_END, &fileend),
			     "failed to seek to end of input in file %s", (*file)->name);
		(*file)->filepos = fileend;
	    }

	    (*file)->blacklist_until = 0;
	    (*file)->blacklist_interval = 0;
	    opened = TRUE;
	}
	
	rv = apr_file_info_get(&file_info, APR_FINFO_INODE | APR_FINFO_MTIME | APR_FINFO_SIZE,
			       (*file)->input->desc.f);

	if ( rv == APR_SUCCESS )
	{
	}
	else if ( rv == APR_INCOMPLETE )
	{ // partial results returned in file_info, we check the valid bitmask
	}
	else
	{
	    throw(rv, "failed to query file information for %s", (*file)->name);
	}
	if ( file_info.valid & APR_FINFO_INODE )
	{
	    (*file)->inode = file_info.inode;
	}
	if ( file_info.valid & APR_FINFO_MTIME )
	{
	    (*file)->mtime = file_info.mtime;
	    (*file)->new_mtime = file_info.mtime;
	}
	if ( file_info.valid & APR_FINFO_SIZE )
	{
	    (*file)->size = file_info.size;
	    (*file)->new_size = file_info.size;
	}

	if ( ((*file)->filepos > 0) && ((*file)->filepos > (*file)->size) )
	{
	    // truncated, seek back to start
	    log_info("input file '%s' was truncated, restarting from the beginning", (*file)->name);

	    // NOT stream
	    (*file)->filepos = 0;
	    (*file)->input->incomplete_len = 0;
	    if ( ((*file)->input->inputfunc != NULL) && ((*file)->input->inputfunc->clean != NULL) )
	    {
		(*file)->input->inputfunc->clean((*file)->input, NULL);
	    }
	    CHECKERR_MSG(apr_file_seek((*file)->input->desc.f, APR_SET, &((*file)->filepos)),
			 "failed to seek to beginning of file %s", (*file)->name);
	}

	if ( opened == TRUE )
	{
	    if ( imconf->num_open_files > imconf->active_files )
	    {
		log_debug("maximum number (>%d) of files open, closing current", imconf->active_files);
		im_file_input_close(module, *file);
		opened = FALSE;
	    }
	    else
	    {
		log_debug("file %s opened", (*file)->name);
	    }
	}
	else
	{
	    log_debug("file %s already opened", (*file)->name);
	}
    }
    catch(e)
    {
	if ( APR_STATUS_IS_ENOENT(e.code) )
	{
	    const char *pattern;
	    file_or_excl_descr_t* file_descr = ((file_or_excl_descr_t*)imconf->file_directives->elts) + imconf->current_file_directive_idx;
	    char * idx = strrchr(file_descr->name, NX_DIR_SEPARATOR[0]);
	    if ( idx == NULL )
	    {
		pattern = file_descr->name;
	    }
	    else
	    {
		pattern = idx + 1;
	    }

	    if ( (existed == TRUE) || (file_descr->is_const == FALSE) || (apr_fnmatch_test(pattern) == 0) )
	    {
		if ( existed != TRUE )
		{
		    log_warn("input file does not exist: %s", (*file)->name);
		}
		else
		{
		    log_info("input file was deleted: %s", (*file)->name);
		}
		if ( (existed != TRUE) && (file_descr->is_const == TRUE) )
		{ // do not warn every PollInterval
		    // when the file appears, with blacklisting it will be read from the beginning when
		    // ReadFromLast is enabled, otherwise it would behave as if it already existed and
		    // the existing data would not be picked up.
		    im_file_input_blacklist(module, *file);
		}
		else
		{
		    nx_config_cache_remove(module->name, (*file)->name);
		    im_file_input_close(module, *file);
		    im_file_filehash_remove(module, file);
		}
	    }
	    else
	    {
		log_warn("input file does not exist: %s", (*file)->name);
		im_file_input_blacklist(module, *file);
	    }
	}
	else
	{
	    log_exception(e);
	    im_file_input_blacklist(module, *file);
	}

	opened = FALSE;
    }

    return ( opened );
}



/* close the first file in the open set which is returning EOF */
static boolean im_file_input_check_close(nx_module_t *module) 
{
    nx_im_file_conf_t *imconf;
    nx_im_file_input_t *file;

    imconf = (nx_im_file_conf_t *) module->config;

    if ( imconf->num_open_files < imconf->active_files )
    {
	return ( TRUE );
    }
    for ( file = NX_DLIST_FIRST(imconf->open_files);
	  file != NULL;
	  file = NX_DLIST_NEXT(file, link) )
    {
	if ( file->num_eof > 0 )
	{
	    im_file_input_get_filepos(module, file, TRUE);
	    im_file_input_close(module, file);
	    return ( TRUE );
	}
    }
    return ( FALSE );
}



// internal function of im_file_check_file()
static boolean size_checker(nx_module_t *module,
			    nx_im_file_input_t *file,
			    const char *fname,
			    apr_finfo_t *finfo)
{
    ASSERT(module != NULL);
    ASSERT(file != NULL);
    ASSERT(fname != NULL);
    ASSERT(finfo != NULL);
    nx_im_file_conf_t *imconf = (nx_im_file_conf_t *) module->config;
    ASSERT(imconf != NULL);

    if ( file->size < finfo->size )
    {
	log_debug("file size of '%s' increased since last check (%"
		APR_UINT64_T_FMT" -> %"APR_UINT64_T_FMT")",
		fname, file->size, finfo->size);
	file->new_size = finfo->size;
	return TRUE;
    }

    if ( finfo->size > file->filepos )
    {
	log_debug("file '%s' has unread data (size: %u > filepos: %u)", fname,
		(unsigned int) finfo->size, (unsigned int) file->filepos);
	file->new_size = finfo->size;
	return TRUE;
    }

    if ( file->filepos > 0 && finfo->size < file->filepos )
    {
	log_debug("input file '%s' was truncated", fname);
	file->new_size = finfo->size;
	file->size = 0;

	nx_config_cache_set_int(module->name, file->name, 0);

	return TRUE;
    }

    return FALSE;
}



/* Warning: 'file' can become invalid after the function returns!! */
static boolean im_file_check_file(nx_module_t *module, 
				  nx_im_file_input_t **file,
				  const char *fname,
				  apr_pool_t *pool)
{
    nx_exception_t e;
    boolean volatile retval = FALSE;
    nx_im_file_conf_t *imconf;

    ASSERT(file != NULL);
    ASSERT(*file != NULL);

    imconf = (nx_im_file_conf_t *) module->config;

    if ( ((*file)->blacklist_until != 0) && ((*file)->blacklist_until > apr_time_now()) )
    {
	log_debug("not checking file %s until blacklisting expires", (*file)->name);
	return ( FALSE );
    }

    if ( (*file)->new_size > (*file)->filepos )
    {
	log_debug("im_file_check_file: '%s' has unread data (%u > %u)", (*file)->name,
		  (unsigned int) (*file)->new_size, (unsigned int) (*file)->filepos);
	if ( im_file_input_check_close(module) == TRUE )
	{
	    im_file_input_open(module, file, FALSE, TRUE);
	    if ( file == NULL )
	    {
		return ( FALSE );
	    }
	}
	return ( TRUE );
    }

    try
    {
	apr_finfo_t finfo_by_name;
	apr_finfo_t finfo_by_handle;
	boolean needopen = FALSE;
	apr_status_t rv_name = APR_SUCCESS, rv_handle = APR_SUCCESS;

	memset(&finfo_by_handle, 0, sizeof(finfo_by_handle));

	log_debug("check file %s (inode: %"APR_UINT64_T_FMT")", fname, (*file)->inode);

	if ((*file)->input != NULL)
	{
	    rv_handle = apr_file_info_get(&finfo_by_handle, APR_FINFO_INODE | APR_FINFO_MTIME | APR_FINFO_SIZE, (*file)->input->desc.f);
	    if ( rv_handle != APR_SUCCESS && rv_handle != APR_INCOMPLETE)
	    {
		throw(rv_name, "apr_file_info_get() failed on file %s", (*file)->input->name);
	    }
	}


	if ( (*file)->inode == 0 )
	{ // no stat info stored yet (initial open failed)
	    needopen = TRUE;
	    log_debug("no stat info for %s", fname);
	}
	else
	{
	    if ( finfo_by_handle.valid & APR_FINFO_SIZE )
	    {
		if ( TRUE == size_checker(module, *file, fname, &finfo_by_handle) )
		{
		    retval = TRUE;
		    needopen = TRUE;
		}
	    }

	    if ( needopen == FALSE )
	    {
		rv_name = apr_stat(&finfo_by_name, fname, APR_FINFO_INODE | APR_FINFO_MTIME | APR_FINFO_SIZE, pool);
		if ( rv_name != APR_SUCCESS && rv_name != APR_INCOMPLETE)
		{
		    throw(rv_name, "apr_stat() failed on file %s", fname);
		}

		if ( (finfo_by_name.valid & APR_FINFO_INODE) && ((*file)->inode != finfo_by_name.inode) )
		{
		    log_info("inode changed for '%s' (%d->%d): reopening possibly rotated file",
			     fname, (int) (*file)->inode, (int) finfo_by_name.inode);

		    nx_config_cache_set_int(module->name, (*file)->name, 0);

		    im_file_input_close(module, *file);
		    (*file)->filepos = 0;
		    // reset the inode
		    (*file)->inode = 0;
		    retval = TRUE;
		    needopen = TRUE;
		}
	    }

	    if ( needopen == FALSE && (finfo_by_handle.valid & APR_FINFO_MTIME) && ((*file)->mtime != finfo_by_handle.mtime) )
	    {
		log_debug("mtime of file '%s' changed", fname);
		(*file)->new_mtime = finfo_by_handle.mtime;
		retval = TRUE;
		needopen = TRUE;
	    }

	    if (needopen == FALSE && finfo_by_handle.valid == 0 && finfo_by_name.valid != 0)
	    {
		if ( finfo_by_name.valid & APR_FINFO_SIZE )
		{
		    if ( TRUE == size_checker(module, *file, fname, &finfo_by_name) )
		    {
			retval = TRUE;
			needopen = TRUE;
		    }
		}

		if ( needopen == FALSE && (finfo_by_name.valid & APR_FINFO_MTIME) && ((*file)->mtime != finfo_by_name.mtime) )
		{
		    log_debug("mtime of file '%s' changed", fname);
		    (*file)->new_mtime = finfo_by_name.mtime;
		    retval = TRUE;
		    needopen = TRUE;
		}
	    }
	}

	if ( rv_name == APR_INCOMPLETE || rv_handle == APR_INCOMPLETE )
	{
	    retval = TRUE;
	    needopen = TRUE;
	}

	if ( needopen == TRUE )
	{
	    im_file_input_check_close(module);
	    im_file_input_open(module, file, FALSE, TRUE);
	}
    }
    catch(e)
    {
	file_or_excl_descr_t* file_descr = ((file_or_excl_descr_t*)imconf->file_directives->elts) + imconf->current_file_directive_idx;
	if ( APR_STATUS_IS_ENOENT(e.code) )
	{
	    const char *pattern;
	    char * idx = strrchr(file_descr->name, NX_DIR_SEPARATOR[0]);
	    if ( idx == NULL )
	    {
		pattern = file_descr->name;
	    }
	    else
	    {
		pattern = idx + 1;
	    }

	    if ( ((*file)->blacklist_until != 0) && (apr_fnmatch_test(pattern) == 0) )
	    {
		log_warn("input file does not exist: %s", fname);
		im_file_input_blacklist(module, *file);
	    }
	    else
	    {
		log_warn("input file was deleted: %s", fname);

		nx_config_cache_remove(module->name, (*file)->name);
		im_file_input_close(module, *file);
		im_file_filehash_remove(module, file);
	    }
	}
	else
	{
	    log_exception(e);
	    im_file_input_blacklist(module, *file);
	}
	retval = FALSE;
    }

    return ( retval );
}



/*
 * Check for modifications to files that are already known.
 */
static boolean im_file_check_files(nx_module_t *module, boolean non_active_only)
{
    nx_im_file_conf_t *imconf;
    apr_pool_t *pool;
    const char *fname;
    boolean retval = FALSE;
    apr_hash_index_t *idx;
    apr_ssize_t keylen;
    nx_im_file_input_t *file, *tmpfile;
    int num_new = 0;

    imconf = (nx_im_file_conf_t *) module->config;

    pool = nx_pool_create_core();

    //log_debug("im_file_check_files");

    if ( non_active_only == FALSE )
    {
	// First check the open file list
	for ( file = NX_DLIST_FIRST(imconf->open_files); file != NULL; )
	{
	    tmpfile = NX_DLIST_NEXT(file, link);
	    if ( im_file_check_file(module, &file, file->name, pool) == TRUE )
	    {
		retval = TRUE;
		num_new++;
		log_debug("check_files found an active file");
	    }
	    file = tmpfile;
	}
    }

    imconf->non_active_modified = FALSE;

    for ( idx = apr_hash_first(pool, imconf->files);
	  idx != NULL;
	  idx = apr_hash_next(idx) )
    {
	apr_hash_this(idx, (const void **) &fname, &keylen, (void **) &file);
	ASSERT(file != NULL);
	ASSERT(fname != NULL);

	if ( file->input == NULL )
	{ // open files have been already checked in the previous loop
	    if ( im_file_check_file(module, &file, fname, pool) == TRUE )
	    {
		retval = TRUE;
		imconf->non_active_modified = TRUE;
		log_debug("non-active modification on %s", fname);
		num_new++;
		if ( num_new >= imconf->active_files )
		{
		    break;
		}
	    }
	}
    }

    apr_pool_destroy(pool);

    if ( retval == FALSE )
    {
	imconf->non_active_modified = FALSE;
    }
/*
    else
    {
	log_debug("non-active modified: %d, total files: %u", imconf->non_active_modified,
		 apr_hash_count(imconf->files));
    }
*/
    return ( retval );
}



/* return a file pointer if the inode is already used by another file */
static nx_im_file_input_t *im_file_check_rename(nx_module_t *module,
						const char *filename)
{
    apr_pool_t *pool;
    nx_im_file_input_t * volatile retval = NULL;
    nx_im_file_input_t *file;
    nx_im_file_conf_t *imconf;
    apr_status_t rv;
    apr_finfo_t finfo;
    apr_hash_index_t *idx;

    imconf = (nx_im_file_conf_t *) module->config;
    pool = nx_pool_create_core();

    rv = apr_stat(&finfo, filename, APR_FINFO_INODE | APR_FINFO_SIZE, pool);
    if ( rv == APR_SUCCESS )
    { // finfo.valid will have all requested results
	for ( idx = apr_hash_first(pool, imconf->files);
	      idx != NULL;
	      idx = apr_hash_next(idx) )
	{
	    apr_hash_this(idx, NULL, NULL, (void **) &file);
	    ASSERT(file != NULL);
	    if ( (file->inode != 0) && (finfo.inode == file->inode) &&
		 (finfo.size == file->size) )
	    {
		retval = file;
		break;
	    }
	}
    }

    apr_pool_destroy(pool);

    return ( retval );
}



static boolean im_file_add_file(nx_module_t *module,
				const char *fname,
				boolean readfromlast,
				boolean single) //< single file only, not wildcarded
{
    nx_im_file_conf_t *imconf;
    nx_im_file_input_t *file;
    apr_off_t filepos = 0;
    int64_t savedpos = 0;
    boolean retval = FALSE;
    apr_pool_t *pool;
    boolean existed = FALSE;
    const char *fname2;
    apr_ssize_t keylen;
    apr_hash_index_t *idx;

    imconf = (nx_im_file_conf_t *) module->config;

    log_debug("im_file_add_file: %s", fname);

    // check if it is already added to the list
    file = (nx_im_file_input_t *) apr_hash_get(imconf->files, fname, APR_HASH_KEY_STRING);

    if ( file == NULL )
    { // not found, add it
	log_debug("adding file: %s", fname);

	if ( imconf->savepos == TRUE )
	{
	    if ( nx_config_cache_get_int(module->name, fname, &savedpos) == TRUE )
	    {
		filepos = (apr_off_t) savedpos;
		if ( filepos > 0 )
		{
		    existed = TRUE;
		}
	    }
	    log_debug("module %s read saved position %ld for %s", module->name,
		      (long int) filepos, fname);
	}

	pool = nx_pool_create_core();
	file = apr_pcalloc(pool, sizeof(nx_im_file_input_t));
	file->pool = pool;
	file->filepos = filepos;
	file->name = apr_pstrdup(pool, fname);

	if ( imconf->renamecheck == TRUE )
	{
	    nx_im_file_input_t *dupe;

	    dupe = im_file_check_rename(module, fname);
	    if ( dupe != NULL )
	    {
		log_info("input file '%s' was possibly renamed/rotated from '%s'," 
			 " will only read new data from this file.", fname, dupe->name);
		file->filepos = dupe->filepos; // do not read the contents again
		im_file_input_close(module, dupe);
		im_file_filehash_remove(module, &dupe);
	    }
	}

	im_file_input_check_close(module);
	retval = im_file_input_open(module, &file, readfromlast, existed);
	if ( file != NULL )
	{
	    apr_hash_set(imconf->files, file->name, APR_HASH_KEY_STRING, (void *) file);
	}
    }
    else
    {
	//log_debug("file %s already added", file->name);
    }

    if ( single == TRUE )
    { // remove everything else
	pool = nx_pool_create_core();
	for ( idx = apr_hash_first(pool, imconf->files);
	      idx != NULL;
	      idx = apr_hash_next(idx) )
	{
	    apr_hash_this(idx, (const void **) &fname2, &keylen, (void **) &file);

	    if ( strcmp(fname, fname2) != 0 )
	    {
		log_debug("not watching file %s anymore", file->name);
		im_file_input_close(module, file);
		im_file_filehash_remove(module, &file);
	    }
	}
	apr_pool_destroy(pool);
    }

    return ( retval );
}



/**
 * Checking if dir+file matches one of exclude elements (in array of excludes)
 *
 * @param module
 * @param dirname filepath to test (NOT glob)
 * @param fname file name to test (NOT glob)
 * @return TRUE when match found among excludes
 */
static boolean im_file_exclude_match(nx_module_t *module, const char* dirname, const char* fname)
{
    ASSERT(module);
    nx_im_file_conf_t *conf = (nx_im_file_conf_t *) module->config;
    ASSERT(conf);
    ASSERT(conf->excludes);

    boolean ret = FALSE;
    int flags = 0;
    if (conf->noescape)
    {
	flags |= APR_FNM_NOESCAPE;
    }

    size_t dirname_len = strlen(dirname);

    int i;
    for ( i = 0; i < conf->excludes->nelts; ++i )
    {
	exclude_element_t* elt = &(((exclude_element_t *)(conf->excludes->elts))[i]);
	boolean path_match;
	size_t exclude_dir_len = strlen(elt->path);

	if ( exclude_dir_len == 2 && elt->path[0] == '.' && elt->path[1] == NX_DIR_SEPARATOR[0] )
	{
	    path_match = TRUE;
	}
	else
	{
#ifdef WIN32
	    path_match = (0 == strncasecmp(elt->path, dirname, exclude_dir_len));
	    flags |= APR_FNM_CASE_BLIND;
#else
	    path_match = (0 == strncmp(elt->path, dirname, exclude_dir_len));
#endif
	}

	if (path_match)
	{
	    if (!conf->recursive && exclude_dir_len != dirname_len)
	    {
		// non recursive case: two path must be equal to match
		continue;
	    }
	    boolean fname_match = (apr_fnmatch(elt->fname_mask, fname, flags) == APR_SUCCESS);
	    if (fname_match)
	    {
		ret = TRUE;
		break;
	    }
	}
    }

    return ret;
}



static boolean im_file_add_file_helper(nx_module_t* module,
					       const char* dirname,
					       const char* fname,
					       boolean readfromlast,
					       apr_finfo_t* finfo,
					       int flags)
{
    char file_fullname[APR_PATH_MAX];

    if ( apr_fnmatch(fname, finfo->name, flags) == APR_SUCCESS )
    {
	// exclude checking
	if ( im_file_exclude_match(module, dirname, finfo->name) == FALSE )
	{
	    log_debug("'%s' matches '%s' in directory '%s'", finfo->name, fname, dirname);
	    if ( dirname[0] == '\0' )
	    {
		apr_snprintf(file_fullname, sizeof (file_fullname), "%s", finfo->name);
	    }
	    else if ( dirname[strlen(dirname) - 1] == NX_DIR_SEPARATOR[0] )
	    {
		apr_snprintf(file_fullname, sizeof (file_fullname), "%s%s", dirname, finfo->name);
	    }
	    else
	    {
		apr_snprintf(file_fullname, sizeof (file_fullname), "%s"NX_DIR_SEPARATOR"%s", dirname, finfo->name);
	    }

	    if ( im_file_add_file(module, file_fullname, readfromlast, FALSE) == TRUE )
	    {
		return TRUE;
	    }
	}
	else
	{
	    log_debug("'%s' matches exclude(s) in directory '%s'", finfo->name, dirname);
	}
    }
    else
    {
	log_debug("'%s' does not match '%s' in directory '%s'", finfo->name, fname, dirname);
    }
    return FALSE;
}



/**
 * Add a single file (to process)
 *  (ONLY in case fname is NOT a glob && imconf->recursive == FALSE)
 *
 * @param module
 * @param pool
 * @param dirname Can NOT be a glob
 * @param fname Can NOT be a glob
 * @param readfromlast  in this function this is not a "controlling" type of parameter, just passed over to other functions
 * @return TRUE when new file was added
 */
static boolean im_file_add_single_file(nx_module_t *module,
				       apr_pool_t *pool,
				       const char *dirname,
				       const char *fname,
				       boolean readfromlast)
{
    nx_exception_t e;
    boolean volatile retval = FALSE;
    apr_status_t volatile rv;
    nx_im_file_conf_t* volatile imconf;
    apr_finfo_t finfo;
    imconf = (nx_im_file_conf_t *) module->config;

    boolean is_glob = (apr_fnmatch_test(fname) != 0);
    ASSERT(is_glob == FALSE && imconf->recursive == FALSE);

    apr_pool_t *local_pool = nx_pool_create_child(pool);
    ASSERT(local_pool != NULL);

    int flags = (imconf->noescape ? APR_FNM_NOESCAPE : 0);
#ifdef WIN32
    flags |= APR_FNM_CASE_BLIND;
#endif

    try
    {
	char *full_name = apr_pstrcat(local_pool, dirname, fname, NULL);
	rv = apr_stat(&finfo, full_name, APR_FINFO_NAME | APR_FINFO_TYPE, local_pool);
	if ( !((rv == APR_SUCCESS) || (rv == APR_INCOMPLETE)) )
	{
	    log_debug("no single file found (%s)", full_name);
	    retval = FALSE;
	}
	else
	{
	    // emulating apr_dir_read()
	    finfo.name = fname;
	    retval = im_file_add_file_helper(module, dirname, fname, readfromlast, &finfo, flags);
	}
    }
    catch(e)
    {
	if (local_pool != NULL)
	{
	    apr_pool_destroy(local_pool);
	    local_pool = NULL;
	}
	rethrow(e);
    }

    if (local_pool != NULL)
    {
	apr_pool_destroy(local_pool);
    }

    return ( retval );
}



/**
 * Read directory contents and add files according to input parameters and config settings
 *  (not allowed in case fname is NOT a glob && imconf->recursive == FALSE)
 *
 * @param module
 * @param pool
 * @param dirname Can NOT be a glob!!! (eg: /home/user/ , /usr/bin , ... etc)
 * @param fname Can be a glob (like *, a*,  a*b, a??b, etc...)
 * @param readfromlast  in this function this is not a "controlling" type of parameter, just passed over to other functions
 * @return TRUE when new files were added
 */
static boolean im_file_add_glob(nx_module_t *module,
				apr_pool_t *pool,
				const char *dirname,
				const char *fname,
				boolean readfromlast)
{
    nx_exception_t e;
    apr_dir_t* volatile dir = NULL;
    boolean volatile retval = FALSE;
    apr_status_t rv;
    nx_im_file_conf_t *imconf;
    imconf = (nx_im_file_conf_t *) module->config;
    int err_count = 0;

    ASSERT(!((apr_fnmatch_test(fname) != 0) == FALSE && imconf->recursive == FALSE));

    apr_pool_t* volatile local_pool = nx_pool_create_child(pool);
    ASSERT(local_pool != NULL);

    int flags = (imconf->noescape ? APR_FNM_NOESCAPE : 0);
#ifdef WIN32
    flags |= APR_FNM_CASE_BLIND;
#endif

    // directory open
    log_debug("reading directory entries under '%s' to check for matching files", dirname);
    rv = apr_dir_open(&dir, dirname, local_pool);
    if ( rv != APR_SUCCESS )
    {
	if ( imconf->warned_no_directory == FALSE )
	{
	    log_aprerror(rv, "failed to open directory: %s", dirname);
	}
	imconf->warned_no_directory = TRUE;
	retval = FALSE;
	apr_pool_destroy(local_pool);
	return retval;
    }
    imconf->warned_no_directory = FALSE;

    apr_array_header_t* dir_entries = apr_array_make(local_pool, 0, sizeof(apr_finfo_t *));
    ASSERT(dir_entries != NULL);

    for ( ; ; )
    {
	apr_finfo_t *finfo = apr_pcalloc(local_pool, sizeof(apr_finfo_t));
	ASSERT(finfo != NULL);
	// scanning directory entries
	rv = apr_dir_read(finfo,
			 APR_FINFO_NAME | APR_FINFO_TYPE | APR_FINFO_CTIME | APR_FINFO_MTIME,
			 dir);
	if ( APR_STATUS_IS_ENOENT(rv) )
	{
	    break;
	}
	if ( APR_STATUS_IS_INCOMPLETE(rv) )
	{
	    if ( (finfo->valid & (APR_FINFO_NAME | APR_FINFO_TYPE)) != (APR_FINFO_NAME | APR_FINFO_TYPE) )
	    {
		if ( imconf->nametype_err_reported == FALSE )
		{
		    log_warn("readdir: missing file name or type (in '%s')", dirname);
		    imconf->nametype_err_reported = TRUE;
		}
		continue;
	    }

	    apr_time_t curr_time = apr_time_now();

	    if ( (finfo->valid & APR_FINFO_CTIME) == 0 )
	    {
		if ( imconf->ctime_err_reported == FALSE )
		{
		    log_warn("readdir: missing CTIME ('%s"NX_DIR_SEPARATOR"%s')", dirname, finfo->name);
		    imconf->ctime_err_reported = TRUE;
		}
		finfo->ctime = curr_time;
	    }
	    if ( (finfo->valid & APR_FINFO_MTIME) == 0 )
	    {
		if ( imconf->mtime_err_reported == FALSE )
		{
		    log_warn("readdir: missing MTIME ('%s"NX_DIR_SEPARATOR"%s')", dirname, finfo->name);
		    imconf->mtime_err_reported = TRUE;
		}
		finfo->mtime = curr_time;
	    }
	}
	else if ( rv != APR_SUCCESS )
	{
	    err_count++;
	    log_aprerror(rv, "readdir failed for %s", dirname);

	    if ( err_count > 3 )
	    {
		log_error("stopped enumerating directory '%s' due to multiple read errors", dirname);
		break;
	    }
	    continue;
	}

	err_count = 0;

	ASSERT(finfo->name != NULL);

	apr_finfo_t **finfo_element = apr_array_push(dir_entries);
	ASSERT(finfo_element != NULL);
	*finfo_element = finfo;

#ifdef WIN32
	// on windows it does not work without this
	(*finfo_element)->name = apr_pstrdup(local_pool, (*finfo_element)->name);
#endif
    }

    if ( imconf->dir_read_comp_fn != NULL )
    {
	qsort(dir_entries->elts, (size_t) dir_entries->nelts,
	      (size_t ) dir_entries->elt_size, imconf->dir_read_comp_fn);
    }

    try
    {
	// directory scan
	int k;
	apr_finfo_t *pfinfo;
	for ( k = 0; k < dir_entries->nelts; k++ )
	{
	    pfinfo = ((apr_finfo_t **) (dir_entries->elts))[k];

	    // processing directory entries
	    if ( ((pfinfo->valid & APR_FINFO_TYPE) != 0) && ((pfinfo->filetype == APR_REG) || (pfinfo->filetype == APR_LNK)) )
	    {
		// entry is a regular file
		if ( TRUE == im_file_add_file_helper(module, dirname, fname, readfromlast, pfinfo, flags) )
		{
		    retval = TRUE;
		}
	    }
	    else if ( ((pfinfo->valid & APR_FINFO_TYPE) != 0) && (pfinfo->filetype == APR_DIR) )
	    {
		// entry is a directory
		if ( (strcmp(pfinfo->name, ".") != 0) && (strcmp(pfinfo->name, "..") != 0) )
		{
		    // not . or ..
		    if ( imconf->recursive == TRUE )
		    {
			char directory_to_scan[APR_PATH_MAX];
			if (dirname[0] == '\0')
			{
			    apr_snprintf(directory_to_scan, sizeof(directory_to_scan), "%s"NX_DIR_SEPARATOR, pfinfo->name);
			}
			else if (dirname[strlen(dirname)-1] == NX_DIR_SEPARATOR[0])
			{
			    apr_snprintf(directory_to_scan, sizeof(directory_to_scan), "%s%s"NX_DIR_SEPARATOR, dirname, pfinfo->name);
			}
			else
			{
			    apr_snprintf(directory_to_scan, sizeof(directory_to_scan), "%s"NX_DIR_SEPARATOR"%s"NX_DIR_SEPARATOR, dirname, pfinfo->name);
			}

			// checking directory against excludes
			if ( im_file_exclude_match(module, dirname, pfinfo->name) == FALSE )
			{
			    log_debug("recursively checking directory contents under '%s'", directory_to_scan);
			    if ( im_file_add_glob(module, local_pool, directory_to_scan, fname, readfromlast) == TRUE )
			    {
				retval = TRUE;
			    }
			    else
			    {
				log_debug("ignoring directory entry '%s'", pfinfo->name);
			    }
			}
			else
			{
			    log_debug("directory '%s' is ignored by matching excludes", directory_to_scan);
			}
		    }
		    else
		    {
			log_debug("recursion not enabled, ignoring subdirectory %s", pfinfo->name);
		    }
		}
	    }
	    else
	    {
		log_debug("skipping unsupported/unknown type of file '%s' in directory '%s'", pfinfo->name, dirname);
	    }

	}
    }
    catch(e)
    {
	if (dir != NULL)
	{
	    apr_dir_close(dir);
	    dir = NULL;
	}
	if (local_pool != NULL)
	{
	    apr_pool_destroy(local_pool);
	    local_pool = NULL;
	}
	rethrow(e);
    }

    if (dir != NULL)
    {
	apr_dir_close(dir);
	dir = NULL;
    }
    if (local_pool != NULL)
    {
	apr_pool_destroy(local_pool);
	local_pool = NULL;
    }

    return ( retval );
}



/** Check for files matching the wildcarded name
 *  Return true if a new file was found
 */
static boolean im_file_check_new(nx_module_t *module, boolean readfromlast)
{
    nx_im_file_conf_t* volatile imconf;
    apr_pool_t* volatile pool = NULL;
    nx_exception_t e;
    boolean volatile retval = FALSE;

    imconf = (nx_im_file_conf_t *) module->config;

    pool = nx_pool_create_child(module->pool);
    ASSERT(pool);

    ASSERT(imconf->file_directives->nelts > 0);
    try {

	while ( imconf->current_file_directive_idx < imconf->file_directives->nelts )
	{
	    char *idx = NULL;
	    char *fname = NULL;
	    char *dirname = NULL;

	    // for expanded exclude directives
	    apr_pool_t* exlcludes_pool = nx_pool_create_child(pool);
	    ASSERT(exlcludes_pool);

	    // new exclude array
	    imconf->excludes = apr_array_make(exlcludes_pool, 0, sizeof(exclude_element_t));

	    ////////////////////
	    // process excludes
	    int i;
	    for ( i = 0; i < imconf->exclude_directives->nelts; ++i )
	    {
		file_or_excl_descr_t* exl_descr = ((file_or_excl_descr_t*) imconf->exclude_directives->elts) + i;
		if ( exl_descr->expr && exl_descr->is_const == FALSE )
		{
		    im_file_eval_expr(module, exl_descr->expr, exl_descr->name, sizeof (exl_descr->name));
		}

		// expanding an exclude file directive
		{
		    idx = NULL;
		    fname = NULL;
		    dirname = NULL;

		    idx = strrchr(exl_descr->name, NX_DIR_SEPARATOR[0]);
		    if ( idx == NULL )
		    {
			fname = exl_descr->name;
		    }
		    else
		    {
			dirname = apr_pstrndup(pool, exl_descr->name, (apr_size_t) (idx - exl_descr->name + 1));
			fname = idx + 1;
		    }

		    if ( fname == exl_descr->name )
		    {
			// relative path with filename only
			exclude_element_t *excl_elt = apr_array_push(imconf->excludes);
			ASSERT(excl_elt);
			excl_elt->path = apr_pstrdup(imconf->excludes->pool, "."NX_DIR_SEPARATOR);
			excl_elt->fname_mask = apr_pstrdup(imconf->excludes->pool, fname);
		    }
		    else
		    {
			ASSERT(dirname);

			// directory glob support
			apr_pool_t *globs_pool = NULL;
			apr_pool_create(&globs_pool, pool);
			ASSERT(globs_pool);

			apr_array_header_t* path_parts_array = NULL;
			apr_array_header_t* result_paths = apr_array_make(globs_pool, 0, sizeof (char*));
			ASSERT(result_paths);

			path_parts_array = nx_filepath_decompose(dirname, TRUE, NX_DIR_SEPARATOR[0], globs_pool);
			if ( path_parts_array->nelts > 0 )
			{
			    apr_array_clear(result_paths);
			    nx_filepath_find_all_paths(path_parts_array, !(imconf->noescape), globs_pool, 0, "",
						       &result_paths);
			}

			char **path;
			do
			{
			    path = apr_array_pop(result_paths);
			    if ( path && *path )
			    {
				exclude_element_t *excl_elt = apr_array_push(imconf->excludes);
				ASSERT(excl_elt);
				excl_elt->path = apr_pstrdup(imconf->excludes->pool, *path);
				excl_elt->fname_mask = apr_pstrdup(imconf->excludes->pool, fname);
			    }
			}
			while ( result_paths->nelts );
		    }
		}
	    }

	    ///////////////////////////
	    // process file directive
	    file_or_excl_descr_t* file_descr = ((file_or_excl_descr_t*) imconf->file_directives->elts) + imconf->current_file_directive_idx;
	    if ( file_descr->expr && file_descr->is_const == FALSE )
	    {
		im_file_eval_expr(module, file_descr->expr, file_descr->name, sizeof (file_descr->name));
	    }

	    idx = NULL;
	    fname = NULL;
	    dirname = NULL;

	    idx = strrchr(file_descr->name, NX_DIR_SEPARATOR[0]);
	    if ( idx == NULL )
	    {
		fname = file_descr->name;
	    }
	    else
	    {
		dirname = apr_pstrndup(pool, file_descr->name, (apr_size_t) (idx - file_descr->name + 1));
		fname = idx + 1;
	    }


	    if ( fname == file_descr->name )
	    {
		// relative path with filename only
		log_debug("A relative path was specified in File, checking directory entries under spooldir");
		boolean file_added = FALSE;
		if ((apr_fnmatch_test(fname) != 0) == FALSE && imconf->recursive == FALSE)
		{
		    file_added = im_file_add_single_file(module, pool, "."NX_DIR_SEPARATOR, fname, readfromlast);
		}
		else
		{
		    file_added = im_file_add_glob(module, pool, "."NX_DIR_SEPARATOR, fname, readfromlast);
		}
		if (file_added == TRUE)
		{
		    retval = TRUE;
		}
	    }
	    else
	    {
		ASSERT(dirname);

		// directory glob support
		apr_pool_t *globs_pool = NULL;
		apr_pool_create(&globs_pool, pool);
		ASSERT(globs_pool);

		apr_array_header_t* path_parts_array = NULL;
		apr_array_header_t* result_paths = apr_array_make(globs_pool, 0, sizeof (char*));
		ASSERT(result_paths);

		path_parts_array = nx_filepath_decompose(dirname, TRUE, NX_DIR_SEPARATOR[0], globs_pool);
		if ( path_parts_array->nelts > 0 )
		{
		    apr_array_clear(result_paths);
		    nx_filepath_find_all_paths(path_parts_array, !(imconf->noescape), globs_pool, 0, "", &result_paths);
		}

		char **path;
		do
		{
		    path = apr_array_pop(result_paths);
		    if ( path && *path )
		    {
			dirname = apr_pstrdup(globs_pool, *path);
		    }
		    if ( dirname )
		    {
			boolean file_added = FALSE;
			if ((apr_fnmatch_test(fname) != 0) == FALSE && imconf->recursive == FALSE)
			{
			    file_added = im_file_add_single_file(module, pool, dirname, fname, readfromlast);
			}
			else
			{
			    file_added = im_file_add_glob(module, pool, dirname, fname, readfromlast);
			}
			if (file_added == TRUE)
			{
			    retval = TRUE;
			}
		    }
		    dirname = NULL;
		}
		while ( result_paths->nelts );
	    }

	    apr_pool_destroy(exlcludes_pool);
	    exlcludes_pool = NULL;
	    ++(imconf->current_file_directive_idx);
	}
	// while
    }
    // try

    catch(e)
    {
	if ( pool != NULL )
	{
	    apr_pool_destroy(pool);
	}
	rethrow(e);
    }


    if ( imconf->current_file_directive_idx >= imconf->file_directives->nelts )
    {
	// reset cycle variable
	imconf->current_file_directive_idx = 0;
    }

    if ( pool != NULL )
    {
	apr_pool_destroy(pool);
    }
    imconf->excludes = NULL;

    return ( retval);
}



static void im_file_add_poll_event(nx_module_t *module, boolean delayed)
{
    nx_event_t *event;
    nx_im_file_conf_t *imconf;

    imconf = (nx_im_file_conf_t *) module->config;
    ASSERT(imconf->poll_event == NULL);

    //log_debug("add_poll_event: %d", delayed);

    event = nx_event_new();
    event->module = module;
    if ( delayed == TRUE )
    {
	event->delayed = TRUE;
	event->time = apr_time_now() + (apr_time_t) (APR_USEC_PER_SEC * imconf->poll_interval);
    }
    else
    {
	event->delayed = FALSE;
    }
    event->type = NX_EVENT_READ;
    event->priority = module->priority;
    imconf->poll_event = nx_event_add(event);
}



static nx_event_t* im_file_add_spec_event(nx_module_t *module, im_file_evt_subtype_t subtype, boolean delayed)
{
    nx_event_t *event;
    nx_im_file_conf_t *imconf;

    imconf = (nx_im_file_conf_t *) module->config;

    apr_time_t evt_time;
    switch (subtype)
    {
	case IM_FILE_EVT_DIRCHECK:
	    evt_time = (apr_time_t) (APR_USEC_PER_SEC * imconf->dircheck_interval);
	    break;
	case IM_FILE_EVT_ONEOFEXEC:
	    evt_time = imconf->oneof_grace_timeout;
	    break;
	default:
	    throw_msg("Unknown im_file specific event subtype: %d", subtype);
    }

    event = nx_event_new();
    event->module = module;
    event->subtype = (int)subtype;
    if ( delayed == TRUE )
    {
	event->delayed = TRUE;
	event->time = apr_time_now() + evt_time;
    }
    else
    {
	event->delayed = FALSE;
    }
    event->type = NX_EVENT_MODULE_SPECIFIC;
    event->priority = module->priority;
    return nx_event_add(event);
}



static void im_file_dircheck_event_cb(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;
    boolean got_data = FALSE;

    imconf = (nx_im_file_conf_t *) module->config;

    imconf->dircheck_event = NULL;

    //log_info("dircheck_event_cb");

    if ( apr_hash_count(imconf->files) > (unsigned int) imconf->num_open_files )
    { // assume we have non-active modifications
	imconf->non_active_modified = TRUE; 
    }
    if ( im_file_check_new(module, FALSE) == TRUE )
    {
	//log_info("dircheck_event_cb detected new files in check_new()");
	got_data = TRUE;
    }
    if ( im_file_check_files(module, FALSE) == TRUE )
    {
	//log_info("dircheck_event_cb detected new files in check_files()");
	got_data = TRUE;
    }

    if ( got_data == TRUE )
    { // force undelayed event
	if ( imconf->poll_event != NULL )
	{
	    nx_event_remove(imconf->poll_event);
	    nx_event_free(imconf->poll_event);
	    imconf->poll_event = NULL;
	}
	im_file_add_poll_event(module, FALSE);
    }

    ASSERT(imconf->dircheck_event == NULL);
    imconf->dircheck_event = im_file_add_spec_event(module, IM_FILE_EVT_DIRCHECK, TRUE);
}



static void im_file_read(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;
    nx_logdata_t *logdata;
    boolean got_eof;
    boolean got_data;
    int evcnt = 0;
    nx_im_file_input_t *file;

    ASSERT(module != NULL);
    imconf = (nx_im_file_conf_t *) module->config;
    imconf->poll_event = NULL;

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
	log_debug("module %s not running, not reading any more data", module->name);
	return;
    }

    if ( imconf->currsrc == NULL )
    {
	ASSERT(imconf->open_files != NULL);
	imconf->currsrc = NX_DLIST_FIRST(imconf->open_files);
	if ( (imconf->currsrc == NULL) && (apr_hash_count(imconf->files) == 0) )
	{
	    if ( imconf->warned_no_input_files == FALSE )
	    {
		log_warn("Module %s has no input files to read", module->name);
	    }
	    imconf->warned_no_input_files = TRUE;
	}
	else
	{
	    imconf->warned_no_input_files = FALSE;
	}
    }

    for ( evcnt = 0; evcnt < IM_FILE_MAX_READ; )
    {
	if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
	{
	    break;
	}

	if ( imconf->currsrc == NULL )
	{
	    break;
	}
	got_data = FALSE;
	got_eof = FALSE;
	boolean rec_success;

	if ( (imconf->currsrc->input != NULL) &&
	     (logdata = imconf->currsrc->input->inputfunc->func(
		 imconf->currsrc->input, imconf->currsrc->input->inputfunc->data)) != NULL )
	{
	    //log_info("read: [%s]", logdata->raw_event->buf);
	    rec_success = nx_module_add_logdata_input(module, imconf->currsrc->input, logdata);
	    got_data = TRUE;
	    if ( rec_success == TRUE )
	    {
		evcnt++;
	    }
	}
	else
	{ // buffer was empty (or couldn't read a full record)
	    im_file_input_get_filepos(module,  imconf->currsrc, TRUE);
	    if ( imconf->currsrc == NULL )
	    {
		break;
	    }

	    nx_config_cache_set_int(module->name, imconf->currsrc->name,
				    (int64_t) imconf->currsrc->filepos);

	    im_file_fill_buffer(module, imconf->currsrc, &got_eof);
	    //log_info("set config cache filepos: %ld", imconf->currsrc->filepos);
	    if ( imconf->currsrc == NULL )
	    {
		break;
	    }
	    if ( (imconf->currsrc->input != NULL) &&
		 (logdata = imconf->currsrc->input->inputfunc->func(
		     imconf->currsrc->input, imconf->currsrc->input->inputfunc->data)) != NULL )
	    {
		rec_success = nx_module_add_logdata_input(module, imconf->currsrc->input, logdata);
		got_data = TRUE;
		if ( rec_success == TRUE )
		{
		    evcnt++;
		}
	    }
	}
	if ( got_eof == TRUE )
	{
	    log_debug("got EOF for %s", imconf->currsrc->name);

	    if ( got_data == FALSE )
	    {
		file = imconf->currsrc;
		if ( file->new_size > 0 )
		{
		    file->size = file->new_size;
		    file->filepos = file->new_size;
		}
		if ( file->new_mtime > 0 )
		{
		    file->mtime = file->new_mtime;
		}

		(file->num_eof)++;
		if ( file->num_eof == 1 )
		{
		    file->first_eof_time = apr_time_now();
		}

		if (file->num_eof >= 2)
		{   // if the file returns another EOF, i.e. did not recieve any data since PollInterval*2, 
		    // then we flush xm_multiline and extension's buffers.
		    // This also avoids the last event sitting in xm_multiline's buffers forever 
		    if ( (file->input != NULL) && (file->input->inputfunc->flush != NULL) )
		    {
			if ( (logdata = file->input->inputfunc->flush(file->input,
								      file->input->inputfunc->data)) != NULL )
			{
			    rec_success = nx_module_add_logdata_input(module, file->input, logdata);
			    if ( rec_success == TRUE )
			    {
				evcnt++;
			    }
			}
		    }
		}
		imconf->currsrc = NX_DLIST_NEXT(file, link);

		if ( imconf->closewhenidle == TRUE )
		{
		    log_debug("closing idle file %s (CloseWhenIdle is enabled)", file->name);
		    im_file_input_close(module, file);
		}
		continue;
	    }
	}
	else // got_eof == FALSE
	{
	    imconf->currsrc->num_eof = 0;
	    imconf->currsrc->first_eof_time = 0;
	}
    }

    if ( nx_module_get_status(module) == NX_MODULE_STATUS_RUNNING )
    {
	boolean delayed = FALSE;

	//log_debug("evcnt: %d", evcnt);

	if ( evcnt < IM_FILE_MAX_READ )
	{
	    if ( (evcnt == 0) && (imconf->currsrc == NULL) )
	    {
		delayed = TRUE;
	    }
	    if ( imconf->non_active_modified == TRUE )
	    {
		//log_debug("may have non-active modifications, checking files");
		delayed = im_file_check_files(module, TRUE) == FALSE;
	    }
	}
	im_file_add_poll_event(module, delayed);
    }
}



static int _cmp_create_time_asc(const void *a, const void *b)
{
    const apr_finfo_t * const *e1 = a;
    const apr_finfo_t * const *e2 = b;

    if ( (*e1)->ctime < (*e2)->ctime )
    {
	return -1;
    }
    else if ( (*e1)->ctime > (*e2)->ctime )
    {
	return 1;
    }

    return 0;
}



static int _cmp_mod_time_asc(const void *a, const void *b)
{
    const apr_finfo_t * const *e1 = a;
    const apr_finfo_t * const *e2 = b;

    if ( (*e1)->mtime < (*e2)->mtime )
    {
	return -1;
    }
    else if ( (*e1)->mtime > (*e2)->mtime )
    {
	return 1;
    }

    return 0;
}



static int _cmp_file_name_asc(const void *a, const void *b)
{
    const apr_finfo_t * const *e1 = a;
    const apr_finfo_t * const *e2 = b;

    return strcmp((*e1)->name, (*e2)->name);
}



static int _cmp_create_time_desc(const void *a, const void *b)
{
    return _cmp_create_time_asc(b, a);
}



static int _cmp_mod_time_desc(const void *a, const void *b)
{
    return _cmp_mod_time_asc(b, a);
}



static int _cmp_file_name_desc(const void *a, const void *b)
{
    return _cmp_file_name_asc(b, a);
}



static im_file_comp_fn_t im_file_cfg_readorder_fn_lookup(const nx_directive_t* conf)
{
    ASSERT(conf != NULL);

    im_file_comp_fn_t ret = NULL;

    const char* val = conf->args;
    if ( (val == NULL) || (*val == '\x0') )
    {
	nx_conf_error(conf, "Missing value");
    }

    if ( strcasecmp(val, "none") == 0 )
    {
    }
    else if ( strcasecmp(val, "CtimeOldestFirst") == 0 )
    {
	ret = _cmp_create_time_asc;
    }
    else if ( strcasecmp(val, "CtimeNewestFirst") == 0 )
    {
	ret = _cmp_create_time_desc;
    }
    else if ( strcasecmp(val, "MtimeOldestFirst") == 0 )
    {
	ret = _cmp_mod_time_asc;
    }
    else if ( strcasecmp(val, "MtimeNewestFirst") == 0 )
    {
	ret = _cmp_mod_time_desc;
    }
    else if ( strcasecmp(val, "NameAsc") == 0 )
    {
	ret = _cmp_file_name_asc;
    }
    else if ( strcasecmp(val, "NameDesc") == 0 )
    {
	ret = _cmp_file_name_desc;
    }
    else
    {
	nx_conf_error(conf, "Invalid value: %s", val);
    }

    return ret;
}



static void im_file_config(nx_module_t *module)
{
    const nx_directive_t * volatile curr;
    const nx_directive_t * volatile curr2;
    nx_im_file_conf_t * volatile imconf;
    boolean  has_dirreadorder = FALSE;
    nx_exception_t e;

    ASSERT(module->directives != NULL);
    curr = module->directives;

    imconf = apr_pcalloc(module->pool, sizeof(nx_im_file_conf_t));
    module->config = imconf;

    imconf->file_directives = apr_array_make (module->pool, 0, sizeof(file_or_excl_descr_t));
    ASSERT(imconf->file_directives);
    imconf->exclude_directives = apr_array_make (module->pool, 0, sizeof(file_or_excl_descr_t));
    ASSERT(imconf->exclude_directives);
    imconf->dir_read_comp_fn = NULL;

    boolean is_file;

    while ( curr != NULL )
    {
	if ( nx_module_common_keyword(curr->directive) == TRUE )
	{
	}
	else if ( (is_file = (strcasecmp(curr->directive, "file") == 0)) ||  strcasecmp(curr->directive, "exclude") == 0)
	{
	    file_or_excl_descr_t descr = {.expr=NULL, .is_const=FALSE, .name=""};
	    apr_array_header_t* volatile directives;

	    if (is_file)
	    {
		directives = imconf->file_directives;
	    }
	    else
	    {
		directives = imconf->exclude_directives;
	    }

	    try
	    {
		descr.expr = nx_expr_parse(module, curr->args, module->pool,
						      curr->filename, curr->line_num, curr->argsstart);
		if ( descr.expr == NULL )
		{
		    throw_msg("invalid or empty expression for File/Exclude: '%s'", curr->args);
		}

		if ( !((descr.expr->rettype == NX_VALUE_TYPE_STRING) ||
		       (descr.expr->rettype == NX_VALUE_TYPE_UNKNOWN)) )
		{
		    throw_msg("string type required in expression, found '%s'",
			      nx_value_type_to_string(descr.expr->rettype));
		}
		if ( descr.expr->type == NX_EXPR_TYPE_VALUE )
		{
		    ASSERT(descr.expr->value.defined == TRUE);
		    if ( descr.expr->value.type != NX_VALUE_TYPE_STRING )
		    {
			throw_msg("%s File/Exclude directive evaluated to '%', string type required",
				  module->name, nx_value_type_to_string(descr.expr->value.type));
		    }
		    apr_cpystrn(descr.name, descr.expr->value.string->buf,
				sizeof(descr.name));
		    descr.is_const = TRUE;
		}
	    }
	    catch(e)
	    {
		log_exception(e);
		nx_conf_error(curr, "invalid expression in 'File/Exclude', string type required");
	    }

	    file_or_excl_descr_t *new_element = apr_array_push(directives);
	    ASSERT(new_element);
	    *new_element = descr;
	}
	else if ( strcasecmp(curr->directive, "savepos") == 0 )
	{
	}
	else if ( strcasecmp(curr->directive, "recursive") == 0 )
	{
	}
	else if ( strcasecmp(curr->directive, "RenameCheck") == 0 )
	{
	}
	else if ( strcasecmp(curr->directive, "CloseWhenIdle") == 0 )
	{
	}
	else if ( strcasecmp(curr->directive, "ReadFromLast") == 0 )
	{
	}
	else if ( strcasecmp(curr->directive, "InputType") == 0 )
	{
	    if ( imconf->inputfunc != NULL )
	    {
		nx_conf_error(curr, "InputType is already defined");
	    }

	    if ( curr->args != NULL )
	    {
		imconf->inputfunc = nx_module_input_func_lookup(curr->args);
	    }
	    if ( imconf->inputfunc == NULL )
	    {
		nx_conf_error(curr, "Invalid InputType '%s'", curr->args);
	    }
	}
	else if ( strcasecmp(curr->directive, "ReadOrder") == 0 )
	{
	    if ( has_dirreadorder == TRUE )
	    {
		nx_conf_error(curr, "Already specified");
	    }
	    imconf->dir_read_comp_fn = im_file_cfg_readorder_fn_lookup(curr);
	    has_dirreadorder = TRUE;
	}
	else if ( strcasecmp(curr->directive, "PollInterval") == 0 )
	{
	    if ( sscanf(curr->args, "%f", &(imconf->poll_interval)) != 1 )
	    {
		nx_conf_error(curr, "invalid PollInterval: %s", curr->args);
            }
	}
	else if ( strcasecmp(curr->directive, "DirCheckInterval") == 0 )
	{
	    if ( sscanf(curr->args, "%f", &(imconf->dircheck_interval)) != 1 )
	    {
		nx_conf_error(curr, "invalid DirCheckInterval: %s", curr->args);
            }
	}
	else if ( strcasecmp(curr->directive, "ActiveFiles") == 0 )
	{
	    if ( sscanf(curr->args, "%d", &(imconf->active_files)) != 1 )
	    {
		nx_conf_error(curr, "invalid ActiveFiles directive: %s", curr->args);
            }
	}
	else if ( strcasecmp(curr->directive, "noescape") == 0 )
	{
	    log_warn("The 'NoEscape' directive at %s:%d has been deprecated, "
		    "use 'EscapeGlobPatterns' global directive instead",
		    curr->filename, curr->line_num);
	}
	else if ( strcasecmp(curr->directive, "OnEOF") == 0 )
	{
	    curr2 = curr->first_child;
	    if ( curr2 == NULL )
	    {
		nx_conf_error(curr, "empty block 'OnEOF'");
	    }

	    if (imconf->oneof_exec != NULL)
	    {
		nx_conf_error(curr, "multiple definition of block 'OnEOF'");
	    }

	    imconf->oneof_grace_timeout = IM_FILE_DEFAULT_GRACETIMEOUT * APR_USEC_PER_SEC;

	    while ( curr2 != NULL )
	    {
		if ( strcasecmp(curr2->directive, "Exec") == 0 )
		{
		}
		else if ( strcasecmp(curr2->directive, "GraceTimeout") == 0 )
		{
		    unsigned grace_timeout;
		    if ( sscanf(curr2->args, "%u", &(grace_timeout)) != 1 )
		    {
			nx_conf_error(curr, "invalid GraceTimeout directive: %s", curr2->args);
		    }
		    imconf->oneof_grace_timeout = grace_timeout * APR_USEC_PER_SEC;
		}
		else
		{
		    nx_conf_error(curr, "invalid directive %s in block 'OnEOF'", curr2->directive);
		}
		curr2 = curr2->next;
	    }

	    imconf->oneof_exec = nx_module_parse_exec_block(module, module->pool, curr->first_child);
	    if ( imconf->oneof_exec == NULL )
	    {
		nx_conf_error(curr, "'Exec' is missing from block 'OnEOF'");
	    }
	}
	else
	{
	    nx_conf_error(curr, "invalid keyword: %s", curr->directive);
	}
	curr = curr->next;
    }

    if ( imconf->inputfunc == NULL )
    {
	imconf->inputfunc = nx_module_input_func_lookup("linebased");
    }
    ASSERT(imconf->inputfunc != NULL);

    imconf->savepos = TRUE;
    nx_cfg_get_boolean(module->directives, "savepos", &(imconf->savepos));

    imconf->readfromlast = TRUE;
    nx_cfg_get_boolean(module->directives, "ReadFromLast", &(imconf->readfromlast));

    imconf->closewhenidle = FALSE;
    nx_cfg_get_boolean(module->directives, "CloseWhenIdle", &(imconf->closewhenidle));

    imconf->recursive = FALSE;
    nx_cfg_get_boolean(module->directives, "recursive", &(imconf->recursive));

    imconf->renamecheck = FALSE;
    nx_cfg_get_boolean(module->directives, "RenameCheck", &(imconf->renamecheck));

    nx_ctx_t *ctx = nx_ctx_get();
    imconf->noescape = (ctx->escape_glob_patterns == FALSE) ? TRUE : FALSE;

    if ( imconf->file_directives->nelts == 0 )
    {
	nx_conf_error(module->directives, "'File' missing for module im_file");
    }

    if ( imconf->poll_interval == 0 )
    {
	imconf->poll_interval = IM_FILE_DEFAULT_POLL_INTERVAL;
    }

    if ( imconf->dircheck_interval == 0 )
    {
	imconf->dircheck_interval = imconf->poll_interval * 2;
    }

    if ( imconf->active_files == 0 )
    {
	imconf->active_files = IM_FILE_DEFAULT_ACTIVE_FILES;
    }

    if ( imconf->oneof_grace_timeout == 0 )
    {
	// setting a minimum grace timeout in order to not flooding nxlog with events
	imconf->oneof_grace_timeout = APR_USEC_PER_SEC / 20;
    }

    imconf->open_files = apr_pcalloc(module->pool, sizeof(nx_im_file_input_list_t));
    imconf->files = apr_hash_make(module->pool);
}



static void im_file_start(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;

    ASSERT(module->config != NULL);

    imconf = (nx_im_file_conf_t *) module->config;
  
    im_file_check_new(module, imconf->readfromlast);
    im_file_add_poll_event(module, FALSE);

    ASSERT(imconf->dircheck_event == NULL);
    im_file_add_spec_event(module, IM_FILE_EVT_DIRCHECK, FALSE);

    ASSERT(imconf->execoneof_event == NULL);
    im_file_add_spec_event(module, IM_FILE_EVT_ONEOFEXEC, FALSE);
}



static void im_file_stop(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;
    nx_im_file_input_t *file;
    apr_hash_index_t *idx;
    apr_ssize_t keylen;
    const char *fname;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);
    imconf = (nx_im_file_conf_t *) module->config;

    log_debug("im_file_stop()");
    while ( (file = NX_DLIST_FIRST(imconf->open_files)) != NULL )
    {
	im_file_input_close(module, file);
    }


    for ( idx = apr_hash_first(NULL, imconf->files);
	  idx != NULL;
	  idx = apr_hash_next(idx) )
    {
	apr_hash_this(idx, (const void **) &fname, &keylen, (void **) &file);
	ASSERT(file != NULL);
	ASSERT(fname != NULL);

	im_file_filehash_remove(module, &file);
    }


    // events are not removed by nx_module_stop_self
    if ( imconf->poll_event != NULL )
    {
	nx_event_remove(imconf->poll_event);
	nx_event_free(imconf->poll_event);
	imconf->poll_event = NULL;
    }
    if ( imconf->dircheck_event != NULL )
    {
	nx_event_remove(imconf->dircheck_event);
	nx_event_free(imconf->dircheck_event);
	imconf->dircheck_event = NULL;
    }

    if ( imconf->execoneof_event != NULL )
    {
	nx_event_remove(imconf->execoneof_event);
	if (imconf->execoneof_event->data != NULL)
	{
	    free(imconf->execoneof_event->data);
	}
	nx_event_free(imconf->execoneof_event);
	imconf->execoneof_event = NULL;
    }
}



static void im_file_pause(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    imconf = (nx_im_file_conf_t *) module->config;

    if ( imconf->poll_event != NULL )
    {
	nx_event_remove(imconf->poll_event);
	nx_event_free(imconf->poll_event);
	imconf->poll_event = NULL;
    }
    // leave the dircheck event running
}



static void im_file_resume(nx_module_t *module)
{
    nx_im_file_conf_t *imconf;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    imconf = (nx_im_file_conf_t *) module->config;

    if ( imconf->poll_event != NULL )
    {
	nx_event_remove(imconf->poll_event);
	nx_event_free(imconf->poll_event);
	imconf->poll_event = NULL;
    }
    im_file_add_poll_event(module, FALSE);
}



static void im_file_event(nx_module_t *module, nx_event_t *event)
{
    ASSERT(event != NULL);
    im_file_evt_subtype_t subtype;

    switch ( event->type )
    {
	case NX_EVENT_READ:
	    im_file_read(module);
	    break;
	case NX_EVENT_MODULE_SPECIFIC:
	    ASSERT(event->subtype != 0);
	    subtype = (im_file_evt_subtype_t)(event->subtype);
	    switch ( subtype )
	    {
		case IM_FILE_EVT_DIRCHECK:
		    im_file_dircheck_event_cb(module);
		    break;
		case IM_FILE_EVT_ONEOFEXEC:
		    im_file_oneofexec_event_cb(module);
		    break;
		default:
		    nx_panic("invalid event subtype: %d", subtype);
	    }
	    break;
	default:
	    nx_panic("invalid event type: %d", event->type);
    }
}


extern nx_module_exports_t nx_module_exports_im_file;

NX_MODULE_DECLARATION nx_im_file_module =
{
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_INPUT,
    NULL,			// capabilities
    im_file_config,		// config
    im_file_start,		// start
    im_file_stop, 		// stop
    im_file_pause,		// pause
    im_file_resume,		// resume
    NULL,			// init
    NULL,			// shutdown
    im_file_event,		// event
    NULL,			// info
    &nx_module_exports_im_file, //exports
};
