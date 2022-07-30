/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#ifndef __NX_IM_FILE_H
#define __NX_IM_FILE_H

#include "../../../common/types.h"
#include "../../../common/expr.h"
#include "../../../common/module.h"

typedef int (*im_file_comp_fn_t)(const void *, const void *);

typedef struct nx_im_file_input_t
{
    NX_DLIST_ENTRY(nx_im_file_input_t) link;
    nx_module_input_t	*input;	///< Input structure, NULL if not open
    apr_pool_t		*pool;	///< Pool to allocate from
    const char		*name;	///< Name of the file
    apr_time_t		mtime;	///< Last modification time
    apr_time_t		new_mtime;///< Last modification time returned by stat()
    apr_ino_t		inode;	///< Inode to monitor if file was rotated
    apr_off_t		filepos;///< File position to resume at after a close
    apr_off_t		size;	///< Last file size
    apr_off_t		new_size;///< File size returned by stat
    int			num_eof;///< The number of EOFs since the last successful read
    apr_time_t          first_eof_time; ///< time when num_eof became 1 otherwise zeroed
    apr_time_t		last_succesful_readtime; ///< last time when apr_file_read() yielded data (not zeroed at opening)
    apr_time_t		blacklist_until; ///< ignore this file until this time
    int			blacklist_interval; ///< seconds to blacklist the file, increased on failure
    boolean             oneof_processed; ///< after <OnEOF> processed re-opening of the file is blocked
} nx_im_file_input_t;


typedef struct nx_im_file_input_list_t nx_im_file_input_list_t;
NX_DLIST_HEAD(nx_im_file_input_list_t, nx_im_file_input_t);

// file or exclude config directive descriptor
typedef struct
{
    nx_expr_t   	*expr;
    boolean		is_const;
    char		name[APR_PATH_MAX];  ///< holds the currently evaluated value of a directive
} file_or_excl_descr_t;


// for exclude array
typedef struct
{
    char                *path;  ///> not glob!
    char                *fname_mask;  ///> can be glob
} exclude_element_t;

typedef struct nx_im_file_conf_t
{
    apr_array_header_t  *file_directives;
    apr_array_header_t  *exclude_directives;
    int			current_file_directive_idx;   ///< global index for file directives processing
    apr_array_header_t  *excludes; ///> elements of 'exclude_element_t'

    boolean 		savepos;
    boolean		readfromlast;
    boolean		recursive;
    boolean		closewhenidle;
    boolean		renamecheck;
    float		poll_interval;
    float		dircheck_interval;
    nx_event_t 		*poll_event;
    nx_event_t 		*dircheck_event;
    nx_event_t          *execoneof_event;
    nx_module_input_func_decl_t *inputfunc;
    int			non_active_modified;	///< file modified in the non-active file set

    int			active_files;	///< Max number of files to keep in open_files
    apr_hash_t		*files; 	///< Contains nx_file_input_t structures
    int			num_open_files; ///< The number of open files in the list
    nx_im_file_input_list_t *open_files;///< The list of open files
    nx_im_file_input_t	*currsrc; 	///< last successfull read from this input file
    boolean		warned_no_input_files;
    boolean		warned_no_directory;
    apr_time_t		lastcheck;	///< time of last check for new data in closed files
    boolean             noescape;  ///< for apr_fnmatch's flags at value name matching

    nx_expr_statement_list_t	*oneof_exec;	///< Statement blocks in <OnEOF> to execute
    apr_time_t                   oneof_grace_timeout; ///< number of microseconds to wait after EOF is detected to evaluate the statement
    im_file_comp_fn_t   dir_read_comp_fn;  ///< comparison function for sorting directory elements

    // vars for file attribute error reports
    boolean nametype_err_reported;
    boolean ctime_err_reported;
    boolean mtime_err_reported;

} nx_im_file_conf_t;



#endif	/* __NX_IM_FILE_H */
