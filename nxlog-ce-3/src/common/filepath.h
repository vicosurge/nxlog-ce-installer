#ifndef __NX_FILEPATH_H
#define __NX_FILEPATH_H

#include <apr_tables.h>
#include <apr_file_info.h>
#include "types.h"


/**
 * Parsing path glob string to array of individual folder globs
 * n.b.: parsing is from left to right, escape sequence first then identifying path separator
 *
 * @param path Path to decompose  (e.g.: "/path/to/logs/[a-zA-Z0-9]* /[a-zA-Z0-9]*-error.log" with no space inside)
 * @param escaping For sequences of "\?" or "\*" or "\\".
 * @param separator Folder separator in path
 * @param pool
 * @return Array of individual path parts
 */
apr_array_header_t *nx_filepath_decompose(const char *path, boolean escaping,
					  const char separator, apr_pool_t *pool);


/**
 * Recursively traverse matching directories
 *
 * @param path_decomposed Array of path elements (by path_decompose())
 * @param escaping Controls APR_FNM_NOESCAPE usage in apr_fnmatch()
 * @param pool
 * @param path_element_idx At first call this should be set to 0 (recursive calls advance this)
 * @param work_path at first Call this should be "" (empty string)
 * @param result_paths[in,out] Array of generated paths (initializes array when *result_paths==NULL)
 */
void nx_filepath_find_all_paths(const apr_array_header_t *path_decomposed, boolean escaping,
				apr_pool_t *pool, int path_element_idx, const char *work_path,
				apr_array_header_t **result_paths);


/**
 * Finds all files in a directory matching a file glob pattern
 *
 * @param path A non glob directory path
 * @param file_glob Glob pattern for file name
 * @param escaping Controls APR_FNM_NOESCAPE usage in apr_fnmatch()
 * @param pool
 * @return Array of matching file names
 */
apr_array_header_t *nx_filepath_find_all_files(const char *path, const char *file_glob, boolean escaping,
					       apr_pool_t *pool);


/**
 *  Concatenates path:
 *  Exaples:
 *
 *  1. nx_filepath_concat(pool, "one", "two", "/") returns "one/two";
 *  2. nx_filepath_concat(pool, "/one", "/two", "/") returns "/one/two";
 *  3. nx_filepath_concat(pool, "one/", "/two/", "/") returns "one/two/";
 *
 * @param mp pool
 * @param left Left part of path
 * @param right Right part of path
 * @param separator Separator
 * @return Result path
 */
char *nx_filepath_concat(apr_pool_t *mp, const char *left, const char *right, const char *separator);


/**
 * Searches files matches glob pattern
 * @param mp pool
 * @param pattern  glob pattern, for example "/Volumes/Work/grok/?av?/?"
 * @param separator
 * @param result pointer to apr array pointer (may be NULL)
 */
void nx_filepath_glob(apr_pool_t *mp, const char *pattern, const char *separator, apr_array_header_t **result);


/**
 * Reqursive find files in path directory
 * @param mp apr memory pool
 * @param path directory to search or file
 * @param result  array of files path.
 */
void nx_filepath_list_files_recursive(apr_pool_t *mp, const char *path, apr_array_header_t ** result);


/**
 *
 * @param path
 * @return TRUE if path is regular file
 */
boolean nx_filepath_is_reg(const char *path);


/**
 * @param path
 * @return TRUE if path is directory
 */
boolean nx_filepath_is_dir(const char *path);


/**
 * @param path
 * @return TRUE if file is exists
 */
boolean nx_filepath_exists(const char *path);


/**
 * @param path
 * @param file_type
 * @return TRUE if path  file type is file_type
 */
boolean nx_filepath_check_type(const char *path, apr_filetype_e file_type);

#endif // __NX_FILEPATH_H