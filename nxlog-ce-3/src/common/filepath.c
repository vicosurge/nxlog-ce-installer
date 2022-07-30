#include "alloc.h"
#include "filepath.h"
#include "error_debug.h"
#include "module.h"
#include "../core/ctx.h"

#include <apr_fnmatch.h>


#define NX_LOGMODULE NX_LOGMODULE_CORE


apr_array_header_t *nx_filepath_decompose(const char *path, boolean escaping,
					  const char separator, apr_pool_t *pool)
{
    ASSERT(path);
    ASSERT(pool);

    // on windows escaping special characters may obstuct decomposing
#ifdef WIN32
    escaping = FALSE;
#endif

    apr_array_header_t *array = apr_array_make(pool, 0, sizeof(char *));
    ASSERT(array);

    const char esc = '\\';

    const char *start_pos = path;
    const char *curr_pos = path;

    for ( ; *curr_pos != '\0'; ++curr_pos )
    {
	if ( *curr_pos == esc && escaping )
	{
	    // check for escaping
	    ++curr_pos;
	    if ( *curr_pos == '*' || *curr_pos == '?' || *curr_pos == esc )
	    {
		continue;
	    }
	    // no escaping found
	    --curr_pos;
	}

	if ( *curr_pos == separator )
	{
	    // path separator found
	    char **new_element = apr_array_push(array);
	    ASSERT(new_element);
	    *new_element = apr_pstrndup(pool, start_pos, curr_pos - start_pos);
	    ASSERT(*new_element);
	    start_pos = curr_pos + 1;
	}
    }

    if ( start_pos < curr_pos )
    {
	// when there is no closing separator
	char **new_element = apr_array_push(array);
	ASSERT(new_element);
	*new_element = apr_pstrndup(pool, start_pos, curr_pos - start_pos);
	ASSERT(*new_element);
    }

    return array;
}


void nx_filepath_find_all_paths(const apr_array_header_t *path_decomposed, boolean escaping,
				apr_pool_t *pool, int path_element_idx, const char *work_path,
				apr_array_header_t **result_paths)
{

    ASSERT(path_decomposed);
    ASSERT(path_decomposed->nelts > 0);
    ASSERT(path_element_idx >= 0);
    ASSERT(path_element_idx <= path_decomposed->nelts);
    ASSERT(work_path);
    ASSERT(result_paths);

    if ( !*result_paths )
    {
	// init out array
	*result_paths = apr_array_make(pool, 0, sizeof(char *));
    }
    ASSERT(*result_paths);

    if ( path_element_idx == path_decomposed->nelts )
    {
	// yields here : work_path
	char **new_path = apr_array_push(*result_paths);
	ASSERT(new_path);
	*new_path = apr_pstrdup((*result_paths)->pool, work_path);
	ASSERT(*new_path);

	return;
    }

    ASSERT(pool);

    apr_pool_t *local_pool;
    apr_pool_create(&local_pool, pool);
    ASSERT(local_pool);

    char *newpath = NULL;
    char *path_element = ((char **) path_decomposed->elts)[path_element_idx];

    // unfortunately backslash occurence needs to be checked also
    boolean is_glob = (apr_fnmatch_test(path_element) != 0 || strchr(path_element, '\\') != NULL);

    apr_dir_t *dir = NULL;
    apr_status_t status;

    if ( !is_glob )
    {
	newpath = apr_pstrcat(local_pool, work_path, path_element, NX_DIR_SEPARATOR, NULL);

	// check if path exists
	status = apr_dir_open(&dir, newpath, local_pool);
	if ( status == APR_SUCCESS )
	{
	    apr_dir_close(dir);
	    dir = NULL;
	    nx_filepath_find_all_paths(path_decomposed, escaping, local_pool, path_element_idx + 1, newpath,
				       result_paths);
	}
    }
    else
    {
	// this is glob
	// check matching directories
	status = apr_dir_open(&dir, work_path, local_pool);
	if ( status == APR_SUCCESS )
	{
	    apr_finfo_t finfo;
	    for ( ;; )
	    {
		// processing directory elements
		status = apr_dir_read(&finfo, APR_FINFO_NAME | APR_FINFO_TYPE | APR_FINFO_LINK, dir);

		if ( APR_STATUS_IS_ENOENT(status))
		{
		    // no more element
		    break;
		}

		if ( status != APR_SUCCESS && status != APR_INCOMPLETE)
		{
		    // some apr_dir_read fail
		    continue;
		}

		if ((finfo.valid & APR_FINFO_TYPE) && (finfo.filetype != APR_DIR))
		{
		    // not a directory
		    continue;
		}

		if ( !(finfo.valid & APR_FINFO_NAME))
		{
		    // apr_dir_read incomplete : no name
		    continue;
		}

		if ((finfo.valid & APR_FINFO_TYPE) && (finfo.filetype == APR_DIR)
		    && strcmp(finfo.name, ".") != 0 && strcmp(finfo.name, "..") != 0 )
		{
		    // directory type item

		    int flags = 0;
		    if ( !escaping )
		    {
			flags |= APR_FNM_NOESCAPE;
		    }
#ifdef WIN32
		    flags |= APR_FNM_CASE_BLIND;
#endif
		    if ( APR_SUCCESS == apr_fnmatch(path_element, finfo.name, flags))
		    {
			// glob matching found
			newpath = apr_pstrcat(local_pool, work_path, finfo.name, NX_DIR_SEPARATOR, NULL);
			nx_filepath_find_all_paths(path_decomposed, escaping, local_pool, path_element_idx + 1, newpath,
						   result_paths);
		    }
		}
	    }
	}
    }

    if ( dir )
    {
	apr_dir_close(dir);
	dir = NULL;
    }

    apr_pool_destroy(local_pool);
    local_pool = NULL;
}


apr_array_header_t *nx_filepath_find_all_files(const char *path, const char *file_glob, boolean escaping,
					       apr_pool_t *pool)
{
    ASSERT(path);
    ASSERT(file_glob);
    ASSERT(pool);

    apr_array_header_t *array = apr_array_make(pool, 0, sizeof(char *));
    ASSERT(array);

    apr_pool_t *local_pool;
    apr_pool_create(&local_pool, pool);
    ASSERT(local_pool);

    apr_dir_t *dir = NULL;
    apr_status_t status;

    status = apr_dir_open(&dir, path, local_pool);
    if ( status == APR_SUCCESS )
    {
	apr_finfo_t finfo;
	for ( ;; )
	{
	    // processing directory elements
	    status = apr_dir_read(&finfo, APR_FINFO_NAME | APR_FINFO_TYPE | APR_FINFO_LINK, dir);

	    if ( APR_STATUS_IS_ENOENT(status))
	    {
		// no more element
		break;
	    }

	    if ( status != APR_SUCCESS && status != APR_INCOMPLETE)
	    {
		// some apr_dir_read fail
		continue;
	    }

	    if ((finfo.valid & APR_FINFO_TYPE) && (finfo.filetype != APR_REG))
	    {
		// not a file
		continue;
	    }

	    if ( !(finfo.valid & APR_FINFO_NAME))
	    {
		// apr_dir_read incomplete : no name
		continue;
	    }

	    if ((finfo.valid & APR_FINFO_TYPE) && (finfo.filetype == APR_REG))
	    {
		// file item

		int flags = 0;
		if ( !escaping )
		{
		    flags |= APR_FNM_NOESCAPE;
		}
#ifdef WIN32
		flags |= APR_FNM_CASE_BLIND;
#endif
		if ( APR_SUCCESS == apr_fnmatch(file_glob, finfo.name, flags))
		{
		    // glob matching found
		    char **found_file = apr_array_push(array);
		    ASSERT(found_file);
		    *found_file = apr_pstrdup(pool, finfo.name);
		    ASSERT(*found_file);
		}
	    }
	}
    }

    if ( dir )
    {
	apr_dir_close(dir);
	dir = NULL;
    }

    apr_pool_destroy(local_pool);
    local_pool = NULL;

    return array;
}


char *nx_filepath_concat(apr_pool_t *mp, const char *left, const char *right, const char *separator)
{
    const char *new_right;
    const char *end;
    char *new_left;
    char *ptr;

    ASSERT(mp);
    ASSERT(separator);
    ASSERT(left);
    ASSERT(right);

    new_left = apr_pstrdup(mp, left);

    // trim ending slashes
    for ( ptr = new_left + strlen(new_left) - 1; ptr >= new_left && *ptr == *separator; ptr-- )
    {
	*ptr = 0;
    }

    end = right + strlen(right);

    //trim trailing slashes
    for ( new_right = right; new_right < end && *new_right == *separator; new_right++ )
    {
    }

    if ( *new_left == 0 && *new_right == 0 )
    {
	return apr_pstrdup(mp, separator);
    }
    if ( *new_left == 0 )
    {
	return apr_pstrdup(mp, new_right);
    }
    return apr_pstrcat(mp, new_left, separator, new_right, NULL);
}


static void fp_glob(apr_pool_t *mp, apr_array_header_t *path_elts, int path_element_idx,
		    const char *current_workdir, boolean escaping, const char *separator,
		    apr_array_header_t *result)
{
    apr_status_t status;
    apr_dir_t *dir;
    char *newpath;
    apr_finfo_t finfo;
    boolean is_leaf;
    char *element;

    ASSERT(mp);
    ASSERT(current_workdir);
    ASSERT(separator);
    ASSERT(result);


    if ( path_elts == NULL)
    {
	return;
    }
    if ( path_elts->nelts == 0 )
    {
	return;
    }
    if ( path_element_idx == path_elts->nelts )
    {
	return;
    }

    is_leaf = path_element_idx == (path_elts->nelts - 1);

    element = APR_ARRAY_IDX(path_elts, path_element_idx, char *);

    if ( apr_fnmatch_test(element))
    {

	status = apr_dir_open(&dir, current_workdir, mp);

	if ( status == APR_SUCCESS )
	{

	    for ( ;; )
	    {
		// processing directory elements
		status = apr_dir_read(&finfo, APR_FINFO_NAME | APR_FINFO_TYPE | APR_FINFO_LINK, dir);

		if ( APR_STATUS_IS_ENOENT(status))
		{
		    // no more element
		    break;
		}

		if ( status != APR_SUCCESS && status != APR_INCOMPLETE)
		{
		    // some apr_dir_read fail
		    continue;
		}

		if ( !(finfo.valid & APR_FINFO_NAME))
		{
		    // apr_dir_read incomplete : no name
		    continue;
		}

		if ((finfo.valid & APR_FINFO_TYPE) && strcmp(finfo.name, ".") != 0 && strcmp(finfo.name, "..") != 0 )
		{

		    int flags = 0;
		    if ( !escaping )
		    {
			flags |= APR_FNM_NOESCAPE;
		    }
#ifdef WIN32
		    flags |= APR_FNM_CASE_BLIND;
#endif

		    if ( APR_SUCCESS == apr_fnmatch(element, finfo.name, flags))
		    {
			newpath = nx_filepath_concat(mp, current_workdir, finfo.name, separator);

			if ( finfo.filetype == APR_DIR )
			{
			    fp_glob(mp, path_elts, path_element_idx + 1, newpath, escaping, separator, result);
			}
			else if ( is_leaf )
			{
			    char **new_element = apr_array_push(result);
			    *new_element = apr_pstrdup(mp, newpath);
			}

		    }
		}
	    }
	}

    }
    else
    {
	newpath = nx_filepath_concat(mp, current_workdir, element, separator);
	status = apr_stat(&finfo, newpath, APR_FINFO_TYPE, mp);

	if ( status != APR_SUCCESS )
	{
	    return;
	}

	if ( finfo.valid & APR_FINFO_TYPE )
	{
	    if ( finfo.filetype == APR_DIR )
	    {
		// Go deeper
		fp_glob(mp, path_elts, path_element_idx + 1, newpath, escaping, separator, result);
	    }
	    else if ( is_leaf )
	    {
		char **new_element = apr_array_push(result);
		*new_element = apr_pstrdup(mp, newpath);
	    }
	}
    }
}


void nx_filepath_glob(apr_pool_t *mp, const char *pattern, const char *separator, apr_array_header_t **result)
{
    apr_array_header_t *elts;
    apr_array_header_t *files;        // temporary array

    ASSERT(mp);
    ASSERT(pattern);
    ASSERT(separator);
    ASSERT(result);

    files = apr_array_make(mp, 0, sizeof(char *));

    elts = nx_filepath_decompose(pattern, FALSE, separator[0], mp);

    fp_glob(mp, elts, 0, "", FALSE, separator, files);

    if ( *result == NULL)
    {
	*result = apr_array_copy(mp, files);
    }
    else
    {
	*result = apr_array_append(mp, *result, files);
    }
}


boolean nx_filepath_exists(const char *path)
{
    apr_status_t rv;
    boolean retval = FALSE;
    apr_finfo_t finfo;

    ASSERT(path);

    apr_pool_t *pool = nx_pool_create_core();

    rv = apr_stat(&finfo, path, APR_FINFO_TYPE, pool);

    if ( rv == APR_SUCCESS )
    {
	retval = TRUE;
    }
    else if ( APR_STATUS_IS_ENOENT(rv))
    {
    }
    else if ( APR_STATUS_IS_ENOTDIR(rv))
    {
    }
    else
    {
	CHECKERR_MSG(rv, "failed to check whether file '%s' exists", path);
    }
    apr_pool_destroy(pool);
    return (retval);
}


boolean nx_filepath_check_type(const char *path, apr_filetype_e file_type)
{
    apr_status_t rv;
    boolean retval = FALSE;
    apr_finfo_t finfo;

    ASSERT(path);

    apr_pool_t *pool = nx_pool_create_core();
    rv = apr_stat(&finfo, path, APR_FINFO_TYPE, pool);

    if ( rv == APR_SUCCESS )
    {
	retval = finfo.filetype == file_type;
    }
    else if ( APR_STATUS_IS_ENOENT(rv))
    {
    }
    else if ( APR_STATUS_IS_ENOTDIR(rv))
    {
    }
    else
    {
	CHECKERR_MSG(rv, "failed to check file '%s' type", path);
    }
    apr_pool_destroy(pool);
    return (retval);
}


boolean nx_filepath_is_dir(const char *path)
{
    ASSERT(path);

    return nx_filepath_check_type(path, APR_DIR);
}


boolean nx_filepath_is_reg(const char *path)
{
    ASSERT(path);

    return nx_filepath_check_type(path, APR_REG);
}


static size_t filepath_find_recursive(apr_pool_t *mp, const char *path, apr_array_header_t *file_list)
{
    apr_finfo_t finfo;
    size_t file_count = 0;
    apr_status_t status;
    apr_dir_t *dir;
    char *newpath;

    if ( !nx_filepath_exists(path))
    {
	return 0;
    }

    if ( nx_filepath_is_dir(path))
    {
	// get all childs
	status = apr_dir_open(&dir, path, mp);

	if ( status == APR_SUCCESS )
	{
	    for ( ;; )
	    {
		// processing directory elements
		status = apr_dir_read(&finfo, APR_FINFO_NAME | APR_FINFO_TYPE | APR_FINFO_LINK, dir);

		if ( APR_STATUS_IS_ENOENT(status))
		{
		    // no more element
		    break;
		}

		if ( status != APR_SUCCESS && status != APR_INCOMPLETE)
		{
		    // some apr_dir_read fail
		    continue;
		}

		if ( !(finfo.valid & APR_FINFO_NAME))
		{
		    // apr_dir_read incomplete : no name
		    continue;
		}

		if ((finfo.valid & APR_FINFO_TYPE) && strcmp(finfo.name, ".") != 0 && strcmp(finfo.name, "..") != 0 )
		{
		    newpath = nx_filepath_concat(mp, path, finfo.name, NX_DIR_SEPARATOR);
		    file_count += filepath_find_recursive(mp, newpath, file_list);
		}
	    }
	}


    }
    else
    {
	*(char **) apr_array_push(file_list) = apr_pstrdup(mp, path);
	file_count = 1;
    }
    return file_count;

}


void nx_filepath_list_files_recursive(apr_pool_t *mp, const char *path, apr_array_header_t **result)
{
    apr_array_header_t *files;

    ASSERT(mp);
    ASSERT(path);
    ASSERT(result);

    files = apr_array_make(mp, 0, sizeof(char *));

    filepath_find_recursive(mp, path, files);

    if ( *result == NULL)
    {
	*result = apr_array_copy(mp, files);
    }
    else
    {
	*result = apr_array_append(mp, *result, files);
    }
}

