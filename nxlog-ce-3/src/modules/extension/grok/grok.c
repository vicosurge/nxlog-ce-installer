#include "grok.h"

#include <apr_portable.h>
#include <apr_fnmatch.h>
#include <apr_file_info.h>
#include <apr_hash.h>
#include <apr_general.h>

#include "../../../common/error_debug.h"
#include "../../../common/exception.h"
#include "../../../common/alloc.h"
#include "../../../common/filepath.h"
#include "../../../common/atomic.h"
#include "../../../common/module.h"


#define NX_LOGMODULE NX_LOGMODULE_MODULE


static boolean is_empty_line(const char *line)
{
    const char *pos = line;

    if ( line == NULL )
    {
	return (FALSE);
    }

    while ( *pos )
    {
	if ( !apr_isspace(*pos) )
	{
	    return (FALSE);
	}
	pos++;
    }
    return (TRUE);
}


static boolean is_comment(const char *line)
{
    const char *pos;

    ASSERT(line);

    pos = line;

    while ( *pos )
    {
	if ( !apr_isspace(*pos) )
	{
	    if ( *pos == '#' )
	    {
		return (TRUE);
	    }
	    return (FALSE);
	}
	pos++;
    }
    return (FALSE);
}


static boolean add_to_hash(apr_pool_t *mp, apr_hash_t *tbl, char *line)
{
    char *key;
    char *value;
    char *end;

    ASSERT(line);
    ASSERT(mp);
    ASSERT(tbl);

    key = apr_strtok(line, " \t", &end);
    value = end;

    if ( (key == NULL) || (value == NULL) || (*value == 0) )
    {
	return (FALSE);
    }
    apr_hash_set(tbl, apr_pstrdup(mp, key), APR_HASH_KEY_STRING, apr_pstrdup(mp, value));

    return (TRUE);
}


static boolean process_line(apr_pool_t *mp, apr_hash_t *tbl, char *line)
{
    ASSERT(line);
    ASSERT(mp);
    ASSERT(tbl);

    if ( is_empty_line(line) || is_comment(line) )
    {
	return (TRUE);
    }
    if ( add_to_hash(mp, tbl, line) == FALSE )
    {
	return (FALSE);
    }

    return (TRUE);
}


static void rtrim(char *line)
{
    int i;

    ASSERT(line);

    for ( i = (int) (strlen(line)) - 1; i >= 0 && isspace(line[i]); i-- )
    {
	line[i] = 0;
    }
}


static void grok_pattern_load_file(const char *filename, apr_hash_t *tbl, apr_pool_t *mp)
{
    char linebuf[65000];
    const int linebuf_len = sizeof(linebuf);
    apr_file_t *file;

    ASSERT(filename);
    ASSERT(tbl);
    ASSERT(mp);

    log_debug("load file: %s", filename);

    memset(linebuf, 0, (size_t) linebuf_len);

    apr_file_open(&file, filename, APR_FOPEN_READ, APR_FPROT_OS_DEFAULT, mp);

    while ( apr_file_gets(linebuf, linebuf_len, file) == APR_SUCCESS )
    {
	rtrim(linebuf);
	if ( process_line(mp, tbl, linebuf) == FALSE )
	{
	    log_warn("error processing %s", linebuf);
	}
    }
    apr_file_close(file);

}


void grok_pattern_load(const char *location, apr_hash_t *tbl, apr_pool_t *mp)
{
    int i;
    char *file_path;
    apr_array_header_t *files = NULL;

    ASSERT(location);
    ASSERT(tbl);
    ASSERT(mp);

    log_debug("Search pattern file by location %s", location);
    if ( apr_fnmatch_test(location) )
    {
	nx_filepath_glob(mp, location, NX_DIR_SEPARATOR, &files);
    }
    else
    {
	nx_filepath_list_files_recursive(mp, location, &files);
    }

    if ( files != NULL )
    {
	for ( i = 0; i < files->nelts; i++ )
	{
	    file_path = APR_ARRAY_IDX(files, i, char*);
	    if ( file_path && *file_path )
	    {
		grok_pattern_load_file(file_path, tbl, mp);
	    }
	}
    }
}


#define OVECCOUNT 60


boolean pcre_match(const char *pattern, const char *subj, nx_grok_t *grok)
{
    const char *error;
    int erroffset;
    int rc;
    int ovector[OVECCOUNT];
    int namecount;
    int name_entry_size;
    unsigned char *tabptr;
    unsigned char *name_table;
    int i;


    ASSERT(grok != NULL);

    if ( grok->re == NULL )
    {
	grok->re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
    }

    nx_grok_set_subj(grok, subj);

    if ( grok->re == NULL )
    {
	throw_msg("PCRE compilation failed at offset %d: %s\n", erroffset, error);
    }

    rc = pcre_exec(grok->re, NULL, grok->subj->buf, (int) grok->subj->len,
		   0, 0, ovector, OVECCOUNT);

    if ( rc < 0 )
    {
	if ( rc == PCRE_ERROR_NOMATCH)
	{
	    log_debug("No match %s \n", subj);
	}
	else
	{
	    log_debug("Matching error %d\n", rc);
	}
	return (FALSE);
    }

    if ( rc == 0 )
    {
	rc = OVECCOUNT / 3;
	log_warn("vector only has room for %d captured substrings", rc - 1);
    }

    nx_grok_reset_matches(grok, (size_t) rc);

    // fill matches
    for ( i = 0; i < rc; i++ )
    {
	nx_grok_set_mach(grok, (size_t) i, ovector);
    }


    pcre_fullinfo(grok->re, NULL, PCRE_INFO_NAMECOUNT, &namecount);

    if ( namecount <= 0 )
    {
	return (TRUE);
    }

    pcre_fullinfo(grok->re, NULL, PCRE_INFO_NAMETABLE, &name_table);
    pcre_fullinfo(grok->re, NULL, PCRE_INFO_NAMEENTRYSIZE, &name_entry_size);

    tabptr = name_table;
    for ( i = 0; i < namecount; i++ )
    {
	int n = (tabptr[0] << 8) | tabptr[1];
	if ( n < rc )
	{
	    nx_grok_set_name(grok, (size_t) n, (const char *) (tabptr + 2));
	}
	tabptr += name_entry_size;
    }
    return (TRUE);
}


static void nx_grok_replace_match(nx_grok_t *grok, size_t idx, const char *to)
{
    size_t left_len;
    size_t right_len;
    const char *left;
    const char *right;
    nx_string_t *subj;

    left_len = nx_grok_get_match(grok, idx)->start_pos;
    right_len = grok->subj->len - nx_grok_get_match(grok, idx)->end_pos;
    left = grok->subj->buf;
    right = grok->subj->buf + nx_grok_get_match(grok, idx)->end_pos;

    subj = nx_string_sprintf(NULL, "%.*s%s%.*s",
			     (int) left_len,  // left-part-length
			     left,      // left part
			     to,        // name
			     (int) right_len, // right parh length
			     right);    // right
    nx_grok_set_subj(grok, subj->buf);
    nx_string_free(subj);
}


nx_string_t *grok_pattern_eval(const char *pattern_val, apr_hash_t *grok_patterns)
{

    const char *grok_pattern = "%\\{((\\w+?)|((\\w+?):(\\w+?)))\\}";
    nx_exception_t e;
    nx_grok_t *grok;
    const char *grok_val;
    nx_string_t *to;
    nx_string_t *result;
    const char *name;

    grok = nx_grok_new();
    nx_grok_set_subj(grok, pattern_val);

    try
    {
	while ( pcre_match(grok_pattern, grok->subj->buf, grok) )
	{
	    if ( grok->maches_num > 3 )
	    {
		/* varian 2 %{GROK:name}*/
		/* replace match */
		name = nx_grok_get_match_value(grok, 4)->buf;
		if ( (grok_val = apr_hash_get(grok_patterns, (const void *) name, APR_HASH_KEY_STRING)) == NULL )
		{
		    /* Cannot convert to pcre pattern */
		    throw_msg("Unknown grok pattern: %s", name);
		}
		to = nx_string_sprintf(NULL, "(?<%s>%s)", nx_grok_get_match_value(grok, 5)->buf, grok_val);
		nx_grok_replace_match(grok, 0, to->buf);
		nx_string_free(to);

	    }
	    else if ( grok->maches_num == 3 )
	    {
		/* varian 1 %{GROK}*/
		name = nx_grok_get_match_value(grok, 2)->buf;
		if ((grok_val = apr_hash_get(grok_patterns, (const void *) name, APR_HASH_KEY_STRING)) == NULL)
		{
		    /* Cannot convert to pcre pattern */
		    throw_msg("Unknown grok pattern: %s", name);
		}
		nx_grok_replace_match(grok, 0, grok_val);
	    }
	    else
	    {
		throw_msg("Bad match group number: %s", grok->maches_num);
	    }
	}
    }
    catch (e)
    {
	log_exception(e);
	nx_grok_free(grok);
	rethrow(e);
    }
    result = grok->subj;
    grok->subj = NULL;
    nx_grok_free(grok);
    return result;
}


void grok_pattern_evaluate_all(apr_hash_t *patterns)
{
    nx_string_t *evaluated = NULL;
    apr_pool_t *pool;
    apr_hash_index_t *hi;

    for ( hi = apr_hash_first(NULL, patterns); hi; hi = apr_hash_next(hi) )
    {
	const char *k;
	char *v;

	apr_hash_this(hi, (const void **) &k, NULL, (void **) &v);
	evaluated = grok_pattern_eval(v, patterns);
	if ( strcmp(evaluated->buf, v) != 0 )
	{
	    pool = apr_hash_pool_get(patterns);
	    apr_hash_set(patterns, (const void *) k, APR_HASH_KEY_STRING, apr_pstrdup(pool, evaluated->buf));
	}
	nx_string_free(evaluated);
    }
}


apr_hash_t *grok_get_module_storage(nx_module_t *module)
{
    apr_hash_t *prepared;

    ASSERT(module != NULL);
    ASSERT(module->pool != NULL);

    prepared = (apr_hash_t *) nx_module_data_get(module, "prepared.grok");
    if ( prepared == NULL)
    {
	prepared = apr_hash_make(module->pool);
	nx_module_data_set(module, "prepared.grok", prepared, NULL);
    }
    ASSERT(prepared != NULL);
    return prepared;
}


nx_grok_t *grok_pattern_match_global(apr_pool_t *mp, const char *subj, apr_hash_t *db, apr_hash_t *mod_storage,
				     nx_grok_list_t *in_use, const char *pattern)
{
    nx_grok_t *grok;
    nx_string_t *arg;
    // lookup compiled re

    if ( (grok = apr_hash_get(mod_storage, pattern, APR_HASH_KEY_STRING)) == NULL )
    {
	log_debug("pattern (%s) not found, eval", pattern);
	// need to prepare
	grok = nx_grok_new();
	arg = grok_pattern_eval(pattern, db);
	nx_string_set(grok->arg, arg->buf, (int) arg->len);
	nx_string_free(arg);
	apr_hash_set(mod_storage, apr_pstrdup(mp, pattern), APR_HASH_KEY_STRING, grok);
	nx_grok_list_push(in_use, grok);
    }

    if ( pcre_match(grok->arg->buf, subj, grok) == FALSE )
    {
	grok = NULL;
    }

    return grok;
}


void nx_grok_reset_matches(nx_grok_t *grok, size_t new_matches_num)
{
    size_t i;

    ASSERT(grok != NULL);
    if ( grok->maches_num != new_matches_num )
    {
	nx_grok_matches_free(grok);
	grok->matches = (nx_grok_match_t **) malloc(sizeof(nx_grok_match_t *) * new_matches_num);
	grok->maches_num = new_matches_num;
	for ( i = 0; i < new_matches_num; i++ )
	{
	    grok->matches[i] = nx_grok_match_new();
	}
    }
    else
    {
	for ( i = 0; i < new_matches_num; i++ )
	{
	    nx_grok_match_reset(grok->matches[i]);
	}
    }
}


void nx_grok_set_arg(nx_grok_t *grok, const char *value)
{
    nx_grok_reset(grok);
    if ( grok->arg )
    {
	grok->arg = nx_string_set(grok->arg, value, (int) strlen(value));
    }
    else
    {
	grok->arg = nx_string_create(value, (int) strlen(value));
    }
}


void nx_grok_free(nx_grok_t *grok)
{
    if ( grok == NULL)
    {
	return;
    }
    nx_grok_reset(grok);

    if ( grok->arg )
    {
	nx_string_free(grok->arg);
    }
    if ( grok->subj )
    {
	nx_string_free(grok->subj);
    }
    free(grok);
}


void nx_grok_reset(nx_grok_t *grok)
{
    if ( grok == NULL)
    {
	return;
    }

    if ( grok->re )
    {
	pcre_free(grok->re);
    }
    nx_grok_matches_free(grok);
}


void nx_grok_matches_free(nx_grok_t *grok)
{
    size_t i;
    ASSERT(grok != NULL);
    if ( grok->maches_num == 0 )
    {
	return;
    }
    for ( i = 0; i < grok->maches_num; i++ )
    {
	if ( grok->matches[i] )
	{
	    nx_grok_match_free(grok->matches[i]);
	}
    }
    free(grok->matches);
    grok->matches = NULL;
    grok->maches_num = 0;
}


void nx_grok_match_free(nx_grok_match_t *match)
{
    if ( match == NULL)
    {
	return;
    }
    if ( match->name )
    {
	nx_string_free(match->name);
    }
    if ( match->value )
    {
	nx_string_free(match->value);
    }
    free(match);
}


nx_grok_match_t *nx_grok_match_new()
{
    nx_grok_match_t *rv;

    rv = (nx_grok_match_t *) malloc(sizeof(nx_grok_match_t));
    memset(rv, 0, sizeof(nx_grok_match_t));
    nx_grok_match_reset(rv);
    return rv;
}


void nx_grok_match_reset(nx_grok_match_t *match)
{
    if ( match == NULL )
    {
	return;
    }
    match->start_pos = 0;
    match->end_pos = 0;
    match->len = 0;
    if ( match->name != NULL )
    {
	nx_string_free(match->name);
    }
    match->name = nx_string_new();
    if ( match->value != NULL )
    {
	nx_string_free(match->value);
	match->value = NULL;
    }
}


nx_grok_t *nx_grok_new()
{
    nx_grok_t *grok;

    grok = (nx_grok_t *) malloc(sizeof(nx_grok_t));
    grok->arg = nx_string_new();
    grok->subj = nx_string_new();
    grok->re = NULL;
    grok->matches = NULL;
    grok->maches_num = 0;
    return grok;
}


nx_grok_match_t *nx_grok_get_match(nx_grok_t *grok, size_t index)
{
    ASSERT(grok->maches_num > index);
    return grok->matches[index];
}


void nx_grok_set_subj(nx_grok_t *grok, const char *value)
{
    if ( grok->subj == NULL )
    {
	grok->subj = nx_string_create(value, (int) strlen(value));
    }
    else if ( grok->subj->buf != value )
    {
	grok->subj = nx_string_set(grok->subj, value, (int) strlen(value));
    }
    nx_grok_reset_matches(grok, grok->maches_num);
}


void nx_grok_set_mach(nx_grok_t *grok, size_t idx, int *ovec)
{
    nx_grok_match_t *match = nx_grok_get_match(grok, idx);
    match->start_pos = (size_t) ovec[2 * idx];
    match->end_pos = (size_t) ovec[2 * idx + 1];
    match->len = (size_t) (ovec[2 * idx + 1] - ovec[2 * idx]);
}


void nx_grok_set_name(nx_grok_t *grok, size_t idx, const char *name)
{
    ASSERT(nx_grok_get_match(grok, idx)->name != NULL);
    nx_string_set(nx_grok_get_match(grok, idx)->name, name, (int) strlen(name));
}


boolean nx_grok_match_has_name(nx_grok_t *grok, size_t idx)
{
    ASSERT(nx_grok_get_match(grok, idx)->name != NULL);
    return nx_grok_get_match(grok, idx)->name->len > 0;
}


const char *nx_grok_match_get_name(nx_grok_t *grok, size_t idx)
{
    ASSERT(nx_grok_get_match(grok, idx)->name != NULL);
    return nx_grok_get_match(grok, idx)->name->buf;
}


nx_string_t *nx_grok_get_match_value(nx_grok_t *grok, size_t idx)
{
    nx_grok_match_t *match;

    ASSERT(grok != NULL);

    match = nx_grok_get_match(grok, idx);
    if ( match->value )
    {
	if ( match->value->len != match->len ||
	     strncmp(match->value->buf, grok->subj->buf + match->start_pos, match->len) != 0 )
	{
	    nx_string_set(match->value, grok->subj->buf + match->start_pos, (int) match->len);
	}
    }
    else
    {
	match->value = nx_string_create(grok->subj->buf + match->start_pos, (int) match->len);
    }
    return match->value;
}


nx_grok_list_t *nx_grok_list_new(apr_pool_t *pool)
{
    nx_grok_list_t *list;
    apr_pool_t *mp;

    ASSERT (pool != NULL);

    mp = nx_pool_create_child(pool);
    list = (nx_grok_list_t *) apr_pcalloc(mp, sizeof(nx_grok_list_t));
    list->pool = mp;
    return list;
}


void nx_grok_list_push(nx_grok_list_t *list, nx_grok_t *grok)
{
    ASSERT(list != NULL);
    ASSERT(list->pool != NULL);

    nx_grok_list_entry_t *entry = (nx_grok_list_entry_t *) apr_pcalloc(list->pool, sizeof(nx_grok_list_entry_t));
    entry->grok = grok;
    NX_DLIST_INSERT_TAIL(list, entry, link);
}


void nx_grok_list_foreach(nx_grok_list_t *list, nx_grok_list_cb func)
{
    nx_grok_list_entry_t *entry;

    ASSERT(func != NULL);

    ASSERT(list != NULL);
    for ( entry = NX_DLIST_FIRST(list);
	  entry != NULL;
	  entry = NX_DLIST_NEXT(entry, link) )
    {
	func(entry->grok);
    }
}
