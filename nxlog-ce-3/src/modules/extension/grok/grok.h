#ifndef GROK_H
#define GROK_H

#include <apr_lib.h>
#include <apr_tables.h>
#include <apr_hash.h>
#include <pcre.h>
#include <stdlib.h>
#include <string.h>

#include "../../../common/str.h"
#include "../../../common/dlist.h"

typedef struct nx_grok_match_t
{
    size_t start_pos;
    size_t end_pos;
    size_t len;
    nx_string_t *name;
    nx_string_t *value;
} nx_grok_match_t;

typedef struct nx_grok_t
{
    nx_string_t *arg;
    nx_string_t *subj;
    pcre *re;
    nx_grok_match_t **matches;
    size_t maches_num;
} nx_grok_t;

typedef struct nx_grok_list_entry_t
{
    nx_grok_t *grok;
    NX_DLIST_ENTRY(nx_grok_list_entry_t) link;
} nx_grok_list_entry_t;

typedef struct nx_grok_list_t
{
    apr_pool_t *pool;
    struct {
	nx_grok_list_entry_t *first;
	nx_grok_list_entry_t *last;
    };
} nx_grok_list_t;

typedef void (*nx_grok_list_cb)(nx_grok_t *);

nx_grok_list_t *nx_grok_list_new(apr_pool_t *pool);
void nx_grok_list_push(nx_grok_list_t *list, nx_grok_t *grok);
void nx_grok_list_foreach(nx_grok_list_t *list, nx_grok_list_cb func);

nx_grok_t *nx_grok_new(void);
void nx_grok_match_reset(nx_grok_match_t *match);
nx_grok_match_t *nx_grok_match_new(void);
void nx_grok_match_free(nx_grok_match_t *match);

void nx_grok_matches_free(nx_grok_t *grok);
void nx_grok_reset(nx_grok_t *grok);
void nx_grok_free(nx_grok_t *grok);
void nx_grok_set_arg(nx_grok_t *grok, const char *value);
void nx_grok_set_subj(nx_grok_t *grok, const char *value);
void nx_grok_set_mach(nx_grok_t *grok, size_t idx, int *ovec);
void nx_grok_set_name(nx_grok_t *grok, size_t idx, const char * name);
boolean nx_grok_match_has_name(nx_grok_t * grok, size_t idx);
const char * nx_grok_match_get_name(nx_grok_t * grok, size_t idx);
void nx_grok_reset_matches(nx_grok_t *grok, size_t new_matches_num);
void grok_pattern_load(const char *location, apr_hash_t *tbl, apr_pool_t *mp);
nx_grok_match_t *nx_grok_get_match(nx_grok_t *grok, size_t index);
void grok_pattern_evaluate_all(apr_hash_t * patterns);

nx_string_t * nx_grok_get_match_value(nx_grok_t *grok, size_t idx);

nx_grok_t *grok_pattern_match_global(apr_pool_t *mp, const char *subj, apr_hash_t *db, apr_hash_t *mod_storage,
				     nx_grok_list_t *in_use, const char *pattern);
apr_hash_t *grok_get_module_storage(nx_module_t *module);


#endif // GROK_H
