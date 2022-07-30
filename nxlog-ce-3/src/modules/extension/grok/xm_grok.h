#include <apr_portable.h>
#include <apr_hash.h>

typedef struct xm_grok_conf_t {
    apr_array_header_t *pattern_files; // pattern location files patterns
    int version;
    apr_thread_mutex_t *mutex;
    nx_grok_list_t *in_use;
} xm_grok_conf_t;

typedef struct xm_grok_pattern_t {

    apr_hash_t * patterns; /* patterns loaded */
    apr_hash_t * resolved; /* patterns incoming and resolved */
    apr_pool_t * pool;
    int version;

} xm_grok_pattern_t;

xm_grok_pattern_t *xm_grok_get_db_checked(nx_module_t *module);


