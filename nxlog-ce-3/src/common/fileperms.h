#ifndef __NX_FILEPERMS_H
#define __NX_FILEPERMS_H

#include "types.h"
#include "cfgfile.h"

typedef struct
{
    // config items
    const char *user;
    const char *group;
    const char *permissions;

    // resolved values
    uid_t   _uid;
    gid_t   _gid;
    mode_t  _perm;
} nx_fileperms_conf_t;

boolean nx_fileperms_config(const nx_directive_t *curr, nx_fileperms_conf_t *conf);
void nx_fileperms_create_dir(apr_pool_t *pool, const nx_fileperms_conf_t *conf, const char *filename);

#ifndef WIN32
void nx_fileperms_setperms(const nx_fileperms_conf_t *conf, const char *file_or_dir_name);
#endif

#endif // __NX_FILEPERMS_H

