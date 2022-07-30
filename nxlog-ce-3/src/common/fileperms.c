
#include <unistd.h>
#include <sys/stat.h>
#ifndef WIN32
#include <pwd.h>
#include <grp.h>
#endif

#include "alloc.h"
#include "exception.h"
#include "cfgfile.h"
#include "fileperms.h"

#define NX_LOGMODULE NX_LOGMODULE_CORE


/**
 * Tests directive and sets perms config
 * 
 * @param curr directive to test
 * @param conf holds config variables
 * @return TRUE if directive was one of "Owner, Group, Perms" and conf was set
 */
boolean nx_fileperms_config(const nx_directive_t *curr, nx_fileperms_conf_t *conf)
{
    ASSERT(curr != NULL);
    ASSERT(conf != NULL);
    boolean ret = TRUE;

    if ( strcasecmp(curr->directive, "user") == 0 )
    {
#ifndef WIN32
	if ( conf->user != NULL )
	{
	    nx_conf_error(curr, "User is already defined");
	}
	conf->user = curr->args;
	struct passwd *pw = getpwnam(conf->user);
	if ( pw == NULL )
	{
	    nx_conf_error(curr, "User '%s' is unknown to system", conf->user);
	}
	conf->_uid = pw->pw_uid;
#else
	log_warn("Directive '%s' at %s:%d is not applicable on Windows", curr->directive, curr->filename, curr->line_num);
#endif

    }
    else if ( strcasecmp(curr->directive, "group") == 0 )
    {
#ifndef WIN32
	if ( conf->group != NULL )
	{
	    nx_conf_error(curr, "Group is already defined");
	}
	conf->group = curr->args;
	struct group *gr = getgrnam(conf->group);
	if ( gr == NULL )
	{
	    nx_conf_error(curr, "group '%s' is unknown to system", conf->group);
	}
	conf->_gid = gr->gr_gid;
#else
	log_warn("Directive '%s' at %s:%d is not applicable on Windows", curr->directive, curr->filename, curr->line_num);
#endif
    }
    else if ( strcasecmp(curr->directive, "perms") == 0 )
    {
#ifndef WIN32
	if ( conf->permissions != 0 )
	{
	    nx_conf_error(curr, "Perms is already defined");
	}
	conf->permissions = curr->args;
	if ( conf->permissions[0] != '0' )
	{
	    nx_conf_error(curr, "%s's octal value must start with '0'", curr->directive);
	}
	const char *mask = conf->permissions + 1;
	size_t i, len = strlen(mask);
	if ( len != 3 )
	{
	    nx_conf_error(curr, "malformed '%s', must have exactly 4 characters", curr->directive);
	}
	for ( i = 0; i < len; ++i )
	{
	    if ( mask[i] < '0' || mask[i] > '7' )
	    {
		nx_conf_error(curr, "only '0'-'7' characters are allowed in %s, found '%c'", curr->directive, mask[i]);
	    }
	    conf->_perm <<= 3;
	    conf->_perm |= (mode_t) (mask[i] - '0');
	}
#else
	log_warn("Directive '%s' at %s:%d is not applicable on Windows", curr->directive, curr->filename, curr->line_num);
#endif
    }
    else
    {
	ret = FALSE;
    }

    return ret;
}


#ifndef WIN32

// copy from apr
static mode_t apr_unix_perms2mode(apr_fileperms_t perms)
{
    mode_t mode = 0;

    if (perms & APR_USETID)
        mode |= S_ISUID;
    if (perms & APR_UREAD)
        mode |= S_IRUSR;
    if (perms & APR_UWRITE)
        mode |= S_IWUSR;
    if (perms & APR_UEXECUTE)
        mode |= S_IXUSR;

    if (perms & APR_GSETID)
        mode |= S_ISGID;
    if (perms & APR_GREAD)
        mode |= S_IRGRP;
    if (perms & APR_GWRITE)
        mode |= S_IWGRP;
    if (perms & APR_GEXECUTE)
        mode |= S_IXGRP;

#ifdef S_ISVTX
    if (perms & APR_WSTICKY)
        mode |= S_ISVTX;
#endif
    if (perms & APR_WREAD)
        mode |= S_IROTH;
    if (perms & APR_WWRITE)
        mode |= S_IWOTH;
    if (perms & APR_WEXECUTE)
        mode |= S_IXOTH;

    return mode;
}



// copy from apr
apr_fileperms_t apr_unix_mode2perms(mode_t mode)
{
    apr_fileperms_t perms = 0;

    if (mode & S_ISUID)
        perms |= APR_USETID;
    if (mode & S_IRUSR)
        perms |= APR_UREAD;
    if (mode & S_IWUSR)
        perms |= APR_UWRITE;
    if (mode & S_IXUSR)
        perms |= APR_UEXECUTE;

    if (mode & S_ISGID)
        perms |= APR_GSETID;
    if (mode & S_IRGRP)
        perms |= APR_GREAD;
    if (mode & S_IWGRP)
        perms |= APR_GWRITE;
    if (mode & S_IXGRP)
        perms |= APR_GEXECUTE;

#ifdef S_ISVTX
    if (mode & S_ISVTX)
        perms |= APR_WSTICKY;
#endif
    if (mode & S_IROTH)
        perms |= APR_WREAD;
    if (mode & S_IWOTH)
        perms |= APR_WWRITE;
    if (mode & S_IXOTH)
        perms |= APR_WEXECUTE;

    return perms;
}



/**
 *
 * @param conf perms values
 * @param file_or_dir_name
 */
void nx_fileperms_setperms(const nx_fileperms_conf_t *conf, const char *file_or_dir_name)
{
    ASSERT(conf != NULL);
    ASSERT(file_or_dir_name != NULL);

    apr_pool_t *tmp_pool = nx_pool_create_child(NULL);

    apr_finfo_t finfo;
    apr_status_t rv;
    rv = apr_stat(&finfo, file_or_dir_name, APR_FINFO_OWNER | APR_FINFO_PROT, tmp_pool);
    if ( APR_STATUS_IS_ENOENT(rv) )
    {
	// no file/directory
	apr_pool_destroy(tmp_pool);
	return;
    }
    else if ( rv != APR_SUCCESS )
    {
	apr_pool_destroy(tmp_pool);
	throw(rv, "apr_stat failed on file/directory '%s'", file_or_dir_name);
    }

    if ( conf->user != NULL || conf->group != NULL )
    {
	uid_t uid = conf->_uid;
	gid_t gid = conf->_gid;

	if ( conf->user == NULL || conf->group == NULL )
	{
	    if ( conf->user == NULL )
	    {
		uid = finfo.user;
	    }
	    if ( conf->group == NULL )
	    {
		gid = finfo.group;
	    }
	}

	if ( (uid != finfo.user) || (gid = finfo.group) )
	{
	    if ( lchown(file_or_dir_name, uid, gid) < 0 )
	    {
		log_errno("Couldn't change owner/group of '%s' to %s%s%s%s ", file_or_dir_name,
			(conf->user == NULL ? " " : "owner="), (conf->user == NULL ? "" : conf->user),
			(conf->group == NULL ? "" : " group="), (conf->group == NULL ? "" : conf->group)
			);
	    }
	}
    }

    if ( conf->permissions != NULL )
    {
	if ( conf->_perm != apr_unix_perms2mode(finfo.protection) )
	{
	    if ( chmod(file_or_dir_name, conf->_perm) < 0 )
	    {
		log_errno("Couldn't chmod() '%s' to %s", file_or_dir_name, conf->permissions);
	    }
	}
    }

    apr_pool_destroy(tmp_pool);
}

#endif


/**
 * Creates a directory for a file
 *
 * @param pool pool to use
 * @param conf conf values
 * @param filename file name in directory to be created
 */
void nx_fileperms_create_dir(apr_pool_t *pool, const nx_fileperms_conf_t *conf, const char *filename)
{
    ASSERT(pool != NULL);
    ASSERT(filename != NULL);
    ASSERT(conf != NULL);

    char pathname[APR_PATH_MAX + 1];
    char *idx;
    apr_pool_t *tmp_pool = NULL;

    idx = strrchr(filename, '/');
#ifdef WIN32
    if ( idx == NULL )
    {
	idx = strrchr(filename, '\\');
    }
#endif

    if ( idx == NULL )
    {
	log_debug("no directory in filename, cannot create");
	return;
    }

    ASSERT(sizeof (pathname) >= (size_t) (idx - filename + 1));
    apr_cpystrn(pathname, filename, (size_t) (idx - filename + 1));

    apr_fileperms_t perms = APR_OS_DEFAULT;

#ifndef WIN32
    if ( conf->permissions != NULL )
    {
	perms = apr_unix_mode2perms(conf->_perm);
    }
#endif

    tmp_pool = nx_pool_create_child(pool);
    apr_status_t rv = apr_dir_make_recursive(pathname, perms, tmp_pool);
    if ( rv != APR_SUCCESS )
    {
	apr_pool_destroy(tmp_pool);
	throw_msg("Couldn't create directory: %s (perms=%s)",
		pathname, conf->permissions != NULL ? conf->permissions : "OS_DEFAULT");
    }
    
    log_debug("Directory '%s' is created", pathname);

    apr_pool_destroy(tmp_pool);
}

