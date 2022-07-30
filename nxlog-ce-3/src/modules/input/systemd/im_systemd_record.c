/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev <avkhadeev@gmail.com>
 */

#include <pwd.h>
#include <grp.h>

#include "../../../common/module.h"
#include <systemd/sd-journal.h>


#define NX_LOGMODULE NX_LOGMODULE_MODULE


static const char * im_systemd_severity[] =
{
    "emerg",
    "alert",
    "critical",
    "error",
    "warning",
    "note",
    "info",
    "debug",
    "UNKNOWN"
};


static const char * im_systemd_facility[] =
{
    "kern",      //kernel messages
    "user",     //user-level messages
    "mail",     //mail system
    "daemon",   //system daemons
    "auth",     //security/authorization messages
    "syslog",   //messages generated internally by syslogd
    "lpr",      //line printer subsystem
    "news",     //network news subsystem
    "uucp",     //UUCP subsystem
    "clock",    //clock daemon
    "authpriv", //security/authorization messages
    "ftp",      //FTP daemon
    "ntp",      //NTP subsystem
    "audit",    //log audit
    "alert",    //log alert
    "cron",     //scheduling daemon
    "local0",   //local use 0 (local0)
    "local1",   //local use 1 (local1)
    "local2",   //local use 2 (local2)
    "local3",   //local use 3 (local3)
    "local4",   //local use 4 (local4)
    "local5",   //local use 5 (local5)
    "local6",   //local use 6 (local6)
    "local7"    //local use 7 (local7)
};


#define CHECK(x) if (!(x)) return FALSE;
#define BETWEEN(x,a,b) (x >= a && x <= b)


static boolean im_systemd_split_data(const void *data, size_t len,
                              char *name, size_t *nlen,
                              char *value, size_t *vlen)
{
    const char *ptr = (const char *) data;
    const char *end = ptr + len;
    size_t namelen;
    size_t vallen;
    size_t i;

    ASSERT(nlen);
    ASSERT(vlen);

    for ( i = 0; ptr < end; ptr++, i++ )
    {
	if ( *ptr == '=' )
	{
	    namelen = i;
	    vallen = (size_t)(end - ptr - 1);

	    if ( name != NULL )
	    {
		*nlen = (namelen < *nlen) ? namelen : *nlen;
		memcpy((void *)name, data, *nlen);
		name[*nlen] = 0;
	    }
	    else
	    {
		*nlen = namelen;
	    }
	    if ( value != NULL )
	    {
		*vlen = (vallen < *vlen) ? vallen : *vlen;
		memcpy((void*)value, ptr + 1, *vlen);
		value[*vlen] = 0;
	    }
	    else
	    {
		*vlen = vallen;
	    }
	    return ( TRUE );
	}
    }
    return ( FALSE );
}


static boolean im_systemd_journal_get_data(sd_journal *journal, const char *field, char *dest, size_t *dlen)
{
    const void *data;
    size_t len;
    size_t nlen;
    int err;
    ASSERT (journal);
    ASSERT (field);
    ASSERT (dlen);

    if ( (err = sd_journal_get_data(journal, field, &data, &len)) < 0 )
    {
	if ( err == -ENOENT )
	{
	    // Probably no such field
	    // It's normal situation
	    return ( FALSE );
	}
	log_error("get field '%s': %s", field, strerror(-err));
	return ( FALSE );
    }

    return im_systemd_split_data(data, len, NULL, &nlen, dest, dlen);
}


static boolean im_systemd_journal_get_str(sd_journal *journal, const char *field, char **zstr)
{
    char *str;
    size_t len;

    CHECK(im_systemd_journal_get_data(journal, field, NULL, &len));
    str = malloc(len + 1);
    str[len] = 0;
    *zstr = str;
    return im_systemd_journal_get_data(journal, field, str, &len);
}


static boolean im_systemd_journal_get_long(sd_journal *journal, const char *field, int64_t *value)
{
    char *str;
    char *endptr;
    boolean rv;

    ASSERT (value);

    CHECK(im_systemd_journal_get_str(journal, field, &str))

    *value = apr_strtoi64(str, &endptr, 10);

    rv = (*endptr == 0);
    free(str);

    return rv;
}


static void im_systemd_process_str(sd_journal *j, nx_logdata_t *logdata,
                            const char *sd_field, const char *nx_field)
{
    char *str;
    if ( im_systemd_journal_get_str(j, sd_field, &str) == TRUE )
    {
	nx_logdata_set_string(logdata, nx_field, str);
	free(str);
    }
}


static void im_systemd_process_long(sd_journal *j, nx_logdata_t *logdata,
                             const char *sd_field, const char *nx_field)
{
    int64_t val;
    if ( im_systemd_journal_get_long(j, sd_field, &val) == TRUE )
    {
	nx_logdata_set_integer(logdata, nx_field, val);
    }
}


static void im_systemd_process_severity(sd_journal *j, nx_logdata_t *logdata)
{
    int64_t severity;
    if( im_systemd_journal_get_long(j, "PRIORITY", &severity) == TRUE )
    {
	if ( BETWEEN(severity, 0, 7) == TRUE )
	{
	    nx_logdata_set_string(logdata, "Severity", im_systemd_severity[severity]);
	}
	nx_logdata_set_integer(logdata, "SeverityValue", severity);
    }
}


static void im_systemd_process_facility(sd_journal *j, nx_logdata_t *logdata)
{
    int64_t facility;

    if( im_systemd_journal_get_long(j, "SYSLOG_FACILITY", &facility) == TRUE )
    {
	if ( BETWEEN(facility, 0, 23)  == TRUE )
	{
	    nx_logdata_set_string(logdata, "Facility", im_systemd_facility[facility]);
	}
	nx_logdata_set_integer(logdata, "FacilityValue", facility);
    }
}


static void im_systemd_process_uid(sd_journal *journal, nx_logdata_t *logdata, const char *sd_field, const char *nx_field)
{
    int64_t uid;
    struct passwd *pwd;

    /*
     *   Can be changed to getpwuid_r() - thread-safe version of getpwuid()
     */
    if ( im_systemd_journal_get_long(journal, sd_field, &uid) == TRUE )
    {
	pwd = getpwuid((uid_t)uid);
	if ( pwd != NULL )
	{
	    nx_logdata_set_string(logdata, nx_field, pwd->pw_name);
	}
	else
	{
	    nx_logdata_set_integer(logdata, sd_field, uid);
	}
    }
}


static void im_systemd_process_gid(sd_journal *journal, nx_logdata_t *logdata, const char *sd_field, const char *nx_field)
{
    int64_t gid;
    struct group *grp;

    /*
     *   Can be changed to getgrgid_r() - thread-safe version of getgrgid()
     */
    if ( im_systemd_journal_get_long(journal, sd_field, &gid) == TRUE )
    {
	grp = getgrgid((gid_t)gid);
	if ( grp != NULL )
	{
	    nx_logdata_set_string(logdata, nx_field, grp->gr_name);
	}
	else
	{
	    nx_logdata_set_integer(logdata, sd_field, gid);
	}
    }
}


static void im_systemd_process_timestamp(sd_journal *j, nx_logdata_t *logdata, const char *sd_field, const char *nx_field)
{
    int64_t timestamp;
    if ( im_systemd_journal_get_long(j, sd_field, &timestamp) == TRUE )
    {
	nx_logdata_set_datetime(logdata, nx_field, timestamp);
    }
}


//Fill record with original field names
static void im_systemd_fill_originals(sd_journal *j, nx_logdata_t *logdata)
{
    const void *data;
    size_t len;
    nx_string_t *name = nx_string_new();
    nx_string_t *value = nx_string_new();
    size_t nlen;
    size_t vlen;

    SD_JOURNAL_FOREACH_DATA(j, data, len)
    {
	if ( im_systemd_split_data(data, len, NULL, &nlen, NULL, &vlen) == FALSE )
	{
	    continue;
	}
	nx_string_ensure_size(name, nlen + 1);
	nx_string_ensure_size(value, vlen + 1);

	im_systemd_split_data(data, len, name->buf, &nlen, value->buf, &vlen);
	nx_logdata_set_string(logdata, name->buf, value->buf);
    }
    nx_string_free(name);
    nx_string_free(value);
}


void im_systemd_process_logdata(sd_journal *journal, nx_logdata_t *logdata)
{
    // User Journal Fields
    im_systemd_process_severity(journal, logdata);
    im_systemd_process_facility(journal, logdata);
    im_systemd_process_str(journal, logdata, "MESSAGE", "Message");
    im_systemd_process_str(journal, logdata, "MESSAGE_ID", "MessageID");
    im_systemd_process_str(journal, logdata, "SYSLOG_IDENTIFIER", "SourceName");
    im_systemd_process_str(journal, logdata, "SYSLOG_PID", "ProcessID");
    im_systemd_process_str(journal, logdata, "CODE_FILE", "CodeFile");
    im_systemd_process_long(journal, logdata, "CODE_LINE", "CodeLine");
    im_systemd_process_str(journal, logdata, "CODE_FUNC", "CodeFunc");
    im_systemd_process_long(journal, logdata, "ERRNO", "Errno");


    //Trusted Journal Fields
    im_systemd_process_long(journal, logdata, "_PID", "ProcessID");
    im_systemd_process_uid(journal, logdata, "_UID", "User");
    im_systemd_process_gid(journal, logdata, "_GID", "Group");
    im_systemd_process_str(journal, logdata, "_COMM", "ProcessName");
    im_systemd_process_str(journal, logdata, "_EXE", "ProcessExecutable");
    im_systemd_process_str(journal, logdata, "_CMDLINE", "ProcessCmdLine");
    im_systemd_process_str(journal, logdata, "_CAP_EFFECTIVE", "Capabilities");
    im_systemd_process_long(journal, logdata, "_AUDIT_SESSION", "AuditSession");
    im_systemd_process_uid(journal, logdata, "_AUDIT_LOGINUID", "AuditUID");
    im_systemd_process_str(journal, logdata, "_SYSTEMD_CGROUP", "SystemdCGroup");
    im_systemd_process_str(journal, logdata, "_SYSTEMD_SESSION", "SystemdSession");
    im_systemd_process_str(journal, logdata, "_SYSTEMD_UNIT", "SystemdUnit");
    im_systemd_process_uid(journal, logdata, "_SYSTEMD_USER_UNIT", "SystemdUserUnit");
    im_systemd_process_uid(journal, logdata, "_SYSTEMD_OWNER_UID", "SystemdOwnerUID");
    im_systemd_process_str(journal, logdata, "_SYSTEMD_SLICE", "SystemdSlice");
    im_systemd_process_str(journal, logdata, "_SELINUX_CONTEXT", "SelinuxContext");
    im_systemd_process_timestamp(journal, logdata, "_SOURCE_REALTIME_TIMESTAMP", "EventTime");
    im_systemd_process_str(journal, logdata, "_BOOT_ID", "BootID");
    im_systemd_process_str(journal, logdata, "_MACHINE_ID", "MachineID");
    im_systemd_process_str(journal, logdata, "_SYSTEMD_INVOCATION_ID", "SysInvID");
    im_systemd_process_str(journal, logdata, "_HOSTNAME", "Hostname");
    im_systemd_process_str(journal, logdata, "_TRANSPORT", "Transport");

    //Kernel Journal Fields
    im_systemd_process_str(journal, logdata, "_KERNEL_DEVICE", "KernelDevice");
    im_systemd_process_str(journal, logdata, "_KERNEL_SUBSYSTEM", "KernelSubsystem");
    im_systemd_process_str(journal, logdata, "_UDEV_SYSNAME", "DevName");
    im_systemd_process_str(journal, logdata, "_UDEV_DEVNODE", "DevNode");
    im_systemd_process_str(journal, logdata, "_UDEV_DEVLINK", "DevLink");

    //Fields to log on behalf of a different program
    im_systemd_process_str(journal, logdata, "COREDUMP_UNIT", "CoredumpUnit");
    im_systemd_process_str(journal, logdata, "COREDUMP_USER_UNIT", "CoredumpUserUnit");
    im_systemd_process_long(journal, logdata, "OBJECT_PID", "ObjProcessID");
    im_systemd_process_uid(journal, logdata, "OBJECT_UID", "ObjUser");
    im_systemd_process_gid(journal, logdata, "OBJECT_GID", "ObjGroup");
    im_systemd_process_str(journal, logdata, "OBJECT_COMM", "ObjProcessName");
    im_systemd_process_str(journal, logdata, "OBJECT_EXE", "ObjProcessExecutable");
    im_systemd_process_str(journal, logdata, "OBJECT_CMDLINE", "ObjProcessCmdLine");
    im_systemd_process_long(journal, logdata, "OBJECT_AUDIT_SESSION", "ObjAuditSession");
    im_systemd_process_uid(journal, logdata, "OBJECT_AUDIT_LOGINUID", "ObjAuditUID");
    im_systemd_process_str(journal, logdata, "OBJECT_SYSTEMD_CGROUP", "ObjSystemdCGroup");
    im_systemd_process_str(journal, logdata, "OBJECT_SYSTEMD_SESSION", "ObjSystemdSession");
    im_systemd_process_str(journal, logdata, "OBJECT_SYSTEMD_UNIT", "ObjSystemdUnit");
    im_systemd_process_uid(journal, logdata, "OBJECT_SYSTEMD_OWNER_UID", "ObjSystemdOwnerUID");

    // fill raw_event field with name=value pairs
    nx_logdata_set_raw_event(logdata);

    //im_systemd_fill_originals(journal, logdata);
}
