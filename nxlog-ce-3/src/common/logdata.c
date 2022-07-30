/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#include "error_debug.h"
#include "exception.h"
#include "logdata.h"
#include "date.h"
#include "module.h"

#define NX_LOGMODULE NX_LOGMODULE_CORE


void nx_logdata_free(nx_logdata_t *logdata)
{
    nx_logdata_field_t *field, *tmpfield;

    ASSERT(logdata != NULL);
    ASSERT(logdata->link.next == NULL);
    ASSERT(logdata->link.prev == NULL);

    field = NX_DLIST_FIRST(&(logdata->fields));
    while ( field != NULL )
    {
	free(field->key);
	nx_value_free(field->value);
	tmpfield = field;
	field = NX_DLIST_NEXT(field, link);
	free(tmpfield);
    }
    free(logdata);
}



void nx_logdata_field_free(nx_logdata_field_t *field)
{
    ASSERT(field != NULL);

    ASSERT(field->link.next == NULL);
    ASSERT(field->link.prev == NULL);

    free(field->key);
    if ( field->value != NULL )
    {
	nx_value_free(field->value);
    }
    free(field);
}



nx_logdata_t *nx_logdata_new_logline(const char *ptr, int len)
{
    nx_logdata_t *logdata;
    nx_value_t *val;

    ASSERT(ptr != NULL);

    logdata = malloc(sizeof(nx_logdata_t));
    memset(logdata, 0, sizeof(nx_logdata_t));
    NX_DLIST_INIT(&(logdata->fields), nx_logdata_field_t, link);
    if ( len == 0 )
    {
	logdata->raw_event = nx_string_new();	
    }
    else
    {
	logdata->raw_event = nx_string_create(ptr, len);
    }
    val = nx_value_new(NX_VALUE_TYPE_STRING);
    val->string = logdata->raw_event;
    nx_logdata_append_field_value(logdata, "raw_event", val);

    return ( logdata );
}



nx_logdata_t *nx_logdata_new()
{
    nx_logdata_t *logdata;
    nx_value_t *val;

    logdata = malloc(sizeof(nx_logdata_t));
    memset(logdata, 0, sizeof(nx_logdata_t));
    NX_DLIST_INIT(&(logdata->fields), nx_logdata_field_t, link);
    logdata->raw_event = nx_string_new_size(NX_LOGDATA_DEFAULT_BUFSIZE);
    val = nx_value_new(NX_VALUE_TYPE_STRING);
    val->string = logdata->raw_event;
    nx_logdata_append_field_value(logdata, "raw_event", val);

    return ( logdata );
}



void nx_logdata_append_logline(nx_logdata_t *logdata, 
			       const char *ptr,
			       int len)
{
    ASSERT(logdata != NULL);
    ASSERT(ptr != NULL);
    ASSERT(logdata->raw_event != NULL);

    uint32_t ptr_len = (uint32_t)strlen(ptr);
    if (len > (int)ptr_len)
    {
	len = ptr_len;
    }
    uint32_t appended_len = ptr_len + logdata->raw_event->len;
    if ( (len < 0 && appended_len > nx_string_get_limit()) || len > (int)nx_string_get_limit() )
    {
	len = (int) ( nx_string_get_limit() - logdata->raw_event->len );
	log_warn("nx_string truncated to limit length %d at nx_logdata_append_logline(), original length is %d",
		nx_string_get_limit(), appended_len);
    }

    nx_string_append(logdata->raw_event, ptr, len);
}



nx_logdata_t *nx_logdata_clone(nx_logdata_t *logdata)
{
    nx_logdata_t *new;
    nx_logdata_field_t *field;
    nx_value_t *value;

    ASSERT(logdata != NULL);

    new = malloc(sizeof(nx_logdata_t));
    memset(new, 0, sizeof(nx_logdata_t));

    for ( field = NX_DLIST_FIRST(&(logdata->fields));
	  field != NULL;
	  field = NX_DLIST_NEXT(field, link) )
    {
	value = nx_value_clone(NULL, field->value);
	nx_logdata_append_field_value(new, field->key, value);
	if ( (field->value->type == NX_VALUE_TYPE_STRING) &&
	     (field->value->defined == TRUE) &&
	     (field->value->string == logdata->raw_event) )
	{
	    new->raw_event = value->string;
	}
    }
    ASSERT(new->raw_event != NULL);
    
    return ( new );
}


/* This function should be used with care because it can cause problems
   since there is only one value per field allowed.
   Use nx_logdata_set_field_value() instead.
*/
void nx_logdata_append_field_value(nx_logdata_t *logdata,
				   const char *key,
				   nx_value_t *value)
{
    nx_logdata_field_t *field;

    ASSERT(logdata != NULL);
    ASSERT(key != NULL);
    ASSERT(value != NULL);

    field = malloc(sizeof(nx_logdata_field_t));
    ASSERT(field != NULL);
    field->value = value;
    field->key = strdup(key);

    NX_DLIST_INSERT_TAIL(&(logdata->fields), field, link);
}



/*
 *  Append if doesn't exist, otherwise replace old value
 */
void nx_logdata_set_field_value(nx_logdata_t *logdata,
				const char *key,
				nx_value_t *value)
{
    nx_logdata_field_t *field;

    ASSERT(logdata != NULL);
    ASSERT(key != NULL);
    ASSERT(value != NULL);

    for ( field = NX_DLIST_FIRST(&(logdata->fields));
	  field != NULL;
	  field = NX_DLIST_NEXT(field, link) )
    {
	if ( strcasecmp(field->key, key) == 0 )
	{
	    if ( strcmp(key, "raw_event") == 0 )
	    {
		if ( (value->defined == TRUE) && (value->type == NX_VALUE_TYPE_STRING) )
		{
		    logdata->raw_event = value->string;
		}
		else
		{
		    nx_value_type_t type = value->type;
		    nx_value_free(value);
		    if ( type != NX_VALUE_TYPE_STRING )
		    {
			throw_msg("'raw_event' cannot be set to %s type.",
				  nx_value_type_to_string(type));
		    }
		    throw_msg("'raw_event' cannot be set to an undefined value.");
		}
	    }
	    nx_value_free(field->value);
	    field->value = value;

	    return;
	}
    }

    nx_logdata_append_field_value(logdata, key, value);
}



/*
 *  Append if doesn't exist, otherwise replace old value
 */
void nx_logdata_set_field(nx_logdata_t *logdata, nx_logdata_field_t *setfield)
{
    nx_logdata_field_t *field;

    ASSERT(logdata != NULL);
    ASSERT(setfield != NULL);

    for ( field = NX_DLIST_FIRST(&(logdata->fields));
	  field != NULL;
	  field = NX_DLIST_NEXT(field, link) )
    {
	if ( strcasecmp(field->key, setfield->key) == 0 )
	{
	    nx_value_free(field->value);
	    field->value = setfield->value;
	    if ( strcmp(field->key, "raw_event") == 0 )
	    {
		if ( (setfield->value->defined == TRUE) && (setfield->value->type == NX_VALUE_TYPE_STRING) )
		{
		    logdata->raw_event = setfield->value->string;
		}
		else
		{
		    logdata->raw_event = nx_string_new_size(10);
		}
	    }
	    free(setfield->key);
	    free(setfield);
	    return;
	}
    }

    NX_DLIST_INSERT_TAIL(&(logdata->fields), setfield, link);
}



/*
 *  Rename a field if it exists
 */
void nx_logdata_rename_field(nx_logdata_t *logdata,
			     const char *old,
			     const char *new)
{
    nx_logdata_field_t *field;
    nx_logdata_field_t *exists = NULL;

    ASSERT(logdata != NULL);
    ASSERT(old != NULL);
    ASSERT(new != NULL);

    if ( strcmp(old, "raw_event") == 0 )
    {
	throw_msg("cannot rename field 'raw_event'");
    }

    for ( field = NX_DLIST_FIRST(&(logdata->fields));
	  field != NULL;
	  field = NX_DLIST_NEXT(field, link) )
    {
	if ( (strcasecmp(field->key, new) == 0) && (strcasecmp(old, new) != 0) )
	{
	    exists = field;
	    break;
	}
    }

    for ( field = NX_DLIST_FIRST(&(logdata->fields));
	  field != NULL;
	  field = NX_DLIST_NEXT(field, link) )
    {
	if ( strcasecmp(field->key, old) == 0 )
	{
	    if ( exists != NULL )
	    { // remove the destination field if it already exists
		if ( strcmp(new, "raw_event") == 0 )
		{
		    if ( field->value->type != NX_VALUE_TYPE_STRING )
		    {
			throw_msg("string type required for 'raw_event'");
		    }
		    logdata->raw_event = field->value->string;
		}
		NX_DLIST_REMOVE(&(logdata->fields), exists, link);
	    }
	    free(field->key);
	    field->key = strdup(new);
	    
	    return;
	}
    }
}



boolean nx_logdata_get_field_value(const nx_logdata_t *logdata,
				   const char *key,
				   nx_value_t *value)
{
    nx_logdata_field_t *field;

    ASSERT(logdata != NULL);
    ASSERT(key != NULL);
    ASSERT(value != NULL);

    for ( field = NX_DLIST_FIRST(&(logdata->fields));
	  field != NULL;
	  field = NX_DLIST_NEXT(field, link) )
    {
	if ( strcasecmp(field->key, key) == 0 )
	{
	    *value = *(field->value);
	    return ( TRUE );
	}
    }

    value->type = NX_VALUE_TYPE_UNKNOWN;
    value->defined = FALSE;

    return ( FALSE );
}



nx_logdata_field_t *nx_logdata_get_field(const nx_logdata_t *logdata,
					 const char *key)
{
    nx_logdata_field_t *field = NULL;

    ASSERT(logdata != NULL);
    ASSERT(key != NULL);

    for ( field = NX_DLIST_FIRST(&(logdata->fields));
	  field != NULL;
	  field = NX_DLIST_NEXT(field, link) )
    {
	if ( strcasecmp(field->key, key) == 0 )
	{
	    return ( field );
	}
    }

    return ( NULL );
}


/**
 * Return TRUE if the field was deleted, FALSE otherwise
 */
boolean nx_logdata_delete_field(nx_logdata_t *logdata,
				const char *key)
{
    nx_logdata_field_t *field = NULL;

    ASSERT(logdata != NULL);
    ASSERT(key != NULL);

    for ( field = NX_DLIST_FIRST(&(logdata->fields));
	  field != NULL;
	  field = NX_DLIST_NEXT(field, link) )
    {
	if ( strcmp(field->key, key) == 0 )
	{
	    if ( strcmp(field->key, "raw_event") == 0 )
	    {
		ASSERT((field->value->defined == TRUE) && 
		       (field->value->type == NX_VALUE_TYPE_STRING));
		ASSERT(logdata->raw_event != NULL);
		if ( logdata->raw_event->len == 0 )
		{
		    return ( FALSE );
		}
		nx_string_set(logdata->raw_event, "", 0);
	    }
	    else
	    {
		NX_DLIST_REMOVE(&(logdata->fields), field, link);
		nx_logdata_field_free(field);
	    }
	    return ( TRUE );
	}
    }

    return ( FALSE );
}



void nx_logdata_set_datetime(nx_logdata_t *logdata,
			     const char *key,
			     apr_time_t datetime)
{
    nx_value_t *val;

    ASSERT(logdata != NULL);

    val = nx_value_new_datetime(datetime);
    
    nx_logdata_set_field_value(logdata, key, val);
}



void nx_logdata_set_string(nx_logdata_t *logdata,
			   const char *key,
			   const char *value)
{
    nx_value_t *val;

    ASSERT(logdata != NULL);

    val = nx_value_new_string(value);
    
    nx_logdata_set_field_value(logdata, key, val);
}



void nx_logdata_set_integer(nx_logdata_t *logdata,
			    const char *key,
			    int64_t value)
{
    nx_value_t *val;

    ASSERT(logdata != NULL);

    val = nx_value_new_integer(value);
    
    nx_logdata_set_field_value(logdata, key, val);
}



void nx_logdata_set_binary(nx_logdata_t *logdata,
			   const char *key,
			   const char *value,
			   unsigned int len)
{
    nx_value_t *val;

    ASSERT(logdata != NULL);

    val = nx_value_new_binary(value, len);
    
    nx_logdata_set_field_value(logdata, key, val);
}



void nx_logdata_set_boolean(nx_logdata_t *logdata,
			    const char *key,
			    boolean value)
{
    nx_value_t *val;

    ASSERT(logdata != NULL);

    val = nx_value_new_boolean(value);
    
    nx_logdata_set_field_value(logdata, key, val);
}


void nx_logdata_dump_fields(nx_logdata_t *logdata)
{
    nx_logdata_field_t *field;
    char *value;

    ASSERT(logdata != NULL);
    
    for ( field = NX_DLIST_FIRST(&(logdata->fields));
	  field != NULL;
	  field = NX_DLIST_NEXT(field, link) )
    {
	value = nx_value_to_string(field->value);
	
	log_info("%s = [%s]", field->key, value);
	free(value);
    }
}


void nx_logdata_set_raw_event(nx_logdata_t *logdata)
{
    nx_logdata_set_raw_event_advanced(logdata, -1, NULL);
}


void nx_logdata_set_raw_event_advanced(nx_logdata_t *logdata, int field_size_limit, const char *field_null_value)
{
    nx_logdata_field_t *field = NULL;
    char tmpstr[64];
    apr_size_t retsize;
    apr_time_t eventtime = 0;
    char *value = NULL;
    nx_string_t *nx_value_escaped = NULL;
    int skip_raw_event = 0, skip_evtime = 0, skip_hostname = 0, skip_severity = 0;
    nx_string_t *body = NULL;
    nx_logdata_field_t *evtime = NULL, *hostname = NULL, *severity = NULL;

    ASSERT(logdata != NULL);
    ASSERT(logdata->raw_event != NULL);

    body = nx_string_new();

    ASSERT(body != NULL);

    nx_string_set(logdata->raw_event, "", -1);

    for ( field = NX_DLIST_FIRST(&(logdata->fields));
          field != NULL;
          field = NX_DLIST_NEXT(field, link) )
    {
        ASSERT(field->value != NULL);

        if ( (skip_raw_event == 0) && (strcasecmp(field->key, "raw_event") == 0) )
	{
            // prevent slow strcasecmp
            skip_raw_event = 1;
            continue;
	}
        else if ( (skip_evtime == 0) && (strcasecmp(field->key, "eventtime") == 0) )
        {
            skip_evtime = 1;
            evtime = field;
            continue;
        }
        else if ( (skip_hostname == 0) && (strcasecmp(field->key, "hostname") == 0) )
        {
            skip_hostname = 1;
            hostname = field;
            continue;
        }
        else if ( (skip_severity == 0) && (strcasecmp(field->key, "severity") == 0) )
        {
            skip_severity = 1;
            severity = field;
            continue;
        }

        if ( field->value->defined == FALSE )
        {
            if ( field_null_value != NULL )
            {
                nx_string_sprintf_append(body, " %s=\"%s\"", field->key, field_null_value);
            }
            continue;
        }
        {
            value = nx_value_to_string(field->value);
            nx_value_escaped = nx_string_create_owned_throw(value, -1);

            ASSERT(nx_value_escaped != NULL);

            nx_string_escape(nx_value_escaped);

            if ( (field_size_limit > 0) && (nx_value_escaped->len > (uint32_t) field_size_limit) )
            {
                nx_value_escaped->buf[field_size_limit] = '\0';
                nx_value_escaped->len = (uint32_t) field_size_limit;
            }

            nx_string_sprintf_append(body, " %s=\"%s\"", field->key, nx_value_escaped->buf);

            nx_string_free(nx_value_escaped);
            value = NULL;
        }
    }

    if ( (evtime != NULL) &&
         (evtime->value->type == NX_VALUE_TYPE_DATETIME) )
    {
	eventtime = evtime->value->datetime;
        nx_date_to_string(tmpstr, sizeof (tmpstr), NULL, &retsize, eventtime);
        nx_string_append(logdata->raw_event, tmpstr, (int) retsize);
    }
    else if ( (evtime != NULL) &&
              (evtime->value->type == NX_VALUE_TYPE_STRING) )
    {
        nx_string_append(logdata->raw_event, evtime->value->string->buf, (int) evtime->value->string->len);
    }
    else
    {
	eventtime = apr_time_now();
        nx_date_to_string(tmpstr, sizeof (tmpstr), NULL, &retsize, eventtime);
        nx_string_append(logdata->raw_event, tmpstr, (int) retsize);
    }

    // create header for raw_event
    nx_string_append(logdata->raw_event, " ", 1);

    // hostname
    if ( (hostname != NULL) &&
         (hostname->value->type == NX_VALUE_TYPE_STRING) )
    {
	nx_string_append(logdata->raw_event, hostname->value->string->buf, (int) hostname->value->string->len);
    }
    else
    {
	const nx_string_t *hoststr = nx_get_hostname();
	nx_string_append(logdata->raw_event, hoststr->buf, (int) hoststr->len);
    }
    nx_string_append(logdata->raw_event, " ", 1);

    // severity
    if ( (severity != NULL) &&
         (severity->value->type == NX_VALUE_TYPE_STRING) )
    {
	nx_string_append(logdata->raw_event, severity->value->string->buf, (int) severity->value->string->len);
    }
    else
    {
	nx_string_append(logdata->raw_event, "INFO", 4);
    }

    // append parsed body
    nx_string_append(logdata->raw_event, body->buf, (int) (body->len));
    
    nx_string_free(body);
}
