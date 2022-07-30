/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 * Author: Roman Avkhadeev <avkhadeev@gmail.com>
 */

#include <apr_lib.h>

#include "../../../common/module.h"
#include "../../../common/event.h"
#include "../../../common/error_debug.h"
#include "../../../common/alloc.h"
#include "../../../common/expr-parser.h"
#include "../../../core/ctx.h"

#include "om_raijin.h"
#include "../../extension/json/yajl/api/yajl_gen.h"
#include "../../extension/json/yajl/api/yajl_parse.h"
#include "../../../modules/extension/json/json.h"

#define NX_LOGMODULE NX_LOGMODULE_MODULE

#define OM_RAIJIN_RAW_EVENT_PREFIX "{\"raw_event\":\""
#define OM_RAIJIN_RAW_EVENT_SUFFIX "\"}\n"

#define OM_RAIJIN_DEFAULT_CONNECT_TIMEOUT (APR_USEC_PER_SEC * 30)
#define OM_RAIJIN_TIMEOUT_SEC 30


static void om_raijin_data_available(nx_module_t *module);
static void om_raijin_flush(nx_module_t *module);
static void om_raijin_add_logdata(nx_module_t *module, nx_logdata_t *logdata);
static void om_raijin_reset(nx_module_t *module);
static boolean _om_raijin_do_handshake(nx_module_t *module);


static void throw_sslerror(const char	*fmt, ...) PRINTF_FORMAT(1,2) NORETURN;
static void throw_sslerror(const char	*fmt, ...)
{
    char buf[NX_LOGBUF_SIZE];
    va_list ap;

    va_start(ap, fmt);
    apr_vsnprintf(buf, NX_LOGBUF_SIZE, fmt, ap);
    va_end(ap);
    throw_msg("%s: %s", buf, ERR_reason_error_string(ERR_get_error()));
}


static boolean _om_raijin_is_ssl_enabled(nx_om_raijin_conf_t *modconf)
{
    return modconf->server.https;
}


static boolean _om_raijin_socket_is_ready(nx_om_raijin_conf_t *modconf)
{
    return (modconf->state == NX_SOCKET_STATE_READY) ? TRUE : FALSE;
}


static boolean _om_raijin_socket_is_handshaking(nx_om_raijin_conf_t *modconf)
{
    return (modconf->state == NX_SOCKET_STATE_HANDSHAKING) ? TRUE : FALSE;
}


static boolean _om_raijin_socket_is_connected(nx_om_raijin_conf_t *modconf)
{
    return (modconf->state == NX_SOCKET_STATE_CONNECTED) ? TRUE : FALSE;
}


static void _om_raijin_reset_socket_state(nx_om_raijin_conf_t *modconf)
{
    log_debug("_om_raijin_reset_socket_state");
    modconf->state = NX_SOCKET_STATE_NONE;
}


static void _om_raijin_set_socket_state(nx_om_raijin_conf_t *modconf, nx_socket_state_t state)
{
    modconf->state = state;
    log_debug("_om_raijin_set_socket_state switch to state %d", modconf->state);

    if ( _om_raijin_socket_is_connected(modconf) == TRUE )
    {
	log_debug("successfully connected to %s:%d", modconf->server.host, modconf->server.port);
	modconf->reconnect = 0;
    }
}


static void om_raijin_add_reconnect_event(nx_module_t *module)
{
    nx_event_t *event;
    nx_om_raijin_conf_t *modconf;

    modconf = (nx_om_raijin_conf_t *) module->config;

    if ( modconf->reconnect_event != NULL )
    {
	return;
    }

    if ( modconf->reconnect == 0 )
    {
	modconf->reconnect = 1;
    }
    else
    {
	modconf->reconnect *= 2;
    }

    if ( modconf->reconnect > 20 * 60 )
    {
	modconf->reconnect = 20 * 60;
    }

    log_debug("om_raijin_add_reconnect_event reconnecting in %d seconds", modconf->reconnect);

    event = nx_event_new();
    event->module = module;
    if ( modconf->reconnect == 0 )
    {
	event->delayed = FALSE;
    }
    else
    {
	event->delayed = TRUE;
	event->time = apr_time_now() + APR_USEC_PER_SEC * modconf->reconnect;
    }
    event->type = NX_EVENT_RECONNECT;
    event->priority = module->priority;
    
    modconf->reconnect_event = nx_event_add(event);
}


static void om_raijin_timeout_event(nx_module_t *module)
{
    nx_event_t *event;
    nx_om_raijin_conf_t *modconf;

    modconf = (nx_om_raijin_conf_t *) module->config;

    if ( modconf->timeout_event != NULL )
    {
	return;
    }

    log_debug("adding new timeout event");

    event = nx_event_new();
    event->module = module;
    event->delayed = TRUE;
    event->type = NX_EVENT_TIMEOUT;
    event->time = apr_time_now() + APR_USEC_PER_SEC * OM_RAIJIN_TIMEOUT_SEC;
    event->priority = module->priority;
    
    modconf->timeout_event = nx_event_add(event);
}


static void om_raijin_add_flush_event(nx_module_t *module)
{
    nx_event_t *event;
    nx_om_raijin_conf_t *modconf;

    modconf = (nx_om_raijin_conf_t *) module->config;

    if ( modconf->flush_event != NULL )
    {
	return;
    }

    event = nx_event_new();
    event->module = module;
    event->delayed = TRUE;
    event->time = apr_time_now() + (apr_time_t) (APR_USEC_PER_SEC * modconf->flush_interval);
    event->type = NX_EVENT_MODULE_SPECIFIC;
    event->priority = module->priority;
    
    modconf->flush_event = nx_event_add(event);
}


static void om_raijin_recreate_request(nx_module_t *module)
{
    nx_om_raijin_conf_t *modconf = (nx_om_raijin_conf_t *) module->config;

    if ( (modconf->bio_reqhdr == NULL) || (modconf->bio_reqbdy == NULL) )
    {
	log_debug("om_raijin_recreate_request no bio");
	return;
    }

    modconf->reqhdrbufsize = (apr_size_t) BIO_get_mem_data(modconf->bio_reqhdr, &(modconf->reqhdrbuf));
    modconf->reqbdybufsize = (apr_size_t) BIO_get_mem_data(modconf->bio_reqbdy, &(modconf->reqbdybuf));

    log_debug("om_raijin_recreate_request: recreated (headers size: %d; body size: %d)", (int) modconf->reqhdrbufsize, (int) modconf->reqbdybufsize);
    modconf->recreate = TRUE;
}


static void om_raijin_disconnect(nx_module_t *module, boolean reconnect)
{
    nx_om_raijin_conf_t *modconf;

    ASSERT(module != NULL);

    modconf = (nx_om_raijin_conf_t *) module->config;

    log_debug("om_raijin_disconnect");

    if ( modconf->ssl != NULL )
    {
	log_debug("om_raijin_disconnect destroy ssl");
	nx_ssl_destroy(&modconf->ssl);
    }

    if ( modconf->sock != NULL )
    {
	log_debug("om_raijin_disconnect close socket");
	nx_module_pollset_remove_socket(module, modconf->sock);
	nx_module_remove_events_by_data(module, modconf->sock);
	apr_socket_close(modconf->sock);
	modconf->sock = NULL;
    }

    _om_raijin_reset_socket_state(modconf);
    apr_pool_clear(modconf->pool);

    if ( reconnect == TRUE )
    {
	log_debug("om_raijin_disconnect reconnect");
	if ( (modconf->reqhdrbufsize > 0) ||
	     (modconf->reqbdybufsize > 0) ||
	     (modconf->resp_wait == TRUE) )
	{
	    log_debug("om_raijin_disconnect recreate");
	    om_raijin_recreate_request(module);
	}

	om_raijin_add_reconnect_event(module);
    }
}


static void om_raijin_reset(nx_module_t *module)
{
    nx_om_raijin_conf_t *modconf;

    ASSERT(module != NULL);

    log_debug("om_raijin_reset");

    modconf = (nx_om_raijin_conf_t *) module->config;

    modconf->resp_wait = FALSE;

    memset(modconf->respbuf, 0, NX_OM_RAIJIN_RESPBUFSIZE);
    modconf->respbuflen = 0;
    modconf->respheaderlen = 0;

    if ( modconf->bio_resp_head != NULL )
    {
	BIO_free_all(modconf->bio_resp_head);
	modconf->bio_resp_head = NULL;
    }

    if ( modconf->bio_resp_body != NULL )
    {
	BIO_free_all(modconf->bio_resp_body);
	modconf->bio_resp_body = NULL;
    }

    if ( modconf->bio_reqbdy != NULL )
    {
        BIO_free_all(modconf->bio_reqbdy);
        modconf->bio_reqbdy = NULL;
    }

    if ( modconf->bio_reqhdr != NULL )
    {
	BIO_free_all(modconf->bio_reqhdr);
	modconf->bio_reqhdr = NULL;
    }

    modconf->bulk_data_cnt = 0;

    modconf->resp_state = NX_OM_RAIJIN_RESP_STATE_START;
    modconf->content_length = 0;
    modconf->got_resp_body = FALSE;
    modconf->got_resp_head = FALSE;
    if ( modconf->timeout_event != NULL )
    {
	nx_event_remove(modconf->timeout_event);
	nx_event_free(modconf->timeout_event);
	modconf->timeout_event = NULL;
    }

    if ( modconf->flush_event != NULL )
    {
	nx_event_remove(modconf->flush_event);
	nx_event_free(modconf->flush_event);
	modconf->flush_event = NULL;
    }

    // POLLIN is to detect disconnection
    if ( modconf->sock != NULL )
    {
	nx_module_pollset_add_socket(module, modconf->sock, APR_POLLIN | APR_POLLHUP);
    }
    // in case we have some data, make sure the module resumes
    om_raijin_data_available(module);
}


static void om_raijin_add_data_available_event(nx_module_t *module, apr_time_t delay)
{
    nx_event_t *event;

    ASSERT(module != NULL);

    event = nx_event_new();
    event->module = module;
    event->type = NX_EVENT_DATA_AVAILABLE;
    event->delayed = (delay != 0) ? TRUE : FALSE;
    event->time = 0;
    if ( delay != 0 )
    {
	event->time = apr_time_now() + delay;
    }
    event->priority = module->priority;
    nx_event_add(event);
}


static void om_raijin_data_available(nx_module_t *module)
{
    nx_logdata_t *logdata;
    nx_om_raijin_conf_t *modconf;
    int datacnt = 0;

    log_debug("om_raijin_data_available");

    modconf = (nx_om_raijin_conf_t *) module->config;

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
	log_debug("module %s not running, not processing any more data", module->name);
	return;
    }

    if ( _om_raijin_is_ssl_enabled(modconf) == TRUE )
    {
	if ( _om_raijin_socket_is_ready(modconf) == TRUE )
	{
	    _om_raijin_set_socket_state(modconf, NX_SOCKET_STATE_HANDSHAKING);
	    om_raijin_timeout_event(module);
	}

	if ( _om_raijin_socket_is_handshaking(modconf) == TRUE )
	{
	    if ( _om_raijin_do_handshake(module) == FALSE )
	    {
		return;
	    }
	}
    }

    if ( _om_raijin_socket_is_connected(modconf) == FALSE )
    {
	return;
    }

    if ( modconf->resp_wait == TRUE )
    {
	log_debug("om_raijin_data_available resp_wait");

	om_raijin_add_data_available_event(module, 100 * 1000);
	nx_module_pollset_wakeup(module);
	return;
    }

    if ( modconf->recreate == TRUE )
    {
	log_debug("om_raijin_data_available send recreate");

	om_raijin_flush(module);
	om_raijin_add_data_available_event(module, 100 * 1000);
	nx_module_pollset_wakeup(module);
	return;
    }

    for ( datacnt = 0; datacnt < NX_OM_RAIJIN_BATCH_SIZE; datacnt++ )
    {
	if ( (logdata = nx_module_logqueue_peek(module)) != NULL )
	{
	    if ( datacnt == 0 )
	    {
		if ( modconf->bio_reqbdy == NULL )
		{
		    if ( (modconf->bio_reqbdy = BIO_new(BIO_s_mem())) == NULL )
		    {
			throw_sslerror("BIO_new() failed");
		    }
		}

	    }
	    om_raijin_add_logdata(module, logdata);
	    nx_module_logqueue_pop(module, logdata);
	    nx_logdata_free(logdata);
	}
	else
	{
	    break;
	}
    }

    if ( modconf->bulk_data_cnt >= modconf->flush_limit )
    {
	om_raijin_flush(module);
    }

    if ( datacnt == NX_OM_RAIJIN_BATCH_SIZE )
    {
	nx_module_data_available(module);
    }
}


static nx_string_t *om_raijin_to_json(nx_logdata_t *logdata)
{
    nx_string_t *retval;

    if ( logdata->raw_event->len == 0 )
    {
	return nx_logdata_to_json_string_ex(logdata);
    }

    // { "raw_event": "value" };
    retval = nx_string_clone(logdata->raw_event);
    nx_string_escape_json(retval);
    nx_string_prepend(retval,
		      OM_RAIJIN_RAW_EVENT_PREFIX,
		      sizeof(OM_RAIJIN_RAW_EVENT_PREFIX) - 1);
    nx_string_append(retval,
		     OM_RAIJIN_RAW_EVENT_SUFFIX,
		     sizeof(OM_RAIJIN_RAW_EVENT_SUFFIX) - 1);

    return retval;
}


static void om_raijin_add_logdata(nx_module_t *module, nx_logdata_t *logdata)
{
    nx_om_raijin_conf_t *modconf;

    modconf = (nx_om_raijin_conf_t *) module->config;

    log_debug("om_raijin_add_logdata");

    (modconf->bulk_data_cnt)++;

    om_raijin_add_flush_event(module);
//    BIO_printf(modconf->bio_reqbdy, "insert into %s.%s ", modconf->dbname, modconf->dbtable);

    if ( nx_json_is_valid(logdata->raw_event->buf, (int) logdata->raw_event->len) != FALSE )
    {
        BIO_write(modconf->bio_reqbdy, logdata->raw_event->buf, (int) logdata->raw_event->len);
        BIO_write(modconf->bio_reqbdy, "\n", 1);
    }
    else
    {
        nx_string_t *json = om_raijin_to_json(logdata);
        BIO_write(modconf->bio_reqbdy, json->buf, (int) json->len);
    }
}


static void om_raijin_create_request(nx_module_t *module)
{
    nx_om_raijin_conf_t *modconf;
    char tmpstr[1000];
    nx_exception_t e;

    modconf = (nx_om_raijin_conf_t *) module->config;

    log_debug("om_raijin_create_request");

    try
    {
	if ( modconf->bio_reqhdr != NULL )
	{
	    BIO_free_all(modconf->bio_reqhdr);
	}
	if ( (modconf->bio_reqhdr = BIO_new(BIO_s_mem())) == NULL )
	{
	    throw_sslerror("BIO_new() failed");
	}

        BIO_puts(modconf->bio_reqhdr, "POST ");

        // Request like: POST %url%/%db_name%/%db_table%
        apr_snprintf(tmpstr, sizeof(tmpstr), "%s%s/%s ",
                         ((modconf->use_proxy == TRUE) ? modconf->server.url : modconf->server.path),
                         modconf->dbname,
                         modconf->dbtable);
        BIO_puts(modconf->bio_reqhdr, tmpstr);

	BIO_puts(modconf->bio_reqhdr, "HTTP/1.1\r\n");
	BIO_puts(modconf->bio_reqhdr, "User-Agent: " PACKAGE "\r\n");
	BIO_puts(modconf->bio_reqhdr, "Host: ");
	BIO_puts(modconf->bio_reqhdr, modconf->server.host);
	BIO_puts(modconf->bio_reqhdr, ":");
	apr_snprintf(tmpstr, sizeof(tmpstr), "%d", modconf->server.port);
	BIO_puts(modconf->bio_reqhdr, tmpstr);
	BIO_puts(modconf->bio_reqhdr, "\r\n");
	BIO_puts(modconf->bio_reqhdr, "Content-Type: application/json; charset=utf-8");
	BIO_puts(modconf->bio_reqhdr, "\r\n");
	BIO_puts(modconf->bio_reqhdr, "Connection: Keep-Alive\r\n");
	BIO_puts(modconf->bio_reqhdr, "Keep-Alive: 300\r\n");
	BIO_puts(modconf->bio_reqhdr, "Content-Length: ");

	modconf->reqbdybufsize = (apr_size_t) BIO_get_mem_data(modconf->bio_reqbdy, &(modconf->reqbdybuf));

	apr_snprintf(tmpstr, sizeof(tmpstr), "%d", (int) modconf->reqbdybufsize);
	BIO_puts(modconf->bio_reqhdr, tmpstr);
	BIO_puts(modconf->bio_reqhdr, "\r\n\r\n");
	modconf->reqhdrbufsize = (apr_size_t) BIO_get_mem_data(modconf->bio_reqhdr, &(modconf->reqhdrbuf));
    }
    catch(e)
    {
	if ( modconf->bio_reqhdr != NULL )
	{
	    BIO_free_all(modconf->bio_reqhdr);
	    modconf->bio_reqhdr = NULL;
	}
	rethrow(e);
    }
}


static void om_raijin_send(nx_module_t *module, const char **reqbuf, size_t *reqbufsize)
{
    apr_size_t nbytes;
    apr_status_t rv;
    nx_om_raijin_conf_t *modconf;
    int sslrv;
    int nbytes2;
    nx_exception_t e;

    modconf = (nx_om_raijin_conf_t *) module->config;

    log_debug("om_raijin_send");

    while ( *reqbufsize > 0 )
    {
	if ( _om_raijin_is_ssl_enabled(modconf) == TRUE )
	{
	    nbytes2 = (int) *reqbufsize;
	    sslrv = nx_ssl_write(modconf->ssl, *reqbuf, &nbytes2);

	    switch ( sslrv )
	    {
		case SSL_ERROR_NONE:
		    *reqbufsize -= (apr_size_t) nbytes2;
		    *reqbuf += (apr_size_t) nbytes2;
		    log_debug("om_raijin sent %d bytes", (int) nbytes2);

		    nx_module_pollset_add_socket(module, modconf->sock, APR_POLLIN | APR_POLLHUP);
		    nx_module_add_poll_event(module);
		    break;
		case SSL_ERROR_ZERO_RETURN: // disconnected
		    log_warn("raijin server disconnected");
		    om_raijin_disconnect(module, TRUE);
		    om_raijin_reset(module);
		    break;
		case SSL_ERROR_WANT_WRITE:
		    nx_module_pollset_add_socket(module, modconf->sock, APR_POLLIN | APR_POLLOUT | APR_POLLHUP);
		    nx_module_add_poll_event(module);
		    break;
		case SSL_ERROR_WANT_READ:
		    nx_module_pollset_add_socket(module, modconf->sock, APR_POLLIN | APR_POLLHUP);
		    nx_module_add_poll_event(module);
		    break;
		default:
		try
			{
			    nx_ssl_check_io_error(modconf->ssl, sslrv);
			}
		catch(e)
		    {
			om_raijin_disconnect(module, TRUE);
			om_raijin_reset(module);
			rethrow(e);
		    }
		    om_raijin_disconnect(module, TRUE);
		    om_raijin_reset(module);
		    break;
	    }
	}
	else
	{
	    nbytes = *reqbufsize;
	    rv = apr_socket_send(modconf->sock, *reqbuf, &nbytes);
	    *reqbufsize -= nbytes;
	    *reqbuf += nbytes;
	    if ( rv != APR_SUCCESS )
	    {
		if ( APR_STATUS_IS_EPIPE(rv) == TRUE )
		{
		    log_debug("om_raijin got EPIPE");
		    om_raijin_disconnect(module, TRUE);
		    break;
		}
		else if ( (APR_STATUS_IS_EINPROGRESS(rv) == TRUE) ||
			  (APR_STATUS_IS_EAGAIN(rv) == TRUE) )
		{
		    log_debug("om_raijin got EAGAIN");
		    nx_module_pollset_add_socket(module, modconf->sock,
						 APR_POLLIN | APR_POLLOUT | APR_POLLHUP);
//		    nx_module_add_poll_event(module);
		    break;
		}
		else
		{
		    throw(rv, "apr_socket_send failed");
		}
	    }
	    else
	    { // Sent OK
		log_debug("om_raijin sent %d bytes (remaining: %d)",
			  (int) nbytes, (int) *reqbufsize);
		nx_module_pollset_add_socket(module, modconf->sock,
					     APR_POLLIN | APR_POLLHUP);
		nx_module_add_poll_event(module);
	    }
	}
    }
}


static void io_err_handler(nx_module_t *module, nx_exception_t *e) NORETURN;
static void io_err_handler(nx_module_t *module, nx_exception_t *e)
{
    ASSERT(e != NULL);
    ASSERT(module != NULL);

    om_raijin_disconnect(module, TRUE);
    rethrow(*e);
}


static void om_raijin_connect(nx_module_t *module)
{
    nx_om_raijin_conf_t *modconf;
    apr_sockaddr_t *sa;
    nx_exception_t e;

    ASSERT(module->config != NULL);

    modconf = (nx_om_raijin_conf_t *) module->config;

    _om_raijin_reset_socket_state(modconf);

    log_debug("om_raijin_connect");

    try
	    {
		if ( modconf->use_proxy == TRUE )
		{
		    log_debug("om_raijin_connect to proxy %s:%d", modconf->proxy_addr, modconf->proxy_port);
		    CHECKERR_MSG(apr_sockaddr_info_get(&sa, modconf->proxy_addr, APR_UNSPEC,
						       modconf->proxy_port, 0, modconf->pool),
				 "apr_sockaddr_info failed for proxy %s:%d",
				 modconf->proxy_addr, modconf->proxy_port);
		}
		else
		{
		    CHECKERR_MSG(apr_sockaddr_info_get(&sa, modconf->server.host, APR_UNSPEC,
						       modconf->server.port, 0, modconf->pool),
				 "apr_sockaddr_info failed for %s:%d",
				 modconf->server.host, modconf->server.port);
		}
		CHECKERR_MSG(apr_socket_create(&(modconf->sock), sa->family, SOCK_STREAM,
					       APR_PROTO_TCP, modconf->pool),
			     "couldn't create tcp socket");
		CHECKERR_MSG(apr_socket_opt_set(modconf->sock, APR_SO_NONBLOCK, 0),
			     "couldn't set SO_NONBLOCK on connecting socket");
		CHECKERR_MSG(apr_socket_timeout_set(modconf->sock, OM_RAIJIN_TIMEOUT_SEC * APR_USEC_PER_SEC),
			     "couldn't set socket timeout on connecting socket");

		if ( modconf->use_proxy == TRUE )
		{
		    log_debug("connecting to proxy %s:%d", modconf->proxy_addr, modconf->proxy_port);
		    CHECKERR_MSG(apr_socket_connect(modconf->sock, sa),
				 "couldn't connect to tcp socket on %s:%d", modconf->proxy_addr,
				 modconf->proxy_port);
		}
		else
		{
		    log_debug("connecting to %s:%d", modconf->server.host, modconf->server.port);
		    CHECKERR_MSG(apr_socket_connect(modconf->sock, sa),
				 "couldn't connect to tcp socket on %s:%d", modconf->server.host,
				 modconf->server.port);
		}

		if ( _om_raijin_is_ssl_enabled(modconf) == TRUE )
		{
		    modconf->ssl = nx_ssl_from_socket_ex(&modconf->ssl_ctx, modconf->sock, modconf->ssl_options, modconf->ssl_cipher_list, BIO_NOCLOSE);
		    ASSERT(modconf->ssl != NULL);

		    CHECKERR_MSG(apr_socket_opt_set(modconf->sock, APR_SO_NONBLOCK, 0),
				 "couldn't set SO_NONBLOCK on connecting socket");
		    CHECKERR_MSG(apr_socket_timeout_set(modconf->sock, OM_RAIJIN_TIMEOUT_SEC * APR_USEC_PER_SEC),
				 "couldn't set socket timeout on connecting socket");
		}

		nx_module_pollset_add_socket(module, modconf->sock, APR_POLLIN | APR_POLLHUP);
		nx_module_add_poll_event(module);

		CHECKERR_MSG(apr_socket_opt_set(modconf->sock, APR_SO_NONBLOCK, 1),
			     "couldn't set SO_NONBLOCK on tcp socket");
		CHECKERR_MSG(apr_socket_timeout_set(modconf->sock, 0),
			     "couldn't set socket timeout on tcp socket");
		CHECKERR_MSG(apr_socket_opt_set(modconf->sock, APR_SO_KEEPALIVE, 1),
			     "couldn't set TCP_KEEPALIVE on connecting socket");

		if ( _om_raijin_is_ssl_enabled(modconf) == TRUE )
		{
		    SSL_set_connect_state(modconf->ssl);
		    _om_raijin_set_socket_state(modconf, NX_SOCKET_STATE_READY);
		}
		else
		{
		    _om_raijin_set_socket_state(modconf, NX_SOCKET_STATE_CONNECTED);
		}

		nx_module_data_available(module);
	    }
    catch(e)
    {
        log_exception(e);
	io_err_handler(module, &e);
    }
}


static void om_raijin_send_request(nx_module_t *module)
{
    nx_om_raijin_conf_t *modconf;

    ASSERT(module->config != NULL);
    modconf = (nx_om_raijin_conf_t *) module->config;


    log_debug("om_raijin_send_request (%d %d)", (int) modconf->reqhdrbufsize,
	      (int) modconf->reqbdybufsize);

    if ( _om_raijin_is_ssl_enabled(modconf) == TRUE )
    {
	if ( _om_raijin_socket_is_ready(modconf) == TRUE )
	{
	    _om_raijin_set_socket_state(modconf, NX_SOCKET_STATE_HANDSHAKING);
	    om_raijin_timeout_event(module);
	}

	if ( _om_raijin_socket_is_handshaking(modconf) == TRUE )
	{
	    if ( _om_raijin_do_handshake(module) == FALSE )
	    {
		return;
	    }
	}
    }

    if ( _om_raijin_socket_is_connected(modconf) == FALSE )
    {
	if ( modconf->reconnect_event == NULL )
	{
	    om_raijin_add_reconnect_event(module);
	    return;
	}
    }

    if ( modconf->reqhdrbufsize + modconf->reqbdybufsize > 0 )
    {
	if ( _om_raijin_socket_is_connected(modconf) == TRUE )
	{
	    om_raijin_timeout_event(module); // add timeout

	    modconf->resp_wait = TRUE;

	    if ( modconf->reqhdrbufsize > 0 )
	    {
		om_raijin_send(module, &(modconf->reqhdrbuf), &(modconf->reqhdrbufsize));
	    }

	    if ( (modconf->reqhdrbufsize == 0) && (modconf->reqbdybufsize > 0) )
	    {
		om_raijin_send(module, &(modconf->reqbdybuf), &(modconf->reqbdybufsize));
	    }
	}
    }
}


static void om_raijin_flush(nx_module_t *module)
{
    nx_om_raijin_conf_t *modconf;

    ASSERT(module->config != NULL);
    modconf = (nx_om_raijin_conf_t *) module->config;

    log_debug("om_raijin_flush");

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
	log_debug("module %s not running, no flush", module->name);
	return;
    }

    if ( (modconf->bulk_data_cnt > 0) || (modconf->recreate == TRUE) )
    {
	om_raijin_create_request(module);
	om_raijin_send_request(module);
    }

    if ( modconf->flush_event != NULL )
    {
	nx_event_remove(modconf->flush_event);
	nx_event_free(modconf->flush_event);
	modconf->flush_event = NULL;
    }
}


static void om_raijin_check_resp_head(nx_module_t *module)
{
    nx_om_raijin_conf_t *modconf;
    char *ptr;
    int i;
    int value_len = 0;
    char *value;

    modconf = (nx_om_raijin_conf_t *) module->config;

    modconf->transfer_encoding[0] = 0;
    modconf->chunked = FALSE;

    BIO_get_mem_data(modconf->bio_resp_head, &ptr);

    if ( strncmp(ptr, "HTTP/", 5) != 0 )
    {
	throw_msg("invalid HTTP response");
    }
    for ( ; *ptr != ' '; ptr++ );
    for ( ; *ptr == ' '; ptr++ );

    if ( !((strncmp(ptr, "201 ", 4) == 0 )
	   || (strncmp(ptr, "202 ", 4) == 0)
	   || (strncmp(ptr, "200 ", 4) == 0)) )
    {
	for ( i = 0; (ptr[i] != '\0') && (ptr[i] != '\r'); i++ );
	ptr[i] = '\0';
	throw_msg("HTTP response status is not OK: %s", ptr);
    }
    for ( i = 0; (ptr[i] != '\0') && (ptr[i] != '\r'); i++ );
    for ( ; (ptr[i] == '\r') || (ptr[i] == '\n'); i++ );
    ptr += i;

    for ( ; ; )
    {
	if ( strncasecmp(ptr, "Content-Length:", 15) == 0 )
	{
	    ptr += 15;
	    for ( ; *ptr == ' '; ptr++ );
	    modconf->content_length = (apr_size_t) atoi(ptr);
	    for ( ; (*ptr != '\0') && (*ptr != '\r'); ptr++ );
	}
	else if ( strncasecmp(ptr, "Transfer-Encoding:", 18) == 0 )
	{
	    ptr += 18;
	    for ( ; *ptr == ' '; ptr++ );
	    value = ptr;
	    for ( ; (*ptr != '\0') && (*ptr != '\r'); ptr++ )
	    {
		value_len ++;
	    }
	    if ( value_len > 0 )
	    {
	        if ( strncmp(value, "chunked", 7) == 0 )
		{
	            modconf->chunked = TRUE;
		}
	        apr_snprintf(modconf->transfer_encoding, sizeof(modconf->transfer_encoding) - 1, "%.*s", value_len, value);
	    }
	}
	else
	{
	    for ( ; (*ptr != '\0') && (*ptr != '\r'); ptr++ );
	}
	if ( *ptr == '\r' )
	{
	    ptr++;
	}
	if ( *ptr == '\n' )
	{
	    ptr++;
	}

	if ( *ptr == '\0' )
	{
	    break;
	}
    }
/*
    if ( modconf->content_length == 0 )
    {
	throw_msg("Content-Length required in response");
    }
*/
    if ( modconf->content_length > 1024*1024*100 )
    {
	throw_msg("Content-Length too large: %u", modconf->content_length);
    }
}


static boolean _om_raijin_do_handshake(nx_module_t *module)
{
    nx_om_raijin_conf_t *modconf;
    int rv;
    int errcode;

    modconf = (nx_om_raijin_conf_t *) module->config;

    if ( _om_raijin_is_ssl_enabled(modconf) == FALSE )
    {
	return TRUE;
    }

    ASSERT(modconf->ssl != NULL);

    if ( !SSL_is_init_finished(modconf->ssl) )
    {
	log_debug("doing handshake");

	if ( (rv = SSL_do_handshake(modconf->ssl)) <= 0 )
	{
	    switch ( (errcode = nx_ssl_check_io_error(modconf->ssl, rv)) )
	    {
		case SSL_ERROR_ZERO_RETURN: // disconnected
		    log_debug("remote socket was closed during SSL handshake");
		    om_raijin_disconnect(module, TRUE);
		    break;
		case SSL_ERROR_WANT_WRITE:
		    log_debug("om_http WANT_WRITE in handshake");
		    nx_module_pollset_add_socket(module, modconf->sock, APR_POLLOUT | APR_POLLHUP);
		    break;
		case SSL_ERROR_WANT_READ:
		    log_debug("om_http WANT_READ in handshake");
		    nx_module_pollset_add_socket(module, modconf->sock, APR_POLLIN | APR_POLLHUP);
		    break;
		default:
		    throw_msg("om_http couldn't write handshake data (error code: %d)", errcode);
	    }
	    return ( FALSE );
	}

	if ( SSL_is_init_finished(modconf->ssl) )
	{
	    log_debug("handshake successful");
	    _om_raijin_set_socket_state(modconf, NX_SOCKET_STATE_CONNECTED);

	    // we need to read socket events, because POLLIN is also needed
	    nx_module_pollset_add_socket(module, modconf->sock, APR_POLLIN | APR_POLLOUT | APR_POLLHUP);

	    // if there is data, send it
	    nx_module_data_available(module);
	}
	else
	{
	    return ( FALSE );
	}
    }

    return ( TRUE );
}


#define NX_OM_RAIJIN_STR_TAG    "tag_reason"
#define NX_OM_RAIJIN_STR_CODE   "error_code"


typedef enum nx_om_raijin_json_parse_current_t
{
    NX_OM_RAIJIN_JSON_PARSE_NONE = 0,
    NX_OM_RAIJIN_JSON_PARSE_TAG  = 1,
    NX_OM_RAIJIN_JSON_PARSE_CODE = 2
} nx_om_raijin_json_parse_current_t;


typedef struct nx_om_raijin_json_parse_ctx_struct_t
{
    nx_om_raijin_json_parse_current_t  current;
    nx_string_t *tag_reason;
    nx_string_t *err_code;
} nx_om_raijin_json_parse_ctx_struct_t;


static nx_string_t *nx_om_raijin_copy_string(const unsigned char *s, size_t l, int *result)
{
    // No need to copy data for now, just keep ptr and length
    nx_string_t *str = nx_string_create_owned((char *) s, (int) l);
    *result = (str == NULL) ? 0 : 1;
    return str;
}


static int nx_om_raijin_yajl_parse_string_cb(void *data, const unsigned char *s, size_t l)
{
    nx_om_raijin_json_parse_ctx_struct_t *ctx = (nx_om_raijin_json_parse_ctx_struct_t *) data;

    int result = 1;

    if ( ctx != NULL )
    {
        if ( ctx->current == NX_OM_RAIJIN_JSON_PARSE_TAG )
        {
            if ( ctx->tag_reason != NULL )
            {
                free(ctx->tag_reason);
            }
            ctx->tag_reason = nx_om_raijin_copy_string(s, l, &result);
        }
        else if ( ctx->current == NX_OM_RAIJIN_JSON_PARSE_CODE )
        {
            if ( ctx->err_code != NULL )
            {
                free(ctx->err_code);
            }
            ctx->err_code = nx_om_raijin_copy_string(s, l, &result);
        }
    }

    ctx->current = NX_OM_RAIJIN_JSON_PARSE_NONE;

    return result;
}


static int nx_om_raijin_yajl_parse_map_key_cb(void *data, const unsigned char *s, size_t l)
{
    nx_om_raijin_json_parse_ctx_struct_t *ctx = (nx_om_raijin_json_parse_ctx_struct_t *) data;
    const char *str = (const char *) s;

    if ( ctx != NULL )
    {
        if ( (strlen(NX_OM_RAIJIN_STR_TAG) == l) &&
             (strncmp(str, NX_OM_RAIJIN_STR_TAG, l) == 0) )
        {
            ctx->current = NX_OM_RAIJIN_JSON_PARSE_TAG;
        }
        else if ( (strlen(NX_OM_RAIJIN_STR_CODE) == l) &&
                  (strncmp(str, NX_OM_RAIJIN_STR_CODE, l) == 0) )
        {
            ctx->current = NX_OM_RAIJIN_JSON_PARSE_CODE;
        }
    }

    return 1;
}


static const yajl_callbacks nx_om_raijin_yajl_callbacks =
{
    /* null        = */ NULL,
    /* boolean     = */ NULL,
    /* integer     = */ NULL,
    /* double      = */ NULL,
    /* number      = */ NULL,
    /* string      = */ nx_om_raijin_yajl_parse_string_cb,
    /* start map   = */ NULL,
    /* map key     = */ nx_om_raijin_yajl_parse_map_key_cb,
    /* end map     = */ NULL,
    /* start array = */ NULL,
    /* end array   = */ NULL
};


static boolean om_raijin_parse_body(nx_om_raijin_conf_t *modconf)
{
    boolean retval = FALSE;
    yajl_handle hand;

    char *data = NULL;
    char *start_ptr = 0, *end_ptr = 0, *iter_ptr = 0;

    nx_om_raijin_json_parse_ctx_struct_t json_ctx =
    {
        .current = NX_OM_RAIJIN_JSON_PARSE_NONE,
        .tag_reason = NULL,
        .err_code = NULL,
    };

    long length = BIO_get_mem_data(modconf->bio_resp_body, &data);

    if ( data == NULL )
    {
        return FALSE;
    }

    start_ptr = data;
    end_ptr = data + length - 1;

    iter_ptr = start_ptr;

    // Trim spaces
    while ( (iter_ptr != end_ptr) &&
            (apr_isspace((unsigned char) *iter_ptr) != 0) )
    {
        ++iter_ptr;
    }

    start_ptr = iter_ptr;
    iter_ptr = end_ptr;

    while ( (iter_ptr != start_ptr) &&
            (apr_isspace(*iter_ptr) != 0) )
    {
        --iter_ptr;
    }

    end_ptr = iter_ptr + 1;

    hand = yajl_alloc(&nx_om_raijin_yajl_callbacks, NULL, (void *) &json_ctx);
    yajl_config(hand, yajl_allow_comments, 1);

    if ( (yajl_parse(hand, (const unsigned char *) start_ptr, (size_t) (end_ptr - start_ptr)) != yajl_status_ok) ||
	 (yajl_complete_parse(hand) != yajl_status_ok) )
    {
	retval = FALSE;
    }
    else
    {
	retval = TRUE;

        if ( (json_ctx.tag_reason != NULL) && (json_ctx.err_code != NULL) )
        {
            log_error("Server error. [%.*s] Reason: \"%.*s\"", json_ctx.err_code->len, json_ctx.err_code->buf, json_ctx.tag_reason->len, json_ctx.tag_reason->buf);
        }
    }

    if ( json_ctx.err_code != NULL )
    {
        free(json_ctx.err_code);
    }

    if ( json_ctx.tag_reason != NULL )
    {
        free(json_ctx.tag_reason);
    }

    yajl_free(hand);

    return retval;
}


static int char2int(char input)
{
    if ( (input >= '0') && (input <= '9') )
    {
        return input - '0';
    }

    if ( (input >= 'A') && (input <= 'F') )
    {
        return input - 'A' + 10;
    }

    if ( (input >= 'a') && (input <= 'f') )
    {
        return input - 'a' + 10;
    }

    return -1;
}


static boolean om_raijin_read_header(nx_om_raijin_conf_t *modconf, char *data, apr_size_t len)
{
    apr_size_t i = 0;

    for ( i = 0; i < len; i++ )
    { // seek to start of body
        switch ( data[i] )
        {
            case '\r':
                switch ( modconf->resp_state )
                {
                    case NX_OM_RAIJIN_RESP_STATE_START:
                        modconf->resp_state = NX_OM_RAIJIN_RESP_STATE_CR;
                        break;
                    case NX_OM_RAIJIN_RESP_STATE_CR_LF:
                        modconf->resp_state = NX_OM_RAIJIN_RESP_STATE_CR_LF_CR;
                        break;
                    default:
                        modconf->resp_state = NX_OM_RAIJIN_RESP_STATE_START;
                        break;
                }
                break;
            case '\n':
                switch ( modconf->resp_state )
                {
                    case NX_OM_RAIJIN_RESP_STATE_CR:
                        modconf->resp_state = NX_OM_RAIJIN_RESP_STATE_CR_LF;
                        break;
                    case NX_OM_RAIJIN_RESP_STATE_CR_LF_CR:
                        modconf->resp_state = NX_OM_RAIJIN_RESP_STATE_CR_LF_CR_LF;
                        break;
                    default:
                        modconf->resp_state = NX_OM_RAIJIN_RESP_STATE_START;
                        break;
                }
                break;
            case '\0':
                throw_msg("invalid HTTP response, zero byte found");
            default:
                modconf->resp_state = NX_OM_RAIJIN_RESP_STATE_START;
                break;
        }

        if ( modconf->resp_state == NX_OM_RAIJIN_RESP_STATE_CR_LF_CR_LF )
        {
            // i + 1 because i is idx started from 0
            BIO_write(modconf->bio_resp_head, data, (int) (i + 1));
	    BIO_write(modconf->bio_resp_head, "\0", 1);
	    modconf->got_resp_head = TRUE;
            modconf->respheaderlen = (int) (i + 1);
            return TRUE;
        }
    }

    return FALSE;
}


static boolean om_raijin_read_chunked_body(nx_om_raijin_conf_t *modconf, char *data, apr_size_t len)
{
    char ch;
    apr_size_t i = 0, start_data = 0, end_data = 0;
    unsigned int chunk_size = 0;
    int digit = 0;

    enum
    {
        RAIJIN_CHUNK_START            = 0,
        RAIJIN_CHUNK_SIZE             = 1,
        RAIJIN_CHUNK_SIZE_CR          = 2,
        RAIJIN_CHUNK_DATA_START       = 3,
        RAIJIN_CHUNK_DATA             = 4,
        RAIJIN_CHUNK_DATA_CR          = 5,
        RAIJIN_LAST_CHUNK_CR          = 6,
        RAIJIN_LAST_CHUNK_CR_LF       = 7,
        RAIJIN_LAST_CHUNK_CR_LF_CR    = 8,
        RAIJIN_LAST_CHUNK_CR_LF_CR_LF = 9,
        RAIJIN_INVALID                = 10
    } state;

    state = RAIJIN_CHUNK_START;

    for ( i = 0; i < len; i++ )
    {
        ch = data[i];
//        log_error("state %d | [%d] '%c' '%02X'", state, i, ch, ch);

        switch ( state )
        {
            case RAIJIN_CHUNK_START:
            {
                digit = char2int(ch);

                // CHUNK_SIZE sequence must start from HEX digit
                if ( digit < 0 )
                {
                    log_debug("Wrong hex digit");
                    return FALSE;
                }

                chunk_size = (unsigned) digit;
                state = RAIJIN_CHUNK_SIZE;

                break;
            }

            case RAIJIN_CHUNK_SIZE:
            {
                digit = char2int(ch);

                // read CHUNK_SIZE hex digit until CRLF
                if ( digit >= 0 )
                {
                    chunk_size = (chunk_size * 16) + (unsigned) digit;
                    break;
                }

                // read CHUNK_SIZE expecting CRLF
                switch ( ch )
                {
                    case '\r':
                    {
                        if ( chunk_size == 0 )
                        {
                            // this is the last chunk without data
                            state = RAIJIN_LAST_CHUNK_CR;
                        }
                        else
                        {
                            // chunk with data
                            state = RAIJIN_CHUNK_SIZE_CR;
                        }
                        break;
                    }
                    default:
                    {
                        log_debug("Wrong CHUNK_SIZE sequence");
                        return FALSE;
                    }
                }

                break;
            }

            case RAIJIN_CHUNK_SIZE_CR:
            {
                switch ( ch )
                {
                    case '\n':
                    {
                        // CHUNK_SIZE sequence complete
                        modconf->content_length += chunk_size;
                        state = RAIJIN_CHUNK_DATA_START;
                        break;
                    }
                    default:
                    {
                        log_debug("Wrong CHUNK_SIZE sequence, expected CRLF");
                        return FALSE;
                    }
                }

                break;
            }

            case RAIJIN_LAST_CHUNK_CR:
            {
                switch ( ch )
                {
                    case '\n':
                    {
                        state = RAIJIN_LAST_CHUNK_CR_LF;
                        break;
                    }
                    default:
                    {
                        log_debug("Wrong LAST_CHUNK sequence, expected 0<CRLF><CRLF> [state %d]", state);
                        return FALSE;
                    }
                }

                break;
            }

            case RAIJIN_LAST_CHUNK_CR_LF:
            {
                switch ( ch )
                {
                    case '\r':
                    {
                        state = RAIJIN_LAST_CHUNK_CR_LF_CR;
                        break;
                    }
                    default:
                    {
                        log_debug("Wrong LAST_CHUNK sequence, expected 0<CRLF><CRLF> [state %d]", state);
                        return FALSE;
                    }
                }

                break;
            }

            case RAIJIN_LAST_CHUNK_CR_LF_CR:
            {
                switch ( ch )
                {
                    case '\n':
                    {
                        state = RAIJIN_LAST_CHUNK_CR_LF_CR_LF;
                        break;
                    }
                    default:
                    {
                        log_debug("Wrong LAST_CHUNK sequence, expected 0<CRLF><CRLF> [state %d]", state);
                        return FALSE;
                    }
                }

                break;
            }

            case RAIJIN_LAST_CHUNK_CR_LF_CR_LF:
            {
                if ( len != (i + 1) )
                {
                    // "unexpected data" at the end
                    log_debug("Response body contains unexpected data after the end sequence");
                    return FALSE;
                }
                return TRUE;
            }

            case RAIJIN_CHUNK_DATA_START:
            {
                // we can jump to data + i + chunk_size
                start_data = i;
                state = RAIJIN_CHUNK_DATA;

                chunk_size--;
                break;
            }

            case RAIJIN_CHUNK_DATA:
            {
                if ( chunk_size == 0 )
                {
                    end_data = i;
                    state = RAIJIN_CHUNK_DATA_CR;
                }

                chunk_size--;
                break;
            }

            case RAIJIN_CHUNK_DATA_CR:
            {
                switch ( ch )
                {
                    case '\n':
                    {
                        int nbyte = 0, size = (int) (end_data - start_data);

                        nbyte = BIO_write(modconf->bio_resp_body, data + start_data, size);

                        if ( nbyte ==  size )
                        {
                            modconf->got_resp_body = TRUE;
                        }
                        else
                        {
                            log_debug("Can't write bio_resp_body");
                            return FALSE;
                        }

                        start_data = 0;
                        end_data = 0;
                        state = RAIJIN_CHUNK_START;

                        break;
                    }
                    default:
                    {
                        log_debug("Wrong LAST_DATA sequence expected CRLF\n");
                        return FALSE;
                    }
                }
                break;
            }

            default:
            {
                log_debug("Wrong state %d", state);
                return FALSE;
            }
        }
    }

    switch ( state )
    {
        case RAIJIN_LAST_CHUNK_CR_LF_CR_LF:
        {
            // i already incremented, must equals to len
            if ( len != i )
            {
                // "unexpected data" at the end
                log_debug("Response body contains unexpected data after the end sequence");
                return FALSE;
            }
            return TRUE;
        }

        default:
        {
            log_debug("Response body parser Wrong state %d", state);
            return FALSE;
        }
    }

    return FALSE;
}


static void om_raijin_read_response(nx_module_t *module)
{
    nx_om_raijin_conf_t *modconf;
    boolean got_eof = FALSE;
    nx_exception_t e;
    boolean has_body = TRUE;

    log_debug("nx_om_raijin_read_response");

    modconf = (nx_om_raijin_conf_t *) module->config;
    ASSERT(modconf != NULL);
    if ( _om_raijin_is_ssl_enabled(modconf) == TRUE )
    {
	if ( _om_raijin_socket_is_ready(modconf) == TRUE )
	{
	    _om_raijin_set_socket_state(modconf, NX_SOCKET_STATE_HANDSHAKING);
	    om_raijin_timeout_event(module);
	}

	if ( _om_raijin_socket_is_handshaking(modconf) == TRUE )
	{
	    if ( _om_raijin_do_handshake(module) == FALSE )
	    {
		return;
	    }
	}
    }

    if ( _om_raijin_is_ssl_enabled(modconf) == TRUE )
    {
        int rv = SSL_ERROR_NONE;
        int nbytes = NX_OM_RAIJIN_RESPBUFSIZE;

        while ( (rv = nx_ssl_read(modconf->ssl, (modconf->respbuf + modconf->respbuflen), &nbytes)) == SSL_ERROR_NONE )
        {
            modconf->respbuflen += nbytes;
            nbytes = (int) (NX_OM_RAIJIN_RESPBUFSIZE - modconf->respbuflen);
        }

	switch ( rv )
	{
	    case SSL_ERROR_NONE:
		break;
	    case SSL_ERROR_ZERO_RETURN: // disconnected
		log_warn("raijin server disconnected");
		om_raijin_disconnect(module, TRUE);
		if ( nbytes == 0 )
		{
		    om_raijin_reset(module);
		    return;
		}
		break;
	    case SSL_ERROR_WANT_WRITE:
	    case SSL_ERROR_WANT_READ:
		log_debug("got EAGAIN for nonblocking read in module %s", module->name);
		break;
	    default:
	    try
	    {
		nx_ssl_check_io_error(modconf->ssl, rv);
	    }
	    catch(e)
	    {
		om_raijin_disconnect(module, TRUE);
		om_raijin_reset(module);
		rethrow(e);
	    }
	    om_raijin_disconnect(module, TRUE);
	    om_raijin_reset(module);
	    return;
	}
    }
    else
    {
        apr_status_t rv;
        apr_size_t nbytes = NX_OM_RAIJIN_RESPBUFSIZE;

        while ( (rv = apr_socket_recv(modconf->sock, (modconf->respbuf + modconf->respbuflen), &nbytes)) == APR_SUCCESS )
        {
            modconf->respbuflen += nbytes;
            nbytes = (apr_size_t) (NX_OM_RAIJIN_RESPBUFSIZE - modconf->respbuflen);
        }

        if ( rv != APR_SUCCESS )
        {
            if ( APR_STATUS_IS_EOF(rv) )
            {
                got_eof = TRUE;
            }
            else if ( APR_STATUS_IS_EAGAIN(rv) )
            {
                log_debug("got EAGAIN for nonblocking read in module %s", module->name);
            }
            else
            {
                throw(rv, "Module %s couldn't read from socket", module->name);
            }
        }

        if ( got_eof == TRUE )
        {
            log_warn("raijin server disconnected");
            om_raijin_disconnect(module, TRUE);
            if ( modconf->respbuflen == 0 )
            {
                om_raijin_reset(module);
                return;
            }
        }
    }

    if ( modconf->bio_resp_head == NULL )
    {
	if ( (modconf->bio_resp_head = BIO_new(BIO_s_mem())) == NULL )
	{
	    throw_sslerror("BIO_new() failed");
	}
    }

    if ( modconf->bio_resp_body == NULL )
    {
	if ( (modconf->bio_resp_body = BIO_new(BIO_s_mem())) == NULL )
	{
	    throw_sslerror("BIO_new() failed");
	}
    }

    if ( modconf->resp_wait == FALSE )
    {
        // Server send unexpected data. Reconnect
        om_raijin_disconnect(module, TRUE);
        om_raijin_reset(module);
        throw_msg("unexpected data from server (%d bytes)", modconf->respbuflen);
    }

//    parse header
//    nx_dump(APR_SUCCESS, NX_LOGLEVEL_DEBUG, NX_LOGMODULE, "READ", respbuf_ptr, len);

    if ( modconf->got_resp_head == FALSE )
    {
	boolean parse_header_res = om_raijin_read_header(modconf,
                                                         modconf->respbuf,
                                                         modconf->respbuflen);

	if ( (parse_header_res == TRUE) &&
             (modconf->respheaderlen > 0) )
	{
	    om_raijin_check_resp_head(module);
	    modconf->resp_state = NX_OM_RAIJIN_RESP_STATE_START;

            if ( modconf->respbuflen == modconf->respheaderlen )
            {
                // If data already processed no need to parse body
                has_body = FALSE;
            }
	}
        else
        {
            BIO_write(modconf->bio_resp_head, modconf->respbuf, modconf->respheaderlen);
            has_body = FALSE;
        }
    }

    // Parse body
    if ( (modconf->chunked == TRUE) &&
         (modconf->respbuflen > 0) &&
         (has_body == TRUE) )
    {
        boolean parse_body_res = om_raijin_read_chunked_body(modconf,
                                                             (modconf->respbuf + modconf->respheaderlen),
                                                             (modconf->respbuflen - modconf->respheaderlen));

//        nx_dump(APR_SUCCESS, NX_LOGLEVEL_DEBUG, NX_LOGMODULE, "BODY", respbuf_ptr, len);

        if ( parse_body_res != TRUE )
        {
            om_raijin_disconnect(module, TRUE);
            om_raijin_reset(module);
            throw_msg("Can't parse response chunked body");
        }

        if ( (parse_body_res == TRUE) &&
             (modconf->content_length > 0) )
        {
            parse_body_res = om_raijin_parse_body(modconf);
        }

        if ( parse_body_res != TRUE )
        {
            om_raijin_disconnect(module, TRUE);
            om_raijin_reset(module);
            throw_msg("Can't parse JSON response");
        }

        //make sure that `got_resp_body` == TRUE even for empty body 0<crlf><crlf>
        modconf->got_resp_body = TRUE;
    }

    if ( modconf->got_resp_body == TRUE )
    {
	log_debug("parsed resp");
	modconf->resp_wait = FALSE;
	modconf->recreate = FALSE;
        modconf->chunked = FALSE;

	modconf->bulk_data_cnt = 0;
	ASSERT(modconf->bio_resp_body != NULL);
	BIO_free_all(modconf->bio_resp_body);
	modconf->bio_resp_body = NULL;

	if ( modconf->bio_reqhdr != NULL )
	{
	    BIO_free_all(modconf->bio_reqhdr);
	    modconf->bio_reqhdr = NULL;
	}
	modconf->reqhdrbufsize = 0;

	if ( modconf->bio_reqbdy != NULL )
	{
	    BIO_free_all(modconf->bio_reqbdy);
	    modconf->bio_reqbdy = NULL;
	}
	modconf->reqbdybufsize = 0;

	om_raijin_reset(module);
	nx_module_data_available(module);
    }
    nx_module_add_poll_event(module);
}


static void om_raijin_parse_url(apr_pool_t *pool,
				       const char *url,
				       nx_om_raijin_server_t *server)
{
    const char *ptr;
    apr_port_t port = 0;
    char portstr[10];
    unsigned int i;

    ASSERT(url != NULL);
    ASSERT(server != NULL);

    server->url = url;

    if ( strncasecmp(url, "http://", 7) == 0 )
    {
	port = 80;
	i = 7;
    }
    else if ( strncasecmp(url, "https://", 8) == 0 )
    {
	port = 443;
	server->https = TRUE;
	i = 8;
    }
    else
    {
	throw_msg("invalid url: %s", url);
    }

    for ( ptr = url + i;
	  (*ptr != '\0') && (*ptr != '/') && (*ptr != ':');
	  ptr++ );
    server->host = apr_pstrndup(pool, url + i, (size_t) (ptr - (url + i)));

    if ( *ptr == ':' )
    {
	ptr++;
	for ( i = 0; apr_isdigit(*ptr); i++, ptr++ )
	{
	    if ( i >= sizeof(portstr) )
	    {
		throw_msg("invalid port [%s]", portstr);
	    }
	    portstr[i] = *ptr;
	}
	portstr[i] = '\0';
	if ( atoi(portstr) == 0 )
	{
	    throw_msg("invalid port [%s]", portstr);
	}
	port = (apr_port_t) atoi(portstr);
    }

    if ( *ptr == '/' )
    {
	// TODO: URLencode
	apr_cpystrn(server->path, ptr, sizeof(server->path));
    }
    else
    {
	server->path[0] = '/';
	server->path[1] = '\0';
    }
    server->port = port;

    log_debug("host: [%s], port: %d, path: [%s]", server->host, server->port, server->path);
}


static void om_raijin_config(nx_module_t *module)
{
    const nx_directive_t * volatile curr;
    nx_om_raijin_conf_t * volatile modconf;
    const char *url;
    nx_exception_t e;
    unsigned int port;
    boolean compression_set = FALSE;

    ASSERT(module->directives != NULL);
    curr = module->directives;

    modconf = apr_pcalloc(module->pool, sizeof(nx_om_raijin_conf_t));
    module->config = modconf;

    while ( curr != NULL )
    {
	if ( nx_module_common_keyword(curr->directive) == TRUE )
	{
	}
	else if ( strcasecmp(curr->directive, "url") == 0 )
	{
	    if ( modconf->server.url != NULL )
	    {
		nx_conf_error(curr, "URL already defined");
	    }

	    url = apr_pstrdup(module->pool, curr->args);
	    try
		    {
			om_raijin_parse_url(module->pool, url, &(modconf->server));
		    }
	    catch(e)
	    {
		log_exception(e);
		nx_conf_error(curr, "Failed to parse url %s", url);
	    }
	}
	else if ( strcasecmp(curr->directive, "SNI") == 0 )
	{
	    if ( modconf->ssl_ctx.sni != NULL )
	    {
		nx_conf_error(curr, "SNI already defined");
	    }
	    modconf->ssl_ctx.sni = apr_pstrdup(module->pool, curr->args);
	}
	else if ( strcasecmp(curr->directive, "httpscertfile") == 0 )
	{
	    if ( modconf->ssl_ctx.certfile != NULL )
	    {
		nx_conf_error(curr, "HTTPSCertFile is already defined");
	    }
	    modconf->ssl_ctx.certfile = nx_cfg_unquote_string(curr, module->pool);
	}
	else if ( strcasecmp(curr->directive, "httpscertkeyfile") == 0 )
	{
	    if ( modconf->ssl_ctx.certkeyfile != NULL )
	    {
		nx_conf_error(curr, "HTTPSCertKeyFile is already defined");
	    }
	    modconf->ssl_ctx.certkeyfile = nx_cfg_unquote_string(curr, module->pool);
	}
	else if ( strcasecmp(curr->directive, "httpskeypass") == 0 )
	{
	    if ( modconf->ssl_ctx.keypass != NULL )
	    {
		nx_conf_error(curr, "HTTPSKeyPass is already defined");
	    }
	    modconf->ssl_ctx.keypass = apr_pstrdup(module->pool, curr->args);
	}
	else if ( strcasecmp(curr->directive, "httpscafile") == 0 )
	{
	    if ( modconf->ssl_ctx.cafile != NULL )
	    {
		nx_conf_error(curr, "HTTPSCAFile is already defined");
	    }
	    modconf->ssl_ctx.cafile = nx_cfg_unquote_string(curr, module->pool);
	}
	else if ( strcasecmp(curr->directive, "httpscadir") == 0 )
	{
	    if ( modconf->ssl_ctx.cadir != NULL )
	    {
		nx_conf_error(curr, "HTTPSCADir is already defined");
	    }
	    modconf->ssl_ctx.cadir = nx_cfg_unquote_string(curr, module->pool);
	}
	else if ( strcasecmp(curr->directive, "httpscrlfile") == 0 )
	{
	    if ( modconf->ssl_ctx.crlfile != NULL )
	    {
		nx_conf_error(curr, "HTTPSCRLFile is already defined");
	    }
	    modconf->ssl_ctx.crlfile = nx_cfg_unquote_string(curr, module->pool);
	}
	else if ( strcasecmp(curr->directive, "httpscrldir") == 0 )
	{
	    if ( modconf->ssl_ctx.crldir != NULL )
	    {
		nx_conf_error(curr, "HTTPSCRLDir is already defined");
	    }
	    modconf->ssl_ctx.crldir = nx_cfg_unquote_string(curr, module->pool);
	}
	else if ( strcasecmp(curr->directive, "HTTPSRequireCert") == 0 )
	{
	}
	else if ( strcasecmp(curr->directive, "HTTPSAllowUntrusted") == 0 )
	{
	}
	else if ( strcasecmp(curr->directive, "SSLProtocol") == 0 )
	{
	    modconf->ssl_options = nx_ssl_parse_protocol(curr->args);
	    if ( modconf->ssl_options == 0 )
	    {
		nx_conf_error(curr, "Invalid parameter for SSLProtocol: %s", curr->args);
	    }
	}
	else if ( strcasecmp(curr->directive, "SSLCompression") == 0 )
	{
	    if ( compression_set == TRUE )
	    {
		nx_conf_error(curr, "SSLCompression already defined");
	    }
	    compression_set = TRUE;
	    nx_cfg_boolean(curr, &(modconf->ssl_ctx.compression));
	}
	else if ( strcasecmp(curr->directive, "DBName") == 0 )
	{
	    if ( modconf->dbname != NULL )
	    {
		nx_conf_error(curr, "DBName already defined");
	    }
	    modconf->dbname = nx_cfg_unquote_string(curr, module->pool);
	}
	else if ( strcasecmp(curr->directive, "DBTable") == 0 )
	{
	    if ( modconf->dbtable != NULL )
	    {
		nx_conf_error(curr, "DBTable already defined");
	    }
	    modconf->dbtable = nx_cfg_unquote_string(curr, module->pool);
	}
	else if ( strcasecmp(curr->directive, "FlushInterval") == 0 )
	{
	    if ( sscanf(curr->args, "%f", &(modconf->flush_interval)) != 1 )
	    {
		nx_conf_error(curr, "invalid FlushInterval: %s", curr->args);
	    }
	}
	else if ( strcasecmp(curr->directive, "FlushLimit") == 0 )
	{
	    if ( sscanf(curr->args, "%d", &(modconf->flush_limit)) != 1 )
	    {
		nx_conf_error(curr, "invalid FlushLimit directive: %s", curr->args);
	    }
	}
	else if ( strcasecmp(curr->directive, "SSLCipher") == 0 )
	{
	    if ( modconf->ssl_cipher_list != NULL )
	    {
		nx_conf_error(curr, "SSLCipher already defined");
	    }
	    modconf->ssl_cipher_list = apr_pstrdup(module->pool, curr->args);
	}
	else if ( strcasecmp(curr->directive, "ProxyAddress") == 0 )
	{
	    if ( modconf->proxy_addr != NULL )
	    {
		nx_conf_error(curr, "proxy address is already defined");
	    }
	    modconf->proxy_addr = apr_pstrdup(module->pool, curr->args);
	}
	else if ( strcasecmp(curr->directive, "ProxyPort") == 0 )
	{
	    if ( modconf->proxy_port != 0 )
	    {
		nx_conf_error(curr, "proxy port is already defined");
	    }
	    if ( sscanf(curr->args, "%u", &port) != 1 )
	    {
		nx_conf_error(curr, "invalid proxy port: %s", curr->args);
	    }
	    modconf->proxy_port = (apr_port_t) port;
	}
	else
	{
	    nx_conf_error(curr, "invalid keyword: %s", curr->directive);
	}
	curr = curr->next;
    }

    if ( modconf->server.url == NULL )
    {
	nx_conf_error(curr, "URL missing");
    }

    if ( _om_raijin_is_ssl_enabled(modconf) == FALSE )
    { // not HTTPS
	curr = module->directives;
	if ( modconf->ssl_ctx.certfile != NULL )
	{
	    nx_conf_error(curr, "'HTTPSCertFile' is only valid for HTTPS");
	}
	if ( modconf->ssl_ctx.certkeyfile != NULL )
	{
	    nx_conf_error(curr, "'HTTPSCertKeyFile' is only valid for HTTPS");
	}
	if ( modconf->ssl_ctx.keypass != NULL )
	{
	    nx_conf_error(curr, "'HTTPSKeyPass' is only valid for HTTPS");
	}
	if ( modconf->ssl_ctx.cafile != NULL )
	{
	    nx_conf_error(curr, "'HTTPSCAFile' is only valid for HTTPS");
	}
	if ( modconf->ssl_ctx.cadir != NULL )
	{
	    nx_conf_error(curr, "'HTTPSCADir' is only valid for HTTPS");
	}
	if ( modconf->ssl_ctx.crlfile != NULL )
	{
	    nx_conf_error(curr, "'HTTPSCRLFile' is only valid for HTTPS");
	}
	if ( modconf->ssl_ctx.crldir != NULL )
	{
	    nx_conf_error(curr, "'HTTPSCRLDir' is only valid for HTTPS");
	}
	if ( modconf->ssl_ctx.sni != NULL )
	{
	    nx_conf_error(curr, "'SNI' is only valid for HTTPS");
	}
    }
    else
    { // HTTPS
	modconf->ssl_ctx.require_cert = TRUE;
	modconf->ssl_ctx.allow_untrusted = FALSE;
	nx_cfg_get_boolean(module->directives, "HTTPSRequireCert",
			   &(modconf->ssl_ctx.require_cert));
	nx_cfg_get_boolean(module->directives, "HTTPSAllowUntrusted",
			   &(modconf->ssl_ctx.allow_untrusted));
    }

    if ( modconf->dbname == NULL )
    {
        nx_conf_error(module->directives, "Mandatory 'DBName' parameter missing");
    }

    if ( modconf->dbtable == NULL )
    {
        nx_conf_error(module->directives, "Mandatory 'DBTable' parameter missing");
    }

    if ( modconf->flush_interval == 0 )
    {
	modconf->flush_interval = NX_OM_RAIJIN_DEFAULT_FLUSH_INTERVAL;
    }

    if ( modconf->flush_limit == 0 )
    {
	modconf->flush_limit = NX_OM_RAIJIN_DEFAULT_FLUSH_LIMIT;
    }

    if ( (modconf->proxy_addr != NULL) && (modconf->proxy_port != 0) )
    {
	log_debug("use proxy %s:%u", modconf->proxy_addr, modconf->proxy_port);
	modconf->use_proxy = TRUE;
    }
}


static void om_raijin_init(nx_module_t *module)
{
    nx_om_raijin_conf_t *modconf;

    modconf = (nx_om_raijin_conf_t *) module->config;

    TRIAL_CHECK();

    modconf->pool = nx_pool_create_child(module->pool);

    if ( _om_raijin_is_ssl_enabled(modconf) == TRUE )
    {
	nx_ssl_ctx_init(&(modconf->ssl_ctx), module->pool);
    }
    nx_module_pollset_init(module);
}


static void om_raijin_event(nx_module_t *module, nx_event_t *event)
{
    nx_om_raijin_conf_t *modconf;
    nx_exception_t e;

    ASSERT(event != NULL);
    ASSERT(module != NULL);

    modconf = (nx_om_raijin_conf_t *) module->config;

    switch ( event->type )
    {
	case NX_EVENT_DATA_AVAILABLE:
	    om_raijin_data_available(module);
	    break;
	case NX_EVENT_READ:
	    try
	    {
		om_raijin_read_response(module);
	    }
	    catch(e)
	    {
		log_exception(e);
		om_raijin_reset(module);
	    }
	    break;
	case NX_EVENT_WRITE:
	    om_raijin_send_request(module);
	    break;
	case NX_EVENT_RECONNECT:
	    modconf->reconnect_event = NULL;
	    om_raijin_connect(module);
	    break;
	case NX_EVENT_DISCONNECT:
	    om_raijin_disconnect(module, TRUE);
	    om_raijin_reset(module);
	    log_error("disconnected");
	    break;
	case NX_EVENT_MODULE_SPECIFIC:
	    modconf->flush_event = NULL;
	    om_raijin_flush(module);
	    break;
	case NX_EVENT_TIMEOUT:
	    log_error("http response timeout from server");
	    modconf->timeout_event = NULL;
	    om_raijin_disconnect(module, TRUE);
	    om_raijin_reset(module);
	    break;
	case NX_EVENT_POLL:
	    if ( (nx_module_get_status(module) == NX_MODULE_STATUS_RUNNING) &&
		 (modconf->sock != NULL) )
	    {
		nx_module_pollset_poll(module, FALSE);
		nx_module_add_poll_event(module);
	    }
	    break;
	default:
	    nx_panic("invalid event type: %d", event->type);
    }
}


static void om_raijin_start(nx_module_t *module)
{
    log_debug("om_raijin_start");
    om_raijin_add_reconnect_event(module);
}

NX_MODULE_DECLARATION nx_om_raijin_module =
{
	NX_MODULE_API_VERSION,
	NX_MODULE_TYPE_OUTPUT,
	NULL,			// capabilities
	om_raijin_config,	// config
	om_raijin_start,	// start
	NULL,		 	// stop
	NULL,			// pause
	NULL,			// resume
	om_raijin_init,	// init
	NULL,			// shutdown
	om_raijin_event,	// event
	NULL,			// info
	NULL,			// exports
};
