/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#include "../../../common/module.h"
#include "../../../common/event.h"
#include "../../../common/error_debug.h"
#include "../../../common/alloc.h"

#include "im_udp.h"
#include <apr_portable.h>
#include <apr_network_io.h>

#ifdef HAVE_RECVMMSG
# if HAVE_DECL_RECVMMSG == 0
// recvmmsg is not defined on AIX7.2 (worked ok prior 7.2), this hack is needed.
int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags, struct timespec *timeout);
# endif
#define MAX_MSGS_COUNT 100
#else
#define MAX_MSGS_COUNT 1
# endif

#define NX_LOGMODULE NX_LOGMODULE_MODULE

#define IM_UDP_DEFAULT_HOST "localhost"
#define IM_UDP_DEFAULT_PORT 514

#define IM_UDP_MAX_DATAGRAM_SIZE 65000

static void im_udp_close_socket(nx_module_t *module)
{
    if ( module->input.desc.s != NULL )
    {
	nx_module_pollset_remove_socket(module, module->input.desc.s);
	apr_socket_close(module->input.desc.s);
	module->input.desc.s = NULL;
    }
    apr_pool_clear(module->input.pool);
}

#ifdef DEBUG_MSG_COUNT
static void debug_msg_count(int count)
{

    static time_t prev = 0;
    time_t now = 0;
    now = time(NULL);
    static int current_msgs_count = 0;

    current_msgs_count += count;
    if (prev != now)
    {
        log_info("received %ld msgs", current_msgs_count);
        current_msgs_count = 0;
        prev = now;
    }
}

#define DEBUG_MSGCOUNT(x) debug_msg_count(x)
#else
#define DEBUG_MSGCOUNT(x)
#endif

#ifndef APR_STATUS_IS_EMSGSIZE
# ifdef __WIN32__
#  define APR_STATUS_IS_EMSGSIZE(s) ((s) == WSAEMSGSIZE)
# else
#  define APR_STATUS_IS_EMSGSIZE(s) ((s) == EMSGSIZE)
# endif
#endif

static void im_udp_logdata_post(nx_module_t * module,
				 apr_sockaddr_t * sa)
{
    apr_status_t rv = APR_SUCCESS;
    nx_logdata_t * logdata;
    char ipstr[64];

    ASSERT(module != NULL);

#ifdef HAVE_APR_SOCKADDR_IP_GETBUF
    if (sa == NULL ||
	    (rv = apr_sockaddr_ip_getbuf(ipstr, sizeof(ipstr), sa)) != APR_SUCCESS )
    {
	log_aprerror(rv, "couldn't get remote IP address");
	apr_cpystrn(ipstr, "unknown", sizeof(ipstr));
    }
    else
    {
	log_debug("UDP log message received from %s", ipstr);
    }
#else
    apr_cpystrn(ipstr, "unknown", sizeof(ipstr));
#endif
    nx_module_input_name_set(&(module->input), ipstr);

    while ( (logdata = module->input.inputfunc->func(&(module->input), module->input.inputfunc->data)) != NULL )
    {
	//log_debug("read: [%s]", logdata->data);
	// FIXME use IP4ADDR/IP6DDR type
	nx_logdata_set_string(logdata, "MessageSourceAddress", ipstr);
	nx_module_add_logdata_input(module, &(module->input), logdata);
    }
}


#ifdef HAVE_RECVMMSG

typedef struct im_udp_data_t
{

    struct mmsghdr *msgs;
    struct iovec *iovecs;
    char **addr_buf;
    int  *addr_len;
    int dg_len;
    int dg_count;
} im_udp_data_t;

im_udp_data_t * im_udp_data_new(apr_pool_t * pool, nx_module_input_t * input)
{
    im_udp_data_t * result;
    int i;
    nx_im_udp_conf_t *imconf;
    apr_size_t msgs_count;

    ASSERT(input->module->config != NULL);

    imconf = (nx_im_udp_conf_t *) input->module->config;
    msgs_count = (apr_size_t) imconf->max_messages;

    ASSERT(input->buf != NULL);

    result = apr_pcalloc(pool, sizeof(im_udp_data_t));

    result->msgs = apr_pcalloc(pool, sizeof(struct mmsghdr) * msgs_count);
    result->iovecs = apr_pcalloc(pool, sizeof(struct iovec) * msgs_count);
    result->addr_buf = apr_pcalloc(pool, sizeof(char *) * msgs_count);
    result->addr_len = apr_pcalloc(pool, sizeof(int) * msgs_count);

    for ( i = 0; i < (int)msgs_count; i++ )
    {
        // Map iovec on input buffer
        result->iovecs[i].iov_base = input->buf + i * IM_UDP_MAX_DATAGRAM_SIZE;
        result->iovecs[i].iov_len = IM_UDP_MAX_DATAGRAM_SIZE;
        result->msgs[i].msg_hdr.msg_iov = &(result->iovecs[i]);
        result->msgs[i].msg_hdr.msg_iovlen = 1;
    }

    result->dg_len = IM_UDP_MAX_DATAGRAM_SIZE;
    result->dg_count = (int)msgs_count;

    return result;
}


static apr_sockaddr_t * fill_sockaddr_from_msghdr( apr_sockaddr_t *buf, struct msghdr * hdr )
{
    if (hdr->msg_name == NULL)
    {
	return ( NULL );
    }
    memcpy(&(buf->sa), hdr->msg_name, hdr->msg_namelen);
    if (hdr->msg_namelen >  APR_OFFSET(struct sockaddr_in *, sin_port))
    {
	buf->family = buf->sa.sin.sin_family;
	if ( buf->sa.sin.sin_port)
        {
	    buf->port = ntohs(buf->sa.sin.sin_port);
        }
    }
    if (buf->sa.sin.sin_family == APR_INET) {
	buf->salen = sizeof(struct sockaddr_in);
	buf->addr_str_len = 16;
	buf->ipaddr_ptr = &(buf->sa.sin.sin_addr);
	buf->ipaddr_len = sizeof(struct in_addr);
    }
#if APR_HAVE_IPV6
    else if (buf->sa.sin.sin_family == APR_INET6) {
	buf->salen = sizeof(struct sockaddr_in6);
	buf->addr_str_len = 46;
	buf->ipaddr_ptr = &(buf->sa.sin6.sin6_addr);
	buf->ipaddr_len = sizeof(struct in6_addr);
    }
#endif
    return ( buf );
}


static void im_udp_get_recvmmsg_buffers(nx_module_t * module,
					im_udp_data_t ** input_buffers,
					apr_sockaddr_t ** sa_buffer)
{
    nx_im_udp_conf_t *imconf;
    int i;
    apr_pool_t * mp;
    im_udp_data_t * data;
    apr_sockaddr_t * sa;

    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    imconf = (nx_im_udp_conf_t*) module->config;
    mp = module->input.pool;

    sa = nx_module_input_data_get(&(module->input), NX_MODULE_INPUT_CONTEXT_RECV_FROM);
    data = nx_module_data_get(module, "udp_buffers");

    // Init sockaddr buffer
    if (sa == NULL)
    {
	sa = apr_pcalloc(mp, sizeof(apr_sockaddr_t));
	nx_module_input_data_set(&(module->input), NX_MODULE_INPUT_CONTEXT_RECV_FROM, sa);
    }

    // Get input buffers
    if (data == NULL)
    {	// Init input buffers
	data = im_udp_data_new(mp, &(module->input));
	nx_module_data_set(module, "udp_buffers", data, NULL);

	// Init recvmmsg structs
	for ( i = 0; i < imconf->max_messages ; i ++ )
	{
	    if (data->addr_buf[i] == NULL )
	    {
		data->addr_len[i] = sizeof(sa->sa);
		data->addr_buf[i] = apr_pcalloc(mp, (size_t)data->addr_len[i]);
		data->msgs[i].msg_hdr.msg_name = data->addr_buf[i];
		data->msgs[i].msg_hdr.msg_namelen = (socklen_t)data->addr_len[i];
	    }
	}
    }
    *sa_buffer = sa;
    *input_buffers = data;
}

static void im_udp_read_recvmmsg(nx_module_t * module)
{
    // create temporary pool
    apr_sockaddr_t *from;
    apr_sockaddr_t * sa_buf;
    apr_os_sock_t fd;
    int i;
    int rv;
    struct msghdr * header;
    im_udp_data_t * udp_data;
    int msg_len;
    int errcode;
    ASSERT(module != NULL);

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
	log_debug("module %s not running, not reading any more data", module->name);
	return;
    }

    ASSERT(module->input.desc_type == APR_POLL_SOCKET);
    ASSERT(module->input.desc.s != NULL);
    ASSERT(module->input.buf != NULL);
    ASSERT(module->config != NULL);


    CHECKERR_MSG(apr_os_sock_get(&fd, module->input.desc.s),
		 "couldn't get socket fd");

    im_udp_get_recvmmsg_buffers(module, &udp_data, &sa_buf);

    if ((rv = recvmmsg(fd, udp_data->msgs, (unsigned)udp_data->dg_count, 0, NULL)) == -1)
    {
	if ( errno == EAGAIN ||
	     errno == ECONNRESET ||
	     errno == ECONNABORTED ||
	     errno == EINTR ||
	     errno == EMSGSIZE ||
	     errno == ETIMEDOUT )
	{
	    nx_module_add_poll_event(module);
	}
	else
	{
	    errcode = errno; // errno could be overwritten be the next call, so let's save it
	    im_udp_close_socket(module);
	    throw(APR_FROM_OS_ERROR(errcode), "Module %s couldn't read from socket", module->name);
	}
    }

    DEBUG_MSGCOUNT(rv);

    for ( i = 0; i < rv; i ++ )
    {
	header = &(udp_data->msgs[i].msg_hdr);
	msg_len = (int)udp_data->msgs[i].msg_len;

	from = fill_sockaddr_from_msghdr(sa_buf, header);

	module->input.buf = udp_data->iovecs[i].iov_base;
	module->input.bufstart = 0;
	module->input.buflen = msg_len;
	module->input.buf[msg_len] = '\0';

	im_udp_logdata_post(module, from);
    }
    // return input buf address
    module->input.buf = udp_data->iovecs[0].iov_base;
}

#endif

static void im_udp_read_recvfrom(nx_module_t *module)
{
    apr_sockaddr_t *sa = NULL;
    apr_status_t rv;


    ASSERT(module != NULL);

    log_debug("im_udp_read_recvfrom: module: '%s(%s)", module->name, module->dsoname);

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_RUNNING )
    {
	log_debug("module %s not running, not reading any more data", module->name);
	return;
    }

    if ( (rv = nx_module_input_fill_buffer_from_socket(&(module->input))) != APR_SUCCESS )
    {
	if ( APR_STATUS_IS_EAGAIN(rv) ||
	     APR_STATUS_IS_ECONNRESET(rv) ||
	     APR_STATUS_IS_ECONNABORTED(rv) ||
	     APR_STATUS_IS_EINTR(rv) ||
	     APR_STATUS_IS_EMSGSIZE(rv) ||
	     APR_STATUS_IS_ETIMEDOUT(rv) )
	{
	    nx_module_add_poll_event(module);
	}
	else
	{
	    im_udp_close_socket(module);
	    throw(rv, "Module %s couldn't read from socket", module->name);
	}
    }

    if ( module->input.buflen == 0 ) 
    { // couldn't read anything
	return; 
    }
    //log_info("Readen %d bytes", module->input.buflen);
    DEBUG_MSGCOUNT(1);

    sa = nx_module_input_data_get(&(module->input), NX_MODULE_INPUT_CONTEXT_RECV_FROM);
    ASSERT(sa != NULL);

    im_udp_logdata_post(module, sa);
}


static void im_udp_config(nx_module_t *module)
{
    const nx_directive_t *curr;
    nx_im_udp_conf_t *imconf;
    unsigned int port;
    boolean max_messages_defined = FALSE;
    boolean use_recvmmsg_defined = FALSE;

    ASSERT(module->directives != NULL);
    curr = module->directives;

    imconf = apr_pcalloc(module->pool, sizeof(nx_im_udp_conf_t));
    module->config = imconf;
    imconf->max_messages = 10;


    while ( curr != NULL )
    {
	if ( nx_module_common_keyword(curr->directive) == TRUE )
	{
	}
	else if ( strcasecmp(curr->directive, "host") == 0 )
	{
	    if ( imconf->host != NULL )
	    {
		nx_conf_error(curr, "host is already defined");
	    }
	    imconf->host = apr_pstrdup(module->pool, curr->args);
	}
	else if ( strcasecmp(curr->directive, "port") == 0 )
	{
	    if ( imconf->port != 0 )
	    {
		nx_conf_error(curr, "port is already defined");
	    }
	    if ( sscanf(curr->args, "%u", &port) != 1 )
	    {
		nx_conf_error(curr, "invalid port: %s", curr->args);
	    }
	    imconf->port = (apr_port_t) port;
	}
	else if ( strcasecmp(curr->directive, "sockbufsize") == 0 )
	{
	    if ( imconf->sockbufsize != 0 )
	    {
		nx_conf_error(curr, "SockBufSize is already defined");
	    }
	    if ( sscanf(curr->args, "%u", &(imconf->sockbufsize)) != 1 )
	    {
		nx_conf_error(curr, "invalid SockBufSize: %s", curr->args);
	    }
	}
	else if ( strcasecmp(curr->directive, "InputType") == 0 )
	{
	    if ( imconf->inputfunc != NULL )
	    {
		nx_conf_error(curr, "InputType is already defined");
	    }

	    if ( curr->args != NULL )
	    {
		imconf->inputfunc = nx_module_input_func_lookup(curr->args);
	    }
	    if ( imconf->inputfunc == NULL )
	    {
		nx_conf_error(curr, "Invalid InputType '%s'", curr->args);
	    }
	}
	else if ( strcasecmp(curr->directive, "MaxMessages") == 0)
	{
	    if ( max_messages_defined )
	    {
		nx_conf_error(curr, "MaxMessages is already defined");
	    }
	    max_messages_defined = TRUE;
	    if ( sscanf(curr->args, "%u", &(imconf->max_messages)) != 1 )
	    {
		nx_conf_error(curr, "invalid MaxMessages: %s", curr->args);
	    }
	    if (imconf->max_messages < 1 || imconf->max_messages > 100)
	    {
		nx_conf_error(curr, "invalid MaxMessages: %s", curr->args);
	    }
	    if (imconf->max_messages > MAX_MSGS_COUNT)
	    {  // Check OS support
		imconf->max_messages = MAX_MSGS_COUNT;
	    }
	}
	else if ( strcasecmp(curr->directive, "UseRecvmmsg") == 0)
	{
#ifndef HAVE_RECVMMSG
		nx_conf_error(curr, "UseRecvmmsg is not supported on this OS");
#endif
	    if (use_recvmmsg_defined)
	    {
		nx_conf_error(curr, "UseRecvmmsg is already defined");
	    }
	    use_recvmmsg_defined = TRUE;
	}
	else
	{
	    nx_conf_error(curr, "invalid keyword: %s", curr->directive);
	}
	curr = curr->next;
    }

    if ( imconf->inputfunc == NULL )
    {
	imconf->inputfunc = nx_module_input_func_lookup("dgram");
    }
    ASSERT(imconf->inputfunc != NULL);

    if ( imconf->host == NULL )
    {
	imconf->host = apr_pstrdup(module->pool, IM_UDP_DEFAULT_HOST);
    }

    if ( imconf->port == 0 )
    {
	imconf->port = IM_UDP_DEFAULT_PORT;
    }

#ifdef HAVE_RECVMMSG
    imconf->use_recvmmsg = TRUE;
    nx_cfg_get_boolean(module->directives, "UseRecvmmsg", &(imconf->use_recvmmsg));
#else
    imconf->use_recvmmsg = FALSE;
#endif

    module->input.pool = nx_pool_create_child(module->pool);
}



static void im_udp_start(nx_module_t *module)
{
    nx_im_udp_conf_t *imconf;
    apr_sockaddr_t *sa;
    nx_exception_t e;

    ASSERT(module->config != NULL);

    imconf = (nx_im_udp_conf_t *) module->config;

    // reallocate buffer
    module->input.bufsize = IM_UDP_MAX_DATAGRAM_SIZE * imconf->max_messages;
    module->input.buf = apr_pcalloc(module->input.pool, (size_t)module->input.bufsize);

    try
    {
	if ( module->input.desc.s == NULL )
	{
	    CHECKERR_MSG(apr_socket_create(&(module->input.desc.s), APR_INET, SOCK_DGRAM,
					   APR_PROTO_UDP, module->input.pool),
			 "couldn't create udp socket");
	    module->input.desc_type = APR_POLL_SOCKET;
	    module->input.module = module;
	    module->input.inputfunc = imconf->inputfunc;

	    CHECKERR_MSG(apr_sockaddr_info_get(&sa, imconf->host, APR_INET, imconf->port, 
					       0, module->input.pool),
			 "apr_sockaddr_info failed for %s:%d", imconf->host, imconf->port);

	    CHECKERR_MSG(apr_socket_bind(module->input.desc.s, sa),
			 "couldn't bind udp socket to %s:%d", imconf->host, imconf->port);

	    CHECKERR_MSG(apr_socket_opt_set(module->input.desc.s, APR_SO_NONBLOCK, 1),
			 "couldn't set SO_NONBLOCK on udp socket");
	    CHECKERR_MSG(apr_socket_timeout_set(module->input.desc.s, 0),
			 "couldn't set socket timeout on udp socket");
	    if ( imconf->sockbufsize != 0 )
	    {
		CHECKERR_MSG(apr_socket_opt_set(module->input.desc.s, APR_SO_RCVBUF,
						imconf->sockbufsize),
			     "couldn't set SO_RCVBUF on udp socket");
	    }
	}
        else
	{
	    log_debug("udp socket already initialized");
	}

	nx_module_pollset_add_socket(module, module->input.desc.s, APR_POLLIN);
    }
    catch(e)
    {
	im_udp_close_socket(module);
	rethrow_msg(e, "failed to start im_udp");
    }

    nx_module_add_poll_event(module);

    log_debug("im_udp started");
}



static void im_udp_stop(nx_module_t *module)
{
    im_udp_close_socket(module);
}



static void im_udp_resume(nx_module_t *module)
{
    ASSERT(module != NULL);

    if ( nx_module_get_status(module) != NX_MODULE_STATUS_STOPPED )
    {
	nx_module_add_poll_event(module);
    }
}



static void im_udp_init(nx_module_t *module)
{
    nx_module_pollset_init(module);
}



static void im_udp_event(nx_module_t *module, nx_event_t *event)
{
    nx_im_udp_conf_t * conf;

    ASSERT(event != NULL);
    ASSERT(module != NULL);
    ASSERT(module->config != NULL);

    conf = (nx_im_udp_conf_t*) module->config;

    switch ( event->type )
    {
	case NX_EVENT_READ:
#ifdef HAVE_RECVMMSG
	    if (conf->use_recvmmsg)
	    {
		im_udp_read_recvmmsg(module);
	    }
	    else
	    {
		im_udp_read_recvfrom(module);
	    }
#else
	    im_udp_read_recvfrom(module);
#endif
	    break;
	case NX_EVENT_POLL:
	    if ( nx_module_get_status(module) == NX_MODULE_STATUS_RUNNING )
	    {
		nx_module_pollset_poll(module, TRUE);
	    }
	    break;
	default:
	    nx_panic("invalid event type: %d", event->type);
    }
}



NX_MODULE_DECLARATION nx_im_udp_module =
{
    NX_MODULE_API_VERSION,
    NX_MODULE_TYPE_INPUT,
    "CAP_NET_BIND_SERVICE",	// capabilities
    im_udp_config,		// config
    im_udp_start,		// start
    im_udp_stop, 		// stop
    NULL,			// pause
    im_udp_resume,		// resume
    im_udp_init,		// init
    NULL,			// shutdown
    im_udp_event,		// event
    NULL,			// info
    NULL,			// exports
};
