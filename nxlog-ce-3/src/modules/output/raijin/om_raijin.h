/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev <avkhadeev@gmail.com>
 */


#ifndef __NX_OM_RAIJIN_H
#define __NX_OM_RAIJIN_H

#include "../../../common/ssl.h"
#include "../../../common/types.h"
#include "../../../common/logdata.h"

#define NX_OM_RAIJIN_RESPBUFSIZE 65536
#define NX_OM_RAIJIN_MAX_INDEX_LEN 512

#define NX_OM_RAIJIN_DEFAULT_FLUSH_INTERVAL 5
#define NX_OM_RAIJIN_DEFAULT_FLUSH_LIMIT 500
#define NX_OM_RAIJIN_BATCH_SIZE 50 /* number of events to read from the queue */

typedef struct nx_om_raijin_server_t
{
    boolean https;
    const char *url;
    const char *host;
    apr_port_t port;
    char path[2048];
} nx_om_raijin_server_t;

typedef enum nx_om_raijin_resp_state_t
{
    NX_OM_RAIJIN_RESP_STATE_START = 0,
    NX_OM_RAIJIN_RESP_STATE_CR,
    NX_OM_RAIJIN_RESP_STATE_CR_LF,
    NX_OM_RAIJIN_RESP_STATE_CR_LF_CR,
    NX_OM_RAIJIN_RESP_STATE_CR_LF_CR_LF,
} nx_om_raijin_resp_state_t;

typedef enum nx_socket_state_e
{
    NX_SOCKET_STATE_NONE = 0,
    NX_SOCKET_STATE_READY,
    NX_SOCKET_STATE_HANDSHAKING,
    NX_SOCKET_STATE_CONNECTED,
} nx_socket_state_t;

typedef struct nx_om_raijin_conf_t 
{
    apr_pool_t		*pool;
    nx_om_raijin_server_t server;
    nx_socket_state_t	state;

    const char 		*dbtable;
    const char 		*dbname;

    const char		*proxy_addr;
    apr_port_t		proxy_port;
    boolean             use_proxy;

    BIO 		*bio_reqhdr;
    const char		*reqhdrbuf;
    apr_size_t		reqhdrbufsize;

    BIO 		*bio_reqbdy;
    const char		*reqbdybuf;
    apr_size_t		reqbdybufsize;

    apr_socket_t	*sock;
    nx_ssl_ctx_t	ssl_ctx;
    SSL			*ssl;
    long		ssl_options;
    const char          *ssl_cipher_list;
    char		respbuf[NX_OM_RAIJIN_RESPBUFSIZE];
    int                 respheaderlen;
    int                 respbuflen;
    BIO			*bio_resp_head;
    BIO			*bio_resp_body;
    apr_size_t		content_length;
    char		transfer_encoding[16];
    nx_om_raijin_resp_state_t resp_state;
    boolean		got_resp_head;
    boolean		got_resp_body;
    boolean		resp_wait; 	///< data send in progress
    boolean		recreate;
    float		flush_interval;
    int			flush_limit;	///< flush request buffer when bulk_data_cnt has reached this
    int			bulk_data_cnt;	///< number of logdata entries in reqbdy
    nx_event_t		*timeout_event;
    nx_event_t		*flush_event;
    nx_event_t		*reconnect_event;
    int			reconnect; // number of seconds after trying to reconnect
    nx_expr_proc_t 	*to_json;
    nx_module_t 	*xm_json;

    boolean		chunked;

} nx_om_raijin_conf_t;

#endif //__NX_OM_RAIJIN_H
