/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#ifndef __NX_SSL_H
#define __NX_SSL_H

#include "types.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <apr_network_io.h>

typedef struct nx_ssl_ctx_t
{
    apr_pool_t		*pool;
    const char		*certfile; 	///< certificate filename
    X509 		*cert;
    const char		*certkeyfile;	///< certificate key filename
    const char		*keypass;	///< password for the cert key
    EVP_PKEY 		*key;
    boolean		require_cert;	///< require peer certification
    boolean		allow_untrusted; ///< allow certificates which cannot be verified
    const char		*cafile; 	///< CA filename for cert verification
    const char		*cadir; 	///< Directory containing CA files for cert verification
    const char		*crlfile; 	///< CRL filename for cert verification
    const char		*crldir; 	///< Directory containing CRL files for cert verification
    const char		*sni;		///< Non-NULL if Server Name Indication is needed
    SSL_CTX		*ssl_ctx;
    boolean		compression;	///< enable compression if compression if TRUE
    int			verify_result;  ///< result of the certificate verification
} nx_ssl_ctx_t;


void nx_ssl_error(boolean printerror,
		  const char *fmt,
		  ...) PRINTF_FORMAT(2,3) NORETURN;

int nx_ssl_check_io_error(SSL *ssl, int retval);
void nx_ssl_ctx_init(nx_ssl_ctx_t *ctx, apr_pool_t *pool);
SSL *nx_ssl_from_socket(nx_ssl_ctx_t *ctx, apr_socket_t *sock, long options, const char* cipher_list);
SSL *nx_ssl_from_socket_ex(nx_ssl_ctx_t *ctx, apr_socket_t *sock, long options, const char* cipher_list, int bio_flag);
int nx_ssl_read(SSL *ssl, char *buf, int *size);
int nx_ssl_write(SSL *ssl, const char *buf, int *size);
void nx_ssl_destroy(SSL **ssl);
long nx_ssl_parse_protocol(const char *str);

#endif	/* __NX_SSL_H */
