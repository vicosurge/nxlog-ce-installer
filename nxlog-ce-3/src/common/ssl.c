/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#include <apr_portable.h>

#include "../core/nxlog.h"
#include "error_debug.h"
#include "ssl.h"

#define NX_LOGMODULE NX_LOGMODULE_MODULE

static int nx_ssl_data_idx = -1;

typedef struct nx_ssl_data_t
{
    nx_ssl_ctx_t    *ssl_ctx;	    ///< configuration context
    apr_socket_t    *sock;	    ///< associated socket
    int             verify_result;  ///< result of the certificate verification
    boolean         no_shutdown;    ///< skip SSL_shutdown()
} nx_ssl_data_t;

static void nx_ssl_locking_callback(int mode, int id, char *file UNUSED, int line UNUSED)
{
    nxlog_t *nxlog;
    
    //log_debug("ssl_locking_callback()");

    nxlog = nxlog_get();

    if ( nxlog->openssl_locks != NULL )
    {
	if ( mode & CRYPTO_LOCK )
	{
	    CHECKERR(apr_thread_mutex_lock(nxlog->openssl_locks[id]));
	}
	else
	{
	    CHECKERR(apr_thread_mutex_unlock(nxlog->openssl_locks[id]));
	}
    }
}


    
static unsigned long nx_ssl_thread_id()
{
    unsigned long ret;
    
    ret = (unsigned long) apr_os_thread_current();

    return ( ret );
}



static void nx_ssl_init_locking(nxlog_t *nxlog)
{
    int i;

    if ( nxlog->openssl_locks == NULL )
    {
	nxlog->openssl_locks = apr_pcalloc(nxlog->pool, ((unsigned int) CRYPTO_num_locks()) * sizeof(apr_thread_mutex_t *));

	for ( i = 0; i < CRYPTO_num_locks(); i++ )
	{
	    CHECKERR(apr_thread_mutex_create(&(nxlog->openssl_locks[i]),
					     APR_THREAD_MUTEX_UNNESTED, nxlog->pool));
	}
    }
    
    CRYPTO_set_id_callback((unsigned long (*)())nx_ssl_thread_id);
    CRYPTO_set_locking_callback((void (*)())nx_ssl_locking_callback);
}



void nx_ssl_error(boolean printerror,
		  const char *fmt,
		  ...)

{
    const char *str;
    unsigned long errcode;
    const char *libstr;
    const char *funcstr;
    nx_loglevel_t loglevel = NX_LOGLEVEL_ERROR;
    nx_ctx_t *ctx;
    char errmsg[512];

    errmsg[0] = '\0';
    if ( fmt != NULL )
    {
	va_list ap;

	va_start(ap, fmt);
	apr_vsnprintf(errmsg, sizeof(errmsg), fmt, ap);
	va_end(ap);
    }

    ctx = nx_ctx_get();
    if ( ctx != NULL )
    {
	loglevel = ctx->loglevel;
    }

    if ( errno == 0 )
    {
	printerror = 0;
    }
    if ( printerror > 0 )
    {
	throw_errno("SSL error, %s", errmsg);
    }

    while ( ((unsigned long) (errcode = ERR_get_error())) > 0 )
    {
	str = ERR_reason_error_string(errcode);
	funcstr = ERR_func_error_string(errcode);
	libstr = ERR_lib_error_string(errcode);
	if ( libstr == NULL )
	{
	    libstr = "unknown";
	}
	if ( funcstr == NULL )
	{
	    funcstr = "unknown";
	}

	if ( str == NULL )
	{
	    if ( errcode == 1 )
	    {
		//log_error("ssl lib usage error");
	    }
	    else
	    {
		throw_msg("unknown SSL error, code: %ld, lib: %s, func: %s",
			  (long int) errcode, libstr, funcstr);
	    }
	}
	else
	{
	    if ( loglevel == NX_LOGLEVEL_DEBUG )
	    {
		throw_msg("SSL error, %s, %s [lib:%s func:%s]", errmsg, str,
			  libstr, funcstr);
	    }
	    else
	    {
		throw_msg("SSL error, %s, %s,", errmsg, str);
	    }
	}
    }
    throw_msg("SSL error: %s", errmsg);
}



int nx_ssl_check_io_error(SSL *ssl, int retval)
{
    int errcode;
    char *ipstr;
    apr_sockaddr_t *sa;
    nx_ssl_data_t *ssl_data;

    ASSERT(ssl != NULL);
    ssl_data = SSL_get_ex_data(ssl, nx_ssl_data_idx);
    ASSERT(ssl_data != NULL);
    ASSERT(ssl_data->sock != NULL);
    CHECKERR_MSG(apr_socket_addr_get(&sa, APR_REMOTE, ssl_data->sock),
                 "couldn't get info on remote socket");
    CHECKERR_MSG(apr_sockaddr_ip_get(&ipstr, sa),
                 "couldn't get IP of remote socket");

    errcode = SSL_get_error(ssl, retval);

    if ( ssl_data->verify_result != 0 )
    { // cert verification failed;
	throw_msg("SSL certificate verification failed: %s (err: %d)",
		  X509_verify_cert_error_string(ssl_data->verify_result),
		  ssl_data->verify_result);
    }

    switch ( errcode  )
    {
	case SSL_ERROR_ZERO_RETURN:
	    //log_info("SSL connection closed");
	    break;
	case SSL_ERROR_WANT_READ:
	    //log_debug("SSL want read");
	    break;
	case SSL_ERROR_WANT_WRITE:
	    //log_debug("SSL want write");
	    break;
	case SSL_ERROR_WANT_CONNECT:
	    //log_debug("SSL want connect");
	    break;
	case SSL_ERROR_WANT_ACCEPT:
	    //log_debug("SSL want accept");
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    //log_debug("SSL want x509 lookup");
	    break;
	case SSL_ERROR_SYSCALL:
	    if ( retval == 0 )
	    {
		//log_debug("EOF during SSL read");
		return ( SSL_ERROR_ZERO_RETURN );
	    }
	    else
	    {
		// don't call SSL_shutdown() after SSL_ERROR_SYSCALL
		// see: https://www.openssl.org/docs/man1.1.1/man3/SSL_shutdown.html
		if ( retval < 0 )
		{
		    ssl_data->no_shutdown = TRUE;
		}

		// openssl does something bad because we get EBADF when the connection
		// is reset during handshake, so we treat this as connection EOF
		if ( (errno == 0) || (errno == EBADF) || (errno == EOF) || (errno == EPIPE) )
		{
		    throw(APR_EOF, "remote ssl socket was reset? (SSL_ERROR_SYSCALL with errno=%d)", errno);
		}
		nx_ssl_error(retval == -1, "SSL_ERROR_SYSCALL: retval %d, errno: %d",
			     retval, errno);
	    }
	    break;
	case SSL_ERROR_SSL:
	    // don't call SSL_shutdown() after SSL_ERROR_SSL
	    // see: https://www.openssl.org/docs/man1.1.1/man3/SSL_shutdown.html
	    if ( retval < 0 )
	    {
		ssl_data->no_shutdown = TRUE;
	    }

	    // openssl does something bad because we get EBADF when the connection
	    // is reset during read/write, so we treat this as connection EOF
	    if ( (errno == EBADF) || (errno == EOF) || (errno == EPIPE) )
	    {
		throw(APR_EOF, "remote ssl socket was reset? (SSL_ERROR_SSL with errno=%d), from %s:%u", errno, ipstr, sa->port);
	    }
	    nx_ssl_error(retval == -1, "SSL_ERROR_SSL: retval %d, from %s:%u", retval, ipstr, sa->port);
	    break;
	default:
	    nx_ssl_error(FALSE, "unknown SSL error (errorcode: %d), from %s:%u", retval, ipstr, sa->port);
	    break;
    }

    return ( errcode );
}



void nx_ssl_ctx_check(struct nx_ssl_ctx_t* ctx);

/**
 * initialize ssl context
 */

void nx_ssl_ctx_init(nx_ssl_ctx_t *ctx, apr_pool_t *pool)
{
    BIO *cert_bio = NULL;
    BIO *key_bio = NULL;
    nxlog_t *nxlog;
    
    //log_debug("SSL init");

    nxlog = nxlog_get();

    nx_lock();
    nx_ssl_init_locking(nxlog);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#else
    OPENSSL_init_ssl(0, NULL);
#endif

    SSL_load_error_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if ( nx_ssl_data_idx == -1 )
    {
        nx_ssl_data_idx = SSL_get_ex_new_index(0, (void *) "ssl_ctx_idx", 0, 0, 0);
    }

    nx_unlock();

    ctx->pool = pool;
    // FIXME: use pool for allocations

    if ( (ctx->certfile != NULL) && (ctx->certkeyfile != NULL) )
    {
	cert_bio = BIO_new_file(ctx->certfile, "r");
	if ( cert_bio == NULL )
	{
	    nx_ssl_error(TRUE, "Failed to open certfile: %s", ctx->certfile);
	}

	key_bio = BIO_new_file(ctx->certkeyfile, "r");
	if ( key_bio == NULL )
	{
	    nx_ssl_error(TRUE, "Failed to open certkey: %s", ctx->certkeyfile);
	}

	ctx->cert = PEM_read_bio_X509(cert_bio, NULL, 0, (void *) ctx->keypass);
	if ( ctx->cert == NULL )
	{
	    BIO_free(cert_bio);
	    nx_ssl_error(FALSE, "couldn't read cert");
	}

	ctx->key = PEM_read_bio_PrivateKey(key_bio, NULL, 0, (void *) ctx->keypass);
	if ( ctx->key == NULL )
	{
	    BIO_free(cert_bio);
	    BIO_free(key_bio);
	    nx_ssl_error(FALSE, "invalid certificate key passphrase [%s], couldn't decrypt key",
			 ctx->keypass);
	}
	BIO_free(key_bio);
	BIO_free(cert_bio);
    }

    nx_ssl_ctx_check(ctx);

    if (ctx->ssl_ctx != NULL)
    {
	SSL_CTX_free(ctx->ssl_ctx);
	ctx->ssl_ctx = NULL;
    }
}



static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    int err;
    int	retval = preverify_ok;
    SSL *ssl;
    nx_ssl_data_t *ssl_data;

    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    ASSERT(ssl != NULL);

    ssl_data = SSL_get_ex_data(ssl, nx_ssl_data_idx);
    ASSERT(ssl_data != NULL);
    ASSERT(ssl_data->ssl_ctx != NULL);

    ssl_data->verify_result = 0;
    log_debug("verify callback (ok: %d)", preverify_ok);
    if ( !preverify_ok )
    {
	err = X509_STORE_CTX_get_error(ctx);
	log_debug("preverification returned non-OK: %s", X509_verify_cert_error_string(err));

	switch ( err )
	{
	    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		if ( ssl_data->ssl_ctx->allow_untrusted == TRUE )
		{
		    retval = 1;
		}
		else
		{
		    retval = 0;
		    ssl_data->verify_result = err;
		}
		break;
	    case X509_V_ERR_UNABLE_TO_GET_CRL:
		log_warn("CRL verification requested but no CRLs found");
		retval = 1;
		break;
	    default:
		retval = 0;
		ssl_data->verify_result = err;
	}
    }

    return ( retval );
}



void nx_ssl_ctx_check(struct nx_ssl_ctx_t* ctx)
{
    int verify_mode = SSL_VERIFY_NONE;
    unsigned long verify_flags = X509_V_FLAG_POLICY_CHECK;
    const SSL_METHOD	*meth;

    meth = SSLv23_method();
    if ( meth == NULL )
    {
	nx_ssl_error(FALSE, "failed to init SSLv23");
    }

    ASSERT(ctx->ssl_ctx == NULL);
    ctx->ssl_ctx = SSL_CTX_new(meth);
    if ( ctx->ssl_ctx == NULL )
    {
	nx_ssl_error(FALSE, "failed to create ssl_ctx");
    }

    if ( (ctx->cafile != NULL) || (ctx->cadir != NULL) )
    {
	if ( SSL_CTX_load_verify_locations(ctx->ssl_ctx, ctx->cafile, ctx->cadir) != 1 )
	{
	    SSL_CTX_free(ctx->ssl_ctx);
	    ctx->ssl_ctx = NULL;
	    nx_ssl_error(FALSE, "failed to load ca cert from '%s'",
			 ctx->cafile == NULL ? ctx->cadir : ctx->cafile);
	}
    }

    if ( (ctx->crlfile != NULL) || (ctx->crldir != NULL) )
    {
	verify_flags |= X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_CRL_CHECK;
	if ( SSL_CTX_load_verify_locations(ctx->ssl_ctx, ctx->crlfile, ctx->crldir) != 1 )
	{
	    SSL_CTX_free(ctx->ssl_ctx);
	    ctx->ssl_ctx = NULL;
	    nx_ssl_error(FALSE, "failed to load crl from '%s'",
			 ctx->crlfile == NULL ? ctx->crldir : ctx->crlfile);
	}
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    X509_VERIFY_PARAM_set_flags(ctx->ssl_ctx->param, verify_flags);
#else
    X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx->ssl_ctx), verify_flags);
#endif

    if ( ctx->allow_untrusted != TRUE )
    {
	verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
    }
    if ( ctx->require_cert == TRUE )
    {
	verify_mode |= SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }

    SSL_CTX_set_verify(ctx->ssl_ctx, verify_mode, (verify_mode & SSL_VERIFY_PEER) ? verify_callback : NULL);

    if ( ctx->cert != NULL )
    {
	if ( SSL_CTX_use_certificate(ctx->ssl_ctx, ctx->cert) != 1 )
	{
	    SSL_CTX_free(ctx->ssl_ctx);
	    ctx->ssl_ctx = NULL;
	    nx_ssl_error(FALSE, "use_certificate() failed");
	}
    }

    if ( ctx->key != NULL )
    {
	if ( SSL_CTX_use_PrivateKey(ctx->ssl_ctx, ctx->key) != 1 )
	{
	    SSL_CTX_free(ctx->ssl_ctx);
	    ctx->ssl_ctx = NULL;
	    nx_ssl_error(FALSE, "use_PrivateKey() failed");
	}
	if ( SSL_CTX_check_private_key(ctx->ssl_ctx) != 1 )
	{
	    SSL_CTX_free(ctx->ssl_ctx);
	    ctx->ssl_ctx = NULL;
	    throw_msg("Private key %s does not match certificate %s",
		      ctx->certkeyfile, ctx->certfile);
	}
    }
}



/**
 * return NULL on error, an SSL structure on success
 */
// FIXME: remove the SSL_CTX member from nx_ssl_ctx_t, and make nx_ssl_ctx_check return the SSL_CTX it creates
SSL *nx_ssl_from_socket_ex(nx_ssl_ctx_t *ctx, apr_socket_t *sock, long options, const char* cipher_list, int bio_flag)
{
    SSL *ssl;
    BIO *bio;
    apr_os_sock_t fd;
    nx_ssl_data_t *ssl_data;

    nx_ssl_ctx_check(ctx); // creates the ctx->ssl_ctx
    ASSERT(ctx->ssl_ctx != NULL);

    SSL_CTX_set_options(ctx->ssl_ctx, options);

    if ( ctx->compression == TRUE )
    {
#ifdef SSL_OP_NO_COMPRESSION
	// SSL_OP_NO_COMPRESSION option enabled by default
	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_COMPRESSION);
#else
	log_warn("SSL/TLS compression was enabled but is unsupported by libssl");
#endif
    }


    if ( (cipher_list != NULL) && strlen(cipher_list) > 0 )
    {
	if ( SSL_CTX_set_cipher_list(ctx->ssl_ctx, cipher_list) == 0 )
	{
	    SSL_CTX_free(ctx->ssl_ctx);
	    ctx->ssl_ctx = NULL;
	    throw_msg("SSLCipher option '%s' does not contain any valid cipher", cipher_list);
	}
    }

    // SSL_new() increases the reference count of ctx->ssl_ctx
    ssl = SSL_new(ctx->ssl_ctx);
    if ( ssl == NULL )
    {
	SSL_CTX_free(ctx->ssl_ctx);
	ctx->ssl_ctx = NULL;
	nx_ssl_error(FALSE, "failed to initialize ssl context");
    }

    //SSL_CTX_free() only decreases the reference count of ctx->ssl_ctx;
    //ctx->ssl_ctx is still referenced by the SSL_new() call above,
    //so it will only be freed by the corresponding SSL_free() call
    SSL_CTX_free(ctx->ssl_ctx);
    ctx->ssl_ctx = NULL;

    if ( ctx->sni != NULL )
    {
#ifdef SSL_set_tlsext_host_name
	if ( SSL_set_tlsext_host_name(ssl, ctx->sni) != 1 )
	{
	    nx_ssl_error(FALSE, "SSL_set_tlsext_host_name() failed");
	}
#else
	throw_msg("SNI support is not available in the SSL library");
#endif
    }

    CHECKERR_MSG(apr_os_sock_get(&fd, sock), "couldn't get fd of accepted socket");

    bio = BIO_new_socket(fd, bio_flag);
    if ( bio == NULL )
    {
	SSL_free(ssl);
	throw_msg("error allocating BIO from socket");
    }

    SSL_set_bio(ssl, bio, bio);

    ssl_data = calloc(sizeof(nx_ssl_data_t), 1);
    ASSERT(ssl_data != NULL);
    ssl_data->sock = sock;
    ssl_data->ssl_ctx = ctx;
    ASSERT(SSL_set_ex_data(ssl, nx_ssl_data_idx, ssl_data) == 1);

    return ( ssl );
}

SSL *nx_ssl_from_socket(nx_ssl_ctx_t *ctx, apr_socket_t *sock, long options, const char* cipher_list)
{
    return nx_ssl_from_socket_ex(ctx, sock, options, cipher_list, BIO_CLOSE);
}

int nx_ssl_read(SSL *ssl, char *buf, int *size)
{
    int retval;

    ASSERT(ssl != NULL);
    ASSERT(buf != NULL);
    ASSERT(size != NULL);
    ASSERT(*size > 0);

    retval = SSL_read(ssl, buf, *size);
    if ( retval > 0 )
    {
	*size = retval;
	return ( SSL_ERROR_NONE );
    }
    else
    {
	*size = 0;
    }
    return ( nx_ssl_check_io_error(ssl, retval) );
}



int nx_ssl_write(SSL *ssl, const char *buf, int *size)
{
    int retval;

    ASSERT(ssl != NULL);
    ASSERT(buf != NULL);
    ASSERT(size != NULL);
    ASSERT(*size > 0);

    retval = SSL_write(ssl, buf, *size);

    if ( retval > 0 )
    {
	*size = retval;
	return ( SSL_ERROR_NONE );
    }
    else
    {
	*size = 0;
    }
    return ( nx_ssl_check_io_error(ssl, retval) );
}



void nx_ssl_destroy(SSL **ssl)
{
    SSL_CTX *ssl_ctx;

    if ( *ssl == NULL )
    {
	return;
    }

    ssl_ctx = SSL_get_SSL_CTX(*ssl);
    SSL_shutdown(*ssl);
    if ( ssl_ctx != NULL )
    {
	SSL_CTX_free(ssl_ctx);
    }
    SSL_free(*ssl);
    *ssl = NULL;
}



static long nx_ssl_protocol_to_int(const char *str)
{
    if ( strcasecmp(str, "SSLv2") == 0 )
    {
	return ~SSL_OP_NO_SSLv2;
    }
    if ( strcasecmp(str, "SSLv3") == 0 )
    {
	return ~SSL_OP_NO_SSLv3;
    }
    if ( strcasecmp(str, "TLSv1") == 0 )
    {
	return ~SSL_OP_NO_TLSv1;
    }
#if defined SSL_OP_NO_TLSv1_2
    if ( strcasecmp(str, "TLSv1.2") == 0 )
    {
	return ~SSL_OP_NO_TLSv1_2;
    }
#endif
#if defined SSL_OP_NO_TLSv1_1
    if ( strcasecmp(str, "TLSv1.1") == 0 )
    {
	return ~SSL_OP_NO_TLSv1_1;
    }
#endif
    return 0;
}

#if defined SSL_OP_NO_TLSv1_2 & defined SSL_OP_NO_TLSv1_1
# define NX_SSL_PROTOCOLS_NONE (SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_1)
#else
# define NX_SSL_PROTOCOLS_NONE (SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1)
#endif

long nx_ssl_parse_protocol(const char *str)
{
    long tmp;
    char protocol[20];
    int p, i = 0;
    long retval = NX_SSL_PROTOCOLS_NONE;

    do
    {
	memset(protocol, 0, sizeof(protocol));
	for ( p = 0 ; ; i++ )
	{
	    if ( p >= (int) sizeof(protocol) )
	    { // protocol name too long
		return ( -1 );
	    }
	    if ( (str[i] == ' ') || (str[i] == ',') || (str[i] == ';') || str[i] == '\0' )
	    {
		if ( p > 0 )
		{
		    tmp = nx_ssl_protocol_to_int(protocol);
		    if ( tmp == 0 )
		    { // invalid protocol
			return ( -1 );
		    }
		    retval &= tmp;
		    break;
		}
	    }
	    else
	    {
		protocol[p] = str[i];
		p++;
	    }
	}
    } while ( str[i] != '\0' );

    if ( retval == NX_SSL_PROTOCOLS_NONE )
    { // didn't get any
	return ( -1 );
    }

    return ( retval );
}
