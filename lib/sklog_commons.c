/*
**    Copyright (C) 2011 Politecnico di Torino, Italy
**
**        TORSEC group -- http://security.polito.it
**        Author: Paolo Smiraglia <paolo.smiraglia@polito.it>
**
**    This file is part of Libsklog.
**
**    Libsklog is free software: you can redistribute it and/or modify
**    it under the terms of the GNU General Public License as published by
**    the Free Software Foundation; either version 2 of the License, or
**    (at your option) any later version.
**
**    Libsklog is distributed in the hope that it will be useful,
**    but WITHOUT ANY WARRANTY; without even the implied warranty of
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**    GNU General Public License for more details.
**
**    You should have received a copy of the GNU General Public License
**    along with Libsklog.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "sklog_commons.h"
#include "sklog_internal.h"

#include <errno.h>
#include <string.h>
#include <jansson.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sys/socket.h>
#include <sys/types.h>

#define MSG_BUFLEN 4096

/*--------------------------------------------------------------------*/
/*                           messaging system                         */
/*--------------------------------------------------------------------*/

typedef enum message_type {
	debug,
	error,
	notify,
	warning,
	query,
	buffer,
	json,
	here,
	
	undefined
} MSG_TYPE;

static void
msg(MSG_TYPE type, const char *source, const int lineno,
	const char *func, const char *fmt, va_list ap)
{
	int curr_errno = errno;
	
	char buf[MSG_BUFLEN+1] = { 0 };
	size_t bufl = 0;
	
	/* append prefix */
	
	switch ( type ) {
		case debug:
			snprintf(buf, MSG_BUFLEN, "[DEBUG]    ");
			bufl = strlen(buf);
			break;
			
		case error:
			snprintf(buf, MSG_BUFLEN, "[ERROR]    ");
			bufl = strlen(buf);
			break;
			
		case notify:
			snprintf(buf, MSG_BUFLEN, "[NOTIFY]   ");
			bufl = strlen(buf);
			break;
			
		case warning:
			snprintf(buf, MSG_BUFLEN, "[WARNING]  ");
			bufl = strlen(buf);
			break;
			
		case query:
			snprintf(buf, MSG_BUFLEN, "[QUERY]    ");
			bufl = strlen(buf);
			break;
			
		case buffer:
			snprintf(buf, MSG_BUFLEN, "[BUFFER]   ");
			bufl = strlen(buf);
			break;
			
		case json:
			snprintf(buf, MSG_BUFLEN, "[JSON]     ");
			bufl = strlen(buf);
			break;
			
		case here:
			snprintf(buf, MSG_BUFLEN, "[I'M HERE] ");
			bufl = strlen(buf);
			break;
			
		default:
			break;
	}
	
	/* indent */
	
	/*
	if (( strcmp(source, "sklog_u.c") == 0 ||
		strcmp(source, "sklog_t.c") == 0 )) {
		strcat(buf+bufl, ">");
		bufl = strlen(buf);
	} else if (( strcmp(source, "sklog_u_internal.c") == 0 ||
		strcmp(source, "sklog_t_internal.c") == 0)) {
		strcat(buf+bufl, ">>");
		bufl = strlen(buf);
	} else if (( strcmp(source, "sklog_internal.c") == 0 ||
		strcmp(source, "sklog_commons.c") == 0 )) {
		strcat(buf+bufl, ">>>");
		bufl = strlen(buf);
	}
	*/
	
	/* append pid */
	
	snprintf(buf+bufl, MSG_BUFLEN-bufl, " (%d) Libsklog ", getpid());
	bufl = strlen(buf);
	
	/* append source, lineno and function */
	
	snprintf(buf+bufl, MSG_BUFLEN-bufl, "(%s:%d): %s()", source, lineno,
		func);
	bufl = strlen(buf);
	
	/* append errno string */
	
	if ( type == error && errno > 0 ) {
		snprintf(buf+bufl, MSG_BUFLEN-bufl, ": %s",
			strerror(curr_errno));
		bufl = strlen(buf);
	}
	
	/* append user defined data */
	
	if ( fmt != NULL ) {
		strcat(buf, ": ");
		bufl = strlen(buf);
		vsnprintf(buf+bufl, MSG_BUFLEN-bufl, fmt, ap);
		bufl = strlen(buf);
	}
	
	strcat(buf, "\n");
	
	fflush(stdout);
	fputs(buf, stderr);
	fflush(stderr);

	return;
}

void
msg_debug(const char *source, const int lineno, const char *func)
{
	msg(debug, source, lineno, func, NULL, 0);
	return;
}

void
msg_error(const char *source, const int lineno, const char *func,
	const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	msg(error, source, lineno, func, fmt, ap);
	va_end(ap);
	return;
}

void
msg_notify(const char *source, const int lineno, const char *func,
	const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	msg(notify, source, lineno, func, fmt, ap);
	va_end(ap);
	return;
}

void
msg_warning(const char *source, const int lineno, const char *func,
	const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	msg(warning, source, lineno, func, fmt, ap);
	va_end(ap);
	return;
}

void
msg_to_implement(const char *func)
{
	fprintf(stderr,"\n+----------------------------------------------------------------------+");
	fprintf(stderr,"\n| %-68s |",func);
	fprintf(stderr,"\n+----------------------------------------------------------------------+");
	fprintf(stderr,"\n|                                                                      |");
	fprintf(stderr,"\n|    This function will be implemented as soon as possible             |");
	fprintf(stderr,"\n|                                                                      |");
	fprintf(stderr,"\n+----------------------------------------------------------------------+");
	fprintf(stderr,"\n\n");
	
	return;
}

void
msg_show_query(const char *source, const int lineno, const char *func,
			   const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	msg(query, source, lineno, func, fmt, ap);
	va_end(ap);
	return;
}

static void
__msg_show_buffer(const char *source, const int lineno,
				  const char *func, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	msg(buffer, source, lineno, func, fmt, ap);
	va_end(ap);
	return;
}

void
msg_show_buffer(const char *source, const int lineno, const char *func,
				const char *bufname, unsigned char *buf,
				unsigned int bufl)
{
	char *b64 = 0;
	
	b64_enc(buf, bufl, &b64);

	__msg_show_buffer(source, lineno, func, "%s: {%s}", bufname, b64);
	
	free(b64);

	return;
}

static void
__msg_json(const char *source, const int lineno, const char *func,
		   const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	msg(json, source, lineno, func, fmt, ap);
	va_end(ap);
	return;
}

void
msg_json(const char *source, const int lineno, const char *func,
		 char *json_str)
{
	json_t *json = 0;
	json_error_t json_error;
	
	char *out_str = 0;
	
	memset(&json_error, 0, sizeof(json_error));
	json = json_loads(json_str, JSON_DECODE_ANY, &json_error);
	
	if ( !json ) {
		ERROR("json_loads() failure: %s", json_error.text);
		return;
	}
	
	out_str = json_dumps(json, 
		JSON_INDENT(2) | JSON_ENSURE_ASCII | JSON_PRESERVE_ORDER);
		
	if ( out_str == 0 ) {
		ERROR("json_dumps() failure");
		return;
	}
		
	__msg_json(source, lineno, func, "\n%s\n", out_str);
	
	free(out_str);
	free(json);
	
	return;
}

void
msg_here(const char *source, const int lineno, const char *func)
{
	msg(here, source, lineno, func, NULL, 0);
	getchar();
	return;
}	

/*--------------------------------------------------------------------*/
/*                          SKLOG_CONNECTION                          */
/*--------------------------------------------------------------------*/

SKLOG_CONNECTION *
SKLOG_CONNECTION_New(void)
{
	#ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_CONNECTION *c = 0;

    c = calloc(1, sizeof(SKLOG_CONNECTION));

    if ( c == 0 ) {
        ERROR("calloc() failure");
        return NULL;
    }

    memset(c, 0, sizeof(c));

    return c;
}

SKLOG_RETURN
SKLOG_CONNECTION_Init(SKLOG_CONNECTION *c, const char *addr,
					  short int port, X509 *cert, EVP_PKEY *privkey,
					  const char *CA_cert_path, int do_verify)
{
	#ifdef DO_TRACE
    DEBUG
    #endif

	int ret = 0;

    SSL_CTX *ctx = 0;
    SSL *ssl = 0;
    BIO *sbio = 0;
    
    int sock = 0;

    /* check input parameters */
    
    if ( c == NULL || addr == NULL || cert == NULL || privkey == NULL ) {
		ERROR("Bad input argument(s). Please, double-check it!");
		return SKLOG_FAILURE;
	}

	/* initialize OpenSSL library */
	
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    /* create SSL_CTX structure*/
    
    ctx = SSL_CTX_new(SSLv3_method());
    
    if ( ctx == 0 ) {
		ERROR("SSL_CTX_new() failure");
		ERR_print_errors_fp(stderr);
        goto error;
	} 

    /* load certificate */
    
    ret = SSL_CTX_use_certificate(ctx, cert);

    if ( ret <= 0 ) {
		ERROR("SSL_CTX_use_certificate() failure");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    /* load server private key */
    
    ret = SSL_CTX_use_PrivateKey(ctx, privkey);

    if ( ret <= 0 ) {
		ERROR("SSL_CTX_use_PrivateKey() failure");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    /* check private key */
    
    if ( SSL_CTX_check_private_key(ctx) <= 0 ) {
		ERROR("SSL_CTX_check_private_key() failure");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( do_verify && CA_cert_path > 0) {

        /* load CA certificate */
        
        ret = SSL_CTX_load_verify_locations(ctx,CA_cert_path,NULL);
    
        if ( ret <= 0 ) {
			ERROR("SSL_CTX_load_verify_locations() failure");
            ERR_print_errors_fp(stderr);
            goto error;
        }

        /* set verification parameters */
        
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,NULL);
        SSL_CTX_set_verify_depth(ctx, 1);
    }

    /* connection socket */
    
    ret = tcp_socket(&sock);
    
    if ( ret == SKLOG_FAILURE ) {
		ERROR("tcp_socket() failure");
		goto error;
	}
	
	ret = tcp_connect(sock, addr, port);
	
	if ( ret == SKLOG_FAILURE ) {
		ERROR("tcp_connect() failure");
		goto error;
	}

    /* setup SSL structure */
	
	ssl = SSL_new(ctx);

    sbio = BIO_new(BIO_s_socket());
    BIO_set_fd(sbio, sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    if ( SSL_connect(ssl) < 0 ) {
		ERROR("SSL_conenct() failure");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    c->ssl_ctx = ctx;
    c->ssl = ssl;
    c->csock = sock;
    c->bio = sbio;

    ERR_free_strings();
    return SKLOG_SUCCESS;

error:

    if ( sbio > 0 )
		BIO_free_all(sbio);
		
    if ( ssl > 0 )
		SSL_free(ssl);
		
    if ( ctx > 0 )
		SSL_CTX_free(ctx);
		
    if ( sock > 0 )
		close(sock);
    
    ERR_free_strings();
    return SKLOG_FAILURE;
}

SKLOG_RETURN
SKLOG_CONNECTION_Destroy(SKLOG_CONNECTION *c)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    
    int rv = SKLOG_SUCCESS;
    
    if ( c == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}
	
	SSL_load_error_strings();

    if ( SSL_shutdown(c->ssl) < 0 ) {
		ERROR("SSL_shutdown() failure");
		ERR_print_errors_fp(stderr);
		rv = SKLOG_FAILURE;
		goto error;
	}
    
    SSL_free(c->ssl);
    SSL_CTX_free(c->ssl_ctx);

    if ( close(c->csock) < 0 ) {
		ERROR("close() failure");
		rv = SKLOG_FAILURE;
	}

error:
	ERR_free_strings();
	return rv;
}

SKLOG_RETURN
SKLOG_CONNECTION_Free(SKLOG_CONNECTION **c)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    
    if ( *c == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}

    free(*c);
    *c = 0;

    return SKLOG_SUCCESS;
}
