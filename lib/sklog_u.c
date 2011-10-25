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

#include "sklog_internal.h"
#include "sklog_u.h"

#ifdef USE_FILE
    #include "storage/sklog_file.h"
#elif USE_SYSLOG
    #include "storage/sklog_syslog.h"
#elif USE_SQLITE
    #include "storage/sklog_sqlite.h"
#else
    //~ todo: manage default case
#endif


#include <confuse.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
//~ #include <arpa/inet.h>

/*--------------------------------------------------------------------*/
/* connection                                                         */
/*--------------------------------------------------------------------*/

//~ static SSL_CTX*
//~ init_ssl_ctx(SKLOG_U_Ctx    *u_ctx,
             //~ int            verify)
//~ {
    //~ #ifdef DO_TRACE
    //~ DEBUG
    //~ #endif
    //~ 
    //~ SSL_CTX *ctx = 0;
    //~ const SSL_METHOD *meth = 0;
    //~ 
    //~ SSL_library_init();
    //~ SSL_load_error_strings();
    //~ 
    //~ /*
     //~ * Create an SSL_METHOD structure 
     //~ * (choose an SSL/TLS protocol version) 
     //~ */
    //~ meth = SSLv3_method();
    //~ 
    //~ /* Create an SSL_CTX structure */
    //~ if ( (ctx = SSL_CTX_new(meth)) == NULL ) {
        //~ ERR_print_errors_fp(stderr);
        //~ goto error;
    //~ }
    //~ 
    //~ if ( verify == 1 ) {
//~ 
        //~ /* Load the client certificate into the SSL_CTX structure */
        //~ if ( SSL_CTX_use_certificate(ctx,u_ctx->u_cert) <= 0 ) {
            //~ ERR_print_errors_fp(stderr);
            //~ goto error;
        //~ }
        //~ 
        //~ /*
         //~ * Load the private-key corresponding
         //~ * to the client certificate
         //~ */
        //~ if ( SSL_CTX_use_PrivateKey(ctx,u_ctx->u_privkey) <= 0 ) {
            //~ 
            //~ goto error;
        //~ }
        //~ 
        //~ /* Check if the client certificate and private-key matches */
        //~ if ( !SSL_CTX_check_private_key(ctx) ) {
            //~ ERROR("Private key does not match the certificate public key");
            //~ goto error;
        //~ }
    //~ }
    //~ 
    //~ /*
     //~ * Load the RSA CA certificate into the SSL_CTX structure This will
     //~ * allow this client to verify the server's certificate.
     //~ */
    //~ 
    //~ if ( !SSL_CTX_load_verify_locations(ctx,u_ctx->t_cert_path,NULL) ) {
        //~ ERR_print_errors_fp(stderr);
        //~ goto error;
    //~ }
    //~ 
    //~ /*
     //~ * Set flag in context to require peer (server) certificate
     //~ * verification
     //~ */
    //~ 
    //~ SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    //~ SSL_CTX_set_verify_depth(ctx,1);
//~ 
    //~ return ctx;
//~ 
//~ error:
    //~ if ( ctx ) SSL_CTX_free(ctx);
    //~ return NULL;
//~ }

//~ static int
//~ tcp_connect(const char *address, short int port)
//~ {
    //~ #ifdef DO_TRACE
    //~ DEBUG
    //~ #endif
    //~ 
    //~ int skt = 0;
    //~ struct sockaddr_in server_addr;
//~ 
    //~ skt = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
//~ 
    //~ if ( skt < 0 ) {
        //~ ERROR("socket() failure")
        //~ return -1;
    //~ }
    //~ 
    //~ memset (&server_addr,0,sizeof(server_addr));
    //~ server_addr.sin_family = AF_INET;
    //~ server_addr.sin_port = htons(port);
    //~ server_addr.sin_addr.s_addr = inet_addr(address);
    //~ 
    //~ /* Establish a TCP/IP connection to the SSL client */
    //~ 
    //~ NOTIFY(address)
    //~ 
    //~ if ( connect(skt, (struct sockaddr*) &server_addr,
                 //~ sizeof(server_addr)) < 0 ) {
        //~ ERROR("connect() failure")
        //~ return -1;
    //~ }
    //~ 
    //~ return skt;
//~ }


//~ static SSL*
//~ init_ssl_structure(SSL_CTX *ctx,int socket)
//~ {
    //~ #ifdef DO_TRACE
    //~ DEBUG
    //~ #endif
    //~ 
    //~ SSL *ssl = 0;
//~ 
    //~ if ( (ssl = SSL_new(ctx)) == NULL ) {
        //~ ERROR("SSL_new() failure")
        //~ goto error;
    //~ }
    //~ 
    //~ /*
     //~ * Assign the socket into the SSL structure
     //~ * (SSL and socket without BIO)
     //~ */
    //~ SSL_set_fd(ssl,socket);
    //~ 
    //~ /* Perform SSL Handshake on the SSL client */
    //~ if ( SSL_connect(ssl) < 0 ) {
        //~ ERROR("SSL_connect() failure")
        //~ goto error;
    //~ }
//~ 
    //~ #ifdef DO_NOTIFY
//~ 
    //~ char *str = 0;
    //~ X509 *server_cert = 0;
//~ 
    //~ /* Get the server's certificate (optional) */
    //~ server_cert = SSL_get_peer_certificate (ssl);    
    //~ 
    //~ if ( server_cert != NULL ) {
//~ 
        //~ fprintf(stderr,"Server certificate:\n");
        //~ 
        //~ str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
        //~ if ( str != NULL ) { 
            //~ fprintf (stderr,"\t subject: %s\n", str);
            //~ free (str);
        //~ }
//~ 
        //~ str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
        //~ if ( str != NULL ) {
            //~ fprintf (stderr,"\t issuer: %s\n", str);
            //~ free(str);
        //~ }
        //~ 
        //~ X509_free (server_cert);
    //~ } else {
        //~ fprintf(stderr,"The SSL server does not have certificate.\n");
    //~ }
//~ 
    //~ #endif
//~ 
    //~ return ssl;
    //~ 
//~ error:
    //~ if ( ssl ) SSL_free(ssl);
    //~ return NULL;
//~ }

static SKLOG_RETURN
conn_open(SKLOG_U_Ctx         *u_ctx,
          SKLOG_CONNECTION    *conn)
{
    SSL_load_error_strings();

    //~ conn->ssl_ctx = init_ssl_ctx(u_ctx,1);
    conn->ssl_ctx = init_ssl_ctx_c(u_ctx->u_cert,u_ctx->u_privkey,
                                   u_ctx->t_cert_path,1);

    if ( conn->ssl_ctx == NULL ) {
        ERROR("init_ssl_ctx() failure")
        return SKLOG_FAILURE;
    }

    conn->socket = tcp_connect(u_ctx->t_address,u_ctx->t_port);

    if ( conn->socket < 0 ) {
        ERROR("tcp_connect() failure")
        return SKLOG_FAILURE;
    }

    conn->ssl = init_ssl_structure_c(conn->ssl_ctx,conn->socket);

    if ( conn->ssl == NULL ) {
        ERROR("init_ssl_structure() failure")
        return SKLOG_FAILURE;
    }

    return SKLOG_SUCCESS;
}

//~ static SKLOG_RETURN
//~ conn_close(SKLOG_CONNECTION    *conn)
//~ {
    //~ SSL_shutdown(conn->ssl);
    //~ close(conn->socket);
    //~ SSL_free(conn->ssl);
    //~ SSL_CTX_free(conn->ssl_ctx);
//~ 
    //~ return SKLOG_SUCCESS;
//~ }

/*--------------------------------------------------------------------*/
/* log an event                                                       */
/*--------------------------------------------------------------------*/

static SKLOG_RETURN
gen_enc_key(SKLOG_U_Ctx        *ctx,
            unsigned char      *enc_key,
            SKLOG_DATA_TYPE    type)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;

    unsigned char *buffer = 0;
    unsigned int buflen = 0;
    unsigned int pos = 0;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    buflen = sizeof(type) + SKLOG_AUTH_KEY_LEN;

    if ( SKLOG_alloc(&buffer,unsigned char,buflen) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    memcpy(&buffer[pos],&type,sizeof(type));
    pos+=sizeof(type);
    memcpy(&buffer[pos],ctx->auth_key,SKLOG_AUTH_KEY_LEN);

    //~ calculate SHA256 message digest
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);

    retval = EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_DigestUpdate(&mdctx,buffer,buflen);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_DigestFinal_ex(&mdctx,enc_key,&buflen);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    EVP_MD_CTX_cleanup(&mdctx);

    SKLOG_free(&buffer);
    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    if ( buffer > 0 ) free(buffer);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
gen_hash_chain(SKLOG_U_Ctx        *ctx,
               unsigned char      *hash_chain,
               unsigned char      *data_enc,
               unsigned int       data_enc_size,
               SKLOG_DATA_TYPE    type)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;

    unsigned char *buffer = 0;
    unsigned int buflen = 0;
    unsigned int pos = 0;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    buflen = sizeof(type) + data_enc_size + SKLOG_HASH_CHAIN_LEN;
    //~ SKLOG_CALLOC(buffer,buflen,char)

    if ( SKLOG_alloc(&buffer,unsigned char,buflen) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    memcpy(&buffer[pos],ctx->last_hash_chain,SKLOG_HASH_CHAIN_LEN);
    pos+=SKLOG_HASH_CHAIN_LEN;
    memcpy(&buffer[pos],data_enc,data_enc_size);
    pos+=data_enc_size;
    memcpy(&buffer[pos],&type,sizeof(type));

    //~ calculate SHA256 message digest
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);

    retval = EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DigestUpdate(&mdctx,buffer,buflen);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = EVP_DigestFinal_ex(&mdctx,hash_chain,&buflen);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    EVP_MD_CTX_cleanup(&mdctx);

    //~ save hash chain for the next generation
    memcpy(ctx->last_hash_chain,hash_chain,SKLOG_HASH_CHAIN_LEN);

    SKLOG_free(&buffer);
    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    if ( buffer > 0 ) free(buffer);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
gen_hmac(SKLOG_U_Ctx      *ctx,
         unsigned char    *hmac,
         unsigned char    *hash_chain)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;
    
    unsigned int hmac_len = 0;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    //~ calculate HMAC using SHA256 message digest
    HMAC_CTX mdctx;
    HMAC_CTX_init(&mdctx);

    retval = HMAC_Init_ex(&mdctx,ctx->auth_key,SKLOG_AUTH_KEY_LEN,
                 EVP_sha256(),NULL);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
                 
    retval = HMAC_Update(&mdctx,hash_chain,SKLOG_HASH_CHAIN_LEN);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    retval = HMAC_Final(&mdctx,hmac,&hmac_len);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    HMAC_CTX_cleanup(&mdctx);
    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
renew_auth_key(SKLOG_U_Ctx    *ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;
    unsigned char *buffer = 0;
    unsigned int buflen = 0;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    //~ SKLOG_CALLOC(buffer,SKLOG_AUTH_KEY_LEN,char)

    if ( SKLOG_alloc(&buffer,unsigned char,SKLOG_AUTH_KEY_LEN)
                                                    == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }
    
    memcpy(buffer,ctx->auth_key,SKLOG_AUTH_KEY_LEN);

    //~ calculate SHA256 message digest
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    
    retval = EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DigestUpdate(&mdctx,buffer,SKLOG_AUTH_KEY_LEN);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DigestFinal_ex(&mdctx,ctx->auth_key,&buflen);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    EVP_MD_CTX_cleanup(&mdctx);

    SKLOG_free(&buffer);
    return SKLOG_SUCCESS;

error:
    if ( buffer > 0 ) free(buffer);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
create_logentry(SKLOG_U_Ctx        *u_ctx,
                SKLOG_DATA_TYPE    type,
                unsigned char      *data,
                unsigned int       data_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char enc_key[SKLOG_ENC_KEY_LEN] = {0};
    unsigned char *data_enc = 0;
    unsigned int data_enc_len = 0;
    unsigned char hash_chain[SKLOG_HASH_CHAIN_LEN] = {0};
    unsigned char hmac[SKLOG_HMAC_LEN] = {0};

    if ( u_ctx == NULL ) {
        ERROR("argument 1 must be not null")
        goto error;
    }
    
    if ( data == NULL )
        WARNING("Data to log is NULL. It's all ok?")

    //~ generate encryption key
    if ( gen_enc_key(u_ctx,enc_key,type) == SKLOG_FAILURE ) {
        ERROR("gen_enc_key() failure")
        goto error;
    }

    //~ encrypt data using the generated encryption key
    //~ if ( aes256_encrypt(&data_enc,&data_enc_len,
                        //~ data,data_len,enc_key) == SKLOG_FAILURE ) {
    if ( aes256_encrypt(data,data_len,enc_key,SKLOG_SESSION_KEY_LEN,
                        &data_enc,&data_enc_len) == SKLOG_FAILURE ) {
        ERROR("encrypt_aes256() failure")
        goto error;
    }

    //~ generate hash-chain element
    if ( gen_hash_chain(u_ctx,hash_chain,data_enc,
                        data_enc_len,type) == SKLOG_FAILURE ) {
        ERROR("gen_hash_chain() failure")
        goto error;
    }

    //~ generate digest of hash-chain using the auth_key A
    if ( gen_hmac(u_ctx,hmac,hash_chain) == SKLOG_FAILURE ) {
        ERROR("gen_hmac() failure")
        goto error;
    }

    //~ re-generate auth_key
    if ( renew_auth_key(u_ctx) == SKLOG_FAILURE ) {
        ERROR("renew_auth_key() failure")
        goto error;
    }

    //~ store log entry

    if ( u_ctx->lsdriver->store_logentry
            (u_ctx->logfile_id,type,data_enc,data_enc_len,hash_chain,hmac)
                == SKLOG_FAILURE ) {
        ERROR("store_logentry() failure")
        goto error;
    }

    /*
    if ( store_logentry(type,data_enc,data_enc_len,
                        hash_chain,hmac) == SKLOG_FAILURE ) {
        ERROR("store_logentry() failure")
        goto error;
    }
    */

    //~ increase logentry counter
    u_ctx->logfile_counter += 1;

    return SKLOG_SUCCESS;

error:
    if ( data_enc > 0 ) free(data_enc);
    return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/* logging session initialization                                     */
/*--------------------------------------------------------------------*/

static SKLOG_RETURN
parse_config_file(char            **t_cert,
                  char            **t_address,
                  int             *t_port,
                  char            **u_cert,
                  char            **u_id,
                  char            **u_privkey,
                  unsigned int    *u_timeout,
                  unsigned int    *logfile_size)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    char buffer[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    int len = 0;

    cfg_opt_t opts[] = {
        CFG_STR("t_cert",SKLOG_DEF_T_CERT_PATH,CFGF_NONE),
        CFG_STR("t_address",SKLOG_DEF_T_ADDRESS,CFGF_NONE),
        CFG_INT("t_port",SKLOG_DEF_T_PORT,CFGF_NONE),
        CFG_STR("u_cert",SKLOG_DEF_U_CERT_PATH,CFGF_NONE),
        CFG_STR("u_id",NULL,CFGF_NONE),
        CFG_STR("u_privkey",SKLOG_DEF_U_RSA_KEY_PATH,CFGF_NONE),
        CFG_INT("u_timeout",SKLOG_DEF_U_TIMEOUT,CFGF_NONE),
        CFG_INT("logfile_size",SKLOG_DEF_LOGFILE_SIZE,CFGF_NONE),
        CFG_END()
    };

    cfg_t *cfg = NULL;
    cfg = cfg_init(opts, CFGF_NONE);

    if( cfg_parse(cfg,SKLOG_U_CONFIG_FILE_PATH) == CFG_PARSE_ERROR ) {
        ERROR("cfg_parse() failure")
        goto error;
    }

    //~ load t_cert
    len = sprintf(buffer,"%s",cfg_getstr(cfg,"t_cert"));
    *t_cert = calloc(len+1,sizeof(char));
    memcpy(*t_cert,buffer,len);
    (*t_cert)[len] = '\0';
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);
    
    //~ load t_address
    len = sprintf(buffer,"%s",cfg_getstr(cfg,"t_address"));
    *t_address = calloc(len+1,sizeof(char));
    memcpy(*t_address,buffer,len);
    (*t_address)[len] = '\0';
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);
    

    //~ load t_port
    *t_port = cfg_getint(cfg,"t_port");

    //~ load u_cert
    len = sprintf(buffer,"%s",cfg_getstr(cfg,"u_cert"));
    *u_cert = calloc(len+1,sizeof(char));
    memcpy(*u_cert,buffer,len);
    (*u_cert)[len] = '\0';
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);
    
    //~ load u_id
    len = sprintf(buffer,"%s",cfg_getstr(cfg,"u_id"));
    *u_id = calloc(len+1,sizeof(char));
    memcpy(*u_id,buffer,len);
    (*u_id)[len] = '\0';
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);

    //~ load u_privkey
    len = sprintf(buffer,"%s",cfg_getstr(cfg,"u_privkey"));
    *u_privkey = calloc(len+1,sizeof(char));
    memcpy(*u_privkey,buffer,len);
    (*u_privkey)[len] = '\0';
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);

    //~ load u_timeout
    *u_timeout = cfg_getint(cfg,"u_timeout");

    //~ load logfile_size
    *logfile_size = cfg_getint(cfg,"logfile_size");

    cfg_free(cfg);

    return SKLOG_SUCCESS;
    
error:
    if ( cfg ) cfg_free(cfg);
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
gen_x0(SKLOG_U_Ctx            *u_ctx,
       SKLOG_PROTOCOL_STEP    p,
       struct timeval         *d,
       unsigned char          **x0,
       unsigned int           *x0_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    ERR_load_crypto_strings();

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;
    unsigned char *dbuf = 0;
    unsigned int dbuf_len = 0;
    unsigned char *cert = 0;
    unsigned char *cert_tmp = 0;
    unsigned int  cert_size = 0;

    //~ serialize timestamp (d)
    serialize_timeval(d,&dbuf,&dbuf_len);

    //~ serialize U's x509 certificate
    cert_size = i2d_X509(u_ctx->u_cert,NULL);

    if ( cert_size < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    cert = OPENSSL_malloc(cert_size);
    cert_tmp = cert;

    /*
     * NOTE:i2d_X509() encodes the certificate u_ctx->u_cert in DER
     * format and store it in the buffer *cert_tmp. After the encode
     * process cert_tmp pointer IS INCREMENTED!!! Damned OpenSSL!
     */
    if ( i2d_X509(u_ctx->u_cert,&cert_tmp) < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    //~ convert p in network order
    uint32_t p_net = htonl(p);

    //~ compose x0 in tlv form

    *x0_len = (sizeof(p_net) + 8) +
              (dbuf_len + 8) +
              (cert_size + 8) +
              (SKLOG_AUTH_KEY_LEN + 8);

    //~ SKLOG_CALLOC(*x0,*x0_len,char)
    if ( SKLOG_alloc(x0,unsigned char, *x0_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    //~ TLV-ize protocol step
    tlv_create(PROTOCOL_STEP,sizeof(p_net),&p_net,buffer);
    memcpy(*x0+ds,buffer,sizeof(p_net)+8);

    ds += (sizeof(p_net) + 8);
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize d
    tlv_create(TIMESTAMP,dbuf_len,dbuf,buffer);
    memcpy(*x0+ds,buffer,dbuf_len+8);

    ds += (dbuf_len + 8);
    memset(buffer,0,SKLOG_BUFFER_LEN);
    SKLOG_free(&dbuf);

    //~ TLV-ize DER encoded C's certificate
    tlv_create(CERT_U,cert_size,cert,buffer);
    memcpy(*x0+ds,buffer,cert_size+8);

    ds += (cert_size + 8);
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize auth_key
    tlv_create(A0_KEY,SKLOG_AUTH_KEY_LEN,u_ctx->auth_key,buffer);
    memcpy(*x0+ds,buffer,SKLOG_AUTH_KEY_LEN+8);

    OPENSSL_free(cert);
    cert = 0;
    ERR_free_strings();
    
    return SKLOG_SUCCESS;

error:
    if ( dbuf > 0 ) free(dbuf);
    if ( cert > 0 ) OPENSSL_free(cert);
    if ( *x0 ) free(*x0);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
gen_e_k0(SKLOG_U_Ctx *u_ctx,
         unsigned char *x0,
         unsigned int x0_len,
         unsigned char *x0_sign,
         unsigned int x0_sign_len,
         unsigned char **e_k0,
         unsigned int *e_k0_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    //~
    //~ encrypt {x0|x0_signature} using session key
    //~

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;

    unsigned char *buffer2 = 0;
    unsigned int buffer2_len = x0_len + 8 +
                               x0_sign_len + 8;

    //~ SKLOG_CALLOC(buffer2,buffer2_len,char)

    if ( SKLOG_alloc(&buffer2,unsigned char,buffer2_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    ds = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize x0
    if ( tlv_create(X0_BUF,x0_len,x0,buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(&buffer2[ds],buffer,x0_len+8);

    ds += (x0_len + 8);
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize x0_signature
    if ( tlv_create(X0_SIGN_U,x0_sign_len,
                    x0_sign,buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(&buffer2[ds],buffer,x0_sign_len+8);

    //~ if ( encrypt_aes256(e_k0,e_k0_len,buffer2,buffer2_len,
                        //~ u_ctx->session_key) == SKLOG_FAILURE ) {
    if ( aes256_encrypt(buffer2,buffer2_len,u_ctx->session_key,
            SKLOG_SESSION_KEY_LEN,e_k0,e_k0_len) == SKLOG_FAILURE ) {
        ERROR("encrypt_aes256() failure")
        goto error;
    }
    SKLOG_free(&buffer2);

    return SKLOG_SUCCESS;

error:
    if ( buffer2 > 0 ) free(buffer2);
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
gen_m0(SKLOG_U_Ctx *u_ctx,
       SKLOG_PROTOCOL_STEP p,
       unsigned char *pke_t_k0,
       unsigned int pke_t_k0_len,
       unsigned char *e_k0,
       unsigned int e_k0_len,
       unsigned char **m0,
       unsigned int *m0_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;
    
    unsigned char *uuid = 0;

    //~ convert p in network order
    uint32_t p_net = htonl(p);

    //~ compose M0 in tlv format
    *m0_len = (sizeof(p_net) + 8) +
              //~ (u_ctx->u_id_len + 8) +
              (UUID_LEN + 8) +
              (pke_t_k0_len + 8) +
              (e_k0_len + 8);

    //~ SKLOG_CALLOC(*m0,*m0_len,char)

    if ( SKLOG_alloc(m0,unsigned char,*m0_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    //~ TLV-ize p
    if ( tlv_create(PROTOCOL_STEP,sizeof(p_net),&p_net,\
                    buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(*m0+ds,buffer,sizeof(p_net)+8);

    ds += sizeof(p_net)+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    /*
    //~ TLV-ize u_id
    if ( tlv_create(ID_U,u_ctx->u_id_len,u_ctx->u_id,
                    buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(*m0+ds,buffer,u_ctx->u_id_len+8);

    ds += u_ctx->u_id_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);
    */

    //~ TLV-ize logfile_id

    if ( SKLOG_alloc(&uuid,unsigned char,UUID_LEN) == SKLOG_FAILURE) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    memcpy(uuid,u_ctx->logfile_id,UUID_LEN);
    
    if ( tlv_create(ID_LOG,UUID_LEN,uuid,buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(*m0+ds,buffer,UUID_LEN+8);

    ds += UUID_LEN+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize pke_t_k0
    if ( tlv_create(PKE_PUB_T,pke_t_k0_len,pke_t_k0,
                    buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(*m0+ds,buffer,pke_t_k0_len+8);

    ds += pke_t_k0_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize e_k0
    if ( tlv_create(ENC_K0,e_k0_len,e_k0,buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(*m0+ds,buffer,e_k0_len+8);

    ds += e_k0_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    return SKLOG_SUCCESS;

error:
    if ( *m0 ) free(*m0);
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
gen_d0(SKLOG_U_Ctx *u_ctx,
       struct timeval *d,
       struct timeval *d_timeout,
       unsigned char *m0,
       unsigned int m0_len,
       unsigned char **d0,
       unsigned int *d0_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;
    unsigned char *dbuf = 0;
    unsigned int dbuf_len = 0;
    unsigned char *dbuf2 = 0;
    unsigned int dbuf2_len = 0;

    if ( m0 == NULL ) {
        ERROR("m0 must be NOT NULL")
        goto error;
    }

    //~ serialize timestamp (d)
    if ( serialize_timeval(d,&dbuf,&dbuf_len) == SKLOG_FAILURE) {
        ERROR("serialize_timeval() failure")
        goto error;
    }

    //~ serialize timestamp (d_timeout)
    if ( serialize_timeval(d_timeout,&dbuf2,
                           &dbuf2_len) == SKLOG_FAILURE) {
        ERROR("serialize_timeval() failure")
        goto error;
    }

    *d0_len = (dbuf_len + 8) +
              (dbuf2_len + 8) +
              (SKLOG_LOG_ID_LEN + 8) +
              (m0_len + 8);

    //~ SKLOG_CALLOC(*d0,*d0_len,char)
    if ( SKLOG_alloc(d0,unsigned char,*d0_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    //~ TLV-ize d
    if ( tlv_create(TIMESTAMP,dbuf_len,dbuf,buffer) == SKLOG_FAILURE) {
        ERROR("tlv_create() failure")
        goto error;
    }
    
    memcpy(*d0+ds,buffer,dbuf_len+8);

    ds += dbuf_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);
    SKLOG_free(&dbuf);

    //~ TLV-ize d_timeout
    if ( tlv_create(TIMESTAMP,dbuf2_len,dbuf2,buffer) == SKLOG_FAILURE) {
        ERROR("tlv_create() failure")
        goto error;
    }
    memcpy(*d0+ds,buffer,dbuf2_len+8);

    ds += dbuf2_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);
    SKLOG_free(&dbuf2);

    //~ TLV-ize log_id
    if ( tlv_create(ID_LOG,SKLOG_LOG_ID_LEN,&u_ctx->logfile_id,
                    buffer) == SKLOG_FAILURE) {
        ERROR("tlv_create() failure")
        goto error;
    }
    memcpy(*d0+ds,buffer,SKLOG_LOG_ID_LEN+8);

    ds += SKLOG_LOG_ID_LEN+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize m0
    if ( tlv_create(M0_MSG,m0_len,m0,buffer) == SKLOG_FAILURE) {
        ERROR("tlv_create() failure")
        goto error;
    }
    memcpy(*d0+ds,buffer,m0_len+8);

    ds += m0_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    return SKLOG_SUCCESS;

error:
    if ( dbuf ) free(dbuf); 
    if ( dbuf2 ) free(dbuf2); 
    if ( *d0 ) free(*d0);
    return SKLOG_FAILURE; 
}

static SKLOG_RETURN
send_m0(SKLOG_U_Ctx *u_ctx,
        //~ void *zmq_requester,
        SSL *ssl,
        unsigned char *m0,
        unsigned int m0_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SSL_load_error_strings();

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    int nwrite = 0;

    if ( tlv_create(M0_MSG,m0_len,m0,buffer) == SKLOG_FAILURE ) {
        ERROR("tlv_create() failure")
        goto error;
    }

    nwrite = SSL_write(ssl,buffer,m0_len+8);

    if ( nwrite < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    } 

    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
receive_m1(SSL *ssl,
           unsigned char **m1,
           unsigned int *m1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SSL_load_error_strings();
    
    unsigned char buf1[SKLOG_BUFFER_LEN] = { 0 };
    unsigned char buf2[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int nread = 0;

    nread = SSL_read(ssl,buf1,SKLOG_BUFFER_LEN-1);

    if ( nread < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    } 

    //~ get m1 from tlv message
    if ( tlv_parse(buf1,M1_MSG,buf2,m1_len) == SKLOG_FAILURE ) {
        ERROR("Message is bad structured: expected M1_MSG");
        goto error;
    }

    //~ SKLOG_CALLOC(*m1,*m1_len,char)
    if ( SKLOG_alloc(m1,unsigned char,*m1_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    memcpy(*m1,buf2,*m1_len);
    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    if ( *m1 > 0 ) free(*m1);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
parse_m1(unsigned char    *m1,
         unsigned int     m1_len,
         SKLOG_PROTOCOL_STEP *p,
         unsigned char *t_id,
         unsigned char **pke_u_k1,
         unsigned int *pke_u_k1_len,
         unsigned char **e_k1,
         unsigned int *e_k1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    
    unsigned int ds = 0;
    unsigned int len = 0;

    if ( tlv_parse(&m1[ds],PROTOCOL_STEP,p,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected PROTOCOLO_STEP");
        goto error;
    }

    ds += len+8;
    len = 0;

    if ( tlv_parse(&m1[ds],ID_T,t_id,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected ID_T");
        goto error;
    }

    ds += len+8;
    len = 0;

    if ( tlv_parse(&m1[ds],PKE_PUB_U,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected PKE_PUB_U");
        goto error;
    }

    //~ SKLOG_CALLOC(*pke_u_k1,len,char)
    if ( SKLOG_alloc(pke_u_k1,unsigned char,len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }
    memcpy(*pke_u_k1,buffer,len);
    *pke_u_k1_len = len;

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    if ( tlv_parse(&m1[ds],ENC_K1,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected ENC_K1");
        goto error;
    }

    //~ SKLOG_CALLOC(*e_k1,len,char)
    if ( SKLOG_alloc(e_k1,unsigned char,len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }
    memcpy(*e_k1,buffer,len);
    *e_k1_len = len;

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    return SKLOG_SUCCESS;

error:
    if (*pke_u_k1 > 0 ) free(*pke_u_k1);
    if (*e_k1 > 0 ) free(*e_k1);
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
parse_e_k1_content(unsigned char    *in,
                   unsigned int     in_len,
                   unsigned char    **x1,
                   unsigned int     *x1_len,
                   unsigned char    **x1_sign,
                   unsigned int     *x1_sign_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;
    unsigned int len = 0;

    if ( tlv_parse(&in[ds],X1_BUF,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("PLAIN buffer is bad structured: expected X1_BUF");
        goto error;
    }

    //~ SKLOG_CALLOC(*x1,len,char)
    if ( SKLOG_alloc(x1,unsigned char,len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    *x1_len = len;
    memcpy(*x1,buffer,len);

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    if ( tlv_parse(&in[ds],X1_SIGN_T,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("PLAIN buffer is bad structured: expected X1_SIGN_T");
        goto error;
    }

    //~ SKLOG_CALLOC(*x1_sign,len,char)
    if ( SKLOG_alloc(x1_sign,unsigned char,len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }

    *x1_sign_len = len;
    memcpy(*x1_sign,buffer,len);

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);
    
    return SKLOG_SUCCESS;

error:
    if ( *x1 > 0 ) free(*x1);
    if ( *x1_sign > 0  ) free(*x1_sign);
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
verify_m1(SKLOG_U_Ctx      *ctx,
          unsigned char    *m1,
          unsigned int     m1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_PROTOCOL_STEP p = 0;
    unsigned char t_id[512] = { 0 };
    unsigned char *pke_u_k1 = 0;
    unsigned int pke_u_k1_len = 0;
    unsigned char *e_k1 = 0;
    unsigned int e_k1_len = 0;

    unsigned char *k1 = 0;
    size_t k1_len = 0;
    size_t len = pke_u_k1_len;

    unsigned char *plain = 0;
    unsigned int plain_len = 0;
    len = e_k1_len;

    unsigned char *x1 = 0;
    unsigned int x1_len = 0;
    unsigned char *x1_sign = 0;
    unsigned int x1_sign_len = 0;

    EVP_PKEY *t_pubkey = NULL;
    
    /* TODO: define how to verify the message */

    ERR_load_crypto_strings();

    //~ parse m1 message
    if ( parse_m1(m1,m1_len,&p,t_id,&pke_u_k1,&pke_u_k1_len,&e_k1,
                  &e_k1_len) == SKLOG_FAILURE ) {
        ERROR("parse_m1() failure")
        goto error;
    }

    //~ decrypt k1 using U's private key
    if ( pke_decrypt(ctx->u_privkey,pke_u_k1,pke_u_k1_len,&k1,
                     &k1_len) == SKLOG_FAILURE ) {
        ERROR("pke_decrypt() failure")
        goto error;
    }

    //~ decrypt {x1,x1_sign} using k1 key 
    //~ if ( decrypt_aes256(k1,e_k1,len,&plain,
                        //~ &plain_len) == SKLOG_FAILURE ) {
    if ( aes256_decrypt(e_k1,e_k1_len,k1,SKLOG_SESSION_KEY_LEN,&plain,
                        &plain_len) == SKLOG_FAILURE ) {
        ERROR("decrypt_aes256() failure")
        goto error;
    }

    //~ parse plain
    if ( parse_e_k1_content(plain,plain_len,&x1,&x1_len,&x1_sign,
                            &x1_sign_len) == SKLOG_FAILURE ) {
        ERROR("parse_plain() failure")
        goto error;
    }

    //~ verify x1_sign
    //~ todo: enhance the verification process
    if ( (t_pubkey = X509_get_pubkey(ctx->t_cert)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( sign_verify(t_pubkey,x1_sign,x1_sign_len,x1,
                     x1_len) == SKLOG_FAILURE ) {
        ERROR("sign_verify() failure")
        goto error;
    }

    ERR_free_strings();
    
    return SKLOG_SUCCESS;

error:
    if ( pke_u_k1 > 0 ) free(pke_u_k1);
    if ( e_k1 > 0 ) free(e_k1);
    if ( k1 > 0 ) free(k1);
    if ( plain > 0 ) free(plain);
    if ( x1 > 0 ) free(x1);
    if ( x1_sign > 0 ) free(x1_sign);
    if ( t_pubkey > 0 ) EVP_PKEY_free(t_pubkey); 

    ERR_free_strings();

    return SKLOG_FAILURE;
}

static SKLOG_RETURN
verify_timeout_expiration(struct timeval *d_timeout)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    struct timeval now;
    long int t1 = 0;
    long int t2 = 0;

    gettimeofday(&now,NULL);

    t1 = (now.tv_sec*1000000)+(now.tv_usec);
    t2 = (d_timeout->tv_sec*1000000)+(d_timeout->tv_usec);

    if ( t2 < t1 ) {
        #ifdef DO_NOTIFY
        NOTIFY("timeout expired")
        #endif
        return SKLOG_FAILURE;
    } else {
        return SKLOG_SUCCESS;
    }
}

static SKLOG_RETURN
initialize_context(SKLOG_U_Ctx    *u_ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    char            *t_cert = 0;
    char            *t_address = 0;
    int             t_port = 0;
    char            *u_cert = 0;
    char            *u_id = 0;
    char            *u_privkey = 0;

    unsigned int    u_timeout = 0;
    unsigned int    logfile_size = 0;

    FILE *fp = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if ( u_ctx == NULL ) {
        ERROR("argument 1 must be not NULL")
        goto error;
    }

    parse_config_file(&t_cert,&t_address,&t_port,&u_cert,&u_id,&u_privkey,
                      &u_timeout,&logfile_size);

    //~ set u_id
    memset(u_ctx->u_id,0,HOST_NAME_MAX+1);
    memcpy(u_ctx->u_id,u_id,strlen(u_id)+1);

    //~ set u_id_len
    u_ctx->u_id_len = strlen(u_id);

    //~ set u_timeout
    u_ctx->u_timeout = u_timeout;

    

    //~ set u_cert
    u_ctx->u_cert = X509_new();

    fp = fopen(u_cert,"r");
    if ( fp != NULL ) {
        if ( !PEM_read_X509(fp,&u_ctx->u_cert,NULL,NULL) ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        fclose(fp);
    } else {
        ERROR("unable to read U's X509 file")
        goto error;
    }

    //~ set u_privkey
    u_ctx->u_privkey = EVP_PKEY_new();

    
    fp = fopen(u_privkey,"r");
    if ( fp != NULL ) {
        if ( !PEM_read_PrivateKey(fp,&u_ctx->u_privkey,NULL,NULL) ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        fclose(fp);
    } else {
        ERROR("unable to read U's private key file")
        goto error;
    }
    
    //~ set t_cert
    u_ctx->t_cert = X509_new();

    if ( (fp = fopen(t_cert,"r")) != NULL ) {
        if ( !PEM_read_X509(fp,&u_ctx->t_cert,NULL,NULL) ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        fclose(fp);
    } else {
        ERROR("unable to read T's X509 file")
        goto error;
    }

    //~ set t_cert_path
    memset(u_ctx->t_cert_path,0,512);
    memcpy(u_ctx->t_cert_path,t_cert,strlen(t_cert)+1);

    //~ set t_address
    memset(u_ctx->t_address,0,512);
    memcpy(u_ctx->t_address,t_address,strlen(t_address)+1);

    //~ set t_port
    u_ctx->t_port = t_port;

    //~ set logfile_size
    u_ctx->logfile_size = logfile_size;

    //~ set logfile_counter
    u_ctx->logfile_counter = 0;

    //~ set logfile_id
    uuid_generate_random(u_ctx->logfile_id);

    //~ set session_key
    RAND_bytes(u_ctx->session_key,SKLOG_SESSION_KEY_LEN);

    //~ set auth_key
    RAND_bytes(u_ctx->auth_key,SKLOG_AUTH_KEY_LEN);

    //~ init last_hash_chain
    memset(u_ctx->last_hash_chain,0,SKLOG_HASH_CHAIN_LEN);

    //~ init x0_hash
    memset(u_ctx->x0_hash,0,SKLOG_HASH_CHAIN_LEN);

    //~ set context_state
    u_ctx->context_state = SKLOG_U_CTX_INITIALIZED;

    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    if ( fp > 0 ) fclose(fp);
    if ( u_ctx->u_cert > 0 ) X509_free(u_ctx->u_cert);
    if ( u_ctx->t_cert > 0 ) X509_free(u_ctx->t_cert);
    if ( u_ctx->u_privkey > 0 ) EVP_PKEY_free(u_ctx->u_privkey);

    memset(u_ctx,0,sizeof(u_ctx));

    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
initialize_logging_session(SKLOG_U_Ctx    *u_ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;

    struct timeval d;
    struct timeval d_timeout;
    struct timeval now;

    unsigned char *x0 = 0;
    unsigned int x0_len = 0;
    SKLOG_PROTOCOL_STEP p = 0;

    unsigned char *pke_t_k0 = 0;
    size_t pke_t_k0_len = 0;

    unsigned char *x0_sign = 0;
    unsigned int x0_sign_len = 0;

    unsigned char *e_k0 = 0;
    unsigned int e_k0_len = 0;

    unsigned char *m0 = 0;
    unsigned int m0_len = 0;

    unsigned char *d0 = 0;
    unsigned int d0_len = 0;

    EVP_MD_CTX mdctx;

    SKLOG_CONNECTION conn = {0,0,0};

    unsigned char *m1 = 0;
    unsigned int m1_len = 0;
    
    const char *reason = 0;

    unsigned char *ts = 0;
    unsigned int ts_len = 0;
    
    char data[4096] = { 0 };
    unsigned int data_len = 0;

    int i = 0;
    int j = 0;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    //~ get current time
    gettimeofday(&d,NULL);

    //~ set timeout
    d_timeout = d;
    d_timeout.tv_sec += u_ctx->u_timeout;

    //~ generate x0
    if ( gen_x0(u_ctx,p,&d,&x0,&x0_len) == SKLOG_FAILURE ) {
        ERROR("gen_x0() failure")
        goto error;
    }

    //~ encrypt k0 using T's public key
    if ( pke_encrypt(u_ctx->t_cert,u_ctx->session_key,
                     SKLOG_SESSION_KEY_LEN,&pke_t_k0,
                     &pke_t_k0_len) == SKLOG_FAILURE ) {
        ERROR("pke_encrypt() failure");
        goto error;
    }

    //~ sign x0 using U's private key
    if ( sign_message(x0,x0_len,u_ctx->u_privkey,
                      &x0_sign,&x0_sign_len) == SKLOG_FAILURE ) {
        ERROR("sign_message() failure")
        goto error;
    }

    //~ encrypt (XO,sign_u_x0) using k0 key
    if ( gen_e_k0(u_ctx,x0,x0_len,x0_sign,x0_sign_len,
                  &e_k0,&e_k0_len) == SKLOG_FAILURE ) {
        ERROR("gen_e_k0() failure")
        goto error;
    }

    //~ generate M0
    if ( gen_m0(u_ctx,p,pke_t_k0,pke_t_k0_len,e_k0,e_k0_len,
                &m0,&m0_len) == SKLOG_FAILURE ) {
        ERROR("gen_m0() failure")
        goto error;
    }

    //~ generate d0
    if ( gen_d0(u_ctx,&d,&d_timeout,m0,m0_len,
                &d0,&d0_len) == SKLOG_FAILURE ) {
        ERROR("gen_d0() failure")
        goto error;
    }

    //~ store x0
    EVP_MD_CTX_init(&mdctx);
    retval = EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DigestUpdate(&mdctx,x0,x0_len);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    retval = EVP_DigestFinal_ex(&mdctx,u_ctx->x0_hash,NULL);

    if ( retval == 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    EVP_MD_CTX_cleanup(&mdctx);

    SKLOG_free(&x0);

    //~ initialize logfile
    if ( u_ctx->lsdriver->init_logfile(u_ctx->logfile_id,&d)
                                                    == SKLOG_FAILURE ) {
        ERROR("u_ctx->lsdriver->init_logfile() failure");
        goto error;
    }

    //~ create firts log entry
    if ( create_logentry(u_ctx,LogfileInitializationType,
                         d0,d0_len) == SKLOG_FAILURE ) {
        ERROR("create_logentry() failure")
        goto error;
    }

    //~ open connection
    if ( conn_open(u_ctx,&conn) == SKLOG_FAILURE ) {
        ERROR("conn_open() failure")
        goto error;
    }

    //~ send m0 to T
    if ( send_m0(u_ctx,conn.ssl,m0,m0_len) == SKLOG_FAILURE ) {
        ERROR("send_m0() failure")
        goto error;
    }
    SKLOG_free(&m0);

    //~ receive m1 from T
    if ( receive_m1(conn.ssl,&m1,&m1_len) == SKLOG_FAILURE ) {
        ERROR("receive_m1() failure")
        goto error;
    }

    //~ close connection
    if ( conn_close(&conn) == SKLOG_FAILURE ) {
        ERROR("conn_close() failure")
        goto error;
    }

    //~ verify timeout expiration
    if ( verify_timeout_expiration(&d_timeout) == SKLOG_FAILURE ) {
        NOTIFY("timeout expired")
        reason = "Timeout Expiration";
        goto failure;
    }

    //~ verify M1
    if ( verify_m1(u_ctx,m1,m1_len) == SKLOG_FAILURE ) {
        ERROR("verify_m1() failure")
        reason = "M1 verification failure";
        goto failure;
    }

    //~ create log entry
    if ( create_logentry(u_ctx,ResponseMessageType,
                         m1,m1_len) == SKLOG_FAILURE ) {
        ERROR("create_logentry() failure")
        goto error;
    }

    ERR_free_strings();
    return SKLOG_SUCCESS;

failure:
    gettimeofday(&now,NULL);
    ts_len = sizeof(now);

    //~ SKLOG_CALLOC(ts,ts_len,char)
    if ( SKLOG_alloc(&ts,unsigned char,ts_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }
    memcpy(ts,&now,ts_len);

    for ( i = 0 , j = 0 ; i < ts_len ; i++ , j+=2 )
        sprintf(data+j,"%2.2x",ts[i]);
    data[j-1] = '-';

    data_len = sprintf(&data[j],"%s",reason);

    if ( create_logentry(u_ctx,AbnormalCloseType,
                         (unsigned char *)data,
                         strlen(data)) == SKLOG_FAILURE ) {
        ERROR("create_logentry() failure")
        goto error;
    }
    SKLOG_free(&ts);
    ERR_free_strings();
    return SKLOG_FAILURE;

error:
    if ( x0 > 0 ) free(x0);
    if ( pke_t_k0 > 0 ) free(pke_t_k0);
    if ( x0_sign > 0 ) free(x0_sign);
    if ( e_k0 > 0 ) free(e_k0);
    if ( m0 > 0 ) free(m0);
    if ( d0 > 0 ) free(d0);
    if ( m1 > 0 ) free(m1);

    ERR_free_strings();
    return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/* flushing logfile                                                   */
/*--------------------------------------------------------------------*/

static SKLOG_RETURN
flush_logfile_init(SSL *ssl)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char msg[512] = { 0 };
    unsigned char data[512] = { 0 };
    unsigned int data_len = 0;

    int nread = 0;
    int nwrite = 0;

    SSL_load_error_strings();

    data_len = strlen("LOGFILE_FLUSH_START");
    memcpy(data,"LOGFILE_FLUSH_START",data_len);

    if ( tlv_create(LE_FLUSH_START,data_len,data,msg) == SKLOG_FAILURE ) {
        ERROR("tlv_create() failure");
        goto error;
    }

    nwrite = SSL_write(ssl,msg,data_len+8);

    if ( nwrite <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
     
    memset(msg,0,512);
    
    nread = SSL_read(ssl,msg,511);

    if ( nread <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    } 

    if ( memcmp(msg,"LE_ACK",6) == 0 ) {
        ERR_free_strings();
        return SKLOG_SUCCESS;
    } else if ( memcmp(msg,"LE_NACK",7) == 0 ) {
        WARNING("received NACK")
        goto error;
    } else {
        ERROR("unexpected message")
        goto error;
    }
    
error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
flush_logfile_terminate(SSL *ssl)
{
    unsigned char msg[512] = { 0 };

    unsigned char data[512] = { 0 };
    unsigned int data_len = 0;

    int nread = 0;
    int nwrite = 0;

    SSL_load_error_strings();

    data_len = strlen("LOGFILE_FLUSH_END");
    memcpy(data,"LOGFILE_FLUSH_END",data_len);

    if ( tlv_create(LE_FLUSH_END,data_len,data,msg) == SKLOG_FAILURE ) {
        ERROR("tlv_create() failure")
        goto error;
    }

    nwrite = SSL_write(ssl,msg,data_len+8);

    if ( nwrite <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    memset(msg,0,512);
    nread = SSL_read(ssl,msg,511);

    if ( nread <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    } 

    if ( memcmp(msg,"LE_ACK",6) == 0 ) {
        ERR_free_strings();
        return SKLOG_SUCCESS;
    } else if ( memcmp(msg,"LE_NACK",7) == 0 ) {
        WARNING("received NACK")
        goto error;
    } else {
        ERROR("unexpected message")
        goto error;
    }

error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
flush_logfile_execute(SKLOG_U_Ctx       *u_ctx,
                      struct timeval    *now)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    //~ open connection

    SKLOG_CONNECTION conn = {0,0,0};

    if ( conn_open(u_ctx,&conn) == SKLOG_FAILURE ) {
        ERROR("conn_open() failure")
        goto error;
    }

    //~ send message: LOGFILE_FLUSH_START
    if ( flush_logfile_init(conn.ssl) == SKLOG_FAILURE ) {
        ERROR("flush_logfile_init() failure")
        goto error;
    }

    //~ flush logfile
    if ( u_ctx->lsdriver->flush_logfile(u_ctx->logfile_id,now,conn.ssl) == SKLOG_FAILURE ) {
        ERROR("u_ctx->lsdriver->flush_logfile() failure");
        goto error;
    }

    //~ send message: LOGFILE_FLUSH_END
    if ( flush_logfile_terminate(conn.ssl) == SKLOG_FAILURE ) {
        ERROR("flush_logfile_terminate() failure")
        goto error;
    }

    //~ close connection
    if ( conn_close(&conn) == SKLOG_FAILURE ) {
        ERROR("conn_close() falilure")
        goto error;
    }

    return SKLOG_SUCCESS;
    
error:
    return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/*                             LOCAL                                  */
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

SKLOG_U_Ctx*
SKLOG_U_NewCtx(void)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_U_Ctx *ctx = calloc(1,sizeof(SKLOG_U_Ctx));

    if ( ctx == NULL ) {
        ERROR("calloc() failure");
        return NULL;
    }
    
    ctx->lsdriver = calloc(1,sizeof(SKLOG_U_STORAGE_DRIVER));

    if ( ctx->lsdriver == NULL ) {
        ERROR("calloc() failure");
        return NULL;
    }

    #ifdef USE_FILE
    ctx->lsdriver->store_logentry =    &sklog_file_u_store_logentry;
    ctx->lsdriver->flush_logfile =     &sklog_file_u_flush_logfile;
    ctx->lsdriver->init_logfile =      &sklog_file_u_init_logfile;
    #elif USE_SYSLOG
    ctx->lsdriver->store_logentry =    &sklog_syslog_u_store_logentry;
    ctx->lsdriver->flush_logfile =     &sklog_syslog_u_flush_logfile;
    ctx->lsdriver->init_logfile =      &sklog_syslog_u_init_logfile;
    #elif USE_SQLITE
    ctx->lsdriver->store_logentry =    &sklog_sqlite_u_store_logentry;
    ctx->lsdriver->flush_logfile =     &sklog_sqlite_u_flush_logfile;
    ctx->lsdriver->init_logfile =      &sklog_sqlite_u_init_logfile;
    #else
    //~ todo: manage default case
    #endif

    return ctx;
}

SKLOG_RETURN
SKLOG_U_FreeCtx(SKLOG_U_Ctx **ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    X509_free((*ctx)->u_cert);
    X509_free((*ctx)->t_cert);
    EVP_PKEY_free((*ctx)->u_privkey);

    memset(*ctx,0,sizeof(SKLOG_U_Ctx));
    *ctx = 0;
    
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
SKLOG_U_LogEvent(SKLOG_U_Ctx        *u_ctx,
                 SKLOG_DATA_TYPE    type,
                 char               *data,
                 unsigned int       data_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char *data_blob = 0;
    unsigned int data_blob_len = 0;

    if ( SKLOG_alloc(&data_blob,unsigned char,data_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }
    memcpy(data_blob,data,data_len);

    //~ check the state of the logging session
    if ( u_ctx->context_state == SKLOG_U_CTX_NOT_INITIALIZED ) {
        if ( initialize_context(u_ctx) == SKLOG_FAILURE ) {
            ERROR("context initialization process fails")
            goto error;
        }
        if ( initialize_logging_session(u_ctx) == SKLOG_FAILURE ) {
            ERROR("loggin session initialization process fails")
            goto error;
        }
    }
    
    //~ write logentry
    if ( create_logentry(u_ctx,type,data_blob,
                         data_len) == SKLOG_FAILURE ) {
        ERROR("create_logentry() failure")
        goto error;
    }

    //~ check if the logging session needs to be renewed
    if ( u_ctx->logfile_counter == u_ctx->logfile_size -1 ) {

        WARNING("The logging session has to be renewed!!!")

        SKLOG_DATA_TYPE type = NormalCloseMessage;
        struct timeval now;

        gettimeofday(&now,NULL);
    
        if ( serialize_timeval(&now,&data_blob,
                               &data_blob_len) == SKLOG_FAILURE ) {
            ERROR("serialize_timeval() failure")
            goto error;
        }

        if ( create_logentry(u_ctx,type,data_blob,
                             data_blob_len) == SKLOG_FAILURE ) {
            ERROR("create_logentry() failure")
            goto error;
        }

        //~ send all generated log-entries to T
        if ( flush_logfile_execute(u_ctx,&now) == SKLOG_FAILURE ) {
            ERROR("flush_logfile_execute() failure")
            goto error;
        }

        //~ flush the current context and mark it as uninitialized
        memset(u_ctx,0,sizeof(*u_ctx));
        u_ctx->context_state = SKLOG_U_CTX_NOT_INITIALIZED;
    }

    free(data_blob);
    return SKLOG_SUCCESS;

error:
    if ( data_blob > 0 ) free(data_blob);
    return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/*                            CLIENT                                  */
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/*                            SERVER                                  */
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
