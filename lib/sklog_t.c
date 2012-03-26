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
#include "sklog_t.h"


#ifdef USE_FILE
    #include "storage/sklog_file.h"
#elif USE_SYSLOG
    #include "storage/sklog_syslog.h"
#elif USE_SQLITE
    #include "storage/sklog_sqlite.h"
#else
    #include "storage/sklog_dummy.h"
    #include "storage/sklog_sqlite.h"
#endif

#include <confuse.h>
#include <signal.h>
#include <sqlite3.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>

#include <uuid/uuid.h>

/*--------------------------------------------------------------------*/
/* connection                                                         */
/*--------------------------------------------------------------------*/

/** to delete
static SSL_CTX*
init_ssl_ctx(const char    *rsa_cert,
             const char    *rsa_privkey,
             int           verify,
             const char    *ca_cert)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int retval = 0;
     
    SSL_CTX *ctx = 0;
    const SSL_METHOD *meth = 0;

    SSL_library_init();
    SSL_load_error_strings();

    meth = SSLv3_method();
    ctx = SSL_CTX_new(meth);
    
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    retval = SSL_CTX_use_certificate_file(ctx, rsa_cert,
                                          SSL_FILETYPE_PEM);

    if ( retval <= 0 ) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    retval = SSL_CTX_use_PrivateKey_file(ctx,rsa_privkey,
                                         SSL_FILETYPE_PEM);

    if ( retval <= 0 ) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    if ( !SSL_CTX_check_private_key(ctx) ) {
        fprintf(stderr,
            "Private key does not match the certificate public key\n");
        return NULL;
    }

    if( verify == 1 && ca_cert != NULL ) {
    
        if ( !SSL_CTX_load_verify_locations(ctx,ca_cert, NULL) ) {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
        
        SSL_CTX_set_verify_depth(ctx,1);
    }

    return ctx;
}
*/

/** to delete
static SSL*
init_ssl_structure(SSL_CTX    *ctx,
                   int        socket,
                   int        verify)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    SSL *ssl = 0;

    char *str = 0;
    X509 *client_cert = NULL;

    SSL_load_error_strings();

    if ( (ssl = SSL_new(ctx)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    SSL_set_fd(ssl, socket);
    
    if ( SSL_accept(ssl) < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    if ( verify == 1 ) {

        client_cert = SSL_get_peer_certificate(ssl);

        if ( client_cert != NULL ) {

            fprintf(stdout,"Client certificate:\n");

            str = X509_NAME_oneline(X509_get_subject_name(client_cert),
                                    0,0);
            
            if ( str == NULL ) {
                ERROR("X509_NAME_oneline() failure")
                goto error;
            }
            
            fprintf(stdout,"\t subject: %s\n",str);
            free (str);

            str = X509_NAME_oneline(X509_get_issuer_name(client_cert),
                                    0,0);

            if ( str == NULL ) {
                ERR_print_errors_fp(stderr);
                goto error;
            }

            fprintf(stdout,"\t issuer: %s\n", str);
            SKLOG_free(&str);
            
            X509_free(client_cert);
        } else {
            NOTIFY("The SSL client does not have certificate");
        }
    }

    ERR_free_strings();
    return ssl;

error:
    ERR_free_strings();
    return NULL;
}
*/

/** to delete
static int
tcp_bind(const char    *address,
         short int     port)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    int skt = 0;
    int optval = 1;
    struct sockaddr_in sa_serv;
    
    if ( (skt = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0 ) {
        ERROR("socket() failure")
        return -1;
    }

    setsockopt(skt,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval));

    memset(&sa_serv,0,sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = inet_addr(address);
    sa_serv.sin_port = htons(port);

    if ( bind(skt,(struct sockaddr*)&sa_serv,sizeof(sa_serv)) < 0 ) {
        ERROR("bind() failure")
        return -1;
    }

    return skt;
}
*/

/*--------------------------------------------------------------------*/
/* logging session initialization                                     */
/*--------------------------------------------------------------------*/

static SKLOG_RETURN
parse_config_file(char    **t_cert,
                  char    **t_privkey,
                  char    **t_privkey_passphrase,
                  char    **t_id,
                  char    **t_address,
                  int     *t_port)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    char buffer[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    int len = 0;

    cfg_opt_t opts[] = {
        CFG_STR("t_cert",SKLOG_DEF_T_CERT_PATH,CFGF_NONE),
        CFG_STR("t_privkey",SKLOG_DEF_T_RSA_KEY_PATH,CFGF_NONE),
        CFG_STR("t_privkey_passphrase",SKLOG_DEF_T_RSA_KEY_PASSPHRASE,CFGF_NONE),
        CFG_STR("t_id",SKLOG_DEF_T_ID,CFGF_NONE),
        CFG_STR("t_address",SKLOG_DEF_T_ADDRESS,CFGF_NONE),
        CFG_INT("t_port",SKLOG_DEF_T_PORT,CFGF_NONE),
        CFG_END()
    };

    cfg_t *cfg = NULL;
    cfg = cfg_init(opts, CFGF_NONE);
    
    if( cfg_parse(cfg,SKLOG_T_CONFIG_FILE_PATH) == CFG_PARSE_ERROR ) {
        ERROR("cfg_parse() failure")
        goto error;
    }

    //~ load t_cert ($ETC_PREFIX/libsklog/certs/ca/ca_cert.pem)
    len = sprintf(buffer,"%s",cfg_getstr(cfg,"t_cert"));
    *t_cert = calloc(len+1,sizeof(char));
    memcpy(*t_cert,buffer,len);
    (*t_cert)[len] = '\0';
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);
    
    //~ load t_privkey ($ETC_PREFIX/libsklog/certs/private/ca_key.pem)
    len = sprintf(buffer,"%s",cfg_getstr(cfg,"t_privkey"));
    *t_privkey = calloc(len+1,sizeof(char));
    memcpy(*t_privkey,buffer,len);
    (*t_privkey)[len] = '\0';
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);

    //~ load t_privkey_passphrase (123456)
    *t_privkey_passphrase = SKLOG_DEF_T_RSA_KEY_PASSPHRASE;
    
    //~ load t_id (t.example.com)
    len = sprintf(buffer,"%s",cfg_getstr(cfg,"t_id"));
    *t_id = calloc(len+1,sizeof(char));
    memcpy(*t_id,buffer,len);
    (*t_id)[len] = '\0';
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);

    //~ load t_address (127.0.0.1)
    len = sprintf(buffer,"%s",cfg_getstr(cfg,"t_address"));
    *t_address = calloc(len+1,sizeof(char));
    memcpy(*t_address,buffer,len);
    (*t_address)[len] = '\0';
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);

    //~ load t_port (5555)
    *t_port = cfg_getint(cfg,"t_port");

    cfg_free(cfg);

    return SKLOG_SUCCESS;
    
error:
    if ( cfg ) cfg_free(cfg);
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
parse_m0(SKLOG_T_Ctx            *t_ctx,
         unsigned char          *m0,
         unsigned int           m0_len,
         SKLOG_PROTOCOL_STEP    *p,
         uuid_t                 *logfile_id,
         unsigned char          **pke_t_k0,
         unsigned int           *pke_t_k0_len,
         unsigned char          **e_k0,
         unsigned int           *e_k0_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    
    unsigned int ds = 0;
    unsigned int len = 0;

    unsigned char uuid_tmp[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    uuid_t uuid;

    if ( tlv_parse(&m0[ds],PROTOCOL_STEP,p,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected PROTOCOLO_STEP");
        return SKLOG_FAILURE;
    }

    ds += len+8;
    len = 0;

    if ( tlv_parse(&m0[ds],ID_LOG,uuid_tmp,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected ID_U");
        return SKLOG_FAILURE;
    }

    memcpy(&uuid,uuid_tmp,len);
    uuid_copy(*logfile_id,uuid);

    ds += len+8;
    len = 0;

    if ( tlv_parse(&m0[ds],PKE_PUB_T,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected PKE_PUB_T");
        return SKLOG_FAILURE;
    }

    if ( SKLOG_alloc(pke_t_k0,unsigned char,len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }
    memcpy(*pke_t_k0,buffer,len);
    *pke_t_k0_len = len;

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    if ( tlv_parse(&m0[ds],ENC_K0,buffer,&len) == SKLOG_FAILURE ) {
        free(*pke_t_k0);
        ERROR("M1 message is bad structured: expected ENC_K0");
        return SKLOG_FAILURE;
    }

    if ( SKLOG_alloc(e_k0,unsigned char,len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }
    memcpy(*e_k0,buffer,len);
    *e_k0_len = len;

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    return SKLOG_SUCCESS;
}

static SKLOG_RETURN
verify_m0_signature(X509             *u_cert,
                    unsigned char    *x0_sign,
                    size_t           x0_sign_len,
                    unsigned char    *x0,
                    unsigned int     x0_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    EVP_PKEY *u_pubkey = 0;

    ERR_load_crypto_strings();

    if ( u_cert == NULL ) {
        ERROR("u_cert variable must be not null");
        goto error;
    }

    if ( x0_sign == NULL ) {
        ERROR("x0_sign variable must be not null");
        goto error;
    }
    if ( x0 == NULL ) {
        ERROR("x0 variable must be not null");
        goto error;
    }

    if ( (u_pubkey = X509_get_pubkey(u_cert)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if ( sign_verify(u_pubkey,x0_sign,x0_sign_len,
                                        x0,x0_len) == SKLOG_FAILURE ) {
        ERROR("sign_verify() failure")
        goto error;
    }

    ERR_free_strings();
    EVP_PKEY_free(u_pubkey);
    
    return SKLOG_SUCCESS;

error:
    if ( u_pubkey > 0 ) EVP_PKEY_free(u_pubkey); 
    ERR_free_strings();

    return SKLOG_FAILURE;
}

static SKLOG_RETURN
verify_m0_certificate(X509 *u_cert)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    if ( u_cert == NULL ) {
        ERROR("u_cert variable must be not null");
        return SKLOG_FAILURE;
    }

    TO_IMPLEMENT;

    return SKLOG_TO_IMPLEMENT;
}

static SKLOG_RETURN
parse_e_k0_content(unsigned char    *in,
                   unsigned int     in_len,
                   unsigned char    **x0,
                   unsigned int     *x0_len,
                   unsigned char    **x0_sign,
                   unsigned int     *x0_sign_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;
    unsigned int len = 0;

    if ( tlv_parse(&in[ds],X0_BUF,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("PLAIN buffer is bad structured: expected X0_BUF");
        return SKLOG_FAILURE;
    }

    if ( SKLOG_alloc(x0,unsigned char,len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }

    *x0_len = len;
    memcpy(*x0,buffer,len);

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    if ( tlv_parse(&in[ds],X0_SIGN_U,buffer,&len) == SKLOG_FAILURE ) {
        free(*x0);
        ERROR("PLAIN buffer is bad structured: expected X0_SIGN_U");
        return SKLOG_FAILURE;
    }

    if ( SKLOG_alloc(x0_sign,unsigned char,len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }

    *x0_sign_len = len;
    memcpy(*x0_sign,buffer,len);

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);
    
    return SKLOG_SUCCESS;
}

// todo: to refine
static SKLOG_RETURN
parse_x0( unsigned char    *x0,
         unsigned int      x0_len,
         X509              **u_cert,
         unsigned char     *auth_key)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    
    unsigned int ds = 0;
    unsigned int len = 0;

    unsigned char *u_cert_buf = 0;
    const unsigned char *u_cert_buf_tmp = 0;

    ERR_load_crypto_strings();

    //~ get protocol step
    if ( tlv_parse(&x0[ds],PROTOCOL_STEP,buffer,
            &len) == SKLOG_FAILURE ) {
        ERROR("X0 buffer is bad structured: expected PROTOCOLO_STEP");
        goto error;
    }
    
    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ get timestamp
    if ( tlv_parse(&x0[ds],TIMESTAMP,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("X0 buffer is bad structured: expected TIMESTAMP");
        goto error;
    }

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ get U's certificate
    if ( tlv_parse(&x0[ds],CERT_U,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("X0 buffer is bad structured: expected CERT_U");
        goto error;
    }

    u_cert_buf = OPENSSL_malloc(len);
    memcpy(u_cert_buf,buffer,len);

    u_cert_buf_tmp = u_cert_buf;

    if ( d2i_X509(u_cert,&u_cert_buf_tmp,len) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ get U's a0
    if (tlv_parse(&x0[ds],A0_KEY,auth_key,&len) == SKLOG_FAILURE ) {
        ERROR("X0 buffer is bad structured: expected A0_KEY");
        goto error;
    }
    
    OPENSSL_free(u_cert_buf);

    return SKLOG_SUCCESS;
    
error:
    if ( u_cert_buf > 0 ) free( u_cert_buf );
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
gen_x1(SKLOG_PROTOCOL_STEP    *p,
       unsigned char          *x0,
       unsigned int           x0_len,
       unsigned char          **x1,
       unsigned int           *x1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char x0_md[SHA256_LEN] = { 0 };
    
    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;

    unsigned int len = 0;
    unsigned char value[SKLOG_BUFFER_LEN] = { 0 };
    unsigned char *tlv = 0;
    
    //~ generate a digest of x0

    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);
    EVP_DigestUpdate(&mdctx,x0,x0_len);
    EVP_DigestFinal_ex(&mdctx,x0_md,NULL)  ;
    EVP_MD_CTX_cleanup(&mdctx);

    //~ increase protocol step
    uint32_t p_net = htonl(*p+1);
    *p += 1;

    /**
    //~ compose x1

    *x1_len = (sizeof(p_net) + 8) +
              SHA256_LEN + 8;

    if ( SKLOG_alloc(x1,unsigned char,*x1_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }
    */

    //~ TLV-ize protocol step

    memcpy(value,&p_net,sizeof(p_net));
    tlv_create_message(PROTOCOL_STEP,sizeof(p_net),value,&tlv,&len);
    memcpy(buffer+ds,tlv,len); free(tlv); ds += len; 
    memset(value,0,SKLOG_SMALL_BUFFER_LEN);

    //~ TLV-ize protocol step

    tlv_create_message(HASH_X0,SHA256_LEN,x0_md,&tlv,&len);
    memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

    *x1_len = ds;
    *x1 = calloc(ds,sizeof(unsigned char));
    memcpy(*x1,buffer,ds);

    return SKLOG_SUCCESS;
}

static SKLOG_RETURN
gen_e_k1(SKLOG_T_Ctx      *t_ctx,
         unsigned char    *k1,
         unsigned char    *x1,
         unsigned int     x1_len,
         unsigned char    *x1_sign,
         unsigned int     x1_sign_len,
         unsigned char    **e_k1,
         unsigned int     *e_k1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    //~
    //~ encrypt {x1|x1_signature} using session key
    //~

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;

    unsigned char *tlv = 0;
    unsigned int len = 0;

    /**
    unsigned char *buffer2 = 0;
    unsigned int buffer2_len = x1_len + 8 +
                               x1_sign_len + 8;

    
    if ( SKLOG_alloc(&buffer2,unsigned char,buffer2_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }
    */


    //~ TLV-ize x1

    tlv_create_message(X1_BUF,x1_len,x1,&tlv,&len);
    memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

    //~ TLV-ize x1_signature

    tlv_create_message(X1_SIGN_T,x1_sign_len,x1_sign,&tlv,&len);
    memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

    if ( aes256_encrypt(buffer,ds,k1,SKLOG_SESSION_KEY_LEN,
                        e_k1,e_k1_len) == SKLOG_FAILURE ) {
        ERROR("encrypt_aes256() failure")
        return SKLOG_FAILURE;
    }

    return SKLOG_SUCCESS;
}

static SKLOG_RETURN
gen_m1(SKLOG_T_Ctx            *t_ctx,
       SKLOG_PROTOCOL_STEP    p,
       unsigned char          *pke_u_k1,
       unsigned int           pke_u_k1_len,
       unsigned char          *e_k1,
       unsigned int           e_k1_len,
       unsigned char          **m1,
       unsigned int           *m1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;

    unsigned int len = 0;
    unsigned char value[SKLOG_BUFFER_LEN] = { 0 };
    unsigned char *tlv = 0;

    //~ convert p in network order
    uint32_t p_net = htonl(p);

    /**
    //~ compose m1 in tlv format
    *m1_len = (sizeof(p_net) + 8) +
              (t_ctx->t_id_len + 8) +
              (pke_u_k1_len + 8) +
              (e_k1_len + 8);

    if ( SKLOG_alloc(m1,unsigned char,*m1_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }
    */

    //~ TLV-ize p

    memcpy(value,&p_net,sizeof(p_net));
    tlv_create_message(PROTOCOL_STEP,sizeof(p_net),value,&tlv,&len);
    memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
    memset(value,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize t_id

    memcpy(value,t_ctx->t_id,t_ctx->t_id_len);
    tlv_create_message(ID_T,t_ctx->t_id_len,value,&tlv,&len);
    memcpy(buffer+ds,tlv,len); free(tlv); ds += len;
    memset(value,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize pke_u_k1

    tlv_create_message(PKE_PUB_U,pke_u_k1_len,pke_u_k1,&tlv,&len);
    memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

    //~ TLV-ize e_k1

    tlv_create_message(ENC_K1,e_k1_len,e_k1,&tlv,&len);
    memcpy(buffer+ds,tlv,len); free(tlv); ds += len;

    *m1_len = ds;
    *m1 = calloc(ds,sizeof(unsigned char));
    memcpy(*m1,buffer,ds);

    return SKLOG_SUCCESS;
}

static SKLOG_RETURN
send_m1(SKLOG_T_Ctx         *t_ctx,
        //~ SSL              *ssl,
        SKLOG_CONNECTION    *conn,
        unsigned char       *m1,
        unsigned int        m1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int wlen = 0;

    unsigned char *tlv = 0;

    tlv_create_message(M1_MSG,m1_len,m1,&tlv,&wlen);
    memcpy(wbuf,tlv,wlen);
    
    #ifdef DO_TRACE
    SHOWBUF("TOUT - M1_MSG", wbuf, wlen);
    #endif

    #ifdef USE_BIO
    if ( BIO_write(conn->bio,wbuf,wlen) <= 0 ) {
        if ( !BIO_should_retry(conn->bio) ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
        }
        //~ to manage
    }
    #endif

    #ifdef USE_SSL
    if ( SSL_write(ssl,wbuf,wlen) < 0 ) {
        ERR_print_errors_fp(stderr);
        return SKLOG_FAILURE;
    }
    #endif

    return SKLOG_SUCCESS;
}

/*--------------------------------------------------------------------*/
/* interactions with U nodes                                          */
/*--------------------------------------------------------------------*/

/** to delete
static SKLOG_RETURN
manage_logsession_init(SKLOG_T_Ctx      *t_ctx,
                       unsigned char    *m0,
                       unsigned int     m0_len,
                       SSL              *ssl,
                       char             *u_ip)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_PROTOCOL_STEP p = 0;
    
    uuid_t logfile_id;

    unsigned char *e_k0 = 0;
    unsigned int e_k0_len = 0;
    unsigned char *pke_t_k0 = 0;
    unsigned int pke_t_k0_len = 0;
    
    unsigned char *k0 = 0;
    unsigned int k0_len = 0;

    unsigned char *plain = 0;
    unsigned int plain_len = 0;

    unsigned char *x0 = 0;
    unsigned int x0_len = 0;
    unsigned char *x0_sign = 0;
    unsigned int x0_sign_len = 0;

    X509 *u_cert = 0;
    unsigned char auth_key[SKLOG_AUTH_KEY_LEN] = { 0 };

    unsigned char *x1 = 0;
    unsigned int x1_len = 0;

    unsigned char k1[SKLOG_SESSION_KEY_LEN] = { 0 };

    unsigned char *x1_sign = 0;
    unsigned int x1_sign_len = 0;

    unsigned char *e_k1 = 0;
    unsigned int e_k1_len = 0;

    unsigned char *pke_u_k1 = 0;

    unsigned char *m1 = 0;
    unsigned int m1_len = 0;

    //~ parse m0
    if ( parse_m0(t_ctx,&m0[8],m0_len,&p,&logfile_id,&pke_t_k0,
                  &pke_t_k0_len,&e_k0,&e_k0_len) == SKLOG_FAILURE ) {
        ERROR("parse_m0() failure")
        goto error;
    }
    SKLOG_free(&m0);

    //~ decrypt k0 using T's private key
    size_t len = 0;
    if ( pke_decrypt(t_ctx->t_priv_key,pke_t_k0,
                     pke_t_k0_len,&k0,&len) == SKLOG_FAILURE ) {
        ERROR("pke_decrypt() failure")
        goto error; //~ m0 verification fails
    }
    k0_len = len;
    SKLOG_free(&pke_t_k0);

    if ( aes256_decrypt(e_k0,e_k0_len,k0,SKLOG_SESSION_KEY_LEN,&plain,
                        &plain_len) == SKLOG_FAILURE ) {
        ERROR("decrypt_aes256() failure")
        goto error; //~ m0 verification fails
    }
    SKLOG_free(&e_k0);
    SKLOG_free(&k0);

    //~ parse plain
    if ( parse_e_k0_content(plain,plain_len,&x0,&x0_len,
                            &x0_sign,&x0_sign_len) == SKLOG_FAILURE ) {
        ERROR("parse_plain() failure")
        goto error;
    }
    SKLOG_free(&plain);

    //~ parse x0
    if ( parse_x0(x0,x0_len,&u_cert,auth_key) == SKLOG_FAILURE ) {
        ERROR("parse_x0() failure")
        goto error;
    }
    */

    /**
     * M0 Verification
     *
     * The M0 message verification may include multiple steps which are
     * not specified. In the paper, authors suggest as verification
     * steps only the signature and certificate verification.
     *
     * Users may define a custom verification steps list.
     */

    /**
    //~ verify U's signature
    if ( verify_m0_signature(u_cert,x0_sign,x0_sign_len,
                                        x0,x0_len) == SKLOG_FAILURE ) {
        ERROR("verify_m0_signature() failure")
        goto error;
    }
    SKLOG_free(&x0_sign);

    //~ check validity of U's certificate
    if ( verify_m0_certificate(u_cert) == SKLOG_FAILURE ) {
        ERROR("verify_m0_certificate() failure")
        goto error;
    }
    
    //----------------------------------------------------------------//

    //~ store auth_key
    if ( t_ctx->lsdriver->store_authkey(u_ip,logfile_id,
                                         auth_key) == SKLOG_FAILURE ) {
        ERROR("store_auth_key() failure")
        goto error;
    }
    
    //~ remove auth_key from memory
    memset(auth_key,0,SKLOG_AUTH_KEY_LEN); 

    //----------------------------------------------------------------//
    //----------------------------------------------------------------//

    //~ generate x1
    if ( gen_x1(&p,x0,x0_len,&x1,&x1_len) == SKLOG_FAILURE ) {
        ERROR("gen_x1() failure")
        goto error;
    }
    SKLOG_free(&x0);

    //~ generate a random session key k1
    RAND_bytes(k1,SKLOG_SESSION_KEY_LEN);

    //~ sign x1 using T's private key
    if ( sign_message(x1,x1_len,t_ctx->t_priv_key,
                      &x1_sign,&x1_sign_len) == SKLOG_FAILURE ) {
        ERROR("sign_message() failure")
        goto error;
    }

    //~ encrypt {x1,x1_sign} using k1 key
    if ( gen_e_k1(t_ctx,k1,x1,x1_len,x1_sign,x1_sign_len,
                  &e_k1,&e_k1_len) == SKLOG_FAILURE ) {
        ERROR("gen_e_k1() failure")
        goto error;
    }
    SKLOG_free(&x1_sign);
    SKLOG_free(&x1);

    //~ encrypt k1 using U's public key
    size_t pke_u_k1_len = 0;
    if ( pke_encrypt(u_cert,k1,SKLOG_SESSION_KEY_LEN,
                     &pke_u_k1,&pke_u_k1_len) == SKLOG_FAILURE ) {
        ERROR("pke_encrypt() failure")
        goto error;
    }
    X509_free(u_cert);
    memset(k1,0,SKLOG_SESSION_KEY_LEN);
    
    //~ generate m1
    if ( gen_m1(t_ctx,p,pke_u_k1,pke_u_k1_len,e_k1,
                e_k1_len,&m1,&m1_len) == SKLOG_FAILURE ) {
        ERROR("gen_m1() failure")
        goto error;
    }
    SKLOG_free(&e_k1);
    SKLOG_free(&pke_u_k1);

    //~ send m1 to U
    if ( send_m1(t_ctx,ssl,m1,m1_len) == SKLOG_FAILURE ) {
        ERROR("send_m1() failure")
        goto error;
    }
    SKLOG_free(&m1);
    
    return SKLOG_SUCCESS;

error:
    if ( pke_t_k0 > 0 )    SKLOG_free(&pke_t_k0); 
    if ( e_k0 > 0 )        SKLOG_free(&e_k0);
    if ( k0 > 0 )          SKLOG_free(&k0);
    if ( plain > 0 )       SKLOG_free(&plain);
    if ( x0 > 0 )          SKLOG_free(&x0);
    if ( x0_sign > 0 )     SKLOG_free(&x0_sign);
    if ( u_cert )      X509_free(u_cert);
    if ( x1 > 0 )          SKLOG_free(&x1);
    if ( x1_sign > 0 )     SKLOG_free(&x1_sign);
    if ( e_k1 > 0 )        SKLOG_free(&e_k1);
    if ( pke_u_k1 > 0 )    SKLOG_free(&pke_u_k1);
    if ( m1 > 0 )          SKLOG_free(&m1);

    return SKLOG_FAILURE;
}
*/

/** do not delete
static SKLOG_RETURN
manage_logfile_flush(SKLOG_T_Ctx    *t_ctx,
                     SSL            *ssl)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int more = 1;

    int nread = 0;
    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };

    uint32_t type = 0;
    unsigned int len = 0;
    unsigned char *value = 0;

    SSL_load_error_strings();
    
    if ( SSL_write(ssl,SKLOG_ACK,SKLOG_ACK_LEN) < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    } 

    while ( more ) {

        nread = SSL_read(ssl,buffer,SKLOG_BUFFER_LEN);

        if ( nread <= 0 ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }

        if ( tlv_get_type(buffer,&type) == SKLOG_FAILURE ) {
            ERROR("tlv_get_type() failure")
            goto error;
        }

        switch ( type ) {
            case LOGENTRY:
                NOTIFY("Received log entry");

                if ( tlv_parse_message(buffer,LOGENTRY,&type,&len,&value) == SKLOG_FAILURE ) {
                    ERROR("tlv_parse_message() failure")
                    goto error;
                }

                if ( t_ctx->lsdriver->store_logentry(value,len) == SKLOG_FAILURE ) {
                    ERROR("t_ctx->lsdriver->store_logentry() failure");
                    goto error;
                }
                
                break;
            case LE_FLUSH_END:
                NOTIFY("Logfile fush terminated!")
                more = 0;
                break;
            default:
                ERROR("protocol error")
                goto error;
                break;
        } 
        
        if ( SSL_write(ssl,SKLOG_ACK,SKLOG_ACK_LEN) < 0 ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        memset(buffer,0,SKLOG_BUFFER_LEN);
    }

    ERR_free_strings();
    return SKLOG_SUCCESS;
    
error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}
*/

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/*                             LOCAL                                  */
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

SKLOG_T_Ctx*
SKLOG_T_NewCtx(void)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    SKLOG_T_Ctx *ctx = calloc(1,sizeof(SKLOG_T_Ctx));

    if ( ctx == NULL ) {
        ERROR("calloc() failure");
        return NULL;
    }

    memset(ctx,0,sizeof(SKLOG_T_Ctx));
    
    ctx->lsdriver = calloc(1,sizeof(SKLOG_T_STORAGE_DRIVER));

    if ( ctx->lsdriver == NULL ) {
        ERROR("calloc() failure");
        return NULL;
    }

    #ifdef USE_FILE
    ctx->lsdriver->store_authkey =     &sklog_file_t_store_authkey;
    ctx->lsdriver->store_m0_msg =      &sklog_file_t_store_m0_msg;
    ctx->lsdriver->store_logentry =    &sklog_file_t_store_logentry;
    #elif USE_SYSLOG
    ctx->lsdriver->store_authkey =     &sklog_syslog_t_store_authkey;
    ctx->lsdriver->store_m0_msg =      &sklog_syslog_t_store_m0_msg;
    ctx->lsdriver->store_logentry =    &sklog_syslog_t_store_logentry;
    #elif USE_SQLITE
    ctx->lsdriver->store_authkey =     &sklog_sqlite_t_store_authkey;
    ctx->lsdriver->store_m0_msg =      &sklog_sqlite_t_store_m0_msg;
    ctx->lsdriver->store_logentry =    &sklog_sqlite_t_store_logentry;
    ctx->lsdriver->retrieve_logfiles = &sklog_sqlite_t_retrieve_logfiles;
    ctx->lsdriver->verify_logfile =    &sklog_sqlite_t_verify_logfile;
    #else
    ctx->lsdriver->store_authkey =     &sklog_sqlite_t_store_authkey;
    ctx->lsdriver->store_m0_msg =      &sklog_sqlite_t_store_m0_msg;
    ctx->lsdriver->store_logentry =    &sklog_sqlite_t_store_logentry;
    ctx->lsdriver->retrieve_logfiles = &sklog_sqlite_t_retrieve_logfiles;
    ctx->lsdriver->verify_logfile =    &sklog_sqlite_t_verify_logfile;
    #endif

    return ctx;
}

SKLOG_RETURN
SKLOG_T_FreeCtx(SKLOG_T_Ctx **ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    if ( *ctx == NULL ) {
		ERROR("argument 1 must be not null");
		return SKLOG_FAILURE;
	}

    X509_free((*ctx)->t_cert);
    EVP_PKEY_free((*ctx)->t_privkey);

    memset(*ctx,0,sizeof(SKLOG_T_Ctx));
    *ctx = 0;
    
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
SKLOG_T_InitCtx(SKLOG_T_Ctx    *t_ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_RETURN retval = SKLOG_SUCCESS;

    FILE *fp = NULL;

    char *t_cert = 0;
    char *t_privkey = 0;
    char *t_privkey_passphrase = 0;
    char *t_id = 0;
    char *t_address = 0;
    int t_port = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if ( t_ctx == NULL ) {
        ERROR("t_ctx must be not null");
        goto error;
    }    

    //~ parse configuration file (to implement)
    retval = parse_config_file(&t_cert,&t_privkey,&t_privkey_passphrase,
                               &t_id,&t_address,&t_port);

    if ( retval == SKLOG_FAILURE ) {
        ERROR("parse_config_file() failure");
        goto error;
    }

    //~ load t_id from config file
    t_ctx->t_id_len = strlen(t_id);
    
    //~ Bugfix: Sebastian Banescu <banescusebi@gmail.com>
    snprintf(t_ctx->t_id,HOST_NAME_MAX,"%s",t_id);

    //~ load T's X509 certificate
    t_ctx->t_cert = 0;
    if ( (fp = fopen(t_cert,"r")) != NULL ) {
        if ( !PEM_read_X509(fp,&t_ctx->t_cert,NULL,NULL) ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        fclose(fp); fp = 0;
    } else {
        ERROR("unable to read T's certificate file")
        goto error;
    }

    t_ctx->t_cert_file_path = t_cert;
    t_ctx->t_privkey_file_path = t_privkey;
    t_ctx->t_address = t_address;
    t_ctx->t_port = t_port;
    
    //~ load T's rsa privkey
    t_ctx->t_privkey = EVP_PKEY_new();
    if ( (fp = fopen(t_privkey,"r")) != NULL ) {
        if ( !PEM_read_PrivateKey(fp,&t_ctx->t_privkey,
                                  NULL,RSA_DEFAULT_PASSPHRASE) ) {
            ERROR("PEM_read_PrivateKey() failure")
            goto error;
        }
        fclose(fp); fp = 0;
    } else {
        ERROR("unable to read T's private key file")
        goto error;
    }

    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    if ( fp > 0 ) fclose(fp);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/*                            SERVER                                  */
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

SKLOG_RETURN
SKLOG_T_ManageLoggingSessionInit(SKLOG_T_Ctx      *t_ctx,
                                 unsigned char    *m0,
                                 unsigned int     m0_len,
                                 char             *u_address,
                                 unsigned char    **m1,
                                 unsigned int     *m1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_PROTOCOL_STEP p = 0;
    
    uuid_t logfile_id;

    unsigned char *e_k0 = 0;
    unsigned int e_k0_len = 0;
    unsigned char *pke_t_k0 = 0;
    unsigned int pke_t_k0_len = 0;
    
    unsigned char *k0 = 0;
    unsigned int k0_len = 0;

    unsigned char *plain = 0;
    unsigned int plain_len = 0;

    unsigned char *x0 = 0;
    unsigned int x0_len = 0;
    unsigned char *x0_sign = 0;
    unsigned int x0_sign_len = 0;

    X509 *u_cert = 0;
    unsigned char auth_key[SKLOG_AUTH_KEY_LEN] = { 0 };

    unsigned char *x1 = 0;
    unsigned int x1_len = 0;

    unsigned char k1[SKLOG_SESSION_KEY_LEN] = { 0 };

    unsigned char *x1_sign = 0;
    unsigned int x1_sign_len = 0;

    unsigned char *e_k1 = 0;
    unsigned int e_k1_len = 0;

    unsigned char *pke_u_k1 = 0;

    unsigned char *m1_tmp = 0;
    unsigned int m1_tmp_len = 0;
    
    if ( t_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}
	
	if ( m0 == NULL ) {
		ERROR("argument 2 must be not NULL");
		return SKLOG_FAILURE;
	}
	
	if ( u_address == NULL ) {
		ERROR("argument 4 must be not NULL");
		return SKLOG_FAILURE;
	}

    //~ parse m0
    //~ if ( parse_m0(t_ctx,&m0[8],m0_len,&p,&logfile_id,&pke_t_k0,
                  //~ &pke_t_k0_len,&e_k0,&e_k0_len) == SKLOG_FAILURE ) {
        //~ ERROR("parse_m0() failure")
        //~ goto error;
    //~ }
    if ( parse_m0(t_ctx,m0,m0_len,&p,&logfile_id,&pke_t_k0,
                  &pke_t_k0_len,&e_k0,&e_k0_len) == SKLOG_FAILURE ) {
        ERROR("parse_m0() failure")
        goto error;
    }
    
    //~ store m0_msg
    if ( t_ctx->lsdriver->store_m0_msg(u_address, logfile_id, m0, m0_len) == SKLOG_FAILURE ) {
        ERROR("store_m0_msg() failure");
        goto error;
    }
    
    SKLOG_free(&m0); // PS: to check

    //~ decrypt k0 using T's private key
    size_t len = 0;
    if ( pke_decrypt(t_ctx->t_privkey,pke_t_k0,
                     pke_t_k0_len,&k0,&len) == SKLOG_FAILURE ) {
        ERROR("pke_decrypt() failure")
        goto error; //~ m0 verification fails
    }
    k0_len = len;
    
    if ( k0_len != SKLOG_SESSION_KEY_LEN ) {
		fprintf(stderr,"Somethings goes wrong: key len is %d\n",k0_len);
		goto error;
	}
	
    SKLOG_free(&pke_t_k0);

    if ( aes256_decrypt(e_k0,e_k0_len,k0,SKLOG_SESSION_KEY_LEN,&plain,
                        &plain_len) == SKLOG_FAILURE ) {
        ERROR("decrypt_aes256() failure")
        goto error; //~ m0 verification fails
    }
    SKLOG_free(&e_k0);
    SKLOG_free(&k0);

    //~ parse plain
    if ( parse_e_k0_content(plain,plain_len,&x0,&x0_len,
                            &x0_sign,&x0_sign_len) == SKLOG_FAILURE ) {
        ERROR("parse_plain() failure")
        goto error;
    }
    SKLOG_free(&plain);

    //~ parse x0
    if ( parse_x0(x0,x0_len,&u_cert,auth_key) == SKLOG_FAILURE ) {
        ERROR("parse_x0() failure")
        goto error;
    }

    /*----------------------------------------------------------------*/
    
    /**
     * M0 Verification
     *
     * The M0 message verification may include multiple steps which are
     * not specified. In the paper, authors suggest as verification
     * steps only the signature and certificate verification.
     *
     * Users may define a custom verification steps list.
     */

    //~ verify U's signature
    if ( verify_m0_signature(u_cert,x0_sign,x0_sign_len,
                                        x0,x0_len) == SKLOG_FAILURE ) {
        ERROR("verify_m0_signature() failure")
        goto error;
    }
    SKLOG_free(&x0_sign);

    //~ check validity of U's certificate
    if ( verify_m0_certificate(u_cert) == SKLOG_FAILURE ) {
        ERROR("verify_m0_certificate() failure")
        goto error;
    }
    
    /*----------------------------------------------------------------*/

    //~ store auth_key
    if ( t_ctx->lsdriver->store_authkey(u_address,logfile_id,
                                         auth_key) == SKLOG_FAILURE ) {
        ERROR("store_auth_key() failure")
        goto error;
    }
    
    //~ remove auth_key from memory
    memset(auth_key,0,SKLOG_AUTH_KEY_LEN); 

    /*----------------------------------------------------------------*/
    /*----------------------------------------------------------------*/

    //~ generate x1
    if ( gen_x1(&p,x0,x0_len,&x1,&x1_len) == SKLOG_FAILURE ) {
        ERROR("gen_x1() failure")
        goto error;
    }
    SKLOG_free(&x0);

    //~ generate a random session key k1
    RAND_bytes(k1,SKLOG_SESSION_KEY_LEN);

    //~ sign x1 using T's private key
    if ( sign_message(x1,x1_len,t_ctx->t_privkey,
                      &x1_sign,&x1_sign_len) == SKLOG_FAILURE ) {
        ERROR("sign_message() failure")
        goto error;
    }

    //~ encrypt {x1,x1_sign} using k1 key
    if ( gen_e_k1(t_ctx,k1,x1,x1_len,x1_sign,x1_sign_len,
                  &e_k1,&e_k1_len) == SKLOG_FAILURE ) {
        ERROR("gen_e_k1() failure")
        goto error;
    }
    SKLOG_free(&x1_sign);
    SKLOG_free(&x1);

    //~ encrypt k1 using U's public key
    size_t pke_u_k1_len = 0;
    if ( pke_encrypt(u_cert,k1,SKLOG_SESSION_KEY_LEN,
                     &pke_u_k1,&pke_u_k1_len) == SKLOG_FAILURE ) {
        ERROR("pke_encrypt() failure")
        goto error;
    }
    X509_free(u_cert);
    memset(k1,0,SKLOG_SESSION_KEY_LEN);
    
    //~ generate m1
    if ( gen_m1(t_ctx,p,pke_u_k1,pke_u_k1_len,e_k1,
                e_k1_len,&m1_tmp,&m1_tmp_len) == SKLOG_FAILURE ) {
        ERROR("gen_m1() failure")
        goto error;
    }
    SKLOG_free(&e_k1);
    SKLOG_free(&pke_u_k1);

    *m1 = m1_tmp;
    *m1_len = m1_tmp_len;
    
    return SKLOG_SUCCESS;

error:
    if ( pke_t_k0 > 0 )    SKLOG_free(&pke_t_k0);
    if ( e_k0 > 0 )        SKLOG_free(&e_k0);
    if ( k0 > 0 )          SKLOG_free(&k0);
    if ( plain > 0 )       SKLOG_free(&plain);
    if ( x0 > 0 )          SKLOG_free(&x0);
    if ( x0_sign > 0 )     SKLOG_free(&x0_sign);
    if ( u_cert )      X509_free(u_cert);
    if ( x1 > 0 )          SKLOG_free(&x1);
    if ( x1_sign > 0 )     SKLOG_free(&x1_sign);
    if ( e_k1 > 0 )        SKLOG_free(&e_k1);
    if ( pke_u_k1 > 0 )    SKLOG_free(&pke_u_k1);

    return SKLOG_FAILURE;
}

SKLOG_RETURN
SKLOG_T_ManageLogfileUpload(SKLOG_T_Ctx         *t_ctx,
                            SKLOG_CONNECTION    *c)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char *tlv = 0;
    unsigned int len = 0;
    unsigned char *value = 0;

    unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int wlen = 0;
    
    unsigned char rbuf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int rlen = 0;

    int more = 1;
    int error = 0;

    SKLOG_TLV_TYPE type = 0;
    
    #ifdef DO_TESTS
    FILE *fp_in = 0;
    FILE *fp_out = 0;
    
    char in[SKLOG_BUFFER_LEN] = { 0 };
    int inl = 0;
    
    char *b64 = 0;
    unsigned char *b64dec = 0;
    #endif
    
    if ( t_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}

    SSL_load_error_strings();
    
    if ( tlv_create_message(LOGFILE_UPLOAD_READY,0,NULL,&tlv,&len) == SKLOG_FAILURE ) {
        ERROR("tlv_create_message() failure");
        goto error;
    }

    memcpy(wbuf,tlv,len);
    wlen = len;
    
    #ifdef DO_TRACE
    SHOWBUF("TOUT - LOGFILE_UPLOAD_READY", wbuf, wlen);
    #endif

#ifdef DO_TESTS
	
	if ( (fp_out = fopen("SKLOG_T_ManageLogfileUpload.out","a+")) != NULL ) {
		b64_enc(wbuf, wlen, &b64);
		fprintf(fp_out, "%s\n", b64);
		fclose(fp_out);
	}
	
#else
	
    #ifdef USE_BIO
    if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif

    #ifdef USE_SSL
    if ( SSL_write(c->ssl,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif
    
#endif /* DO_TESTS */

    memset(wbuf,0,SKLOG_BUFFER_LEN); wlen=0;

#ifdef DO_TESTS
	fp_in = fopen("SKLOG_T_ManageLogfileUpload.in","r");
#endif

    while ( more ) {

#ifdef DO_TESTS
		
		if ( fp_in != NULL ) {
			fscanf(fp_in, "%s", in);
			inl = strlen(in);
			b64_dec(in, inl, &b64dec, &rlen);
			memcpy(rbuf, b64dec, rlen);
			memset(in, 0, SKLOG_BUFFER_LEN);
		}
		
#else
        
        #ifdef USE_BIO
        if ( (rlen = BIO_read(c->bio,rbuf,SKLOG_BUFFER_LEN)) <= 0 ) {
                ERR_print_errors_fp(stderr);
                return SKLOG_FAILURE;
        }
        #endif
        #ifdef USE_SSL
        if ( (rlen = SSL_read(c->ssl,rbuf,SKLOG_BUFFER_LEN)) <= 0 ) {
                ERR_print_errors_fp(stderr);
                return SKLOG_FAILURE;
        }
        #endif
        
#endif /* DO_TESTS */

        if ( tlv_get_type(rbuf,&type) == SKLOG_FAILURE ) {
            ERROR("tlv_get_type() failure");
            goto error;
        }

        switch ( type ) {
            case UPLOAD_LOGENTRY:
				
				#ifdef DO_TRACE
		        SHOWBUF("TIN - UPLOAD_LOGENTRY",rbuf,rlen);
		        #endif
		        
                //~ NOTIFY("Received log entry");

                if ( tlv_parse_message(rbuf,NOTYPE,NULL,&len,&value) == SKLOG_FAILURE ) {
                    ERROR("tlv_parse_message() failure")
                    goto error;
                }

                if ( t_ctx->lsdriver->store_logentry(value,len) == SKLOG_FAILURE ) {
                    ERROR("t_ctx->lsdriver->store_logentry() failure");
                    goto error;
                }

                if ( tlv_create_message(UPLOAD_LOGENTRY_ACK,0,NULL,&tlv,&len) == SKLOG_FAILURE ) {
                    ERROR("tlv_create_message() failure");
                    goto error;
                }
                memcpy(wbuf,tlv,len); wlen = len;
                
                #ifdef DO_TRACE
		        SHOWBUF("TOUT - UPLOAD_LOGENTRY_ACK", wbuf, wlen);
		        #endif

			#ifdef DO_TESTS
				b64_enc(wbuf, wlen, &b64);
				fp_out = fopen("SKLOG_T_ManageLogfileUpload.out","a+");
				fprintf(fp_out, "%s\n", b64);
				fclose(fp_out);
				free(b64);
			#else
                #ifdef USE_BIO
                if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
                        ERR_print_errors_fp(stderr);
                        return SKLOG_FAILURE;
                }
                #endif
                #ifdef USE_SSL
                if ( SSL_write(c->ssl,wbuf,wlen) <= 0 ) {
                        ERR_print_errors_fp(stderr);
                        return SKLOG_FAILURE;
                }
                #endif
            #endif /* DO_TESTS */
                
                break;
            case LOGFILE_UPLOAD_END:
				#ifdef DO_TRACE
		        SHOWBUF("TIN - LOGFILE_UPLOAD_END", rbuf, rlen);
		        #endif
		        #ifdef DO_TRACE
                NOTIFY("Logfile Upload Terminated");
                #endif
                more = 0;
                break;
            default:
                ERROR("Protocol Error");
                error = 1;
                break;
        }

        if ( error ) 
            goto error;
    } //~ while
    
#ifdef DO_TESTS
	fclose(fp_in);
#endif
    
    ERR_free_strings();
    return SKLOG_SUCCESS;

error:
    ERR_free_strings();
    return SKLOG_FAILURE;
}

SKLOG_RETURN
SKLOG_T_ManageLogfileRetrieve(SKLOG_T_Ctx         *t_ctx,
                              SKLOG_CONNECTION    *c)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char *tlv = 0;
    unsigned char *value = 0;
    unsigned int len = 0;

    unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int wlen = 0;
    
    #ifdef DO_TESTS
    FILE *fp_out = 0;
	char *b64 = 0;
    #endif
    
    if ( t_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}

    t_ctx->lsdriver->retrieve_logfiles(&value,&len);

    if ( tlv_create_message(LOG_FILES,len,value,&tlv,&wlen) == SKLOG_FAILURE ) {
        ERROR("tlv_create_message() failure");
        return SKLOG_FAILURE;
    }
    memcpy(wbuf,tlv,wlen); free(tlv);
    
    #ifdef DO_TRACE
    SHOWBUF("TOUT - LOG_FILES",wbuf,wlen);
    #endif

#ifdef DO_TESTS
	b64_enc(wbuf,wlen,&b64);
	
	if ( (fp_out = fopen("SKLOG_T_ManageLogfileRetrieve.out", "w+")) != NULL ) {
		fprintf(fp_out, "%s", b64);
		fclose(fp_out);
	}
#else
    #ifdef USE_BIO
    if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif

    #ifdef USE_SSL
    if ( SSL_write(c->ssl,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif
#endif

    return SKLOG_SUCCESS;
}

SKLOG_RETURN
SKLOG_T_ManageLogfileVerify(SKLOG_T_Ctx         *t_ctx,
                            SKLOG_CONNECTION    *c,
                            char                *logfile_id)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int wlen = 0;

    unsigned char uuid[UUID_STR_LEN+1] = { 0 };

    unsigned char *tlv = 0;
    
    if ( t_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}
	
	if ( logfile_id == NULL ) {
		ERROR("argument 3 must be not NULL");
		return SKLOG_FAILURE;
	}

    memcpy(uuid,logfile_id,UUID_STR_LEN);

    if ( t_ctx->lsdriver->verify_logfile(uuid) == SKLOG_FAILURE ) {
        tlv_create_message(VERIFY_LOGFILE_FAILURE,0,NULL,&tlv,&wlen);
        memcpy(wbuf,tlv,wlen); free(tlv);
    } else {
        tlv_create_message(VERIFY_LOGFILE_SUCCESS,0,NULL,&tlv,&wlen);
        memcpy(wbuf,tlv,wlen); free(tlv);
    }

	#ifdef DO_TRACE
	SHOWBUF("TOUT - VERIFY_LOGFILE_(SUCCESS|FAILURE)", wbuf, wlen);
	#endif

    #ifdef USE_BIO
    if ( BIO_write(c->bio,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif

    #ifdef USE_SSL
    if ( SSL_write(c->ssl,wbuf,wlen) <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
    }
    #endif

    return SKLOG_SUCCESS;
}

void sigchld_h (int signum)
{
    pid_t pid;
    int status;
    char msg[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    while ( (pid = waitpid(-1,&status,WNOHANG)) > 0)
    
    sprintf(msg,"child %d terminated with status %d",pid,status);
    NOTIFY(msg);
}

SKLOG_RETURN
SKLOG_T_RunServer(SKLOG_T_Ctx    *t_ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SKLOG_CONNECTION *c = 0;
    int enable_verify = 0;

    unsigned char rbuf[SKLOG_BUFFER_LEN] = { 0 };
    int  rlen = 0;
    unsigned char wbuf[SKLOG_BUFFER_LEN] = { 0 };
    int  wlen = 0;

    int ret = 0;

    struct sockaddr_in    sa_cli;
    socklen_t             client_len = 0;

    pid_t pid = 0;

    char logfile_uuid[UUID_STR_LEN+1] = { 0 };

    uint32_t msg_type = 0;
    unsigned int len = 0;
    unsigned char *value = 0;

    unsigned char *m0 = 0;
    unsigned int  m0_len = 0;

    unsigned char *m1 = 0;
    unsigned int  m1_len = 0;

    char u_address[INET_ADDRSTRLEN] = { 0 };
    
    if ( t_ctx == NULL ) {
		ERROR("argument 1 must be not NULL");
		return SKLOG_FAILURE;
	}

    c = new_connection();

    //----------------------------------------------------------------//
    //             initialize SSL_CTX and SSL structures              //
    //----------------------------------------------------------------//
    
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    //~ create SSL_CTX structure
    c->ssl_ctx = SSL_CTX_new(SSLv3_method());

    //~ load server certificate
    ret = SSL_CTX_use_certificate(c->ssl_ctx,t_ctx->t_cert);

    if ( ret <= 0 ) {
        ERR_print_errors_fp(stderr);
        return SKLOG_FAILURE;
    }

    //~ load server private key
    ret = SSL_CTX_use_PrivateKey(c->ssl_ctx,t_ctx->t_privkey);

    if ( ret <= 0 ) {
        ERR_print_errors_fp(stderr);
        return SKLOG_FAILURE;
    }

    //~ check private key
    if ( SSL_CTX_check_private_key(c->ssl_ctx) <= 0 ) {
        ERR_print_errors_fp(stderr);
        return SKLOG_FAILURE;
    }

    if ( enable_verify ) {

        //~ load CA certificate
        ret = SSL_CTX_load_verify_locations(c->ssl_ctx,
                                            t_ctx->t_cert_file_path,
                                            NULL);
    
        if ( ret <= 0 ) {
            ERR_print_errors_fp(stderr);
            return SKLOG_FAILURE;
        }

        //~ set verification parameters
        SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_PEER,NULL);
        SSL_CTX_set_verify_depth(c->ssl_ctx, 1);
    }

    c->ssl = SSL_new(c->ssl_ctx);

    //~ create and bind lsock
    c->lsock = tcp_bind(t_ctx->t_address,t_ctx->t_port);

    if ( c->lsock < 0 ) {
        ERROR("tcp_bind() failure")
        return SKLOG_FAILURE;
    }
    
    //~ listen on the listen socket 
    if ( listen(c->lsock,5) < 0 ) {
        ERROR("listen() failure");
        return SKLOG_FAILURE;
    }

    //----------------------------------------------------------------//
    //                          SERVER WORK                           //
    //----------------------------------------------------------------//

    signal(SIGCHLD,sigchld_h);
    
    while ( 1 ) {
    
        //~ create csock
        c->csock = accept(c->lsock,(struct sockaddr*)&sa_cli,&client_len);

        pid = fork();

        if ( pid < 0 ) {
        //------------------------------------------------------------//
        //                        fork() error                        //
        //------------------------------------------------------------//
            
            ERROR("fork() fails")
            return SKLOG_FAILURE;
            
        } else if ( pid == 0 ) {
        //------------------------------------------------------------//
        //                       children process                     //
        //------------------------------------------------------------//

            //~ close lsock
            close(c->lsock);
            
            //~ setup BIO structure
            c->bio = BIO_new(BIO_s_socket());
            BIO_set_fd(c->bio,c->csock,BIO_NOCLOSE);
            SSL_set_bio(c->ssl,c->bio,c->bio);
        
            //~ SSL handshake (server side)
            ret = SSL_accept(c->ssl);
    
            //~ read from bio
            if ( (rlen = BIO_read(c->bio,rbuf,SKLOG_BUFFER_LEN-1)) <= 0 ) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
            
            //~ parse received data
            if ( tlv_get_type(rbuf,&msg_type) == SKLOG_FAILURE ) {
                ERROR("tlv_get_type() failure")
                goto failure;
            }

            switch ( msg_type ) {
                
                case M0_MSG:
                //----------------------------------------------------//
                //              initialize logging session            //
                //----------------------------------------------------//
                    #ifdef DO_TRACE
                    NOTIFY("received M0_MSG message");
                    SHOWBUF("TIN - M0_MSG", rbuf, rlen);
                    #endif

                    tlv_get_len(rbuf,&m0_len);
                    tlv_get_value(rbuf,&m0);

                    inet_ntop(AF_INET,&(sa_cli.sin_addr),u_address,INET_ADDRSTRLEN);

                    ret = SKLOG_T_ManageLoggingSessionInit(t_ctx,
                        m0,m0_len,u_address,&m1,&m1_len);

                    if ( ret == SKLOG_FAILURE ) {
                        ERROR("SKLOG_T_ManageLoggingSessionInit() failure");
                        goto failure;
                    }

                    memcpy(wbuf,m1,m1_len);
                    wlen = m1_len; free(m1);

                    if ( (ret = send_m1(t_ctx,c,wbuf,wlen) ) == SKLOG_FAILURE ) {
                        ERROR("send_m1() failure");
                        goto failure;
                    }
                    
                    break;
                    
                case LOGFILE_UPLOAD_REQ:
                //----------------------------------------------------//
                //                logfile upload request              //
                //----------------------------------------------------//
                    #ifdef DO_TRACE
                    NOTIFY("received LOGFILE_UPLOAD_REQ message");
                    SHOWBUF("TIN - LOGFILE_UPLOAD_REQ", rbuf, rlen);
                    #endif
                    
                    ret = SKLOG_T_ManageLogfileUpload(t_ctx,c);
                    
                    if ( ret == SKLOG_FAILURE ) {
                        ERROR("SKLOG_T_ManageLogfileUpload() failure");
                        goto failure;
                    }
                    
                    break;
                case RETR_LOG_FILES:
                //----------------------------------------------------//
                //             retrieve logfile list request          //
                //----------------------------------------------------//
                    #ifdef DO_TRACE
                    NOTIFY("received RETR_LOG_FILES message");
                    SHOWBUF("TIN - RETR_LOG_FILES", rbuf, rlen);
                    #endif

                    ret = SKLOG_T_ManageLogfileRetrieve(t_ctx,c);

                    if ( ret == SKLOG_FAILURE ) {
                        ERROR("SKLOG_T_ManageLogfileRetrieve() failure");
                        goto failure;
                    }

                    break;

                case VERIFY_LOGFILE:
                //----------------------------------------------------//
                //              logfile verification request          //
                //----------------------------------------------------//
                    #ifdef DO_TRACE
                    NOTIFY("received VERIFY_LOGFILE message");
                    SHOWBUF("TIN - VERIFY_LOGFILE", rbuf, rlen);
                    #endif
                    
                    tlv_get_len(rbuf,&len);
                    tlv_get_value(rbuf,&value);

                    memcpy(logfile_uuid,value,UUID_STR_LEN);
                    
                    
                    SKLOG_T_ManageLogfileVerify(t_ctx,c,logfile_uuid);
                    break;
                default:
                    NOTIFY("protocol error");
                    break;
            }
failure:
            destroy_ssl_connection(c);
            free_conenction(c);
            exit(0);
            
        } else {
        //------------------------------------------------------------//
        //                     parent process                         //
        //------------------------------------------------------------//

            NOTIFY("Server says: goodbye...");
            close(c->csock);

        }
    }

    destroy_ssl_connection(c);
    free_conenction(c);
    return SKLOG_SUCCESS;
}

/** to delete
SKLOG_RETURN
SKLOG_T_Run(SKLOG_T_Ctx    *t_ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SSL_CTX *ssl_ctx = 0;
    SSL *ssl = 0;

    int lskt = 0;
    int cskt = 0;

    pid_t pid = 0;
    int childcount = 0;

    //~ init SSL context
    ssl_ctx = init_ssl_ctx(t_ctx->t_cert_path,
                           t_ctx->t_priv_key_path,NULL,0);

    if ( ssl_ctx == NULL ) {
        ERROR("init_ssl_ctx() failure")
        return SKLOG_FAILURE;
    }

    //~ create and bind the listen socket
    lskt = tcp_bind(t_ctx->t_address,t_ctx->t_port);

    if ( lskt < 0 ) {
        ERROR("tcp_bind() failure")
        return SKLOG_FAILURE;
    }

    //~ listen on the listen socket 
    if ( listen(lskt,5) < 0 ) {
        ERROR("listen() failure");
        return SKLOG_FAILURE;
    }

    while ( 1 ) {
        
        //~ accept new connection
        struct sockaddr_in cli_addr;
        char cli_ip[INET_ADDRSTRLEN] = { 0 };
        
        socklen_t cli_addr_len = 0;
        
        cli_addr_len = sizeof(cli_addr);
        if ( (cskt = accept(lskt,(struct sockaddr *)&cli_addr,
                            &cli_addr_len)) < 0 ) {
            ERROR("accept() failure");
            return SKLOG_FAILURE;
        }

        pid = fork();

        if ( pid < 0 ) {
            ERROR("fork() failure")
            return SKLOG_FAILURE;
        } else if ( pid == 0 ) { //~ children process

            if ( inet_ntop(AF_INET,&(cli_addr.sin_addr),
                           cli_ip,INET_ADDRSTRLEN) == NULL ) {
                close(lskt);
                ERROR("inet_ntop() failure");
                return SKLOG_FAILURE;
            }

            close(lskt);

            //~ init SSL structure
            //~ ssl = init_ssl_structure_s(ssl_ctx,cskt,1);
            ssl = SSL_new(ssl_ctx);

            if ( ssl == NULL ) {
                close(cskt);
                ERROR("init_ssl_structure() failure");
                return SKLOG_FAILURE;
            } 

            //~ --------------------------------------------------------
            //~ do something
            unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
            unsigned int nread = 0;

            unsigned char *m0 = 0;
            unsigned int m0_len = 0;

            SKLOG_RETURN retval = SKLOG_SUCCESS;

            nread = SSL_read(ssl,buffer,SKLOG_BUFFER_LEN);

            if ( nread < 0 ) {
                SSL_shutdown(ssl);
                close(cskt);
                SSL_free(ssl);
                SSL_CTX_free(ssl_ctx);
                ERROR("SSL_read() failure")
                return SKLOG_FAILURE;
            }

            SKLOG_TLV_TYPE type = 0;

            if ( tlv_get_type(buffer,&type) == SKLOG_FAILURE ) {
                ERROR("tlv_get_type() failure")
                goto failure;
            }

            switch ( type ) {
                case M0_MSG:
                    NOTIFY("received m0 message")
                    
                    m0_len =  nread;
                    //~ SKLOG_CALLOC(m0,m0_len,char);
                    if ( SKLOG_alloc(&m0,unsigned char,m0_len) == SKLOG_FAILURE ) {
                        ERROR("SKLOG_alloc() failure");
                        retval = SKLOG_FAILURE;
                    }
                    memcpy(m0,buffer,m0_len);
                    if ( manage_logsession_init(t_ctx,m0,m0_len,ssl,cli_ip)
                            == SKLOG_FAILURE ) {
                        ERROR("logging session initialization fails")
                        retval = SKLOG_FAILURE;
                    }
                    break;
                case LE_FLUSH_START:
                    manage_logfile_flush(t_ctx,ssl);
                    break;
                default:
                    NOTIFY("received unexpected message")
                    break;
            } 
            //~ --------------------------------------------------------
failure:
            SSL_shutdown(ssl);
            close(cskt);
            SSL_free(ssl);
            SSL_CTX_free(ssl_ctx);
            return retval;

        } else { //~ parent process
            
            while ( childcount ) {
                pid = waitpid((pid_t)-1,NULL,WNOHANG);
                if ( pid < 0 ) {
                    ERROR("waitpid() failure")
                } else if ( pid == 0 ) {
                    break;
                } else {
                    childcount--;
                }
            }
        }
    }

    close(lskt);
    
    return SKLOG_SUCCESS; 
}
*/

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/*                            CLIENT                                  */
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
