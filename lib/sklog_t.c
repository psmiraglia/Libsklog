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
#ifdef USE_SQLITE
    #include "storage/sklog_sqlite.h"
#else
    #include "storage/sklog_file.h"
#endif

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

    /*
     * Create an SSL_METHOD structure
     * (chose an SSL/TLS protocol version)
     */

    meth = SSLv3_method();
    ctx = SSL_CTX_new(meth);
    
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    /* Load the server certificate into the SSL_CTX structure */

    retval = SSL_CTX_use_certificate_file(ctx, rsa_cert,
                                          SSL_FILETYPE_PEM);

    if ( retval <= 0 ) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    /* Load the private-key corresponding to the server certificate */

    retval = SSL_CTX_use_PrivateKey_file(ctx,rsa_privkey,
                                         SSL_FILETYPE_PEM);

    if ( retval <= 0 ) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    /* Check if the server certificate and private-key matches */
    if ( !SSL_CTX_check_private_key(ctx) ) {
        fprintf(stderr,
            "Private key does not match the certificate public key\n");
        return NULL;
    }

    if( verify == 1 && ca_cert != NULL ) {
    
        /* Load the RSA CA certificate into the SSL_CTX structure */
        if ( !SSL_CTX_load_verify_locations(ctx,ca_cert, NULL) ) {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        
        /* Set to require peer (client) certificate verification */
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
        
        /* Set the verification depth to 1 */
        SSL_CTX_set_verify_depth(ctx,1);
    }

    return ctx;
}

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
    
    /* Assign the socket into the SSL structure
     * (SSL and socket without BIO)
     */

    SSL_set_fd(ssl, socket);
    
    /* Perform SSL Handshake on the SSL server */
    if ( SSL_accept(ssl) < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    if ( verify == 1 ) {

        /* Get the client's certificate (optional) */
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
    
    /* Set up a TCP socket */

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

/*--------------------------------------------------------------------*/
/* logging session initialization                                     */
/*--------------------------------------------------------------------*/

// todo: to implement
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

    TO_IMPLEMENT

    *t_cert = SKLOG_DEF_T_CERT_PATH;
    *t_privkey = SKLOG_DEF_T_RSA_KEY_PATH;
    *t_privkey_passphrase = SKLOG_DEF_T_RSA_KEY_PASSPHRASE;
    *t_id = SKLOG_DEF_T_ID;
    *t_address = SKLOG_DEF_T_ADDRESS;
    *t_port = SKLOG_DEF_T_PORT;

    return SKLOG_TO_IMPLEMENT;
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

// todo: to implement
static SKLOG_RETURN
verify_m0(void)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

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
    unsigned char buffer[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;
    
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

    //~ compose x1

    *x1_len = (sizeof(p_net) + 8) +
              SHA256_LEN + 8;

    if ( SKLOG_alloc(x1,unsigned char,*x1_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }

    //~ TLV-ize protocol step
    tlv_create(PROTOCOL_STEP,sizeof(p_net),&p_net,buffer);
    memcpy(&x0[ds],buffer,sizeof(p_net)+8);

    ds += (sizeof(p_net) + 8);
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);

    //~ TLV-ize protocol step
    tlv_create(HASH_X0,SHA256_LEN,x0_md,buffer);
    memcpy(&x0[ds],buffer,SHA256_LEN+8);

    ds += (SHA256_LEN + 8);
    memset(buffer,0,SKLOG_SMALL_BUFFER_LEN);

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

    unsigned char *buffer2 = 0;
    unsigned int buffer2_len = x1_len + 8 +
                               x1_sign_len + 8;

    if ( SKLOG_alloc(&buffer2,unsigned char,buffer2_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }

    ds = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize x1
    tlv_create(X1_BUF,x1_len,x1,buffer);
    memcpy(&buffer2[ds],buffer,x1_len+8);

    ds += (x1_len + 8);
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize x1_signature
    tlv_create(X1_SIGN_T,x1_sign_len,x1_sign,buffer);
    memcpy(&buffer2[ds],buffer,x1_sign_len+8);

    if ( aes256_encrypt(buffer2,buffer2_len,k1,SKLOG_SESSION_KEY_LEN,
                        e_k1,e_k1_len) == SKLOG_FAILURE ) {
        free(buffer2);
        ERROR("encrypt_aes256() failure")
        return SKLOG_FAILURE;
    }

    SKLOG_free(&buffer2);
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

    //~ convert p in network order
    uint32_t p_net = htonl(p);

    //~ compose m1 in tlv format
    *m1_len = (sizeof(p_net) + 8) +
              (t_ctx->t_id_len + 8) +
              (pke_u_k1_len + 8) +
              (e_k1_len + 8);

    if ( SKLOG_alloc(m1,unsigned char,*m1_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        return SKLOG_FAILURE;
    }

    //~ TLV-ize p
    tlv_create(PROTOCOL_STEP,sizeof(p_net),&p_net,buffer);
    memcpy(*m1+ds,buffer,sizeof(p_net)+8);

    ds += sizeof(p_net)+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize t_id
    tlv_create(ID_T,t_ctx->t_id_len,t_ctx->t_id,buffer);
    memcpy(*m1+ds,buffer,t_ctx->t_id_len+8);

    ds += t_ctx->t_id_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize pke_u_k1
    tlv_create(PKE_PUB_U,pke_u_k1_len,pke_u_k1,buffer);
    memcpy(*m1+ds,buffer,pke_u_k1_len+8);

    ds += pke_u_k1_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize e_k1
    tlv_create(ENC_K1,e_k1_len,e_k1,buffer);
    memcpy(*m1+ds,buffer,e_k1_len+8);

    ds += e_k1_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    return SKLOG_SUCCESS;
}

static SKLOG_RETURN
send_m1(SKLOG_T_Ctx      *t_ctx,
        SSL              *ssl,
        unsigned char    *m1,
        unsigned int     m1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    int nwrite = 0;

    tlv_create(M1_MSG,m1_len,m1,buffer);

    nwrite = SSL_write(ssl,buffer,m1_len+8);

    if ( nwrite < 0 ) {
        ERROR("SSL_write() failure")
        return SKLOG_FAILURE;
    } 

    return SKLOG_SUCCESS;
}

/*--------------------------------------------------------------------*/
/* interactions with U nodes                                          */
/*--------------------------------------------------------------------*/

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
        goto error;
    }
    k0_len = len;
    SKLOG_free(&pke_t_k0);

    if ( aes256_decrypt(e_k0,e_k0_len,k0,SKLOG_SESSION_KEY_LEN,&plain,
                        &plain_len) == SKLOG_FAILURE ) {
        ERROR("decrypt_aes256() failure")
        goto error;
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

    //~ store auth_key
    if ( t_ctx->lsdriver->store_authkey(u_ip,logfile_id,auth_key) == SKLOG_FAILURE ) {
        ERROR("store_auth_key() failure")
        goto error;
    }
    
    //~ remove auth_key from memory
    memset(auth_key,0,SKLOG_AUTH_KEY_LEN); 
    
    //~ verify m0:
    if ( verify_m0() == SKLOG_FAILURE ) {
        ERROR("verify_m0() failure")
        goto error;
    }
    SKLOG_free(&x0_sign);

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

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
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

    #ifdef USE_SQLITE
    ctx->lsdriver->store_authkey =     &sklog_sqlite_t_store_authkey;
    ctx->lsdriver->store_logentry =    &sklog_sqlite_t_store_logentry;
    #else
    ctx->lsdriver->store_authkey =     &sklog_file_t_store_authkey;
    ctx->lsdriver->store_logentry =    &sklog_file_t_store_logentry;
    #endif

    return ctx;
}

SKLOG_RETURN
SKLOG_T_FreeCtx(SKLOG_T_Ctx **ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    X509_free((*ctx)->t_cert);
    EVP_PKEY_free((*ctx)->t_priv_key);

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
    snprintf(t_ctx->t_id,strlen(t_id),t_id);

    //~ load T's X509 certificate
    t_ctx->t_cert = 0;
    t_ctx->t_cert_size = 0;
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

    t_ctx->t_cert_path = t_cert;
    t_ctx->t_priv_key_path = t_privkey;
    t_ctx->t_address = t_address;
    t_ctx->t_port = t_port;
    
    //~ load T's rsa privkey
    t_ctx->t_priv_key = EVP_PKEY_new();
    if ( (fp = fopen(t_privkey,"r")) != NULL ) {
        if ( !PEM_read_PrivateKey(fp,&t_ctx->t_priv_key,
                                  NULL,t_privkey_passphrase) ) {
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
                           t_ctx->t_priv_key_path,0,NULL);

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
            ssl = init_ssl_structure(ssl_ctx,cskt,1);

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
