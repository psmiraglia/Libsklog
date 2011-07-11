#include "sklog_internal.h"
#include "sklog_u.h"

#include <confuse.h>
#include <sqlite3.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include <openssl/ssl.h>
#include <arpa/inet.h>

/*--------------------------------------------------------------------*/
/* connection                                                         */
/*--------------------------------------------------------------------*/

static SSL_CTX*
init_ssl_ctx(SKLOG_U_Ctx    *u_ctx,
             int            verify)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    SSL_CTX *ctx = 0;
    const SSL_METHOD *meth = 0;
    
    SSL_library_init();
    SSL_load_error_strings();
    
    /*
     * Create an SSL_METHOD structure 
     * (choose an SSL/TLS protocol version) 
     */
    meth = SSLv3_method();
    
    /* Create an SSL_CTX structure */
    if ( (ctx = SSL_CTX_new(meth)) == NULL ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    if ( verify == 1 ) {

        /* Load the client certificate into the SSL_CTX structure */
        if ( SSL_CTX_use_certificate(ctx,u_ctx->u_cert) <= 0 ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        
        /*
         * Load the private-key corresponding
         * to the client certificate
         */
        if ( SSL_CTX_use_PrivateKey(ctx,u_ctx->u_privkey) <= 0 ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }
        
        /* Check if the client certificate and private-key matches */
        if ( !SSL_CTX_check_private_key(ctx) ) {
            ERROR("Private key does not match the certificate public key");
            goto error;
        }
    }
    
    /*
     * Load the RSA CA certificate into the SSL_CTX structure This will
     * allow this client to verify the server's certificate.
     */
    
    if ( !SSL_CTX_load_verify_locations(ctx,u_ctx->t_cert_path,NULL) ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }
    
    /*
     * Set flag in context to require peer (server) certificate
     * verification
     */
    
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    SSL_CTX_set_verify_depth(ctx,1);

    return ctx;

error:
    if ( ctx ) SSL_CTX_free(ctx);
    return NULL;
}

static int
tcp_connect(const char *address, short int port)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    int skt = 0;
    struct sockaddr_in server_addr;

    skt = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);

    if ( skt < 0 ) {
        ERROR("socket() failure")
        return -1;
    }
    
    memset (&server_addr,0,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);       /* Server Port number */
    server_addr.sin_addr.s_addr = inet_addr(address); /* Server IP */
    
    /* Establish a TCP/IP connection to the SSL client */
    
    if ( connect(skt, (struct sockaddr*) &server_addr,
                 sizeof(server_addr)) < 0 ) {
        ERROR("connect() failure")
        return -1;
    }
    
    return skt;
}


static SSL*
init_ssl_structure(SSL_CTX *ctx,int socket)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    SSL *ssl = 0;

    if ( (ssl = SSL_new(ctx)) == NULL ) {
        ERROR("SSL_new() failure")
        goto error;
    }
    
    /* Assign the socket into the SSL structure
     * (SSL and socket without BIO)
     */
    SSL_set_fd(ssl,socket);
    
    /* Perform SSL Handshake on the SSL client */
    if ( SSL_connect(ssl) < 0 ) {
        ERROR("SSL_connect() failure")
        goto error;
    }

    #ifdef HAVE_NOTIFY

    char *str = 0;
    X509 *server_cert = 0;

    /* Get the server's certificate (optional) */
    server_cert = SSL_get_peer_certificate (ssl);    
    
    if ( server_cert != NULL ) {

        fprintf(stderr,"Server certificate:\n");
        
        str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
        if ( str != NULL ) { 
            fprintf (stderr,"\t subject: %s\n", str);
            free (str);
        }

        str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
        if ( str != NULL ) {
            fprintf (stderr,"\t issuer: %s\n", str);
            free(str);
        }
        
        X509_free (server_cert);
    } else {
        fprintf(stderr,"The SSL server does not have certificate.\n");
    }

    #endif

    return ssl;
    
error:
    if ( ssl ) SSL_free(ssl);
    return NULL;
}

static SKLOG_RETURN
conn_open(SKLOG_U_Ctx         *u_ctx,
          SKLOG_CONNECTION    *conn)
{
    SSL_load_error_strings();

    conn->ssl_ctx = init_ssl_ctx(u_ctx,1);

    if ( conn->ssl_ctx == NULL ) {
        ERROR("init_ssl_ctx() failure")
        return SKLOG_FAILURE;
    }

    conn->socket = tcp_connect(u_ctx->t_address,u_ctx->t_port);

    if ( conn->socket < 0 ) {
        ERROR("tcp_connect() failure")
        return SKLOG_FAILURE;
    }

    conn->ssl = init_ssl_structure(conn->ssl_ctx,conn->socket);

    if ( conn->ssl == NULL ) {
        ERROR("init_ssl_structure() failure")
        return SKLOG_FAILURE;
    }

    return SKLOG_SUCCESS;
}

static SKLOG_RETURN
conn_close(SKLOG_CONNECTION    *conn)
{
    SSL_shutdown(conn->ssl);
    close(conn->socket);
    SSL_free(conn->ssl);
    SSL_CTX_free(conn->ssl_ctx);

    return SKLOG_SUCCESS;
}

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

    unsigned char *buffer = 0;
    unsigned int buflen = 0;
    unsigned int pos = 0;

    buflen = sizeof(type) + SKLOG_AUTH_KEY_LEN;
    SKLOG_CALLOC(buffer,buflen,char)

    memcpy(&buffer[pos],&type,sizeof(type));
    pos+=sizeof(type);
    memcpy(&buffer[pos],ctx->auth_key,SKLOG_AUTH_KEY_LEN);

    //~ calculate SHA256 message digest
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);
    EVP_DigestUpdate(&mdctx,buffer,buflen);
    EVP_DigestFinal_ex(&mdctx,enc_key,&buflen);
    EVP_MD_CTX_cleanup(&mdctx);

    free(buffer);

    return SKLOG_SUCCESS;
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

    unsigned char *buffer = 0;
    unsigned int buflen = 0;
    unsigned int pos = 0;

    buflen = sizeof(type) + data_enc_size + SKLOG_HASH_CHAIN_LEN;
    SKLOG_CALLOC(buffer,buflen,char)

    memcpy(&buffer[pos],ctx->last_hash_chain,SKLOG_HASH_CHAIN_LEN);
    pos+=SKLOG_HASH_CHAIN_LEN;
    memcpy(&buffer[pos],data_enc,data_enc_size);
    pos+=data_enc_size;
    memcpy(&buffer[pos],&type,sizeof(type));

    //~ calculate SHA256 message digest
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);
    EVP_DigestUpdate(&mdctx,buffer,buflen);
    EVP_DigestFinal_ex(&mdctx,hash_chain,&buflen);
    EVP_MD_CTX_cleanup(&mdctx);

    //~ save hash chain for the next generation
    memcpy(ctx->last_hash_chain,hash_chain,SKLOG_HASH_CHAIN_LEN);

    free(buffer);

    return SKLOG_SUCCESS;
}

static SKLOG_RETURN
gen_hmac(SKLOG_U_Ctx      *ctx,
         unsigned char    *hmac,
         unsigned char    *hash_chain)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned int hmac_len = 0;

    //~ calculate HMAC using SHA256 message digest
    HMAC_CTX mdctx;
    HMAC_CTX_init(&mdctx);
    HMAC_Init_ex(&mdctx,ctx->auth_key,SKLOG_AUTH_KEY_LEN,
                 EVP_sha256(),NULL);
    HMAC_Update(&mdctx,hash_chain,SKLOG_HASH_CHAIN_LEN);
    HMAC_Final(&mdctx,hmac,&hmac_len);
    HMAC_CTX_cleanup(&mdctx);

    return SKLOG_SUCCESS;
}

static SKLOG_RETURN
renew_auth_key(SKLOG_U_Ctx    *ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char *buffer = 0;
    unsigned int buflen = 0;

    SKLOG_CALLOC(buffer,SKLOG_AUTH_KEY_LEN,char)
    memcpy(buffer,ctx->auth_key,SKLOG_AUTH_KEY_LEN);

    //~ calculate SHA256 message digest
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);
    EVP_DigestUpdate(&mdctx,buffer,SKLOG_AUTH_KEY_LEN);
    EVP_DigestFinal_ex(&mdctx,ctx->auth_key,&buflen);
    EVP_MD_CTX_cleanup(&mdctx);

    free(buffer);

    return SKLOG_SUCCESS;
}

static int
sql_callback(void    *NotUsed,
             int     argc,
             char    **argv,
             char    **azColName)
{
    int i = 0;
    for ( i = 0 ; i < argc ; i++ )
        fprintf(stderr,
            "%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    fprintf(stderr,"\n");
    return 0;
}

static SKLOG_RETURN
store_logentry(SKLOG_DATA_TYPE    type,
               unsigned char      *data_enc,
               unsigned int       data_enc_len,
               unsigned char      *hash_chain,
               unsigned char      *hmac)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    //~ TODO: store auth_key not in plaintext

    sqlite3 *db = 0;
    char *err_msg = 0;

    char buffer[4096] = { 0 };
    int i = 0;
    int j = 0;

    char buf_type[9] = { 0 };
    sprintf(buf_type,"%8.8x",htonl(type));

    char *buf_data = 0;
    buf_data = calloc(1+(data_enc_len*2),sizeof(char)); 
    for ( i = 0 , j = 0 ; i < data_enc_len ; i++ , j += 2)
        sprintf(buf_data+j,"%2.2x",data_enc[i]);

    char buf_hash[1+(SKLOG_HASH_CHAIN_LEN*2)] = { 0 };
    for ( i = 0 , j = 0 ; i < SKLOG_HASH_CHAIN_LEN ; i++ , j += 2)
        sprintf(buf_hash+j,"%2.2x",hash_chain[i]);

    char buf_hmac[1+(SKLOG_HMAC_LEN*2)] = { 0 };
    for ( i = 0 , j = 0 ; i < SKLOG_HMAC_LEN ; i++ , j += 2)
        sprintf(buf_hmac+j,"%2.2x",hmac[i]);

    sqlite3_open(SKLOG_U_DB,&db);
    
    if ( db == NULL ) {
        fprintf(stderr,
            "SQLite3: Can't open database: %s\n",sqlite3_errmsg(db));
        goto error;
    }

    sprintf(buffer,"insert into LOG_ENTRY values ('%s','%s','%s','%s')",
                   buf_type,buf_data,buf_hash,buf_hmac);

    if ( sqlite3_exec(db,buffer,sql_callback,0,
                      &err_msg) != SQLITE_OK ) {
        fprintf(stderr, "SQLite3: SQL error: %s\n",err_msg);
        goto error;
    }

    sqlite3_close(db);

    return SKLOG_SUCCESS;

error:
    if ( db ) sqlite3_close(db);
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

    if ( u_ctx == NULL ) {
        ERROR("argument 1 must be not null")
        goto error;
    }
    
    if ( data == NULL )
        WARNING("Data to log is NULL. It's all ok?")

    //~ generate encryption key
    unsigned char enc_key[SKLOG_ENC_KEY_LEN] = {0};

    if ( gen_enc_key(u_ctx,enc_key,type) == SKLOG_FAILURE ) {
        ERROR("gen_enc_key() failure")
        goto error;
    }

    //~ encrypt data using the generated encryption key
    unsigned char *data_enc = 0;
    unsigned int data_enc_len = 0;

    if ( encrypt_aes256(&data_enc,&data_enc_len,
                        data,data_len,enc_key) == SKLOG_FAILURE ) {
        ERROR("encrypt_aes256() failure")
        goto error;
    }

    //~ generate hash-chain element
    unsigned char hash_chain[SKLOG_HASH_CHAIN_LEN] = {0};

    if ( gen_hash_chain(u_ctx,hash_chain,data_enc,
                        data_enc_len,type) == SKLOG_FAILURE ) {
        ERROR("gen_hash_chain() failure")
        goto error;
    }

    //~ generate digest of hash-chain using the auth_key A
    unsigned char hmac[SKLOG_HMAC_LEN] = {0};

    if ( gen_hmac(u_ctx,hmac,hash_chain) == SKLOG_FAILURE ) {
        ERROR("gen_hmac() failure")
        goto error;
    }

    //~ re-generate auth_key
    if ( renew_auth_key(u_ctx) == SKLOG_FAILURE ) {
        ERROR("renew_auth_key() failure")
        goto error;
    }

    //~ save log entry to database
    if ( store_logentry(type,data_enc,data_enc_len,
                        hash_chain,hmac) == SKLOG_FAILURE ) {
        ERROR("store_logentry() failure")
        goto error;
    }

    //~ increase logentry counter
    u_ctx->logfile_counter += 1;

    return SKLOG_SUCCESS;

error:
    if ( data_enc != 0 ) free(data_enc);
    return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/* logging session initialization                                     */
/*--------------------------------------------------------------------*/

static SKLOG_RETURN
parse_config_file(char            *t_cert,
                  char            *t_address,
                  int             *t_port,
                  char            *u_cert,
                  char            *u_id,
                  char            *u_privkey,
                  unsigned int    *u_timeout,
                  unsigned int    *logfile_size)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    cfg_opt_t opts[] = {
        CFG_STR("t_cert",SKLOG_DEF_T_CERT_PATH,CFGF_NONE),
        CFG_STR("t_address",NULL,CFGF_NONE),
        CFG_INT("t_port",0,CFGF_NONE),
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
    sprintf(t_cert,"%s",cfg_getstr(cfg,"t_cert"));

    //~ load t_address
    sprintf(t_address,"%s",cfg_getstr(cfg,"t_address"));

    //~ load t_port
    *t_port = cfg_getint(cfg,"t_port");

    //~ load u_cert
    sprintf(u_cert,"%s",cfg_getstr(cfg,"u_cert"));

    //~ load u_id
    sprintf(u_id,"%s",cfg_getstr(cfg,"u_id"));

    //~ load u_privkey
    sprintf(u_privkey,"%s",cfg_getstr(cfg,"u_privkey"));

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

    //~ serialize timestamp (d)
    unsigned char *dbuf = 0;
    unsigned int dbuf_len = 0;
    serialize_timeval(d,&dbuf,&dbuf_len);

    //~ serialize U's x509 certificate
    unsigned char *cert = 0;
    unsigned char *cert_tmp = 0;
    unsigned int  cert_size = 0;

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

    //~ compose X0 in tlv form

    *x0_len = (sizeof(p_net) + 8) +
              (dbuf_len + 8) +
              //~ ((u_ctx->u_cert_size) + 8) +
              (cert_size + 8) +
              (SKLOG_AUTH_KEY_LEN + 8);

    SKLOG_CALLOC(*x0,*x0_len,char)

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
    free(dbuf);

    //~ TLV-ize DER encoded C's certificate
    //~ tlv_create(CERT_U,u_ctx->u_cert_size,cert,buffer);
    tlv_create(CERT_U,cert_size,cert,buffer);
    //~ memcpy(*x0+ds,buffer,u_ctx->u_cert_size+8);
    memcpy(*x0+ds,buffer,cert_size+8);

    ds += (cert_size + 8);
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize auth_key
    tlv_create(A0_KEY,SKLOG_AUTH_KEY_LEN,u_ctx->auth_key,buffer);
    memcpy(*x0+ds,buffer,SKLOG_AUTH_KEY_LEN+8);

    OPENSSL_free(cert);
    ERR_free_strings();
    
    return SKLOG_SUCCESS;

error:
    if ( dbuf ) free(dbuf);
    if ( cert ) OPENSSL_free(cert);
    if ( *x0 ) free(*x0);
    ERR_free_strings();
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
gen_e_k0(SKLOG_U_Ctx *u_ctx,
         unsigned char *X0,
         unsigned int X0_len,
         unsigned char *X0_sign,
         unsigned int X0_sign_len,
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
    unsigned int buffer2_len = X0_len + 8 +
                               X0_sign_len + 8;

    SKLOG_CALLOC(buffer2,buffer2_len,char)

    ds = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize x0
    if ( tlv_create(X0_BUF,X0_len,X0,buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(&buffer2[ds],buffer,X0_len+8);

    ds += (X0_len + 8);
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize x0_signature
    if ( tlv_create(X0_SIGN_U,X0_sign_len,
                    X0_sign,buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(&buffer2[ds],buffer,X0_sign_len+8);

    if ( encrypt_aes256(e_k0,e_k0_len,buffer2,buffer2_len,
                        u_ctx->session_key) == SKLOG_FAILURE ) {
        ERROR("encrypt_aes256() failure")
        goto error;
    }
    free(buffer2);

    return SKLOG_SUCCESS;

error:
    if ( buffer2 ) free(buffer2);
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
gen_m0(SKLOG_U_Ctx *u_ctx,
       SKLOG_PROTOCOL_STEP p,
       unsigned char *pke_t_k0,
       unsigned int pke_t_k0_len,
       unsigned char *e_k0,
       unsigned int e_k0_len,
       unsigned char **M0,
       unsigned int *M0_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;

    //~ convert p in network order
    uint32_t p_net = htonl(p);

    //~ compose M0 in tlv format
    *M0_len = (sizeof(p_net) + 8) +
              (u_ctx->u_id_len + 8) +
              (pke_t_k0_len + 8) +
              (e_k0_len + 8);

    SKLOG_CALLOC(*M0,*M0_len,char)

    //~ TLV-ize p
    if ( tlv_create(PROTOCOL_STEP,sizeof(p_net),&p_net,\
                    buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(*M0+ds,buffer,sizeof(p_net)+8);

    ds += sizeof(p_net)+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize u_id
    if ( tlv_create(ID_U,u_ctx->u_id_len,u_ctx->u_id,
                    buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(*M0+ds,buffer,u_ctx->u_id_len+8);

    ds += u_ctx->u_id_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize pke_t_k0
    if ( tlv_create(PKE_PUB_T,pke_t_k0_len,pke_t_k0,
                    buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(*M0+ds,buffer,pke_t_k0_len+8);

    ds += pke_t_k0_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize e_k0
    if ( tlv_create(ENC_K0,e_k0_len,e_k0,buffer) == SKLOG_FAILURE )
        goto error;
    memcpy(*M0+ds,buffer,e_k0_len+8);

    ds += e_k0_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    return SKLOG_SUCCESS;

error:
    if ( *M0 ) free(*M0);
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
gen_d0(SKLOG_U_Ctx *u_ctx,
       struct timeval *d,
       struct timeval *d_timeout,
       unsigned char *M0,
       unsigned int M0_len,
       unsigned char **D0,
       unsigned int *D0_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    if ( M0 == NULL ) {
        ERROR("m0 must be NOT NULL")
        return SKLOG_FAILURE;
    }

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int ds = 0;

    //~
    //~ compose D0
    //~

    //~ serialize timestamp (d)
    unsigned char *dbuf = 0;
    unsigned int dbuf_len = 0;
    serialize_timeval(d,&dbuf,&dbuf_len);

    //~ serialize timestamp (d_timeout)
    unsigned char *dbuf2 = 0;
    unsigned int dbuf2_len = 0;

    if ( serialize_timeval(d_timeout,&dbuf2,
                           &dbuf2_len) == SKLOG_FAILURE)
        goto error;

    *D0_len = (dbuf_len + 8) +
              (dbuf2_len + 8) +
              (SKLOG_LOG_ID_LEN + 8) +
              (M0_len + 8);

    SKLOG_CALLOC(*D0,*D0_len,char)

    //~ TLV-ize d
    if ( tlv_create(TIMESTAMP,dbuf_len,dbuf,buffer) == SKLOG_FAILURE)
        goto error;
    memcpy(*D0+ds,buffer,dbuf_len+8);

    ds += dbuf_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);
    free(dbuf);

    //~ TLV-ize d_timeout
    if ( tlv_create(TIMESTAMP,dbuf2_len,dbuf2,buffer) == SKLOG_FAILURE)
        goto error;
    memcpy(*D0+ds,buffer,dbuf2_len+8);

    ds += dbuf2_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);
    free(dbuf2);

    //~ TLV-ize log_id
    if ( tlv_create(ID_LOG,SKLOG_LOG_ID_LEN,&u_ctx->logfile_id,
                    buffer) == SKLOG_FAILURE)
        goto error;
    memcpy(*D0+ds,buffer,SKLOG_LOG_ID_LEN+8);

    ds += SKLOG_LOG_ID_LEN+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    //~ TLV-ize M0
    if ( tlv_create(M0_MSG,M0_len,M0,buffer) == SKLOG_FAILURE)
        goto error;
    memcpy(*D0+ds,buffer,M0_len+8);

    ds += M0_len+8;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    return SKLOG_SUCCESS;

error:
    if ( dbuf ) free(dbuf); 
    if ( dbuf2 ) free(dbuf2); 
    if ( *D0 ) free(*D0);
    return SKLOG_FAILURE; 
}

static SKLOG_RETURN
send_m0(SKLOG_U_Ctx *u_ctx,
        //~ void *zmq_requester,
        SSL *ssl,
        unsigned char *M0,
        unsigned int M0_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    SSL_load_error_strings();

    unsigned char buffer[SKLOG_BUFFER_LEN] = { 0 };
    int nwrite = 0;

    if ( tlv_create(M0_MSG,M0_len,M0,buffer) == SKLOG_FAILURE )
        goto error;

    nwrite = SSL_write(ssl,buffer,M0_len+8);

    if ( nwrite < 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    } 
    
    return SKLOG_SUCCESS;

error:
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
receive_m1(SSL *ssl,
           unsigned char **M1,
           unsigned int *M1_len)
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
    if ( tlv_parse(buf1,M1_MSG,buf2,M1_len) == SKLOG_FAILURE ) {
        ERROR("Message is bad structured: expected M1_MSG");
        goto error;
    }

    SKLOG_CALLOC(*M1,*M1_len,char)
    memcpy(*M1,buf2,*M1_len);

    return SKLOG_SUCCESS;

error:
    if ( *M1 ) free(*M1); 
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
parse_m1(unsigned char    *M1,
         unsigned int     M1_len,
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

    if ( tlv_parse(&M1[ds],PROTOCOL_STEP,p,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected PROTOCOLO_STEP");
        goto error;
    }

    ds += len+8;
    len = 0;

    if ( tlv_parse(&M1[ds],ID_T,t_id,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected ID_T");
        goto error;
    }

    ds += len+8;
    len = 0;

    if ( tlv_parse(&M1[ds],PKE_PUB_U,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected PKE_PUB_U");
        goto error;
    }

    SKLOG_CALLOC(*pke_u_k1,len,char)
    memcpy(*pke_u_k1,buffer,len);
    *pke_u_k1_len = len;

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    if ( tlv_parse(&M1[ds],ENC_K1,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("M1 message is bad structured: expected ENC_K1");
        goto error;
    }

    SKLOG_CALLOC(*e_k1,len,char)
    memcpy(*e_k1,buffer,len);
    *e_k1_len = len;

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    return SKLOG_SUCCESS;

error:
    if (*pke_u_k1) free(*pke_u_k1);
    if (*e_k1) free(*e_k1);
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

    SKLOG_CALLOC(*x1,len,char)

    *x1_len = len;
    memcpy(*x1,buffer,len);

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);

    if ( tlv_parse(&in[ds],X1_SIGN_T,buffer,&len) == SKLOG_FAILURE ) {
        ERROR("PLAIN buffer is bad structured: expected X1_SIGN_T");
        goto error;
    }

    SKLOG_CALLOC(*x1_sign,len,char)

    *x1_sign_len = len;
    memcpy(*x1_sign,buffer,len);

    ds += len+8;
    len = 0;
    memset(buffer,0,SKLOG_BUFFER_LEN);
    
    return SKLOG_SUCCESS;

error:
    if ( *x1 ) free(*x1);
    if ( *x1_sign ) free(*x1_sign);
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
verify_m1(SKLOG_U_Ctx      *ctx,
          unsigned char    *M1,
          unsigned int     M1_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    /* TODO: define how to verify the message */

    //~ parse M1 message
    SKLOG_PROTOCOL_STEP p = 0;
    unsigned char t_id[512] = { 0 };
    unsigned char *pke_u_k1 = 0;
    unsigned int pke_u_k1_len = 0;
    unsigned char *e_k1 = 0;
    unsigned int e_k1_len = 0;
    
    if ( parse_m1(M1,M1_len,&p,t_id,&pke_u_k1,&pke_u_k1_len,&e_k1,
                  &e_k1_len) == SKLOG_FAILURE ) {
        ERROR("parse_m1() failure")
        goto error;
    }

    //~ decrypt k1 using U's private key
    unsigned char *k1 = 0;
    size_t k1_len = 0;
    size_t len = pke_u_k1_len;

    if ( pke_decrypt(ctx->u_privkey,pke_u_k1,len,&k1,
                     &k1_len) == SKLOG_FAILURE ) {
        ERROR("pke_decrypt() failure")
        goto error;
    }

    //~ decrypt {x1,x1_sign} using k1 key 
    unsigned char *plain = 0;
    unsigned int plain_len = 0;
    len = e_k1_len;

    if ( decrypt_aes256(k1,e_k1,len,&plain,
                        &plain_len) == SKLOG_FAILURE ) {
        ERROR("decrypt_aes256() failure")
        goto error;
    }

    //~ parse plain
    unsigned char *x1 = 0;
    unsigned int x1_len = 0;
    unsigned char *x1_sign = 0;
    unsigned int x1_sign_len = 0;

    if ( parse_e_k1_content(plain,plain_len,&x1,&x1_len,&x1_sign,
                            &x1_sign_len) == SKLOG_FAILURE ) {
        ERROR("parse_plain() failure")
        goto error;
    }

    //~ verify x1_sign
    //~ TODO: enhance the verification process
    EVP_PKEY *t_pubkey = NULL;

    ERR_load_crypto_strings();

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
    if ( pke_u_k1 ) free(pke_u_k1);
    if ( e_k1 ) free(e_k1);
    if ( k1 ) free(k1);
    if ( plain ) free(plain);
    if ( x1 ) free(x1);
    if ( x1_sign ) free(x1_sign);
    if ( t_pubkey ) EVP_PKEY_free(t_pubkey); 

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

    char            t_cert[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    char            t_address[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    int             t_port = 0;
    char            u_cert[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    char            u_id[HOST_NAME_MAX+1] = { 0 };
    char            u_privkey[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    unsigned int    u_timeout = 0;
    unsigned int    logfile_size = 0;

    FILE *fp = 0;

    if ( u_ctx == NULL ) {
        ERROR("argument 1 must be not NULL")
        goto error;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    parse_config_file(t_cert,t_address,&t_port,u_cert,u_id,u_privkey,
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

    if ( (fp = fopen(u_cert,"r")) != NULL ) {
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

    if ( (fp = fopen(u_privkey,"r")) != NULL ) {
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
    if ( fp ) fclose(fp);
    if ( u_ctx->u_cert ) X509_free(u_ctx->u_cert);
    if ( u_ctx->t_cert ) X509_free(u_ctx->t_cert);
    if ( u_ctx->u_privkey ) EVP_PKEY_free(u_ctx->u_privkey);

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

    struct timeval d;
    struct timeval d_timeout;
    struct timeval now;
    SKLOG_PROTOCOL_STEP p = 0;

    unsigned char *M0 = 0;
    unsigned int M0_len = 0;

    unsigned char *D0 = 0;
    unsigned int D0_len = 0;

    unsigned char *M1 = 0;
    unsigned int M1_len = 0;

    //~ get current time
    gettimeofday(&d,NULL);

    //~ set timeout
    d_timeout = d;
    d_timeout.tv_sec += u_ctx->u_timeout;

    //~ generate X0
    unsigned char *X0 = 0;
    unsigned int X0_len = 0;

    if ( gen_x0(u_ctx,p,&d,&X0,&X0_len) == SKLOG_FAILURE ) {
        ERROR("gen_x0() failure")
        goto error;
    }

    //~ encrypt k0 using T's public key
    unsigned char *pke_t_k0 = 0;
    size_t pke_t_k0_len = 0;

    if ( pke_encrypt(u_ctx->t_cert,u_ctx->session_key,
                     SKLOG_SESSION_KEY_LEN,&pke_t_k0,
                     &pke_t_k0_len) == SKLOG_FAILURE ) {
        ERROR("pke_encrypt() failure");
        goto error;
    }

    //~ sign X0 using U's private key
    unsigned char *X0_sign = 0;
    unsigned int X0_sign_len = 0;

    if ( sign_message(X0,X0_len,u_ctx->u_privkey,
                      &X0_sign,&X0_sign_len) == SKLOG_FAILURE ) {
        ERROR("sign_message() failure")
        goto error;
    }

    //~ encrypt (XO,sign_u_X0) using k0 key
    unsigned char *e_k0 = 0;
    unsigned int e_k0_len = 0;

    if ( gen_e_k0(u_ctx,X0,X0_len,X0_sign,X0_sign_len,
                  &e_k0,&e_k0_len) == SKLOG_FAILURE ) {
        ERROR("gen_e_k0() failure")
        goto error;
    }

    //~ generate M0
    

    if ( gen_m0(u_ctx,p,pke_t_k0,pke_t_k0_len,e_k0,e_k0_len,
                &M0,&M0_len) == SKLOG_FAILURE ) {
        ERROR("gen_m0() failure")
        goto error;
    }

    //~ generate D0


    if ( gen_d0(u_ctx,&d,&d_timeout,M0,M0_len,
                &D0,&D0_len) == SKLOG_FAILURE ) {
        ERROR("gen_d0() failure")
        goto error;
    }

    //~ store X0
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha256(),NULL);
    EVP_DigestUpdate(&mdctx,X0,X0_len);
    EVP_DigestFinal_ex(&mdctx,u_ctx->x0_hash,NULL)  ;
    EVP_MD_CTX_cleanup(&mdctx);

    free(X0);

    //~ create firts log entry
    if ( create_logentry(u_ctx,LogfileInitializationType,
                         D0,D0_len) == SKLOG_FAILURE ) {
        ERROR("create_logentry() failure")
        goto error;
    }

    //~ open connection
    SKLOG_CONNECTION conn = {0,0,0};

    if ( conn_open(u_ctx,&conn) == SKLOG_FAILURE ) {
        ERROR("conn_open() failure")
        goto error;
    }

    //~ send m0 to T
    if ( send_m0(u_ctx,conn.ssl,M0,M0_len) == SKLOG_FAILURE ) {
        ERROR("send_m0() failure")
        goto error;
    }
    
    free(M0);

    //~ receive m1 from T


    if ( receive_m1(conn.ssl,&M1,&M1_len) == SKLOG_FAILURE ) {
        ERROR("receive_m1() failure")
        goto error;
    }

    //~ close connection
    if ( conn_close(&conn) == SKLOG_FAILURE ) {
        ERROR("conn_close() failure")
        goto error;
    }

    //~ verify timeout expiration
    const char *reason = 0;
    
    if ( verify_timeout_expiration(&d_timeout) == SKLOG_FAILURE ) {
        NOTIFY("timeout expired")
        reason = "Timeout Expiration";
        goto failure;
    }

    //~ verify M1
    if ( verify_m1(u_ctx,M1,M1_len) == SKLOG_FAILURE ) {
        ERROR("verify_m1() failure")
        reason = "M1 verification failure";
        goto failure;
    }

    if ( create_logentry(u_ctx,ResponseMessageType,
                         M1,M1_len) == SKLOG_FAILURE ) {
        ERROR("create_logentry() failure")
        goto error;
    }
    
    return SKLOG_SUCCESS;

failure:
    gettimeofday(&now,NULL);
    unsigned char *ts = 0;
    unsigned int ts_len = 0;
    
    char data[4096] = { 0 };
    unsigned int data_len = 0;
    int i = 0;
    int j = 0;

    ts_len = sizeof(now);
    SKLOG_CALLOC(ts,ts_len,char)
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
    free(ts);
    
    return SKLOG_FAILURE;

error:
    if ( X0 > 0 ) free(X0);
    if ( pke_t_k0 > 0 ) free(pke_t_k0);
    if ( X0_sign > 0 ) free(X0_sign);
    if ( e_k0 > 0 ) free(e_k0);
    if ( M0 > 0 ) free(M0);
    if ( D0 > 0 ) free(D0);
    if ( M1 > 0 ) free(M1);

    return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/* flushing logfile                                                   */
/*--------------------------------------------------------------------*/

static SKLOG_RETURN
flush_logfile_init(SSL *ssl)
{
    SSL_load_error_strings();
    
    unsigned char msg[512] = { 0 };
    unsigned char data[512] = { 0 };
    unsigned int data_len = 0;

    int nread = 0;
    int nwrite = 0;

    data_len = strlen("LOGFILE_FLUSH_START");
    memcpy(data,"LOGFILE_FLUSH_START",data_len);

    if ( tlv_create(LE_FLUSH_START,data_len,data,msg) == SKLOG_FAILURE )
        goto error;

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
        return SKLOG_SUCCESS;
    } else if ( memcmp(msg,"LE_NACK",7) == 0 ) {
        WARNING("received NACK")
        goto error;
    } else {
        ERROR("unexpected message")
        goto error;
    }
    
error:
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
flush_logfile_send_logentry(SSL                    *ssl,
                            const unsigned char    *type,
                            unsigned int           type_len,
                            const unsigned char    *data_enc,
                            unsigned int           data_enc_len,
                            const unsigned char    *y,
                            unsigned int           y_len,
                            const unsigned char    *z,
                            unsigned int           z_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char msg[SKLOG_BUFFER_LEN] = { 0 };
    unsigned char buf[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int displacement = 0;

    int nread = 0;
    int nwrite = 0;

    if ( tlv_create(LOGENTRY_TYPE,type_len,(void *)type,
                    &buf[displacement]) == SKLOG_FAILURE )
        goto error;
    displacement += type_len+8;
    
    if ( tlv_create(LOGENTRY_DATA,data_enc_len,(void *)data_enc,
                    &buf[displacement]) == SKLOG_FAILURE )
        goto error;
    displacement += data_enc_len+8;
    
    if ( tlv_create(LOGENTRY_HASH,y_len,(void *)y,
                    &buf[displacement]) == SKLOG_FAILURE )
        goto error;
    displacement += y_len+8;
    
    if ( tlv_create(LOGENTRY_HMAC,z_len,(void *)z,
                    &buf[displacement]) == SKLOG_FAILURE )
        goto error;
    displacement += z_len+8;

    if ( tlv_create(LOGENTRY,displacement,buf,msg) == SKLOG_FAILURE )
        goto error;

    nwrite = SSL_write(ssl,msg,displacement+8);
    
    if ( nwrite <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    memset(msg,0,SKLOG_BUFFER_LEN);
    nread = SSL_read(ssl,msg,SKLOG_BUFFER_LEN-1);

    if ( nread <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    } 

    if ( memcmp(msg,"LE_ACK",6) == 0 ) {
        return SKLOG_SUCCESS;
    } else if ( memcmp(msg,"LE_NACK",7) == 0 ) {
        WARNING("received NACK")
        goto error;
    } else {
        ERROR("unexpected message")
        goto error;
    }
    
error:
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

    data_len = strlen("LOGFILE_FLUSH_END");
    memcpy(data,"LOGFILE_FLUSH_END",data_len);

    if ( tlv_create(LE_FLUSH_END,data_len,data,msg) == SKLOG_FAILURE )
        goto error;

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
        return SKLOG_SUCCESS;
    } else if ( memcmp(msg,"LE_NACK",7) == 0 ) {
        WARNING("received NACK")
        goto error;
    } else {
        ERROR("unexpected message")
        goto error;
    }

error:
    return SKLOG_FAILURE;
}

static SKLOG_RETURN
flush_logfile(SKLOG_U_Ctx    *u_ctx)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    sqlite3 *db = 0;
    sqlite3_stmt *stmt = 0;
    const char *query = 0;
    char *err_msg = 0;
    int sql_step = 0;
    
    sqlite3_open(SKLOG_U_DB,&db);
    
    if ( db == NULL ) {
        fprintf(stderr,
            "SQLite3: Can't open database: %s\n",sqlite3_errmsg(db));
        goto error;
    }

    query = "select * from LOG_ENTRY";

    if ( sqlite3_prepare_v2(db,query,strlen(query)+1,
                            &stmt,NULL) != SQLITE_OK ) {
        fprintf(stderr,
                "SQLite3: sqlite3_prepare_v2() failure: %s\n",
                sqlite3_errmsg(db));
        goto error;
    }

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
    int go_next = 1;
    const unsigned char *type = 0;
    unsigned int type_len = 0;
    const unsigned char *enc_data = 0;
    unsigned int enc_data_len = 0;
    const unsigned char *y = 0;
    unsigned int y_len = 0;
    const unsigned char *z = 0;
    unsigned int z_len = 0;
    
    while ( go_next ) {
        sql_step = sqlite3_step(stmt);

        switch ( sql_step ) {
            case SQLITE_ROW:
                type = sqlite3_column_text(stmt,0);
                type_len = sqlite3_column_bytes(stmt,0);
                
                enc_data = sqlite3_column_text(stmt,1);
                enc_data_len = sqlite3_column_bytes(stmt,1);
                
                y_len = sqlite3_column_bytes(stmt,2);
                y = sqlite3_column_text(stmt,2);
                
                z_len = sqlite3_column_bytes(stmt,3);
                z = sqlite3_column_text(stmt,3);

                if ( flush_logfile_send_logentry(conn.ssl,type,type_len,
                                                 enc_data,enc_data_len,
                                                 y,y_len,z,z_len)
                                                    == SKLOG_FAILURE )
                    goto error;

                break;
            case SQLITE_DONE:
                go_next = 0;
                break;
            default:
                fprintf(stderr,"SQLite3: %s\n",sqlite3_errmsg(db));
                goto error;
                break;
        }
    }

    query = "delete from LOG_ENTRY";

    if ( sqlite3_exec(db,query,sql_callback,0,&err_msg) != SQLITE_OK ) {
        fprintf(stderr, "SQLite3: SQL error: %s\n",err_msg);
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
    if ( db ) sqlite3_close(db);
    if ( err_msg ) sqlite3_free(err_msg);
    
    return SKLOG_FAILURE;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

SKLOG_U_Ctx
SKLOG_U_NewCtx(void)
{
    #ifdef DO_TRACE
    DEBUG
    #endif
    
    SKLOG_U_Ctx ctx = {
        SKLOG_U_CTX_NOT_INITIALIZED,
        {0},0,0,0,0,
        0,{0},{0},0,
        0,0,{0},
        {0},{0},{0},{0}
    };

    return ctx;
}

SKLOG_RETURN
SKLOG_U_CreateLogentry(SKLOG_U_Ctx        *u_ctx,
                       SKLOG_DATA_TYPE    type,
                       char               *data,
                       unsigned int       data_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char *data_blob = 0;
    unsigned int data_blob_len = 0;
    SKLOG_CALLOC(data_blob,data_len,char)
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
        if ( flush_logfile(u_ctx) == SKLOG_FAILURE ) {
            ERROR("flush_logfile() failure")
            goto error;
        }

        //~ flush the current context and mark it as uninitialized
        memset(u_ctx,0,sizeof(*u_ctx));
        u_ctx->context_state = SKLOG_U_CTX_NOT_INITIALIZED;
    }

    return SKLOG_SUCCESS;

error:
    if ( data_blob ) free(data_blob);
    return SKLOG_FAILURE;
}