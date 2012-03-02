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

#include "sklog_sqlite.h"

#include <netinet/in.h>

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

/*--------------------------------------------------------------------*/
/*                             u                                      */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
sklog_sqlite_u_store_logentry(uuid_t             logfile_id,
                              SKLOG_DATA_TYPE    type,
                              unsigned char      *data,
                              unsigned int       data_len,
                              unsigned char      *hash,
                              unsigned char      *hmac)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    //~ todo: store auth_key not in plaintext

    sqlite3 *db = 0;
    char *err_msg = 0;

    char query[SKLOG_BUFFER_LEN] = { 0 };
    char f_uuid[UUID_STR_LEN+1] = { 0 };
    
    int i = 0;
    
    /**
    int i = 0;
    int j = 0;
    */

    char *buf_data = 0;
    /** disabled
    char buf_hash[1+(SKLOG_HASH_CHAIN_LEN*2)] = { 0 };
    char buf_hmac[1+(SKLOG_HMAC_LEN*2)] = { 0 };
    */
    char *buf_hash = 0;
    char *buf_hmac = 0;

    //~ compose query
    
    uuid_unparse_lower(logfile_id,f_uuid);
    f_uuid[UUID_STR_LEN] = '\0';

#ifdef DISABLE_ENCRYPTION
    /**
    buf_data = calloc(1+(data_len*2),sizeof(char)); 
    for ( i = 0 , j = 0 ; i < data_len ; i++ , j += 2)
        sprintf(buf_data+j,"%2.2x",data[i]);
    */
    switch (type) {
        case LogfileInitializationType:
        case ResponseMessageType:
        case AbnormalCloseType:
        case NormalCloseMessage:
            b64_enc(data,data_len,&buf_data);
            break;
        case Undefined:
            buf_data = calloc(data_len+1,sizeof(char));
            if ( buf_data == 0 ) {
                ERROR("calloc() failure");
                goto error;
            }
            memcpy(buf_data,data,data_len);
            buf_data[data_len] = 0;
            
            //~ sanitise data
            //~ NOTE: to check
		    for ( i = 0 ; i < strlen(buf_data) ; i++ ) {
				switch ( buf_data[i] ) {
					case 34:
					case 37:
					case 39:
					case 96:
						buf_data[i] = 32;
					default:
						break;
				}  
			}
		     
            break;
    }
#else
    if ( b64_enc(data,data_len,&buf_data) == SKLOG_FAILURE ) {
        ERROR("b64_enc() failure");
        goto error;
    }
#endif

    /** disabled
    for ( i = 0 , j = 0 ; i < SKLOG_HASH_CHAIN_LEN ; i++ , j += 2)
        sprintf(buf_hash+j,"%2.2x",hash[i]);
    for ( i = 0 , j = 0 ; i < SKLOG_HMAC_LEN ; i++ , j += 2)
        sprintf(buf_hmac+j,"%2.2x",hmac[i]);
    */

    if ( b64_enc(hash,SKLOG_HASH_CHAIN_LEN,&buf_hash) == SKLOG_FAILURE ) {
        ERROR("b64_enc() failure");
        goto error;
    }
    
    if ( b64_enc(hmac,SKLOG_HMAC_LEN,&buf_hmac) == SKLOG_FAILURE ) {
        ERROR("b64_enc() failure");
        goto error;
    }
    
    

    snprintf(
        query,SKLOG_BUFFER_LEN-1,
        "insert into LOGENTRY (f_id,e_type,e_data,e_hash,e_hmac) \
 values ((select f_id from LOGFILE where f_uuid = '%s'),%d,'%s','%s','%s')",
        f_uuid,type,buf_data,buf_hash,buf_hmac);

    sqlite3_open(SKLOG_U_DB,&db);
    
    if ( db == NULL ) {
        fprintf(stderr,
            "SQLite3: Can't open database: %s\n",sqlite3_errmsg(db));
        goto error;
    }

    if ( sqlite3_exec(db,query,sql_callback,0,
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

SKLOG_RETURN
sklog_sqlite_u_flush_logfile(uuid_t    logfile_id,
                             struct timeval *now,
                             SKLOG_CONNECTION       *c)
                             //~ SSL       *ssl)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    sqlite3 *db = 0;
    sqlite3_stmt *stmt = 0;
    char query[SKLOG_BUFFER_LEN] = { 0 };
    char *err_msg = 0;
    int sql_step = 0;

    char f_uuid[UUID_STR_LEN+1] = { 0 };

    const unsigned char *tmp = 0;

    unsigned char *type = 0;
    unsigned int type_len = 0;
    SKLOG_DATA_TYPE type_tmp = 0;
    unsigned char *enc_data = 0;
    unsigned int enc_data_len = 0;
    unsigned char *y = 0;
    unsigned int y_len = 0;
    unsigned char *z = 0;
    unsigned int z_len = 0;

    int go_next = 1;

    struct tm ts;
    char ts_str[SKLOG_SMALL_BUFFER_LEN] = { 0 };

    sqlite3_open(SKLOG_U_DB,&db);
    
    if ( db == NULL ) {
        fprintf(stderr,
            "SQLite3: Can't open database: %s\n",sqlite3_errmsg(db));
        goto error;
    }

    //~ compose query
    uuid_unparse_lower(logfile_id,f_uuid);
    f_uuid[UUID_STR_LEN] = '\0';
    
    sprintf(
        query,
        "select * from LOGENTRY where f_id = (select f_id from LOGFILE where f_uuid='%s')",
        f_uuid
    );

    if ( sqlite3_prepare_v2(db,query,strlen(query)+1,
                            &stmt,NULL) != SQLITE_OK ) {
        fprintf(stderr,
                "SQLite3: sqlite3_prepare_v2() failure: %s\n",
                sqlite3_errmsg(db));
        goto error;
    }

    //~ flush logfile
    
    while ( go_next ) {
        sql_step = sqlite3_step(stmt);

        switch ( sql_step ) {
            case SQLITE_ROW:
                type_tmp = sqlite3_column_int(stmt,2);
                type_tmp = htonl(type_tmp);
                //~ tmp = sqlite3_column_text(stmt,0);
                //~ type_len = sqlite3_column_bytes(stmt,0);
                type_len = sizeof(type_tmp);
                if ( SKLOG_alloc(&type,unsigned char,type_len) == SKLOG_FAILURE ) {
                    ERROR("SKLOG_alloc() failure");
                    goto error;
                }
                memcpy(type,&type_tmp,type_len);

                tmp = sqlite3_column_text(stmt,3);
                enc_data_len = sqlite3_column_bytes(stmt,3);
                if ( SKLOG_alloc(&enc_data,unsigned char,enc_data_len) == SKLOG_FAILURE ) {
                    ERROR("SKLOG_alloc() failure");
                    goto error;
                }
                memcpy(enc_data,tmp,enc_data_len);

                tmp = sqlite3_column_text(stmt,4);
                y_len = sqlite3_column_bytes(stmt,4);
                if ( SKLOG_alloc(&y,unsigned char,y_len) == SKLOG_FAILURE ) {
                    ERROR("SKLOG_alloc() failure");
                    goto error;
                }
                memcpy(y,tmp,y_len);

                tmp = sqlite3_column_text(stmt,5);
                z_len = sqlite3_column_bytes(stmt,5);
                if ( SKLOG_alloc(&z,unsigned char,z_len) == SKLOG_FAILURE ) {
                    ERROR("SKLOG_alloc() failure");
                    goto error;
                }
                memcpy(z,tmp,z_len);

                #ifdef USE_SSL
                if ( flush_logfile_send_logentry(c->ssl,f_uuid,
                #endif
                #ifdef USE_BIO
                if ( flush_logfile_send_logentry(c->bio,f_uuid,
                #endif
                                                 type,type_len,
                                                 enc_data,enc_data_len,
                                                 y,y_len,
                                                 z,z_len)
                                                    == SKLOG_FAILURE ) {
                    ERROR("flush_logfile_send_logentry() failure")
                    goto error;
                }

                SKLOG_free(&type);
                SKLOG_free(&enc_data);
                SKLOG_free(&y);
                SKLOG_free(&z);

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

    memset(query,0,SKLOG_BUFFER_LEN);

    if ( localtime_r(&(now->tv_sec),&ts) == NULL ) {
        ERROR("localtime_r() failure");
        goto error;
    }

    if ( strftime(ts_str,SKLOG_SMALL_BUFFER_LEN,"%Y-%m-%d %H:%M:%S",&ts) == 0 ) {
        ERROR("strftime() failure");
        goto error;
    }

    sprintf(
        query,
        "update LOGFILE set ts_end='%s' where f_uuid='%s'",
        ts_str,f_uuid
    );

    if ( sqlite3_exec(db,query,sql_callback,0,&err_msg) != SQLITE_OK ) {
        fprintf(stderr, "SQLite3: SQL error: %s\n",err_msg);
        goto error;
    }

    if ( db ) sqlite3_close(db);
    if ( err_msg ) sqlite3_free(err_msg);
    return SKLOG_SUCCESS;

error:
    if ( db ) sqlite3_close(db);
    if ( err_msg ) sqlite3_free(err_msg);
    return SKLOG_FAILURE;
}

SKLOG_RETURN
sklog_sqlite_u_init_logfile(uuid_t            logfile_id,
                            struct timeval    *t)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    sqlite3 *db = 0;
    char *err_msg = 0;

    char query[SKLOG_SMALL_BUFFER_LEN] = { 0 };

    struct tm ts;
    char ts_str[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    char uuid_str[UUID_STR_LEN+1] = { 0 };

    if ( localtime_r(&(t->tv_sec),&ts) == NULL ) {
        ERROR("localtime_r() failure");
        goto error;
    }

    if ( strftime(ts_str,SKLOG_SMALL_BUFFER_LEN,"%Y-%m-%d %H:%M:%S",&ts) == 0 ) {
        ERROR("strftime() failure");
        goto error;
    }

    uuid_unparse_lower(logfile_id,uuid_str);
    uuid_str[UUID_STR_LEN] = '\0';

    sprintf(query,
        "insert into LOGFILE (f_uuid,ts_start,ts_end) values ('%s','%s','0000-00-00 00:00:00')",
        uuid_str,ts_str);

    //~ fprintf(stderr,"\n\n%s\n\n",query);
    //~ getchar();

    sqlite3_open(SKLOG_U_DB,&db);
    
    if ( db == NULL ) {
        fprintf(stderr,
            "SQLite3: Can't open database: %s\n",sqlite3_errmsg(db));
        goto error;
    }

    if ( sqlite3_exec(db,query,sql_callback,0,&err_msg) != SQLITE_OK ) {
        fprintf(stderr, "SQLite3: SQL error: %s\n",err_msg);
        goto error;
    }

    sqlite3_close(db);

    return SKLOG_SUCCESS;

error:
    if ( db ) sqlite3_close(db);
    return SKLOG_FAILURE; 
}

/*--------------------------------------------------------------------*/
/*                             t                                      */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
sklog_sqlite_t_store_authkey(char             *u_ip,
                             uuid_t           logfile_id,
                             unsigned char    *authkey)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    //~ TODO: store authkey not as plaintext

    sqlite3 *db = 0;
    char *err_msg = 0;

    char query[SKLOG_SMALL_BUFFER_LEN] = { 0 };
    //~ char key[(SKLOG_AUTH_KEY_LEN*2)+1] = { 0 };
    char *key = 0;
    //~ int i = 0, j = 0;

    char f_uuid[UUID_STR_LEN+1] = { 0 };

    //~ compose query

    uuid_unparse_lower(logfile_id,f_uuid);
    f_uuid[UUID_STR_LEN] = '\0';

    /**
    for ( i = 0 , j = 0 ; i < SKLOG_AUTH_KEY_LEN ; i++ , j += 2)
        sprintf(key+j,"%2.2x",authkey[i]);
    key[(SKLOG_AUTH_KEY_LEN*2)] = '\0';
    */

    b64_enc(authkey,SKLOG_AUTH_KEY_LEN,&key);

    sprintf(
        query,
        "insert into AUTHKEY (u_ip,f_uuid,authkey) values ('%s','%s','%s')",
        u_ip,f_uuid,key
    );

    //~ execute query

    sqlite3_open(SKLOG_T_DB,&db);
    
    if ( db == NULL ) {
        fprintf(stderr,
            "SQLite3: Can't open database: %s\n",sqlite3_errmsg(db));
        sqlite3_close(db);
        return SKLOG_FAILURE;
    }

    if ( sqlite3_exec(db,query,sql_callback,0,
                      &err_msg) != SQLITE_OK ) {
        fprintf(stderr, "SQLite3: SQL error: %s\n",err_msg);
        sqlite3_free(err_msg);
        return SKLOG_FAILURE;
    }

    sqlite3_close(db);

    return SKLOG_SUCCESS;
}                             

SKLOG_RETURN
sklog_sqlite_t_store_logentry(unsigned char    *blob,
                              unsigned int     blob_len)
{
   #ifdef DO_TRACE
    DEBUG
    #endif

    int i = 0;

    uint32_t type = 0;
    unsigned int len = 0;
    unsigned char *value = 0;

    char f_uuid[UUID_STR_LEN+1] = { 0 };

    SKLOG_DATA_TYPE w = 0;
    char *d = 0;
    unsigned int dl = 0;
    char *y = 0;
    unsigned int yl = 0;
    char *z = 0;
    unsigned int zl = 0;

    sqlite3 *db = 0;
    char *err_msg = 0;
    char query[SKLOG_BUFFER_LEN] = { 0 };
    
    //~ get logfile id

    if ( tlv_parse_message(blob+i,ID_LOG,
                           &type,&len,&value) == SKLOG_FAILURE) {
        ERROR("tlv_parse_message() failure");
        goto error;
    }

    memcpy(f_uuid,value,len);
    f_uuid[UUID_STR_LEN] = '\0';
    i += (len + 8);
    
    //~ get logentry type

    if ( tlv_parse_message(blob+i,LOGENTRY_TYPE,
                           &type,&len,&value) == SKLOG_FAILURE) {
        ERROR("tlv_parse_message() failure");
        goto error;
    }

    memcpy(&w,value,len);
    w = ntohl(w);
    i += (len + 8);

    //~ get logentry message

    if ( tlv_parse_message(blob+i,LOGENTRY_DATA,
                           &type,&len,&value) == SKLOG_FAILURE ) {
        ERROR("tlv_parse_message() failure");
        goto error;
    }

    dl = len;
    if ( SKLOG_alloc(&d,char,dl+1) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }
    
    memcpy(d,value,dl);
    d[dl]='\0';

    i += (len + 8);
    
    //~ get logentry hash
    
    if ( tlv_parse_message(blob+i,LOGENTRY_HASH,
                           &type,&len,&value) == SKLOG_FAILURE ) {
        ERROR("tlv_parse_message() failure");
        goto error;
    }

    yl = len;
    if ( SKLOG_alloc(&y,char,yl+1) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }
    memcpy(y,value,yl);
    y[yl]='\0';

    i += (len + 8);
    
    //~ get logentry hmac

    if ( tlv_parse_message(blob+i,LOGENTRY_HMAC,
                           &type,&len,&value) == SKLOG_FAILURE ) {
        ERROR("tlv_parse_message() failure");
        goto error;
    }

    zl = len;
    if ( SKLOG_alloc(&z,char,zl+1) == SKLOG_FAILURE ) {
        ERROR("SKLOG_alloc() failure");
        goto error;
    }
    memcpy(z,value,zl);
    z[zl]='\0';

    i += (len + 8);

    //~ compose query

    sprintf(
        query,
        "insert into LOGENTRY (f_uuid,e_type,e_data,e_hash,e_hmac) values ('%s',%d,'%s','%s','%s')",
        f_uuid,w,d,y,z
    );

    SKLOG_free(&d);
    SKLOG_free(&y);
    SKLOG_free(&z);

    //~ exec query

    sqlite3_open(SKLOG_T_DB,&db);
    
    if ( db == NULL ) {
        fprintf(stderr,
            "SQLite3: Can't open database: %s\n",sqlite3_errmsg(db));
        sqlite3_close(db);
        goto error;
    }

    if ( sqlite3_exec(db,query,sql_callback,0,
                      &err_msg) != SQLITE_OK ) {
        fprintf(stderr, "SQLite3: SQL error: %s\n",err_msg);
        sqlite3_free(err_msg);
        goto error;
    }

    sqlite3_close(db);
    return SKLOG_SUCCESS;

error:
    if ( d > 0 ) SKLOG_free(d); 
    if ( y > 0 ) SKLOG_free(y); 
    if ( z > 0 ) SKLOG_free(z);
     
    return SKLOG_FAILURE;
}

SKLOG_RETURN
sklog_sqlite_t_retrieve_logfiles(unsigned char    **uuid_list,
                                 unsigned int     *uuid_list_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    unsigned char str[SKLOG_BUFFER_LEN] = { 0 };

    const unsigned char *token = 0;
    unsigned int token_len = 0;
    unsigned int ds = 0;

    sqlite3 *db = 0;
    sqlite3_stmt *stmt = 0;
    char query[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int query_len = 0;
    char *err_msg = 0;
    int sql_step = 0;

    int go_next = 1;

    //~ open database
    sqlite3_open(SKLOG_T_DB,&db);
    
    if ( db == NULL ) {
        fprintf(stderr,
            "SQLite3: Can't open database: %s\n",sqlite3_errmsg(db));
        goto error;
    }

    //~ compose query
    
    query_len = sprintf(query,"select * from AUTHKEY");

    if ( sqlite3_prepare_v2(db,query,query_len+1,
                            &stmt,NULL) != SQLITE_OK ) {
        fprintf(stderr,
                "SQLite3: sqlite3_prepare_v2() failure: %s\n",
                sqlite3_errmsg(db));
        goto error;
    }

    //~ flush logfile
    
    while ( go_next ) {
        sql_step = sqlite3_step(stmt);

        switch ( sql_step ) {
            case SQLITE_ROW:
            
                token = sqlite3_column_text(stmt,2);
                token_len = sqlite3_column_bytes(stmt,2);

                memcpy(str+ds,token,token_len); ds+= token_len;
                str[ds++] = ';';

                break;
            case SQLITE_DONE:
                go_next = 0;
                str[ds++] = '\0';
                
                break;
            default:
                fprintf(stderr,"SQLite3: %s\n",sqlite3_errmsg(db));
                goto error;
                break;
        }
    }

    *uuid_list_len = ds;
    *uuid_list = calloc(ds,sizeof(unsigned char));
    memcpy(*uuid_list,str,ds);

    if ( db ) sqlite3_close(db);
    if ( err_msg ) sqlite3_free(err_msg);
    return SKLOG_SUCCESS;

error:
    if ( db ) sqlite3_close(db);
    if ( err_msg ) sqlite3_free(err_msg);
    return SKLOG_FAILURE;
}

SKLOG_RETURN
sklog_sqlite_t_verify_logfile(unsigned char *uuid)
{
    #ifdef DO_TRACE
    DEBUG;
    #endif

    int rv = 0;

    /****/

    const unsigned char *db_text_b = 0;
    unsigned int db_text_blen = 0;

    char *b64_b = 0;
    unsigned int b64_blen = 0;

    unsigned char *b = 0;
    unsigned int blen = 0;
    
    /****/


    //~ char rbuf[SKLOG_BUFFER_LEN] = { 0 };

    //~ const unsigned char *tmps = 0;
    //~ unsigned int tmps_len = 0;
    unsigned int tmpi = 0;

    sqlite3 *db = 0;
    sqlite3_stmt *stmt = 0;
    char query[SKLOG_BUFFER_LEN] = { 0 };
    int  query_len = 0;
    int sqlite_ret = 0;

    uint32_t w = 0;

    unsigned char e_type[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int  e_type_len = 0;

    unsigned char e_data[SKLOG_BUFFER_LEN] = { 0 };
    unsigned int  e_data_len = 0;

    unsigned char e_hash[SKLOG_HASH_CHAIN_LEN] = { 0 };
    unsigned char e_hmac[SKLOG_HMAC_LEN] = { 0 };
    
    unsigned char e_hash_prev[SKLOG_HASH_CHAIN_LEN] = { 0 };
    unsigned char e_hash_curr[SKLOG_HASH_CHAIN_LEN] = { 0 };
    unsigned char e_hmac_curr[SKLOG_HMAC_LEN] = { 0 };

    unsigned char authkey[SKLOG_AUTH_KEY_LEN] = { 0 };
    unsigned char buf[SKLOG_AUTH_KEY_LEN] = { 0 };

    //~ int i = 0 , j = 0 , c = 0;

    EVP_MD_CTX mdctx;

    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    //----------------------------------------------------------------//
    //                        get authkey                             //
    //----------------------------------------------------------------//

    //~ compose query
    query_len = sprintf(query,
        "SELECT authkey FROM AUTHKEY WHERE f_uuid='%s'",uuid);

    //~ open database
    sqlite3_open(SKLOG_T_DB,&db);
    
    if ( db == NULL ) {
        fprintf(stderr,
            "SQLite3: Can't open database: %s\n",sqlite3_errmsg(db));
        goto error;
    }

    //~ exec query
    if ( sqlite3_prepare_v2(db,query,query_len+1,&stmt,NULL) != SQLITE_OK ) {
        fprintf(stderr,
            "SQLite3: sqlite3_prepare_v2() failure: %s\n",
            sqlite3_errmsg(db));
        goto error;
    }

    while ( 1 ) {

        sqlite_ret = sqlite3_step(stmt);

        switch ( sqlite_ret ) {
            case SQLITE_ROW:

                db_text_b = sqlite3_column_text(stmt,0);
                db_text_blen = sqlite3_column_bytes(stmt,0);

                if ( ( b64_b = calloc(db_text_blen+1,sizeof(char)) ) == NULL ) {
                    ERROR("calloc() failure");
                    goto error;
                }
                memset(b64_b,0,db_text_blen+1);
                memcpy(b64_b,db_text_b,db_text_blen);
                b64_blen = strlen(b64_b);
                if ( b64_dec(b64_b,b64_blen,&b,&blen) == SKLOG_FAILURE ) {
                    ERROR("b64_dec() failure");
                    goto error;
                }

                memcpy(authkey,b,blen);

                free(b64_b);
                /**
                fprintf(stderr,"/n>>> ");
                for ( i = 0 ; i < SKLOG_AUTH_KEY_LEN ; i++ )
                    fprintf(stderr,"%2.2x ",authkey[i]);
                fprintf(stderr,"<<</n/n");
                getchar();
                */
            
                /**
                tmps = sqlite3_column_text(stmt,0);      // get text
                tmps_len = sqlite3_column_bytes(stmt,0); // get text len

                b64buf = calloc(tmps_len+1,sizeof(char));
                memcpy(b64buf,tmps,tmps_len);

                fprintf(stderr,">>>> %s\n\n",tmps);
                getchar();

                b64_dec("YW55IGNhcm5hbCBwbGVhc3VyZQ==\0",strlen("YW55IGNhcm5hbCBwbGVhc3VyZQ==\0"),NULL,NULL);

                memcpy(rbuf,tmps,tmps_len);

                for ( i = 0 , j = 0 ; i < tmps_len ; i += 2 , j++ ) {
                    sscanf(rbuf+i,"%2x",&c); authkey[j] = c;
                }

                memset(rbuf,0,SKLOG_BUFFER_LEN);
                */
                break;
            case SQLITE_DONE:
                goto terminate_authkey;
                break;
            default:
                goto error;
                break;
        }
    }

terminate_authkey:

    //~ close database
    sqlite3_close(db);

    //----------------------------------------------------------------//
    //                           verify                               //
    //----------------------------------------------------------------//
    

    //~ compose query
    query_len = sprintf(query,
        "SELECT e_type,e_data,e_hash,e_hmac FROM LOGENTRY WHERE f_uuid = '%s'",uuid);

    //~ open database
    sqlite3_open(SKLOG_T_DB,&db);
    
    if ( db == NULL ) {
        fprintf(stderr,
            "SQLite3: Can't open database: %s\n",sqlite3_errmsg(db));
        goto error;
    }

    //~ exec query
    if ( sqlite3_prepare_v2(db,query,query_len+1,&stmt,NULL) != SQLITE_OK ) {
        fprintf(stderr,
            "SQLite3: sqlite3_prepare_v2() failure: %s\n",
            sqlite3_errmsg(db));
        goto error;
    }

    while ( 1 ) {

        sqlite_ret = sqlite3_step(stmt);

        switch ( sqlite_ret ) {
            case SQLITE_ROW:

                //----------------------------------------------------//
                //                     parse row                      //
                //----------------------------------------------------//
                
                //~ get e_type
                tmpi = sqlite3_column_int(stmt,0); w = tmpi; e_type_len = sizeof(w);
                memcpy(e_type,&w,e_type_len);

                //~ get e_data
#ifdef DISABLE_ENCRYPTION
                switch ( w ) {
                    case LogfileInitializationType:
                    case ResponseMessageType:
                    case AbnormalCloseType:
                    case NormalCloseMessage:
                        db_text_b = sqlite3_column_text(stmt,1);
                        db_text_blen = sqlite3_column_bytes(stmt,1);
        
                        if ( (b64_b = calloc(db_text_blen+1,sizeof(char))) == NULL ) {
                            ERROR("calloc() failure");
                            goto error;
                        }
                        memset(b64_b,0,db_text_blen+1);
                        memcpy(b64_b,db_text_b,db_text_blen);
                        b64_blen = strlen(b64_b);
                        if ( b64_dec(b64_b,b64_blen,&b,&blen) == SKLOG_FAILURE ) {
                            ERROR("b64_dec() failure");
                            goto error;
                        }
        
                        memcpy(e_data,b,blen);
                        e_data_len = blen;
                        
                        free(b64_b);
                        break;
                    case Undefined:
                        db_text_b = sqlite3_column_text(stmt,1);
                        db_text_blen = sqlite3_column_bytes(stmt,1);
        
                        memcpy(e_data,db_text_b,db_text_blen);
                        e_data_len = db_text_blen;
                        break;
                }
#else
                db_text_b = sqlite3_column_text(stmt,1);
                db_text_blen = sqlite3_column_bytes(stmt,1);

                if ( (b64_b = calloc(db_text_blen+1,sizeof(char))) == NULL ) {
                    ERROR("calloc() failure");
                    goto error;
                }
                memset(b64_b,0,db_text_blen+1);
                memcpy(b64_b,db_text_b,db_text_blen);
                b64_blen = strlen(b64_b);
                if ( b64_dec(b64_b,b64_blen,&b,&blen) == SKLOG_FAILURE ) {
                    ERROR("b64_dec() failure");
                    goto error;
                }

                memcpy(e_data,b,blen);
                e_data_len = blen;
                
                free(b64_b);
#endif
                /**
                tmps = sqlite3_column_text(stmt,1);
                tmps_len = sqlite3_column_bytes(stmt,1);

                fprintf(stderr,">>>> %s\n\n",tmps);
                getchar();

                memcpy(rbuf,tmps,tmps_len);

                for ( i = 0 , j = 0 ; i < tmps_len ; i += 2 , j++ ) {
                    sscanf(&rbuf[i],"%2x",&c); e_data[j] = c;
                }
                e_data_len = tmps_len/2;
                memset(rbuf,0,SKLOG_BUFFER_LEN);
                */
                
                //~ get e_hash

                db_text_b = sqlite3_column_text(stmt,2);
                db_text_blen = sqlite3_column_bytes(stmt,2);

                if ( (b64_b = calloc(db_text_blen+1,sizeof(char))) == NULL ) {
                    ERROR("calloc() failure");
                    goto error;
                }
                memset(b64_b,0,db_text_blen+1);
                memcpy(b64_b,db_text_b,db_text_blen);
                b64_blen = strlen(b64_b);
                if ( b64_dec(b64_b,b64_blen,&b,&blen) == SKLOG_FAILURE ) {
                    ERROR("b64_dec() failure");
                    goto error;
                }

                if ( blen != SKLOG_HASH_CHAIN_LEN ) {
                    ERROR("something goes wrong!!!");
                    goto error;
                }
                
                memcpy(e_hash,b,blen);
                
                free(b64_b);
                
                /**
                tmps = sqlite3_column_text(stmt,2);
                tmps_len = sqlite3_column_bytes(stmt,2);
                memcpy(rbuf,tmps,tmps_len);

                for ( i = 0 , j = 0 ; i < tmps_len ; i += 2 , j++ ) {
                    sscanf(&rbuf[i],"%2x",&c); e_hash[j] = c;
                }
                memset(rbuf,0,SKLOG_BUFFER_LEN);
                */

                //~ get e_hmac

                db_text_b = sqlite3_column_text(stmt,3);
                db_text_blen = sqlite3_column_bytes(stmt,3);

                if ( (b64_b = calloc(db_text_blen+1,sizeof(char))) == NULL ) {
                    ERROR("calloc() failure");
                    goto error;
                }
                memset(b64_b,0,db_text_blen+1);
                memcpy(b64_b,db_text_b,db_text_blen);
                b64_blen = strlen(b64_b);
                if ( b64_dec(b64_b,b64_blen,&b,&blen) == SKLOG_FAILURE ) {
                    ERROR("b64_dec() failure");
                    goto error;
                }

                if ( blen != SKLOG_HMAC_LEN ) {
                    ERROR("something goes wrong!!!");
                    goto error;
                }
                
                memcpy(e_hmac,b,blen);
                
                free(b64_b);
                
                /**
                tmps = sqlite3_column_text(stmt,3);
                tmps_len = sqlite3_column_bytes(stmt,3);
                memcpy(rbuf,tmps,tmps_len);

                for ( i = 0 , j = 0 ; i < tmps_len ; i += 2 , j++ ) {
                    sscanf(&rbuf[i],"%2x",&c); e_hmac[j] = c;
                }
                memset(rbuf,0,SKLOG_BUFFER_LEN);
                */

                //----------------------------------------------------//
                //                regenerate hash chain               //
                //----------------------------------------------------//

                EVP_MD_CTX_init(&mdctx);
    
                if ( EVP_DigestInit_ex(&mdctx,EVP_sha256(),NULL) == 0 ) {
                    ERR_print_errors_fp(stderr);
                    goto error;
                }
            
                if ( EVP_DigestUpdate(&mdctx,e_hash_prev,SKLOG_HASH_CHAIN_LEN) == 0 ) {
                    ERR_print_errors_fp(stderr);
                    goto error;
                }
                
                if ( EVP_DigestUpdate(&mdctx,e_data,e_data_len) == 0 ) {
                    ERR_print_errors_fp(stderr);
                    goto error;
                }
                
                if ( EVP_DigestUpdate(&mdctx,e_type,e_type_len) == 0 ) {
                    ERR_print_errors_fp(stderr);
                    goto error;
                }
            
                if ( EVP_DigestFinal_ex(&mdctx,e_hash_curr,NULL) == 0 ) {
                    ERR_print_errors_fp(stderr);
                    goto error;
                }
            
                EVP_MD_CTX_cleanup(&mdctx);

                //----------------------------------------------------//
                //                    generate hmac                   //
                //----------------------------------------------------//

                rv = hmac(e_hash_curr,
                    SKLOG_HASH_CHAIN_LEN,
                    authkey,
                    SKLOG_AUTH_KEY_LEN,
                    e_hmac_curr,NULL);

                if ( rv == SKLOG_FAILURE ) {
                    ERROR("hmac() failure");
                    goto error;
                }

                //----------------------------------------------------//
                //                    verify results                  //
                //----------------------------------------------------//

                if ( memcmp(e_hash_curr,e_hash,SKLOG_HASH_CHAIN_LEN) != 0 ) {
                    ERROR("Verification Failure: message digests are not equal");
                    goto error;
                }
                
                if ( memcmp(e_hmac_curr,e_hmac,SKLOG_HMAC_LEN) != 0 ) {
                    ERROR("Verification Failure: hmac are not equal");
                    goto error;
                }

                //----------------------------------------------------//
                //                    renew authkey                   //
                //----------------------------------------------------//

                sha256(authkey,SKLOG_AUTH_KEY_LEN,buf,NULL);
                memcpy(authkey,buf,SKLOG_AUTH_KEY_LEN);

                //----------------------------------------------------//
                //                      save data                     //
                //----------------------------------------------------//
                memcpy(e_hash_prev,e_hash_curr,SKLOG_HASH_CHAIN_LEN);
                memset(e_hash_curr,0,SKLOG_HASH_CHAIN_LEN);
            
                break;
            case SQLITE_DONE:
                goto terminate_verify;
                break;
            default:
                goto error;
                break;
        }
    }
terminate_verify:

    //~ close db
    sqlite3_close(db);
    
    return SKLOG_SUCCESS;
    
error:
    //~ close db
    sqlite3_close(db);
    return SKLOG_FAILURE;
}
