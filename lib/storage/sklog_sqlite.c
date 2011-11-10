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

#ifdef USE_SQLITE

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
    int j = 0;

    char *buf_data = 0;
    char buf_hash[1+(SKLOG_HASH_CHAIN_LEN*2)] = { 0 };
    char buf_hmac[1+(SKLOG_HMAC_LEN*2)] = { 0 };

    //~ compose query
    
    uuid_unparse_lower(logfile_id,f_uuid);
    f_uuid[UUID_STR_LEN] = '\0';

    buf_data = calloc(1+(data_len*2),sizeof(char)); 

    for ( i = 0 , j = 0 ; i < data_len ; i++ , j += 2)
        sprintf(buf_data+j,"%2.2x",data[i]);
    for ( i = 0 , j = 0 ; i < SKLOG_HASH_CHAIN_LEN ; i++ , j += 2)
        sprintf(buf_hash+j,"%2.2x",hash[i]);
    for ( i = 0 , j = 0 ; i < SKLOG_HMAC_LEN ; i++ , j += 2)
        sprintf(buf_hmac+j,"%2.2x",hmac[i]);

    sprintf(
        query,
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
    char key[(SKLOG_AUTH_KEY_LEN*2)+1] = { 0 };
    int i = 0, j = 0;

    char f_uuid[UUID_STR_LEN+1] = { 0 };

    //~ compose query

    uuid_unparse_lower(logfile_id,f_uuid);
    f_uuid[UUID_STR_LEN] = '\0';

    for ( i = 0 , j = 0 ; i < SKLOG_AUTH_KEY_LEN ; i++ , j += 2)
        sprintf(key+j,"%2.2x",authkey[i]);
    key[(SKLOG_AUTH_KEY_LEN*2)] = '\0';

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
#endif /* USE_SQLITE */

