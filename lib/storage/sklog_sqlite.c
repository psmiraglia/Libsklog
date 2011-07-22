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

SKLOG_RETURN
sklog_sqlite_u_store_logentry(SKLOG_DATA_TYPE    type,
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

    char buffer[4096] = { 0 };
    int i = 0;
    int j = 0;

    char buf_type[9] = { 0 };
    sprintf(buf_type,"%8.8x",htonl(type));

    char *buf_data = 0;
    buf_data = calloc(1+(data_len*2),sizeof(char)); 
    for ( i = 0 , j = 0 ; i < data_len ; i++ , j += 2)
        sprintf(buf_data+j,"%2.2x",data[i]);

    char buf_hash[1+(SKLOG_HASH_CHAIN_LEN*2)] = { 0 };
    for ( i = 0 , j = 0 ; i < SKLOG_HASH_CHAIN_LEN ; i++ , j += 2)
        sprintf(buf_hash+j,"%2.2x",hash[i]);

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

SKLOG_RETURN
sklog_sqlite_u_flush_logfile(SSL *ssl)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    sqlite3 *db = 0;
    sqlite3_stmt *stmt = 0;
    const char *query = 0;
    char *err_msg = 0;
    int sql_step = 0;

    const unsigned char *tmp = 0;

    unsigned char *type = 0;
    unsigned int type_len = 0;
    unsigned char *enc_data = 0;
    unsigned int enc_data_len = 0;
    unsigned char *y = 0;
    unsigned int y_len = 0;
    unsigned char *z = 0;
    unsigned int z_len = 0;

    int go_next = 1;

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

    //~ flush logfile
    
    while ( go_next ) {
        sql_step = sqlite3_step(stmt);

        switch ( sql_step ) {
            case SQLITE_ROW:
                tmp = sqlite3_column_text(stmt,0);
                type_len = sqlite3_column_bytes(stmt,0);
                if ( SKLOG_alloc(&type,unsigned char,type_len) == SKLOG_FAILURE ) {
                    ERROR("SKLOG_alloc() failure");
                    goto error;
                }
                memcpy(type,tmp,type_len);

                tmp = sqlite3_column_text(stmt,1);
                enc_data_len = sqlite3_column_bytes(stmt,1);
                if ( SKLOG_alloc(&enc_data,unsigned char,enc_data_len) == SKLOG_FAILURE ) {
                    ERROR("SKLOG_alloc() failure");
                    goto error;
                }
                memcpy(enc_data,tmp,enc_data_len);

                tmp = sqlite3_column_text(stmt,2);
                y_len = sqlite3_column_bytes(stmt,2);
                if ( SKLOG_alloc(&y,unsigned char,y_len) == SKLOG_FAILURE ) {
                    ERROR("SKLOG_alloc() failure");
                    goto error;
                }
                memcpy(y,tmp,y_len);

                tmp = sqlite3_column_text(stmt,3);
                z_len = sqlite3_column_bytes(stmt,3);
                if ( SKLOG_alloc(&z,unsigned char,z_len) == SKLOG_FAILURE ) {
                    ERROR("SKLOG_alloc() failure");
                    goto error;
                }
                memcpy(z,tmp,z_len);

                if ( flush_logfile_send_logentry(ssl,type,type_len,
                                                 enc_data,enc_data_len,
                                                 y,y_len,z,z_len)
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

    query = "delete from LOG_ENTRY";

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
