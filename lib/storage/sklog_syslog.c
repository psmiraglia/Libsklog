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

#ifdef USE_SYSLOG

#include "sklog_syslog.h"

/*--------------------------------------------------------------------*/
/*                             u                                      */
/*--------------------------------------------------------------------*/

SKLOG_RETURN
sklog_syslog_u_store_logentry(uuid_t             logfile_id,
                              SKLOG_DATA_TYPE    type,
                              unsigned char      *data,
                              unsigned int       data_len,
                              unsigned char      *hash,
                              unsigned char      *hmac)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    int i = 0;
    int j = 0;

    char ident[UUID_STR_LEN+1] = { 0 };

    char *buf_data = 0;
    char buf_hash[1+(SKLOG_HASH_CHAIN_LEN*2)] = { 0 };
    char buf_hmac[1+(SKLOG_HMAC_LEN*2)] = { 0 };

    //~ create log ident
    uuid_unparse_lower(logfile_id,ident);
    ident[UUID_STR_LEN] = '\0';

    //~ serialize data
    buf_data = calloc(1+(data_len*2),sizeof(char));
    
    if ( buf_data < 0 ) {
        ERROR("calloc() failure");
        return SKLOG_FAILURE;
    }
    
    for ( i = 0 , j = 0 ; i < data_len ; i++ , j += 2)
        sprintf(buf_data+j,"%2.2x",data[i]);
    buf_data[data_len*2] = '\0';

    //~ serialize hash
    for ( i = 0 , j = 0 ; i < SKLOG_HASH_CHAIN_LEN ; i++ , j += 2)
        sprintf(buf_hash+j,"%2.2x",hash[i]);
    buf_hash[SKLOG_HASH_CHAIN_LEN*2] = '\0';

    //~ serialize hmac
    for ( i = 0 , j = 0 ; i < SKLOG_HMAC_LEN ; i++ , j += 2)
        sprintf(buf_hmac+j,"%2.2x",hmac[i]);
    buf_hmac[SKLOG_HMAC_LEN*2] = '\0';

    //~ open connection to syslogd
    openlog(ident,LOG_NDELAY,SKLOG_FACILITY);

    //~ send message to syslogd
    syslog(SKLOG_SEVERITY,"[%d] [%s] [%s] [%s]",type,buf_data,buf_hash,buf_hmac);
    
    //~ close connection with syslogd
    closelog();
    
    return SKLOG_SUCCESS;
}                        


SKLOG_RETURN
sklog_syslog_u_flush_logfile(uuid_t    logfile_id,
                             struct timeval *now,
                             SSL       *ssl)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    TO_IMPLEMENT;

    return SKLOG_TO_IMPLEMENT;
}

SKLOG_RETURN
sklog_syslog_u_init_logfile(uuid_t            logfile_id,
                            struct timeval    *t)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    TO_IMPLEMENT;

    return SKLOG_TO_IMPLEMENT;
}                        


/*--------------------------------------------------------------------*/
/*                             t                                      */
/*--------------------------------------------------------------------*/
SKLOG_RETURN
sklog_syslog_t_store_authkey(char             *u_ip,
                             uuid_t           logfile_id,
                             unsigned char    *authkey)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    TO_IMPLEMENT;

    return SKLOG_TO_IMPLEMENT;
}

SKLOG_RETURN
sklog_syslog_t_store_logentry(unsigned char    *blob,
                              unsigned int     blob_len)
{
    #ifdef DO_TRACE
    DEBUG
    #endif

    TO_IMPLEMENT;

    return SKLOG_TO_IMPLEMENT;
}

#endif /* USE_SYSLOG */
