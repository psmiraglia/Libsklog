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

//~ #include "sklog_sqlite.h"
#include "sklog_dummy.h"

SKLOG_RETURN
sklog_dummy_u_store_logentry(uuid_t             logfile_id,
							 SKLOG_DATA_TYPE    type,
							 unsigned char      *data,
							 unsigned int       data_len,
							 unsigned char      *hash,
							 unsigned char      *hmac)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
sklog_dummy_u_flush_logfile(uuid_t    logfile_id,
                            struct timeval *now,
                            SKLOG_CONNECTION       *c)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    return SKLOG_SUCCESS;
}
                            
SKLOG_RETURN
sklog_dummy_u_init_logfile(uuid_t            logfile_id,
                           struct timeval    *t)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    return SKLOG_SUCCESS;
}
                           
SKLOG_RETURN
sklog_dummy_t_store_authkey(char             *u_ip,
                            uuid_t           logfile_id,
                            unsigned char    *authkey)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
sklog_dummy_t_store_logentry(unsigned char    *blob,
                             unsigned int     blob_len)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
sklog_dummy_t_retrieve_logfiles(unsigned char    **uuid_list,
                                unsigned int     *uuid_list_len)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    return SKLOG_SUCCESS;
}

SKLOG_RETURN
sklog_dummy_t_verify_logfile(unsigned char *uuid)
{
	#ifdef DO_TRACE
    DEBUG
    #endif
    return SKLOG_SUCCESS;
}
