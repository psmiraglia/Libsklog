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

#include "sklog_misc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

#include <jansson.h>

#include <openssl/err.h>
#include <openssl/evp.h>


/*--------------------------------------------------------------------*/
/*                      U driver callbacks                            */
/*--------------------------------------------------------------------*/

/*
 * deprecated
 * 
 */
 
SKLOG_RETURN sklog_misc_u_store_logentry(uuid_t logfile_id,
	SKLOG_DATA_TYPE	type, unsigned char *data, unsigned int	data_len,
	unsigned char *hash, unsigned char *hmac)
{
	NOTIFY("%s", MSG_NOT_IMPLEMENTED);
	return SKLOG_SUCCESS;
}

/*
 * ok
 */
 
SKLOG_RETURN sklog_misc_u_store_logentry_v2(char *logfile_id,
	char *logentry)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	FILE *fp = 0;
	char filename[BUF_512+1] = { 0x0 };
	
	/* chech input parameters */
	
	if ( logfile_id == NULL || logentry == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* open logfile */
	
	rv = snprintf(filename, BUF_512, "%s/%s.log", LOGFILE_PATH,
		logfile_id);
		
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	fp = fopen(filename, "a");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* write logentry */
	
	rv = fprintf(fp, "%s\n", logentry);
	
	if ( rv < 0 ) {
		ERROR("fprintf() failure");
		return SKLOG_FAILURE;
	}
	
	/* close file */
	
	fclose(fp);
	
	return SKLOG_SUCCESS;
}

/*
 * deprecated
 * 
 */

SKLOG_RETURN sklog_misc_u_flush_logfile(uuid_t logfile_id,
	unsigned long now, SKLOG_CONNECTION *c)
{
	NOTIFY("%s", MSG_NOT_IMPLEMENTED);
	return SKLOG_SUCCESS;
}

/*
 * ok
 */
 	
SKLOG_RETURN sklog_misc_u_flush_logfile_v2(char *logfile_id,
	char *logs[], unsigned int *logs_size)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	FILE *fp = 0;
	char filename[BUF_512+1] = { 0x0 };
	
	char buf[BUF_8192+1] = { 0x0 };
	int bufl = 0;
	
	int counter = 0;
	
	/* chech input parameters */
	
	if ( logfile_id == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* open logfile */
	
	rv = snprintf(filename, BUF_512, "%s/%s.log", LOGFILE_PATH,
		logfile_id);
		
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	fp = fopen(filename, "r");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* read file */
	
	while ( !feof(fp) ) {
		
		/**
		 * NOTE
		 * 
		 * fgets() reads in at most one less than size characters from
		 * stream and stores them into the buffer pointed to by s.
		 * Reading stops after an EOF or a newline. If a newline is
		 * read, it is stored into the  buffer. A terminating null byte
		 * ('\0') is stored after the last character in the buffer.
		 * 
		 */
		 
		if ( fgets(buf, BUF_8192, fp) != NULL ) {
		
			bufl = strlen(buf);
			
			logs[counter] = calloc(bufl+1, sizeof(char));
			
			if ( logs[counter] == NULL ) {
				ERROR("calloc() failure");
				fclose(fp);
				return SKLOG_FAILURE;
			}
			
			memcpy(logs[counter], buf, bufl);
			
			memset(buf, 0, BUF_8192);
			
			counter++;
		}
	}
	
	*logs_size = counter;
	
	fclose(fp);
	
	return SKLOG_SUCCESS;
}

/*
 * deprecated
 * 
 */

SKLOG_RETURN sklog_misc_u_init_logfile(uuid_t logfile_id,
	unsigned long t)
{
	NOTIFY("%s", MSG_NOT_IMPLEMENTED);
	return SKLOG_SUCCESS;
}

/*
 * ok
 */
	
SKLOG_RETURN sklog_misc_u_init_logfile_v2(char *logfile_id,
	unsigned long t)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	FILE *fp = 0;
	char filename[BUF_512+1] = { 0x0 };
	
	char timestamp[BUF_512+1] = { 0x0 };
	
	/* chech input parameters */
	
	if ( logfile_id == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* ascii-ze timestamp */
	
	rv = time_usec2ascii(timestamp, t);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("time_usec2ascii() failure");
		return SKLOG_FAILURE;
	}
	
	/* open logfile */
	
	rv = snprintf(filename, BUF_512, "%s/%s.log", LOGFILE_PATH,
		logfile_id);
		
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	fp = fopen(filename, "w+");
	
	if ( fp == NULL ) {
		ERROR("Unable to create file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* write init metadata */
	
	fprintf(fp, "# LOGFILE_ID: %s\n", logfile_id);
	fprintf(fp, "# OPENED: %s\n\n", timestamp);
	
	fclose(fp);
	
	return SKLOG_SUCCESS;
}

SKLOG_RETURN sklog_misc_u_close_logfile_v2(char *logfile_id,
	unsigned long t)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	FILE *fp = 0;
	char filename[BUF_512+1] = { 0x0 };
	
	char timestamp[BUF_512+1] = { 0x0 };
	
	/* chech input parameters */
	
	if ( logfile_id == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* ascii-ze timestamp */
	
	rv = time_usec2ascii(timestamp, t);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("time_usec2ascii() failure");
		return SKLOG_FAILURE;
	}
	
	/* open logfile */
	
	rv = snprintf(filename, BUF_512, "%s/%s.log", LOGFILE_PATH,
		logfile_id);
		
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	fp = fopen(filename, "a");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* write close metadata */
	
	fprintf(fp, "\n# CLOSED: %s", timestamp);
	
	fclose(fp);
	
	return SKLOG_SUCCESS;
}

/*
 * 
 */
 
SKLOG_RETURN sklog_misc_u_dump_raw(char *logfile_id,
	const char *filename)
{
	return SKLOG_SUCCESS;
}

/*
 * 
 */
 
SKLOG_RETURN sklog_misc_u_dump_json(char *logfile_id,
	const char *filename)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	FILE *in = 0;
	char fin[BUF_512+1] = { 0x0 };
	
	FILE *out = 0;
	
	char line[BUF_8192+1] = { 0x0 };
	int eol = 0;
	
	char opened[BUF_512+1] = { 0x0 };
	char closed[BUF_512+1] = { 0x0 };
	
	int is_the_first = 1;
	
	int i = 0;
	
	/* check input parameters */
	
	if ( logfile_id == NULL || filename == NULL ) {
		ERROR(MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* open files */
	
	rv = snprintf(fin, BUF_512, "%s/%s.log", LOGFILE_PATH, logfile_id);
	
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	in = fopen(fin, "r");
	
	if ( in == NULL ) {
		ERROR("Unable to open file %s", fin);
		return SKLOG_FAILURE;
	}
	
	out = fopen(filename, "w+");
	
	if ( out == NULL ) {
		ERROR("Unable to open file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* read */
	
	/* ignore first line */
	
	fgets(line, BUF_8192, in);
	memset(line, 0, BUF_8192);
	
	/* get opened */

	fgets(line, BUF_8192, in);
	
	if ( line[0] == '#' ) {
		i = 0;
		while ( line[i++] != ':');
		i++;
		memcpy(opened, line+i, strlen(line)-i-1);
	}
	
	fprintf(out, "{\"logfile_id\":\"%s\",\"opened\":\"%s\",\"logs\":[",
		logfile_id, opened);

	while ( !feof(in) ) {
		
		fgets(line, BUF_8192, in);
		
		if ( line[0] == '#' ) {
			i = 0;
			while ( line[i++] != ':');
			i++;
			memcpy(closed, line+i, strlen(line)-i);
			continue;
		}
		
		if ( line[0] == '\n' || line[0] == '\0' ) {
			memset(line, 0, BUF_8192);
			continue;
		}

		/* remove newline */
		
		eol = strlen(line);
		line[eol-1] = '\0';
		
		if ( is_the_first ) {
			fprintf(out, "%s", line);
			is_the_first = 0;
		} else {
			fprintf(out, ",%s", line);
		}
		
		memset(line, 0, BUF_8192);
	}
	
	fprintf(out, "],\"closed\":\"%s\"}\n", closed);
	
	fclose(in);
	fclose(out);
	
	return SKLOG_SUCCESS;
}	

/*
 * 
 */
 	
SKLOG_RETURN sklog_misc_u_dump_soap(char *logfile_id,
	const char *filename)
{
	return SKLOG_SUCCESS;
}

/*--------------------------------------------------------------------*/
/*                      T driver callbacks                            */
/*--------------------------------------------------------------------*/

static int sql_callback(void *NotUsed, int argc, char **argv,
	char **azColName)
{
	int i = 0;
	for ( i = 0 ; i < argc ; i++ )
		ERROR("%s = %s", azColName[i], argv[i] ? argv[i] : "NULL");
	return 0;
}

/*
 * deprecated
 * 
 */
 
SKLOG_RETURN sklog_misc_t_store_authkey(char *u_ip, uuid_t logfile_id,
	unsigned char *authkey)
{
	
	/**
	 * 
	 * strores authkeys in database
	 * 
	 * | key | ip_address | logfile_id | {authkey} |
	 * 
	 */
	
	return SKLOG_SUCCESS;
}

/*
 * ok
 * 
 */
 
SKLOG_RETURN sklog_misc_t_store_authkey_v2(char *address,
	char *logfile_id, unsigned char *authkey)
{
	
	/**
	 * 
	 * strores authkeys in database
	 * 
	 * | key | ip_address | logfile_id | {authkey} |
	 * 
	 */
	 
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	sqlite3 *db = 0;
	char *sql_err_msg = 0;
	char query[BUF_4096+1] = { 0x0 };
	
	char *key = 0;
	
	/* check input parameters */
	
	if ( address == NULL || logfile_id == NULL || authkey == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* compose query */
	
	rv = b64_enc(authkey, SKLOG_AUTH_KEY_LEN, &key);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_enc() failure");
		return SKLOG_FAILURE;
	}
	
	snprintf(query, BUF_4096,
		"insert into AUTHKEY (u_ip,f_uuid,authkey) values ('%s','%s','%s')",
		address, logfile_id, key);
		
	free(key);
		
	/* exec query */
	
	sqlite3_open(SKLOG_T_DB, &db);
	
	if ( db == NULL ) {
		ERROR("sqlite3_open() failure: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return SKLOG_FAILURE;
	}
	
	rv = sqlite3_exec(db, query, sql_callback, 0, &sql_err_msg);

	if ( rv != SQLITE_OK ) {
		ERROR("sqlite3_exec() failure: %s", sql_err_msg);
		sqlite3_free(sql_err_msg);
		sqlite3_close(db);
		return SKLOG_FAILURE;
	}

	sqlite3_free(sql_err_msg);
	sqlite3_close(db);
	 
	return SKLOG_SUCCESS;
}

/*
 * deprecated
 * 
 */
 
SKLOG_RETURN sklog_misc_t_store_m0_msg(char *u_ip, uuid_t	logfile_id,
	unsigned char *m0, unsigned int	m0_len)
{
	/**
	 * 
	 * strores m0 messages in database
	 * 
	 * | key | ip_address | logfile_id | m0_message |
	 * 
	 */
	 
	return SKLOG_SUCCESS;
}
	
/*
 * ok
 * 
 */
 
SKLOG_RETURN sklog_misc_t_store_m0_msg_v2(char *address,
	char *logfile_id, unsigned char *m0, unsigned int m0_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	sqlite3 *db = 0;
	char *sql_err_msg = 0;
	
	char query[BUF_8192+1] = { 0x0 };
	
	char *m0b64 = 0;
	
	/* chech input parameters */
	
	if ( address == NULL || logfile_id == NULL || m0 == NULL ) {
		ERROR("%s", MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* compose query */
	
	rv = b64_enc(m0, m0_len, &m0b64);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_enc() failure");
		return SKLOG_FAILURE;
	}
	
	snprintf(query, BUF_8192,
		"insert into M0MSG (u_ip,f_uuid,m0_msg) values ('%s','%s','%s')",
		address, logfile_id, m0b64);
	
	/* exec query */
	
	sqlite3_open(SKLOG_T_DB, &db);
	
	if ( db == NULL ) {
		ERROR("sqlite3_open() failure: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return SKLOG_FAILURE;
	}
	
	rv = sqlite3_exec(db, query, sql_callback, 0, &sql_err_msg);

	if ( rv != SQLITE_OK ) {
		ERROR("sqlite3_exec() failure: %s", sql_err_msg);
		sqlite3_free(sql_err_msg);
		sqlite3_close(db);
		return SKLOG_FAILURE;
	}

	sqlite3_free(sql_err_msg);
	sqlite3_close(db);
	
	return SKLOG_SUCCESS;
}	

/*
 * deprecated
 * 
 */
 	
SKLOG_RETURN sklog_misc_t_store_logentry(unsigned char *blob,
	unsigned int blob_len)
{
	/**
	 * 
	 * probably will be deprecate
	 * 
	 */
	 
	return SKLOG_SUCCESS;
}

SKLOG_RETURN
sklog_misc_t_store_logentry_v2 (char *logfile_id, char *logentry,
								unsigned int logentry_len)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = 0;
	
	FILE *fp = 0;
	char filename[BUF_512+1] = { 0x0 };
	
	/* chech input parameters */
	
	if ( logfile_id == NULL || logentry == NULL ) {
		ERROR(MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* open logfile */
	
	rv = snprintf(filename, BUF_512, "%s/T/%s.log", LOGFILE_PATH,
		logfile_id);
		
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		return SKLOG_FAILURE;
	}
	
	fp = fopen(filename, "a");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file %s", filename);
		return SKLOG_FAILURE;
	}
	
	/* write logentry */
	
	rv = fprintf(fp, "%s\n", logentry);
	
	if ( rv < 0 ) {
		ERROR("fprintf() failure");
		return SKLOG_FAILURE;
	}
	
	/* close file */
	
	fclose(fp);
	
	return SKLOG_SUCCESS;
}

/*
 * deprecated
 * 
 */
 
SKLOG_RETURN sklog_misc_t_retrieve_logfiles(unsigned char	**uuid_list,
	unsigned int *uuid_list_len)
{
	/**
	 * 
	 * probably will be deprecate
	 * 
	 */
	 
	return SKLOG_SUCCESS;
}

/*
 * ok
 * 
 */
 	
SKLOG_RETURN sklog_misc_t_retrieve_logfiles_v2(char *uuid_list[],
	unsigned int *uuid_list_size)
{
	#ifdef DO_TRACE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	sqlite3 *db = 0;
	sqlite3_stmt *stmt = 0;
	
	char query[BUF_512+1] = { 0x0 };
	
	char *sql_err_msg = 0;
	int sql_step = 0;
	
	int one_step_forward = 1;
	int counter = 0;
	
	const unsigned char *text = 0;
	int bytes = 0;
	
	/* compose query */
	
	snprintf(query, BUF_512, "select * from AUTHKEY");
	
	/* exec query */
	
	
	sqlite3_open(SKLOG_T_DB, &db);
	
	if ( db == NULL ) {
		ERROR("sqlite3_open() failure: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return SKLOG_FAILURE;
	}
	
	rv = sqlite3_prepare_v2(db, query, strlen(query)+1, &stmt, NULL);
	
	if ( rv != SQLITE_OK ) {
		ERROR("sqlite3_prepare_v2() failure: %s", sqlite3_errmsg(db));
		return SKLOG_FAILURE;
	}
	
	/* flush */
	
	while ( one_step_forward > 0 ) {
		
		sql_step = sqlite3_step(stmt);
		
		switch ( sql_step ) {
			
			case SQLITE_ROW:
				text = sqlite3_column_text(stmt,
					TAB_M0MSG_COL_LOGFILEID);
				bytes = sqlite3_column_bytes(stmt,
					TAB_M0MSG_COL_LOGFILEID);
				
				uuid_list[counter] = calloc(bytes+1, sizeof(char));
				memset(uuid_list[counter], 0, bytes+1);
				memcpy(uuid_list[counter], text, bytes);
				counter++;
				break;
				
			case SQLITE_DONE:
				one_step_forward = 0;
				break;
				
			default:
				ERROR("sqlite3_step() failure: %s", sqlite3_errmsg(db));
				one_step_forward = -1;
				break;
		} 
	}
	
	if ( one_step_forward < 0 ) {
		sqlite3_close(db);
		sqlite3_free(sql_err_msg);
		return SKLOG_FAILURE;
	}
	
	*uuid_list_size = counter;
	
	sqlite3_close(db);
	sqlite3_free(sql_err_msg);
		
	return SKLOG_SUCCESS;
}

/*
 * deprecated
 * 
 */
 	
SKLOG_RETURN sklog_misc_t_verify_logfile(unsigned char *uuid)
{
	return SKLOG_SUCCESS;
}

/*
 * ok
 * 
 */

SKLOG_RETURN sklog_misc_t_verify_logfile_v2(char *logfile_id)
{
	#ifdef DO_TARCE
	DEBUG
	#endif
	
	int rv = SKLOG_SUCCESS;
	
	char buf[BUF_4096+1] = { 0x0 };
	
	unsigned char *blob = { 0x0 };
	unsigned int blob_len = 0;
	
	/* SQLite */
	
	sqlite3 *db = 0;
	sqlite3_stmt *stmt = 0;
	char query[BUF_4096+1] = { 0 };
	int  query_len = 0;
	const unsigned char *sql_text = 0;
	
	/* Jansson lib */
	
	json_error_t json_error;
	json_t *log = 0;
	json_t *umberlog_data = 0;
	
	int tmp_type = 0;
	char *tmp_data = 0;
	char *tmp_hash = 0;
	char *tmp_hmac = 0;
	char *tmp_session = 0;
	
	/* file parsing */
	
	char filename[BUF_512+1] = { 0x0 };
	FILE *fp = 0;
	
	char c = 0;
	int eol = 0;
	
	char logentry_prev[BUF_8192+1] = { 0x0 };
	char logentry[BUF_8192+1] = { 0x0 };
	
	int is_the_first = 1;
	
	/* verification */
	
	unsigned char authkey[SKLOG_AUTH_KEY_LEN] = { 0x0 };
	unsigned char authkey_temp[SKLOG_AUTH_KEY_LEN] = { 0x0 };
	
	unsigned char data[BUF_8192+1] = { 0x0 };
	unsigned int data_len = 0;
	
	unsigned char type[BUF_512+1] = { 0x0 };
	unsigned int type_len = 0;
	
	EVP_MD_CTX mdctx;
	
	/* previous values */
	
	unsigned char hash_p[SKLOG_HASH_CHAIN_LEN] = { 0x0 };
	unsigned char hmac_p[SKLOG_HMAC_LEN] = { 0x0 };
	
	/* current values */
	
	unsigned char hash_c[SKLOG_HASH_CHAIN_LEN] = { 0x0 };
	unsigned char hmac_c[SKLOG_HMAC_LEN] = { 0x0 };
	
	/* re-generated values */
	
	unsigned char hash_g[SKLOG_HASH_CHAIN_LEN] = { 0x0 };
	unsigned char hmac_g[SKLOG_HMAC_LEN] = { 0x0 };
	
	/* ------- */
	/*  start  */
	/* ------- */
	
	/* check input parameters */
	
	if ( logfile_id == NULL ) {
		ERROR(MSG_BAD_INPUT_PARAMS);
		return SKLOG_FAILURE;
	}
	
	/* -------------------- */
	/*  get authkey from db */
	/* -------------------- */
	
	query_len = snprintf(query, BUF_4096,
		"SELECT * FROM AUTHKEY WHERE f_uuid='%s'",
		logfile_id);
		
	sqlite3_open(SKLOG_T_DB, &db);
	
	if ( db == NULL ) {
		ERROR("sqlite3_open() failure: %s", sqlite3_errmsg(db));
		goto db_error;
	}
	
	rv = sqlite3_prepare_v2(db, query, query_len, &stmt, NULL);
	
	if ( rv != SQLITE_OK ) {
		ERROR("sqlite3_prepare_v2() failure: %s", sqlite3_errmsg(db));
		goto db_error;
	}
	
	rv = sqlite3_step(stmt);
	
	if ( rv == SQLITE_ROW ) {
		
		sql_text = sqlite3_column_text(stmt, TAB_AUTHKEY_COL_AUTHKEY);
		
		rv = snprintf(buf, BUF_4096, "%s", sql_text);
		
		if ( rv < 0 ) {
			ERROR("snprintf() failure");
			goto db_error;
		}
		
		rv = b64_dec(buf, strlen(buf), &blob, &blob_len);
		memset(buf, 0, BUF_4096); 
		
		if ( rv == SKLOG_FAILURE ) {
			ERROR("b64_dec() failure");
			goto db_error;
		}
		
		memcpy(authkey, blob, blob_len);
		free(blob);
		
	} else if (rv == SQLITE_DONE) {
		WARNING(MSG_SQL_SELECT_EMPTY);
		goto db_error;
	} else {
		ERROR("sqlite3_step() failure: %s", sqlite3_errmsg(db));
		goto db_error;
	}
	
	sqlite3_close(db);
	db = 0;
	
	/* ---------------------------- */
	/*  start verification process  */
	/* ---------------------------- */
	
	/* open file */
	
	rv = snprintf(filename, BUF_512, "%s/T/%s.log", LOGFILE_PATH,
		logfile_id);
	/*	
	rv = snprintf(filename, BUF_512, "%s/%s.log", LOGFILE_PATH,
		logfile_id);
	*/
		
	if ( rv < 0 ) {
		ERROR("snprintf() failure");
		goto error;
	}
	
	fp = fopen(filename, "r");
	
	if ( fp == NULL ) {
		ERROR("Unable to open file %s", filename);
		goto error;
	}
	
	while ( !feof(fp) ) {
		
		fgets(logentry, BUF_8192, fp);
		
		eol = strlen(logentry);
		logentry[eol-1]='\0';
		
		c = logentry[0];
		
		if ( c == '#' || c == '\n' || c == '\0' ) {
			memset(logentry, 0, BUF_8192);
			continue;
		}
		
		if ( is_the_first ) {
			memcpy(logentry_prev, logentry, BUF_8192);
			is_the_first = 0;
		}
		
		/* ---------------- */
		/*  parse logentry  */
		/* ---------------- */
		
		memset(&json_error, 0, sizeof(json_error));
		
		log = json_loads(logentry, JSON_DECODE_ANY, &json_error);
		
		if ( log == NULL ) {
			ERROR("json_loads() failure: %s", json_error.text);
			goto error;
		}
		
		memset(&json_error, 0, sizeof(json_error));
		
		rv = json_unpack_ex(log, &json_error, JSON_STRICT,
			"{s:s, s:i, s:o, s:s, s:s}",
			"sk_session", &tmp_session,
			"sk_type", &tmp_type,
			"sk_data", &umberlog_data,
			"sk_hash", &tmp_hash,
			"sk_hmac", &tmp_hmac
		);
		
		if ( rv < 0 ) {
			ERROR("json_unpack_ex() failure: %s", json_error.text);
			goto error;
		}
		
		if ( umberlog_data == NULL ) {
			ERROR("json_unpack_ex() failure");
			goto error;
		}
		
		/* get type */
		
		type_len = sizeof(tmp_type);
		memcpy(type, &tmp_type, type_len);
		
		/* get data */
		
		tmp_data = json_dumps(umberlog_data,
			JSON_COMPACT | JSON_PRESERVE_ORDER | JSON_ENSURE_ASCII);
		
		if ( tmp_data == NULL ) {
			ERROR("json_dumps() failure");
			goto error;
		}
		
		data_len = strlen(tmp_data);
		memcpy(data, tmp_data, data_len); //~ snprintf((char *)data, BUF_8192, "%s", tmp_data);
		free(tmp_data);
		
		/* get hash */
		
		memcpy(buf, tmp_hash, strlen(tmp_hash)); //~ snprintf(buf, BUF_4096, "%s", tmp_hash);
		
		rv = b64_dec(buf, strlen(buf), &blob, &blob_len);

		if ( rv == SKLOG_FAILURE ) {
			ERROR("b64_dec() failure");
			goto error;
		}
		
		memset(buf, 0, BUF_4096);
		
		memcpy(hash_c, blob, blob_len);
		
		free(blob);
		blob_len = 0;
		
		/* get hmac */
		
		memcpy(buf, tmp_hmac, strlen(tmp_hmac)); //~ snprintf(buf, BUF_4096, "%s", tmp_hmac);
		
		rv = b64_dec(buf, strlen(buf), &blob, &blob_len);
		
		if ( rv == SKLOG_FAILURE ) {
			ERROR("b64_dec() failure");
			goto error;
		}
		
		memset(buf, 0, BUF_4096);
		
		memcpy(hmac_c, blob, blob_len);
		
		free(blob);
		blob_len = 0;
		
		/* ----------------- */
		/*  regenerate hash  */
		/* ----------------- */
		
		OpenSSL_add_all_digests();
		ERR_load_crypto_strings();
		
		EVP_MD_CTX_init(&mdctx);
		
		if ( EVP_DigestInit_ex(&mdctx, EVP_sha256(), NULL) == 0 ) {
			ERROR("EVP_DigestInit_ex() failure");
			ERR_print_errors_fp(stderr);
			goto openssl_error;
		}
	
		if ( EVP_DigestUpdate(&mdctx, hash_p, SKLOG_HASH_CHAIN_LEN) == 0 ) {
			ERROR("EVP_DigestUpdate() failure");
			ERR_print_errors_fp(stderr);
			goto openssl_error;
		}
		
		if ( EVP_DigestUpdate(&mdctx, data, data_len) == 0 ) {
			ERROR("EVP_DigestUpdate() failure");
			ERR_print_errors_fp(stderr);
			goto openssl_error;
		}
		
		if ( EVP_DigestUpdate(&mdctx, type, type_len) == 0 ) {
			ERROR("EVP_DigestUpdate() failure");
			ERR_print_errors_fp(stderr);
			goto openssl_error;
		}
	
		if ( EVP_DigestFinal_ex(&mdctx, hash_g, NULL) == 0 ) {
			ERROR("EVP_DigestFinal_ex() failure");
			ERR_print_errors_fp(stderr);
			goto openssl_error;
		}

		EVP_MD_CTX_cleanup(&mdctx);
		ERR_free_strings();
		
		/* ----------------- */
		/*  regenerate hmac  */
		/* ----------------- */
		
		rv = hmac(hash_g, SKLOG_HASH_CHAIN_LEN, authkey,
			SKLOG_AUTH_KEY_LEN, hmac_g, NULL);
			
		if ( rv == SKLOG_FAILURE ) {
			ERROR("hmac() failure");
			goto error;
		}
		
		/* ---------------- */
		/*  verify results  */
		/* ---------------- */
		
		rv = memcmp(hash_g, hash_c, SKLOG_HASH_CHAIN_LEN);

		if ( rv != 0 ) {
			ERROR("Verification Failure: message digests are not equal!");
			goto verification_failure;
		}
		
		rv = memcmp(hmac_g, hmac_c, SKLOG_HMAC_LEN);
		
		if ( rv != 0 ) {
			ERROR("Verification Failure: hmac are not equal!");
			goto verification_failure;
		}
		
		/* --------------- */
		/*  renew authkey  */
		/* --------------- */
		
		rv = sha256(authkey, SKLOG_AUTH_KEY_LEN, authkey_temp, NULL);
		
		if ( rv == SKLOG_FAILURE ) {
			ERROR("sha256() failure");
			goto error;
		}
		
		memcpy(authkey, authkey_temp, SKLOG_AUTH_KEY_LEN);
		memset(authkey_temp, 0, SKLOG_AUTH_KEY_LEN);
		
		/* ----------- */
		/*  save data  */
		/* ----------- */
		
		memcpy(hash_p, hash_c, SKLOG_HASH_CHAIN_LEN);
		memcpy(hmac_p, hmac_c, SKLOG_HMAC_LEN);
	}
	
	fclose(fp);
	
	return SKLOG_SUCCESS;

db_error:
	if ( db != NULL ) 
		sqlite3_close(db);
	goto error;

openssl_error:
	EVP_MD_CTX_cleanup(&mdctx);
	ERR_free_strings();
	goto error;

verification_failure:
	if ( fp != NULL ) 
		fclose(fp);
	return SKLOG_VERIFICATION_FAILURE;
	
error:
	if ( fp != NULL ) 
		fclose(fp);
	return SKLOG_FAILURE;
}






















