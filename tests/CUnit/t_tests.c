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

#include "sklog_tests.h"

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include <sklog_t.h>
#include <sklog_internal.h>

#include <sqlite3.h>

#define  SKLOG_T_DB  VAR_PREFIX"/libsklog/db/t.db"

SKLOG_T_Ctx *tctx = 0;
int rv = SKLOG_SUCCESS;

char logfile_id[UUID_STR_LEN] = { 0 };

unsigned char *m0 = 0;
unsigned int m0_len = 0;

unsigned char *m1 = 0;
unsigned int m1_len = 0;

unsigned char *m1_eval = 0;
unsigned int m1_eval_len = 0;

unsigned char *retrieve_message_eval = 0;
unsigned int retrieve_message_eval_len = 0;

const unsigned char verify_success[8] = {0x00, 0x00, 0x01, 0x04, 0 };
const unsigned char verify_fail[8] = {0x00, 0x00, 0x01, 0x05, 0 };


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

static void clean_database(void)
{
    sqlite3 *db = 0;
    char *err_msg = 0;

    char query1[128] = { 0 };
    char query2[128] = { 0 };
    char query3[128] = { 0 };

    //~ compose query
    sprintf(query1, "delete from AUTHKEY");
    sprintf(query2, "delete from M0MSG");
    sprintf(query3, "delete from LOGENTRY");

    //~ execute query

    sqlite3_open(SKLOG_T_DB, &db);
    
    if ( db == NULL ) {
        fprintf(stderr, "SQLite3: Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    if ( sqlite3_exec(db, query1, sql_callback, 0, &err_msg) != SQLITE_OK ) {
        fprintf(stderr, "SQLite3: SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return;
    }
    
    if ( sqlite3_exec(db, query2, sql_callback, 0, &err_msg) != SQLITE_OK ) {
        fprintf(stderr, "SQLite3: SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return;
    }
    
    if ( sqlite3_exec(db, query3, sql_callback, 0, &err_msg) != SQLITE_OK ) {
        fprintf(stderr, "SQLite3: SQL error: %s\n",err_msg);
        sqlite3_free(err_msg);
        return;
    }

    sqlite3_close(db);

    return;
}

int init_tSuite(void)
{
	FILE *fp = 0;
	
	char b64buf[BUFSIZE] = { 0 };


	/* blank all .out files */
	
	fp = fopen("SKLOG_T_ManageLogfileRetrieve.out","w");
	fclose(fp);
	fp = fopen("SKLOG_T_ManageLogfileUpload.out","w");
	fclose(fp);
	
	/* clean database */
	
	fprintf(stdout, "Database Path: %s\n", SKLOG_T_DB);
	clean_database();
	
	/* load evaluation variables */
	
	/* load M0 */
	
	if ( ( fp = fopen("data/m0_msg.dat", "r") ) == NULL ) {
		fprintf(stderr, "Unable to open file m0_msg.dat\n");
		return 1;
	}
	fscanf(fp, "%s", b64buf);
	fclose(fp);
	
	b64_dec(b64buf, strlen(b64buf), &m0, &m0_len);
	memset(b64buf, 0, BUFSIZE);
	
	/* load M1 */
	
	if ( ( fp = fopen("data/m1_msg_eval.dat", "r") ) == NULL ) {
		fprintf(stderr, "Unable to open file m1_msg_eval.dat\n");
		return 1;
	}
	fscanf(fp, "%s", b64buf);
	fclose(fp);
	
	b64_dec(b64buf, strlen(b64buf), &m1_eval, &m1_eval_len);
	memset(b64buf, 0, BUFSIZE);
	
	/* load retrieve message */
	
	if ( ( fp = fopen("data/retrieve_eval.dat", "r") ) == NULL ) {
		fprintf(stderr, "Unable to open file retrieve_message_eval.dat\n");
		return 1;
	}
	fscanf(fp, "%s", b64buf);
	fclose(fp);
	
	b64_dec(b64buf, strlen(b64buf), &retrieve_message_eval, &retrieve_message_eval_len);
	memset(b64buf, 0, BUFSIZE);
	
	return 0;
}

int clean_tSuite(void)
{
	free(m1);
	free(m1_eval);
	free(retrieve_message_eval);
	return 0;
}

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

//~ OK
void test_SKLOG_T_NewCtx(void)
{
	/** test **/
	
	tctx = SKLOG_T_NewCtx();
	CU_ASSERT_PTR_NOT_NULL(tctx);
}

//~ OK
void test_SKLOG_T_InitCtx(void)
{
	/* checking for malformed inputs */
	
	rv = SKLOG_T_InitCtx(NULL);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_FAILURE);
	
	/** test **/
	
	rv = SKLOG_T_InitCtx(tctx);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_SUCCESS);
}

//~ OK
void test_SKLOG_T_ManageLoggingSessionInit(void)
{
	/* checking for malformed inputs */
	
	rv = SKLOG_T_ManageLoggingSessionInit(NULL,NULL,0,NULL,&m1,&m1_len);
	CU_ASSERT_EQUAL_FATAL(rv, SKLOG_FAILURE);
	
	rv = SKLOG_T_ManageLoggingSessionInit(tctx,NULL,0,NULL,&m1,&m1_len);
	CU_ASSERT_EQUAL_FATAL(rv, SKLOG_FAILURE);
	
	rv = SKLOG_T_ManageLoggingSessionInit(tctx,m0,m0_len,NULL,&m1,&m1_len);
	CU_ASSERT_EQUAL_FATAL(rv, SKLOG_FAILURE);
	
	/** test **/
	
	/* run function */
	
	rv = SKLOG_T_ManageLoggingSessionInit(tctx,m0,m0_len,"127.0.0.1",&m1,&m1_len);
	
	/* check results */
	
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL_FATAL(m1);
	CU_ASSERT_TRUE_FATAL(((m1_len > 0) ? CU_TRUE : CU_FALSE));
	CU_ASSERT_EQUAL_FATAL(m1_len, m1_eval_len);
	CU_ASSERT_STRING_EQUAL_FATAL(m1, m1_eval);
}

//~ OK
void test_SKLOG_T_ManageLogfileRetrieve(void)
{
	FILE *fp = 0;
	
	unsigned char *retrieve_message = 0;
	unsigned int retrieve_message_len = 0;
	
	char b64[BUFSIZE] = { 0 };
	
	/* checking for malformed input */
	
	rv = SKLOG_T_ManageLogfileRetrieve(NULL,NULL);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_FAILURE);
	
	/** test **/
	
	/* run function */
	rv = SKLOG_T_ManageLogfileRetrieve(tctx,NULL);
	
	/* chech results */
	
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_SUCCESS);
	
	/* load retrieve message */
	
	if ( ( fp = fopen("data/retrieve.dat", "r") ) == NULL ) {
		CU_FAIL_FATAL("Unable to open file retrieve_message_eval.dat");
	}
	fscanf(fp, "%s", b64);
	fclose(fp);
	
	b64_dec(b64, strlen(b64), &retrieve_message, &retrieve_message_len);
	memset(b64, 0, BUFSIZE);
	
	CU_ASSERT_STRING_EQUAL_FATAL(retrieve_message, retrieve_message_eval);
	
	free(retrieve_message);
}

//~ OK
void test_SKLOG_T_ManageLogfileUpload(void)
{
	/* checking for malformed input */
	
	rv = SKLOG_T_ManageLogfileUpload(NULL,NULL);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_FAILURE);
	
	/** test **/
	
	rv = SKLOG_T_ManageLogfileUpload(tctx,NULL);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_SUCCESS);
}

//~ OK
void test_SKLOG_T_ManageLogfileVerify(void)
{
	FILE *fp = 0;
	unsigned char *blob = 0;
	unsigned int blob_len = 0;
	
	char b64[BUFSIZE] = { 0 };
	
	/* checking for malformed input */
	
	rv = SKLOG_T_ManageLogfileVerify(NULL,NULL,NULL);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_FAILURE);
	
	rv = SKLOG_T_ManageLogfileVerify(tctx,NULL,NULL);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_FAILURE);
	
	/** test **/
	
	/* get logfileid */
	
	if ( ( fp = fopen("data/logfileid.dat", "r") ) == NULL ) {
		CU_FAIL_FATAL("Unable to open file");
	}
	
	fscanf(fp, "%s", b64);
	fclose(fp);
	b64_dec(b64, strlen(b64), &blob, &blob_len);
	
	sklog_uuid_unparse(blob, logfile_id);
	
	free(blob);
	memset(b64, 0, BUFSIZE);
	
	/* run function */
	
	rv = SKLOG_T_ManageLogfileVerify(tctx,NULL,logfile_id);
	
	/* check results */
	
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_SUCCESS);
	
	/* get verify result */
	
	if ( ( fp = fopen("data/verify_result.dat", "r") ) == NULL ) {
		CU_FAIL_FATAL("Unable to open file");
	}
	
	fscanf(fp, "%s", b64);
	fclose(fp);
	b64_dec(b64, strlen(b64), &blob, &blob_len);
	
	CU_ASSERT_STRING_EQUAL_FATAL(blob, verify_success);
	
	free(blob);
	memset(b64, 0, BUFSIZE);
}

//~ OK
void test_SKLOG_T_FreeCtx(void)
{
	SKLOG_T_Ctx *tmp = 0;
	
	/* checking for malformed input */
	
	rv = SKLOG_T_FreeCtx(&tmp);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_FAILURE);
	
	/* test */
	
	rv = SKLOG_T_FreeCtx(&tctx);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_SUCCESS);
	CU_ASSERT_PTR_NULL_FATAL(tctx);
}
