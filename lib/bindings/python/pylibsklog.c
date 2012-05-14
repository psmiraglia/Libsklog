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

#include <Python.h>

#include <string.h>
#include <sklog_u.h>
#include <sklog_t.h>
#include <sklog_internal.h>
#include <uuid/uuid.h>

static PyObject *py_SKLOG_U_NewCtx(PyObject* self, PyObject* args)
{
    SKLOG_U_Ctx *ctx = SKLOG_U_NewCtx();

    if ( ctx == NULL ) {
        ERROR("SKLOG_U_NewCtx() failure");
        return Py_BuildValue("s","SKLOG_U_NewCtx() failure");
    }

    return Py_BuildValue("l",ctx);
}

static PyObject *py_SKLOG_U_Open(PyObject* self, PyObject* args)
{
    char *le1 = 0;
    char *le2 = 0;
    unsigned int le1_len = 0;
    unsigned int le2_len = 0;
    
    //~ char logid[UUID_STR_LEN+1] = {0};
    char logid[SKLOG_UUID_STR_LEN+1] = {0};
    

    long int ctx_addr = 0;
    SKLOG_U_Ctx *ctx = 0;

    PyArg_ParseTuple(args,"l",&ctx_addr);
    ctx = (SKLOG_U_Ctx *)ctx_addr;

    if ( SKLOG_U_Open(ctx,&le1,&le1_len,&le2,&le2_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_Open() failure");
        return Py_BuildValue("s","SKLOG_U_Open() failure");
    }
    
    //~ uuid_unparse_lower(ctx->logfile_id,logid);
    sklog_uuid_unparse(ctx->logfile_id,logid);
    
    //~ return Py_BuildValue("s#s#s#",logid,UUID_STR_LEN,le1,le1_len,le2,le2_len);
    return Py_BuildValue("s#s#s#",logid,SKLOG_UUID_STR_LEN,le1,le1_len,le2,le2_len);
}

static PyObject *py_SKLOG_U_Open_m0(PyObject* self, PyObject* args)
{
	SKLOG_U_Ctx *ctx = 0;
    long int ctx_addr = 0;
	
	unsigned char *m0 = 0;
	unsigned int m0_len = 0;
	
	char *le1 = 0;
	unsigned int le1_len = 0;
	
	struct timeval timeout;
	
	char *b64 = 0;
	
	int rv = 0;

	/* get U context */
	
	PyArg_ParseTuple(args,"l",&ctx_addr);
    ctx = (SKLOG_U_Ctx *)ctx_addr;
    
    /* initialize context */
	
	rv = initialize_context(ctx);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("context initialization process fails")
        goto error;
	}
	
	ctx->logging_session_mgmt = SKLOG_MANUAL;
	
	/* generate m0 */
	
	rv = generate_m0_message(ctx, &m0, &m0_len, &timeout, &le1,
		&le1_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("generate_m0_message() failure");
		goto error;
	}
	
	/* return */
	
	b64_enc(m0, m0_len, &b64);
	
	return Py_BuildValue("s#s#", b64, strlen(b64), le1, le1_len);
	
error:
	return Py_BuildValue("");
}

static PyObject *py_SKLOG_U_Open_m1(PyObject* self, PyObject* args)
{
	int rv = 0;
	
	SKLOG_U_Ctx *ctx = 0;
    long int ctx_addr = 0;
    
    char m1_b64[4096] = { 0 };
    
    unsigned char *m1 = 0;
    unsigned int m1_len = 0;
    
    char *le2 = 0;
	unsigned int le2_len = 0;
	
	struct timeval timeout;
    
    
	
	PyArg_ParseTuple(args,"ls",&ctx_addr, m1_b64);
    
    /* get U context */
    
    ctx = (SKLOG_U_Ctx *)ctx_addr;
    
    /* get m1 message and decode from base64 */
    
    b64_dec(m1_b64, strlen(m1_b64), &m1, &m1_len);
    
    /* check m1 message */
    
    rv = verify_m1_message(ctx, m1, m1_len, &timeout, &le2, &le2_len);
    
    if ( rv == SKLOG_FAILURE ) {
		ERROR("verify_m1_message() failure");
		goto error;
	}
	
	/* free memory */
	
	free(m1);
	
	return Py_BuildValue("s#", le2, le2_len);
	
error:

	/* free memory */
	
	if ( m1 ) 
		free(m1);
	
	return Py_BuildValue("");
}

static PyObject *py_SKLOG_U_LogEvent(PyObject* self, PyObject* args)
{
    char *le1 = 0;
    unsigned int le1_len = 0;

    int type = 0;
    char *data = 0;
    unsigned int data_len = 0;

    long int ctx_addr = 0;
    SKLOG_U_Ctx *ctx = 0;
    
    //~ char logid[UUID_STR_LEN+1] = {0};
    char logid[SKLOG_UUID_STR_LEN+1] = {0};

    PyArg_ParseTuple(args,"lls#",&ctx_addr,&type,&data,&data_len);

    ctx = (SKLOG_U_Ctx *)ctx_addr;

    if ( SKLOG_U_LogEvent(ctx,type,data,data_len,&le1,&le1_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_LogEvent() failure");
        return Py_BuildValue("s","SKLOG_U_LogEvent() failure");
    }
    
    //~ uuid_unparse_lower(ctx->logfile_id,logid);
    sklog_uuid_unparse(ctx->logfile_id,logid);

    //~ return Py_BuildValue("s#s#",logid,UUID_STR_LEN,le1,le1_len);
    return Py_BuildValue("s#s#",logid,SKLOG_UUID_STR_LEN,le1,le1_len);
}

static PyObject *py_SKLOG_U_Close(PyObject* self, PyObject* args)
{
    char *le1 = 0;
    unsigned int le1_len = 0;

    long int ctx_addr = 0;
    SKLOG_U_Ctx *ctx = 0;
    
    //~ char logid[UUID_STR_LEN+1] = {0};
    char logid[SKLOG_UUID_STR_LEN+1] = {0};

    PyArg_ParseTuple(args,"l",&ctx_addr);
    ctx = (SKLOG_U_Ctx *)ctx_addr;

    if ( SKLOG_U_Close(ctx,&le1,&le1_len) == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_Close() failure");
        return Py_BuildValue("s","SKLOG_U_Close() failure");
    }
    
    //~ uuid_unparse_lower(ctx->logfile_id,logid);
    sklog_uuid_unparse(ctx->logfile_id,logid);
    
    //~ return Py_BuildValue("s#s#",logid,UUID_STR_LEN,le1,le1_len);
    return Py_BuildValue("s#s#",logid,SKLOG_UUID_STR_LEN,le1,le1_len);
}

static PyObject *py_SKLOG_U_FreeCtx(PyObject* self, PyObject* args)
{
    long int ctx_addr = 0;
    SKLOG_U_Ctx *ctx = 0;

    PyArg_ParseTuple(args,"l",&ctx_addr);
    ctx = (SKLOG_U_Ctx *)ctx_addr;

    if ( SKLOG_U_FreeCtx(&ctx) == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_FreeCtx() failure");
        return Py_BuildValue("s","SKLOG_U_FreeCtx() failure");
    }

    return Py_BuildValue("");
}

static PyObject *py_SKLOG_T_ManageLoggingSessionInit(PyObject* self, PyObject* args)
{
	const char *m1_msg = 
	"AAAADgAAAAQAAAABAAAACAAAAA10LmV4YW1wbGUuY29tAAAAEAAAAICEAQn6EmzsFn"
	"+8EUUxCAsCaPEOfJr1rC+6OWT/yHhMrq0fZRQ5jMVNW2Gzu4AgKD/7s5ZaySgzkXP8"
	"Aa9YJMSM0rruFgaWepfZqgk14lsnpACfemPZz2e6F8Wne7edc/2vcsnoB6wLzp3lJt"
	"y8zKEhzE9KGmpWkiH8yrr7tjFUlwAAAAUAAAJQZpA8gzPenPc265YV5vOKPNMq99lg"
	"ut5bQOzr/cEd+vEvhRG8mWSIcCV/fae2Z6g5iubSCW/hAYoKsIVPjv6BfeVZTV40LS"
	"arS4JJXZO0wBrTK+PBTcxIR1HRfAfZVMY1wfC7ryYfJK6rI55faybNLkHooc2XzpZy"
	"3hmRXwNVitOjs3rVzkAWXstAim3a2Z3VwZnCI8srk5DMLtZ95wIM8IAXJNbe1zVRTl"
	"DdRmKe5BRMFKK41PxgoDa+EjXW/uk3jaqkmRnusEq3r9ezwf8w+90I9wZEBvQtwlgz"
	"LMJipSeeoeSB4po2WEQwrydvSD89/zkb24Ch00Uyr5kh65yKV0NvKUq59KI+YhuUNg"
	"p/c2u8K+TDKtc62/48FJ5aIZOHggKXdwJfluJ6R3DhnvHxkFCwA88ErTcUw3YDo03H"
	"OfhtAfisMVq8EYmnQ8awqR92+TnEovQ/ANAvapMenA439xMAKcQWljRIPEIAXEHt/c"
	"RKrYAwF8DduIETzG+HZaPnBsxJDPadbJQG2eUXFmr1lDpyTxPgJNCYpbGHWs24K5en"
	"g1TOI7tcnPMovtzaggyb1Mpc5HSwPgpyC+T6mi5Ba85wn3cM21BgZdCC+WBMg7iCs5"
	"gu1Qr7UCoq9gUSqJHaFe10VSgtZo5gKZHEDFa9qzUcGOXg05pg/oR2XvjkBjEroQgn"
	"xfTMm2JdIAaxSg2G+7mb5O1gtvXWVgoMp8kZRjrURGaNGbydSculGeuy3m9P9EUdJC"
	"Z5mn+gWXAnrDV8J9BasQnCD4B0MYD+rQcnNw==";

	return Py_BuildValue("s#", m1_msg, strlen(m1_msg));
}

/*
 * Bind Python function names to our C functions
 * 
 */

static PyMethodDef pylibsklog_methods[] = {
    {"SKLOG_U_NewCtx", py_SKLOG_U_NewCtx, METH_VARARGS},
    {"SKLOG_U_Open", py_SKLOG_U_Open, METH_VARARGS},
    {"SKLOG_U_Open_m0", py_SKLOG_U_Open_m0, METH_VARARGS},
    {"SKLOG_U_Open_m1", py_SKLOG_U_Open_m1, METH_VARARGS},
    {"SKLOG_U_LogEvent", py_SKLOG_U_LogEvent, METH_VARARGS},
    {"SKLOG_U_Close", py_SKLOG_U_Close, METH_VARARGS},
    {"SKLOG_U_FreeCtx", py_SKLOG_U_FreeCtx, METH_VARARGS},
    {"SKLOG_T_ManageLoggingSessionInit", py_SKLOG_T_ManageLoggingSessionInit, METH_VARARGS},
    {NULL, NULL}
};

/*
 * Python calls this to let us initialize our module
 * 
 */

void initlibsklog()
{
	(void) Py_InitModule("libsklog", pylibsklog_methods);
}
