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

#include "sklog_u.h"
#include "sklog_t.h"
#include "sklog_internal.h"

#include <string.h>

#include <uuid/uuid.h>

/*
 * U API bindings
 * 
 */
 
static PyObject *py_SKLOG_U_NewCtx(PyObject *self, PyObject *args)
{
    SKLOG_U_Ctx *ctx = SKLOG_U_NewCtx();

    if ( ctx == NULL ) {
        ERROR("SKLOG_U_NewCtx() failure");
        return Py_BuildValue("i", SKLOG_FAILURE);
    }

    return Py_BuildValue("l", ctx);
}

static PyObject *py_SKLOG_U_InitCtx(PyObject *self, PyObject *args)
{
	int rv = SKLOG_SUCCESS;
	
	SKLOG_U_Ctx *ctx = 0;
	long int ctx_addr = 0;
	
	/* parse input arguments */
	
	PyArg_ParseTuple(args, "l", &ctx_addr);
	
	ctx = (SKLOG_U_Ctx *) ctx_addr;
	
	/* --------- */
    /*  binding  */
    /* --------- */
	
	rv = SKLOG_U_InitCtx(ctx);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_U_InitCtx() failure");
		return Py_BuildValue("i", SKLOG_FAILURE);
	}
	
	return Py_BuildValue("i", SKLOG_SUCCESS);
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

static PyObject *py_SKLOG_U_Open_M0(PyObject *self, PyObject *args)
{
	int rv = SKLOG_SUCCESS;
	
	SKLOG_U_Ctx *ctx = 0;
	long int ctx_addr = 0;
	
	unsigned char *m0 = 0;
	unsigned int m0_len = 0;
	
	char *logentry = 0;
	unsigned int logentry_len = 0;
	
	char *b64 = 0;
	
	/* parse input arguments */
	
	PyArg_ParseTuple(args, "l", &ctx_addr);
	
	ctx = (SKLOG_U_Ctx *) ctx_addr;
	
	/* --------- */
    /*  binding  */
    /* --------- */
	
	rv = SKLOG_U_Open_M0(ctx, &m0, &m0_len, &logentry, &logentry_len);
		
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_U_Open_MO() failure");
		return Py_BuildValue("i", rv);
	}
	
	/* encode M0 as base64 */
	
	rv = b64_enc(m0, m0_len, &b64);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_enc() failure");
		return Py_BuildValue("i", rv);
	}
	
	free(m0);
	
	/* return */
	
	return Py_BuildValue("s#s#", b64, strlen(b64), logentry,
		logentry_len);
}

static PyObject *py_SKLOG_U_Open_M1(PyObject *self, PyObject *args)
{
	int rv = 0;
	
	SKLOG_U_Ctx *ctx = 0;
    long int ctx_addr = 0;
    
    unsigned char *m1 = 0;
    unsigned int m1_len = 0;
    
    char *logentry = 0;
	unsigned int logentry_len = 0;
    
    char b64[BUF_4096+1] = { 0x0 };
    
    /* parse input arguments */
    
	PyArg_ParseTuple(args,"ls",&ctx_addr, b64);
    
    ctx = (SKLOG_U_Ctx *) ctx_addr;
    
    rv = b64_dec(b64, strlen(b64), &m1, &m1_len);
    
    if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_dec() failure");
		return Py_BuildValue("i", rv);
	}
	
	/* ---------- */
	/*  bindings  */
	/* ---------- */
    
    rv = SKLOG_U_Open_M1(ctx, m1, m1_len, &logentry, &logentry_len);
    
    if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_U_Open_M1() failure");
		return Py_BuildValue("i", rv);
	}
	
	free(m1);
	
	/* return */
	
	return Py_BuildValue("s#", logentry, logentry_len);
}

static PyObject *py_SKLOG_U_LogEvent(PyObject *self, PyObject *args)
{
	int rv = SKLOG_SUCCESS;
    
    SKLOG_U_Ctx *ctx = 0;
    long int ctx_addr = 0;
    
    char *logentry = 0;
    unsigned int logentry_len = 0;
    
    int type = 0;
    char *data = 0;
    unsigned int data_len = 0;
    
	/* parse input parameters */
	
    PyArg_ParseTuple(args, "lls#", &ctx_addr, &type, &data, &data_len);

    ctx = (SKLOG_U_Ctx *)ctx_addr;
    
    /* --------- */
    /*  binding  */
    /* --------- */
    
    rv = SKLOG_U_LogEvent(ctx, type, data, data_len, &logentry,
		&logentry_len);

    if ( rv == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_LogEvent() failure");
        return Py_BuildValue("i", rv);
    }
    
    free(data);
    
    /* return */
    
    return Py_BuildValue("s#", logentry, logentry_len);
}

static PyObject *py_SKLOG_U_Close(PyObject *self, PyObject *args)
{
	int rv = SKLOG_SUCCESS;

    SKLOG_U_Ctx *ctx = 0;
    long int ctx_addr = 0;
    
    char *logentry = 0;
    unsigned int logentry_len = 0;
    
	/* parse input parameters */
	
    PyArg_ParseTuple(args,"l",&ctx_addr);
    
    ctx = (SKLOG_U_Ctx *)ctx_addr;
    
    /* --------- */
    /*  binding  */
    /* --------- */
    
    rv = SKLOG_U_Close(ctx, &logentry, &logentry_len);

    if ( rv == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_Close() failure");
        return Py_BuildValue("i", rv);
    }
    
    /* return */
    
    return Py_BuildValue("s#", logentry, logentry_len);
}

static PyObject *py_SKLOG_U_FreeCtx(PyObject *self, PyObject *args)
{
    int rv = SKLOG_SUCCESS;
    
    SKLOG_U_Ctx *ctx = 0;
    long int ctx_addr = 0;

	/* parse input parameters */
	
    PyArg_ParseTuple(args, "l", &ctx_addr);
    
    ctx = (SKLOG_U_Ctx *) ctx_addr;
    
    /* --------- */
    /*  binding  */
    /* --------- */

	rv = SKLOG_U_FreeCtx(&ctx);

    if ( rv == SKLOG_FAILURE ) {
        ERROR("SKLOG_U_FreeCtx() failure");
        return Py_BuildValue("i", rv);
    }

    return Py_BuildValue("i", rv);
}


/*
 * T API bindings
 * 
 */

static PyObject *py_SKLOG_T_NewCtx(PyObject *self, PyObject *args)
{
    SKLOG_T_Ctx *ctx = SKLOG_T_NewCtx();

    if ( ctx == NULL ) {
        ERROR("SKLOG_T_NewCtx() failure");
        return Py_BuildValue("i", SKLOG_FAILURE);
    }

    return Py_BuildValue("l", ctx);	
}

static PyObject *py_SKLOG_T_InitCtx(PyObject *self, PyObject *args)
{
	int rv = SKLOG_SUCCESS;
	
	SKLOG_T_Ctx *ctx = 0;
	long int ctx_addr = 0;
	
	/* parse input arguments */
	
	PyArg_ParseTuple(args, "l", &ctx_addr);
	
	ctx = (SKLOG_T_Ctx *) ctx_addr;
	
	/* --------- */
    /*  binding  */
    /* --------- */
	
	rv = SKLOG_T_InitCtx(ctx);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_T_InitCtx() failure");
		return Py_BuildValue("i", rv);
	}
	
	return Py_BuildValue("i", rv);
}

static PyObject *py_SKLOG_T_FreeCtx(PyObject *self, PyObject *args)
{
	int rv = SKLOG_SUCCESS;
    
    SKLOG_T_Ctx *ctx = 0;
    long int ctx_addr = 0;

	/* parse input parameters */
	
    PyArg_ParseTuple(args, "l", &ctx_addr);
    
    ctx = (SKLOG_T_Ctx *) ctx_addr;
    
    /* --------- */
    /*  binding  */
    /* --------- */

	rv = SKLOG_T_FreeCtx(&ctx);

    if ( rv == SKLOG_FAILURE ) {
        ERROR("SKLOG_T_FreeCtx() failure");
        return Py_BuildValue("i", rv);
    }

    return Py_BuildValue("i", rv);
}

static PyObject *py_SKLOG_T_ManageLoggingSessionInit(PyObject* self, PyObject* args)
{
	int rv = SKLOG_SUCCESS;
	
	SKLOG_T_Ctx *ctx = 0;
	long int ctx_addr = 0;
	
	char *b64 = 0;
	
	char *host = "127.0.0.1";
	
	unsigned char *m0 = 0;
	unsigned int m0_len = 0;
	
	unsigned char *m1 = 0;
	unsigned int m1_len = 0;
	
	/* parse input arguments */
	
	PyArg_ParseTuple(args, "ls", &ctx_addr, &b64);
	
	NOTIFY("%s", b64);
	
	ctx = (SKLOG_T_Ctx *) ctx_addr;
	
	rv = b64_dec(b64, strlen(b64), &m0, &m0_len);
    
    if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_dec() failure");
		return Py_BuildValue("i", rv);
	}
	
	/* --------- */
    /*  binding  */
    /* --------- */
    
    rv = SKLOG_T_ManageLoggingSessionInit(ctx, m0, m0_len, host,
		&m1, &m1_len);
    
    if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_T_ManageLoggingSessionInit() failure");
		return Py_BuildValue("i", rv);
	}
	
	rv = b64_enc(m1, m1_len, &b64);
	
	if ( rv == SKLOG_FAILURE ) {
		ERROR("b64_enc() failure");
		return Py_BuildValue("i", rv);
	}
	
	return Py_BuildValue("s#", b64, strlen(b64));
}

static PyObject *py_SKLOG_T_ManageLogfileRetrieve(PyObject *self, PyObject *args)
{
	int rv = SKLOG_SUCCESS;
	
	SKLOG_T_Ctx *ctx = 0;
	long int ctx_addr = 0;
	
	char *list[BUF_1024] = { 0x0 };
	unsigned int list_size = 0;
	
	int i = 0;
	
	PyObject *tuple = 0;
	PyObject *logfile_id = 0;
	
	/* parse input arguments */
	
	PyArg_ParseTuple(args, "l", &ctx_addr);
	
	ctx = (SKLOG_T_Ctx *) ctx_addr;
	
	/* --------- */
    /*  binding  */
    /* --------- */
    
    rv = SKLOG_T_ManageLogfileRetrieve(ctx, list, &list_size);
    
    if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_T_ManageLogfileRetrieve() failure");
		return Py_BuildValue("i", rv);
	}
	
	/* generate tuple */
	
	tuple = PyTuple_New(list_size);
	
	if ( tuple == NULL ) {
		ERROR("PyTuple_New() failure");
		return Py_BuildValue("i", SKLOG_FAILURE);
	}
	
	for ( i = 0 ; i < list_size ; i++ ) {
		
		logfile_id = PyString_FromString(list[i]);
		
		if ( logfile_id == NULL ) {
			ERROR("PyString_FromString() failure");
			return Py_BuildValue("i", SKLOG_FAILURE);
		}
		
		PyTuple_SetItem(tuple, i, logfile_id);
	}
	
	return tuple;
}

static PyObject *py_SKLOG_T_ManageLogfileVerify(PyObject *self, PyObject *args)
{
	int rv = SKLOG_SUCCESS;
	
	SKLOG_T_Ctx *ctx = 0;
	long int ctx_addr = 0;
	
	char *logfile_id = 0x0;
	
	/* parse input arguments */
	
	PyArg_ParseTuple(args, "ls", &ctx_addr, &logfile_id);
	
	ctx = (SKLOG_T_Ctx *) ctx_addr;
	
	/* --------- */
    /*  binding  */
    /* --------- */
    
    rv = SKLOG_T_ManageLogfileVerify(ctx, logfile_id);
    
    if ( rv == SKLOG_FAILURE ) {
		ERROR("SKLOG_T_ManageLogfileVerify() failure");
		return Py_BuildValue("i", rv);
	}
	
	return Py_BuildValue("i", SKLOG_SUCCESS);
}

/*
 * Bind Python function names to our C functions
 * 
 */

static PyMethodDef pylibsklog_methods[] = {
	
    {"SKLOG_U_NewCtx", py_SKLOG_U_NewCtx, METH_VARARGS},
    {"SKLOG_U_InitCtx", py_SKLOG_U_InitCtx, METH_VARARGS},
    {"SKLOG_U_Open", py_SKLOG_U_Open, METH_VARARGS},
    {"SKLOG_U_Open_M0", py_SKLOG_U_Open_M0, METH_VARARGS},
    {"SKLOG_U_Open_M1", py_SKLOG_U_Open_M1, METH_VARARGS},
    {"SKLOG_U_LogEvent", py_SKLOG_U_LogEvent, METH_VARARGS},
    {"SKLOG_U_Close", py_SKLOG_U_Close, METH_VARARGS},
    {"SKLOG_U_FreeCtx", py_SKLOG_U_FreeCtx, METH_VARARGS},
    
    {"SKLOG_T_NewCtx", py_SKLOG_T_NewCtx, METH_VARARGS},
    {"SKLOG_T_FreeCtx", py_SKLOG_T_FreeCtx, METH_VARARGS},
    {"SKLOG_T_InitCtx", py_SKLOG_T_InitCtx, METH_VARARGS},
    {"SKLOG_T_ManageLoggingSessionInit",
		py_SKLOG_T_ManageLoggingSessionInit, METH_VARARGS},
    {"SKLOG_T_ManageLogfileRetrieve",
		py_SKLOG_T_ManageLogfileRetrieve, METH_VARARGS},
    {"SKLOG_T_ManageLogfileVerify",
		py_SKLOG_T_ManageLogfileVerify, METH_VARARGS},
	
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
