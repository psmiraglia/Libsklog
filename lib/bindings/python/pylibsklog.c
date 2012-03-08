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

/*
 * Bind Python function names to our C functions
 */

static PyMethodDef pylibsklog_methods[] = {
    {"SKLOG_U_NewCtx", py_SKLOG_U_NewCtx, METH_VARARGS},
    {"SKLOG_U_Open", py_SKLOG_U_Open, METH_VARARGS},
    {"SKLOG_U_LogEvent", py_SKLOG_U_LogEvent, METH_VARARGS},
    {"SKLOG_U_Close", py_SKLOG_U_Close, METH_VARARGS},
    {"SKLOG_U_FreeCtx", py_SKLOG_U_FreeCtx, METH_VARARGS},
    {NULL, NULL}
};

/*
 * Python calls this to let us initialize our module
 */

void initlibsklog()
{
	(void) Py_InitModule("libsklog", pylibsklog_methods);
}
