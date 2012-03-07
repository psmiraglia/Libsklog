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
#include <uuid/uuid.h>

static int sklog_uuid_unparse(uuid_t u, char *out)
{
	/*
	 * The logfile_id is an UUID which is used to identify a
	 * logging session. Such as id is placed as SYSLOGTAG into
	 * the logentries. In the RFC 3164, the dimension on SYSLOGTAG is
	 * limited to 32 character but the function uuid_unparse_lower()
	 * convert logfile_id in a 36 character string, hence it can't be
	 * used.
	 * 
	 * The function sklog_uuid_unparse() produce the same result of
	 * the function uuid_unparse_lower() removing the four characters
	 * '-' which are part of the standard UUID structure.
	 * 
	 * Esamples:
	 * 
	 * uuid_unparse_lower() produces:
	 * 		
	 * 		b188dc8a-6877-11e1-a215-0025b345ca14 (36 characters)
	 * 
	 * sklog_uuid_unparse() produces:
	 * 
	 * 		b188dc8a687711e1a2150025b345ca14 (32 characters)
	 * 
	 * Ref: http://www.ietf.org/rfc/rfc3164.txt - Section 4.1.3
	 */
	  
	int i = 0;
	int j = 0;
	
	for( i = 0 , j = 0 ; i < UUID_LEN ; i++ , j+=2 )
		sprintf(&out[j],"%2.2x",u[i]);
		
	return 0;
}

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
