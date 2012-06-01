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

#ifndef SKLOG_U_H
#define SKLOG_U_H

#include "sklog_commons.h"
#include "sklog_u_internal.h"

SKLOG_U_Ctx *
SKLOG_U_NewCtx (void);

SKLOG_RETURN
SKLOG_U_InitCtx (SKLOG_U_Ctx *ctx);

SKLOG_RETURN
SKLOG_U_FreeCtx (SKLOG_U_Ctx **ctx);

SKLOG_RETURN
SKLOG_U_LogEvent (SKLOG_U_Ctx *ctx, SKLOG_DATA_TYPE type,
				  char *event, unsigned int event_len, char **logentry,
				  unsigned int *logentry_len);

SKLOG_RETURN
SKLOG_U_Open (SKLOG_U_Ctx *ctx, char **le1, unsigned int *le1_len,
			  char **le2, unsigned int *le2_len);
	
SKLOG_RETURN
SKLOG_U_Open_M0 (SKLOG_U_Ctx *ctx, unsigned char **m0,
				 unsigned int *m0_len, char **logentry,
				 unsigned int *logentry_len);
	
SKLOG_RETURN
SKLOG_U_Open_M1 (SKLOG_U_Ctx *ctx, unsigned char *m1,
				 unsigned int m1_len, char **logentry,
				 unsigned int *logentry_len);

SKLOG_RETURN
SKLOG_U_Close (SKLOG_U_Ctx *ctx, char **logentry,
			   unsigned int *logentry_len);
	
SKLOG_RETURN
SKLOG_U_FlushLogfile (SKLOG_U_Ctx *ctx, char *logs[],
					  unsigned int *logs_size);
	
SKLOG_RETURN
SKLOG_U_DumpLogfile (SKLOG_U_Ctx *ctx, const char *filename,
					 SKLOG_DUMP_MODE dump_mode);

#endif /* SKLOG_U_H */
