/*
**	Copyright (C) 2011 Politecnico di Torino, Italy
**
**		TORSEC group -- http://security.polito.it
**		Author: Paolo Smiraglia <paolo.smiraglia@polito.it>
**
**	This file is part of Libsklog.
**
**	Libsklog is free software: you can redistribute it and/or modify
**	it under the terms of the GNU General Public License as published by
**	the Free Software Foundation; either version 2 of the License, or
**	(at your option) any later version.
**
**	Libsklog is distributed in the hope that it will be useful,
**	but WITHOUT ANY WARRANTY; without even the implied warranty of
**	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**	GNU General Public License for more details.
**
**	You should have received a copy of the GNU General Public License
**	along with Libsklog.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SKLOG_T_H
#define SKLOG_T_H

#include "sklog_commons.h"
#include "sklog_t_internal.h"

SKLOG_T_Ctx* SKLOG_T_NewCtx(void);

SKLOG_RETURN SKLOG_T_FreeCtx(SKLOG_T_Ctx **t_ctx);

SKLOG_RETURN SKLOG_T_InitCtx(SKLOG_T_Ctx *t_ctx);

SKLOG_RETURN SKLOG_T_ManageLoggingSessionInit(SKLOG_T_Ctx *t_ctx,
	unsigned char *m0, unsigned int m0_len, char *u_address,
	unsigned char **m1, unsigned int *m1_len);

SKLOG_RETURN SKLOG_T_ManageLogfileUpload(SKLOG_T_Ctx *t_ctx,
	SKLOG_CONNECTION *c);

SKLOG_RETURN SKLOG_T_ManageLogfileRetrieve(SKLOG_T_Ctx *t_ctx,
	char *logfile_list[], unsigned int *logfile_list_len);

SKLOG_RETURN SKLOG_T_ManageLogfileVerify(SKLOG_T_Ctx *t_ctx,
	char *logfile_id);

SKLOG_RETURN SKLOG_T_RunServer(SKLOG_T_Ctx *t_ctx);

#endif /* SKLOG_T_H */
