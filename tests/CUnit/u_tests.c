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

#include <sklog_u.h>


SKLOG_U_Ctx *uctx = 0;


int init_uSuite(void)
{
	return 0;
}

int clean_uSuite(void)
{
	return 0;
}

void test_SKLOG_U_NewCtx(void) {
	uctx = SKLOG_U_NewCtx();
	CU_ASSERT_PTR_NOT_NULL_FATAL(uctx);
}

void test_SKLOG_U_Open(void) {
	CU_PASS(TEST_TO_IMPLEMENT)
}

void test_SKLOG_U_LogEvent(void) {
	CU_PASS(TEST_TO_IMPLEMENT)
}

void test_SKLOG_U_Close(void) {
	CU_PASS(TEST_TO_IMPLEMENT)
}

void test_SKLOG_U_FreeCtx(void) {
	
	int rv = SKLOG_SUCCESS;
	
	SKLOG_U_Ctx *tmp = 0;
	
	rv = SKLOG_U_FreeCtx(&tmp);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_FAILURE);
	
	rv = SKLOG_U_FreeCtx(&uctx);
	CU_ASSERT_EQUAL_FATAL(rv,SKLOG_SUCCESS);
	CU_ASSERT_PTR_NULL_FATAL(uctx);
}
