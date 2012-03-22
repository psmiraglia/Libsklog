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

#ifndef CUNIT_SKLOG_TESTS
#define CUNIT_SKLOG_TESTS

/*--------------------------------------------------------------------*/
/*                              U tests                               */
/*--------------------------------------------------------------------*/

int init_uSuite(void);
int clean_uSuite(void);

void test_SKLOG_U_NewCtx(void);
void test_SKLOG_U_Open(void);
void test_SKLOG_U_LogEvent(void);
void test_SKLOG_U_Close(void);
void test_SKLOG_U_FreeCtx(void);

/*--------------------------------------------------------------------*/
/*                              T tests                               */
/*--------------------------------------------------------------------*/

/**
int init_tSuite(void);
int clean_tSuite(void);
*/

/*--------------------------------------------------------------------*/
/*                              V tests                               */
/*--------------------------------------------------------------------*/

/**
int init_vSuite(void);
int clean_vSuite(void);
*/

#endif /* CUNIT_SKLOG_TESTS */
