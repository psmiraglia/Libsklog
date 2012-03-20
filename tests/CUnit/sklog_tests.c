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

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <CUnit/Basic.h>
#include <CUnit/Automated.h>

#include "sklog_tests.h"

#define BUFLEN 512

int main (void) {
	
	time_t now;
	char fname[BUFLEN] = { 0 };
	CU_pSuite uSuite = 0;
	/**
	CU_pSuite tSuite = 0;
	CU_pSuite vSuite = 0;
	*/

	//~ gen file name
	
	now = time(NULL);
	snprintf(fname,BUFLEN-1,"%ju",now);
	
	//~ initialize registry
	
	if ( CU_initialize_registry() != CUE_SUCCESS ) {
		return CU_get_error();
	}
	
	//~ add suite to the registry
	
	if ( (uSuite = CU_add_suite("U Tests", init_uSuite, clean_uSuite)) == NULL ) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	
	//~ add test functions to the suite
	
	if ( (NULL == CU_add_test(uSuite, "SKLOG_U_NewCtx()", test_SKLOG_U_NewCtx)) ||
		 (NULL == CU_add_test(uSuite, "SKLOG_U_FreeCtx()", test_SKLOG_U_FreeCtx))
	) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	
	/**
	//~ add suite to the registry
	
	if ( (tSuite = CU_add_suite("T Tests", init_tSuite, clean_tSuite)) == NULL ) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	
	//~ add test functions to the suite
	
	if ( (NULL == CU_add_test(tSuite, "foo desc 1", fooTest1)) ||
		 (NULL == CU_add_test(tSuite, "foo desc 2", fooTest2)) ) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	
	//~ add suite to the registry
	
	if ( (uSuite = CU_add_suite("V Tests", init_vSuite, clean_vSuite)) == NULL ) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	
	//~ add test functions to the suite
	
	if ( (NULL == CU_add_test(vSuite, "foo desc 1", fooTest1)) ||
		 (NULL == CU_add_test(vSuite, "foo desc 2", fooTest2)) ) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	*/
	
	//~ run tests
	
	CU_basic_set_mode(CU_BRM_VERBOSE);
	
	//~ results on stdout
	
	CU_basic_run_tests();
	
	//~ results in XML file
	
	CU_set_output_filename(fname);
	CU_automated_run_tests();
	
	CU_cleanup_registry();
	return CU_get_error();
}

