#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "sklog_tests.h"
#include <google/cmockery.h>

// A test case that does nothing and succeeds.
void null_test_success(void **state) {
}

int main(int argc, char **argv) {
	
    const UnitTest u_tests[] = {
		unit_test(u_test_context_init),
		unit_test(u_test_context_free),
		unit_test(u_test_context_mgmt),
		unit_test(u_test_open_params),
	};
 
    const UnitTest t_tests[] = {
		unit_test(t_test_context_init),
		unit_test(t_test_context_free),
		unit_test(t_test_context_mgmt),
	};
	
    const UnitTest v_tests[] = {
		unit_test(v_test_context_init),
		unit_test(v_test_context_free),
		unit_test(v_test_context_mgmt),
	};
    
    printf("Starting running U tests...\n");
    run_tests(u_tests);
    
    printf("\n\nStarting running V tests...\n");
    run_tests(v_tests);
    
    printf("\n\nStarting running T tests...\n");
    run_tests(t_tests);
    
    return 0;
}
