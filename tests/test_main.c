/*
 * Auris - Test Suite Main
 * Unit test runner using Check framework
 */

#include <stdlib.h>
#include <check.h>

/* Test suite declarations */
Suite *syscall_table_suite(void);
Suite *trace_store_suite(void);
Suite *profiler_suite(void);
Suite *dataflow_suite(void);
Suite *graph_suite(void);
Suite *policy_suite(void);
Suite *json_utils_suite(void);
Suite *pattern_match_suite(void);
Suite *arm_regs_suite(void);

int main(void)
{
    int number_failed;
    SRunner *sr;
    
    sr = srunner_create(syscall_table_suite());
    srunner_add_suite(sr, trace_store_suite());
    srunner_add_suite(sr, profiler_suite());
    srunner_add_suite(sr, dataflow_suite());
    srunner_add_suite(sr, graph_suite());
    srunner_add_suite(sr, policy_suite());
    srunner_add_suite(sr, json_utils_suite());
    srunner_add_suite(sr, pattern_match_suite());
    srunner_add_suite(sr, arm_regs_suite());
    
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
