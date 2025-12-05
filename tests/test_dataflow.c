/*
 * Auris - Data Flow Tests
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "dataflow.h"
#include "syscall_table.h"

static void setup(void)
{
    sg_syscall_table_init();
}

static void teardown(void)
{
    sg_syscall_table_cleanup();
}

START_TEST(test_dataflow_init_cleanup)
{
    sg_dataflow_ctx_t ctx;
    sg_error_t err = sg_dataflow_init(&ctx);
    ck_assert_int_eq(err, SG_OK);
    
    sg_dataflow_cleanup(&ctx);
}
END_TEST

START_TEST(test_path_sensitivity)
{
    sg_sensitivity_t sens;
    
    sens = sg_path_sensitivity("/home/user/.ssh/id_rsa");
    ck_assert_int_eq(sens, SENSITIVITY_CRITICAL);
    
    sens = sg_path_sensitivity("/etc/shadow");
    ck_assert_int_eq(sens, SENSITIVITY_CRITICAL);
    
    sens = sg_path_sensitivity("/etc/passwd");
    ck_assert_int_eq(sens, SENSITIVITY_MEDIUM);
    
    sens = sg_path_sensitivity("/tmp/random_file");
    ck_assert_int_eq(sens, SENSITIVITY_NONE);
    
    sens = sg_path_sensitivity("/home/user/.aws/credentials");
    ck_assert_int_eq(sens, SENSITIVITY_CRITICAL);
}
END_TEST

START_TEST(test_is_sensitive_path)
{
    ck_assert(sg_is_sensitive_path("/home/user/.ssh/id_rsa"));
    ck_assert(sg_is_sensitive_path("/etc/shadow"));
    ck_assert(sg_is_sensitive_path("/home/user/.netrc"));
    ck_assert(!sg_is_sensitive_path("/tmp/test.txt"));
    ck_assert(!sg_is_sensitive_path("/usr/bin/ls"));
}
END_TEST

START_TEST(test_sensitive_path_reason)
{
    const char *reason;
    
    reason = sg_sensitive_path_reason("/home/user/.ssh/id_rsa");
    ck_assert_ptr_nonnull(reason);
    ck_assert(strstr(reason, "SSH") != NULL || strstr(reason, "key") != NULL);
    
    reason = sg_sensitive_path_reason("/tmp/test.txt");
    ck_assert_ptr_null(reason);
}
END_TEST

START_TEST(test_dataflow_taint)
{
    sg_dataflow_ctx_t ctx;
    sg_dataflow_init(&ctx);
    
    ck_assert(!sg_dataflow_is_tainted(&ctx, 5));
    
    sg_dataflow_mark_tainted(&ctx, 5, "/etc/shadow", SENSITIVITY_CRITICAL);
    
    ck_assert(sg_dataflow_is_tainted(&ctx, 5));
    ck_assert_int_eq(sg_dataflow_get_sensitivity(&ctx, 5), SENSITIVITY_CRITICAL);
    
    sg_dataflow_handle_close(&ctx, 5);
    ck_assert(!sg_dataflow_is_tainted(&ctx, 5));
    
    sg_dataflow_cleanup(&ctx);
}
END_TEST

START_TEST(test_dataflow_dup)
{
    sg_dataflow_ctx_t ctx;
    sg_dataflow_init(&ctx);
    
    sg_dataflow_mark_tainted(&ctx, 3, "/etc/passwd", SENSITIVITY_MEDIUM);
    sg_dataflow_handle_dup(&ctx, 3, 7);
    
    ck_assert(sg_dataflow_is_tainted(&ctx, 7));
    ck_assert_int_eq(sg_dataflow_get_sensitivity(&ctx, 7), SENSITIVITY_MEDIUM);
    
    sg_dataflow_cleanup(&ctx);
}
END_TEST

Suite *dataflow_suite(void)
{
    Suite *s;
    TCase *tc_core;
    
    s = suite_create("DataFlow");
    tc_core = tcase_create("Core");
    
    tcase_add_checked_fixture(tc_core, setup, teardown);
    
    tcase_add_test(tc_core, test_dataflow_init_cleanup);
    tcase_add_test(tc_core, test_path_sensitivity);
    tcase_add_test(tc_core, test_is_sensitive_path);
    tcase_add_test(tc_core, test_sensitive_path_reason);
    tcase_add_test(tc_core, test_dataflow_taint);
    tcase_add_test(tc_core, test_dataflow_dup);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}
