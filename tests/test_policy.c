/*
 * Auris - Policy Tests
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "policy.h"
#include "syscall_table.h"

static void setup(void)
{
    sg_syscall_table_init();
}

static void teardown(void)
{
    sg_syscall_table_cleanup();
}

START_TEST(test_policy_alloc_free)
{
    sg_policy_t *policy = sg_policy_alloc();
    ck_assert_ptr_nonnull(policy);
    ck_assert_ptr_nonnull(policy->rules);
    ck_assert_int_eq(policy->rule_count, 0);
    
    sg_policy_free(policy);
}
END_TEST

START_TEST(test_policy_add_rule)
{
    sg_policy_t *policy = sg_policy_alloc();
    
    sg_error_t err = sg_policy_add_rule(policy, SYS_read, POLICY_ACTION_ALLOW,
                                         NULL, "Test rule");
    ck_assert_int_eq(err, SG_OK);
    ck_assert_int_eq(policy->rule_count, 1);
    
    const sg_policy_rule_t *rule = sg_policy_get_rule(policy, SYS_read);
    ck_assert_ptr_nonnull(rule);
    ck_assert_int_eq(rule->action, POLICY_ACTION_ALLOW);
    ck_assert_str_eq(rule->reason, "Test rule");
    
    sg_policy_free(policy);
}
END_TEST

START_TEST(test_policy_remove_rule)
{
    sg_policy_t *policy = sg_policy_alloc();
    
    sg_policy_add_rule(policy, SYS_read, POLICY_ACTION_ALLOW, NULL, NULL);
    sg_policy_add_rule(policy, SYS_write, POLICY_ACTION_ALLOW, NULL, NULL);
    ck_assert_int_eq(policy->rule_count, 2);
    
    sg_error_t err = sg_policy_remove_rule(policy, SYS_read);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_int_eq(policy->rule_count, 1);
    
    ck_assert_ptr_null(sg_policy_get_rule(policy, SYS_read));
    ck_assert_ptr_nonnull(sg_policy_get_rule(policy, SYS_write));
    
    sg_policy_free(policy);
}
END_TEST

START_TEST(test_policy_check)
{
    sg_policy_t *policy = sg_policy_alloc();
    policy->allow_unknown = false;
    
    sg_policy_add_rule(policy, SYS_read, POLICY_ACTION_ALLOW, NULL, NULL);
    sg_policy_add_rule(policy, SYS_write, POLICY_ACTION_BLOCK, NULL, NULL);
    
    sg_policy_action_t action;
    
    action = sg_policy_check(policy, SYS_read, NULL);
    ck_assert_int_eq(action, POLICY_ACTION_ALLOW);
    
    action = sg_policy_check(policy, SYS_write, NULL);
    ck_assert_int_eq(action, POLICY_ACTION_BLOCK);
    
    /* Unknown syscall should alert */
    action = sg_policy_check(policy, SYS_socket, NULL);
    ck_assert_int_eq(action, POLICY_ACTION_ALERT);
    
    sg_policy_free(policy);
}
END_TEST

START_TEST(test_policy_check_with_path)
{
    sg_policy_t *policy = sg_policy_alloc();
    
    sg_policy_add_rule(policy, SYS_openat, POLICY_ACTION_BLOCK,
                       "/etc/*", "Block /etc access");
    sg_policy_add_rule(policy, SYS_openat, POLICY_ACTION_ALLOW,
                       "/tmp/*", "Allow /tmp access");
    
    sg_policy_action_t action;
    
    action = sg_policy_check(policy, SYS_openat, "/etc/passwd");
    ck_assert_int_eq(action, POLICY_ACTION_BLOCK);
    
    action = sg_policy_check(policy, SYS_openat, "/tmp/test");
    ck_assert_int_eq(action, POLICY_ACTION_ALLOW);
    
    sg_policy_free(policy);
}
END_TEST

START_TEST(test_policy_add_essential)
{
    sg_policy_t *policy = sg_policy_alloc();
    
    sg_error_t err = sg_policy_add_essential(policy);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_int_gt(policy->rule_count, 0);
    
    /* Check that essential syscalls are allowed */
    ck_assert_ptr_nonnull(sg_policy_get_rule(policy, SYS_read));
    ck_assert_ptr_nonnull(sg_policy_get_rule(policy, SYS_write));
    ck_assert_ptr_nonnull(sg_policy_get_rule(policy, SYS_exit));
    
    sg_policy_free(policy);
}
END_TEST

START_TEST(test_policy_generate_minimal)
{
    sg_policy_t *policy = NULL;
    
    sg_error_t err = sg_policy_generate_minimal(&policy);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_ptr_nonnull(policy);
    ck_assert_int_gt(policy->rule_count, 0);
    ck_assert_int_eq(policy->default_mode, ENFORCE_MODE_BLOCK);
    
    sg_policy_free(policy);
}
END_TEST

START_TEST(test_policy_validate)
{
    sg_policy_t *policy = sg_policy_alloc();
    
    /* Empty policy ID should fail */
    policy->policy_id[0] = '\0';
    sg_error_t err = sg_policy_validate(policy);
    ck_assert_int_eq(err, SG_ERR_POLICY);
    
    /* Valid policy */
    strcpy(policy->policy_id, "test-policy");
    err = sg_policy_validate(policy);
    ck_assert_int_eq(err, SG_OK);
    
    sg_policy_free(policy);
}
END_TEST

START_TEST(test_policy_to_json)
{
    sg_policy_t *policy = sg_policy_alloc();
    strcpy(policy->policy_id, "test-policy");
    sg_policy_add_rule(policy, SYS_read, POLICY_ACTION_ALLOW, NULL, "Test");
    
    char *json = sg_policy_to_json(policy);
    ck_assert_ptr_nonnull(json);
    ck_assert(strstr(json, "test-policy") != NULL);
    ck_assert(strstr(json, "rules") != NULL);
    
    free(json);
    sg_policy_free(policy);
}
END_TEST

START_TEST(test_policy_from_json)
{
    const char *json = "{"
        "\"policy_id\":\"test-123\","
        "\"binary_path\":\"/bin/test\","
        "\"default_mode\":1,"
        "\"allow_unknown\":false,"
        "\"rules\":["
            "{\"syscall_nr\":63,\"syscall_name\":\"read\",\"action\":0,\"enabled\":true}"
        "]"
    "}";
    
    sg_policy_t *policy = NULL;
    sg_error_t err = sg_policy_from_json(json, &policy);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_ptr_nonnull(policy);
    ck_assert_str_eq(policy->policy_id, "test-123");
    ck_assert_int_eq(policy->rule_count, 1);
    
    sg_policy_free(policy);
}
END_TEST

START_TEST(test_policy_to_text)
{
    sg_policy_t *policy = sg_policy_alloc();
    strcpy(policy->policy_id, "test-policy");
    strcpy(policy->binary_path, "/bin/test");
    sg_policy_add_rule(policy, SYS_read, POLICY_ACTION_ALLOW, NULL, "Allow read");
    
    char *text = sg_policy_to_text(policy);
    ck_assert_ptr_nonnull(text);
    ck_assert(strstr(text, "test-policy") != NULL);
    ck_assert(strstr(text, "ALLOW") != NULL);
    ck_assert(strstr(text, "read") != NULL);
    
    free(text);
    sg_policy_free(policy);
}
END_TEST

Suite *policy_suite(void)
{
    Suite *s;
    TCase *tc_core;
    
    s = suite_create("Policy");
    tc_core = tcase_create("Core");
    
    tcase_add_checked_fixture(tc_core, setup, teardown);
    
    tcase_add_test(tc_core, test_policy_alloc_free);
    tcase_add_test(tc_core, test_policy_add_rule);
    tcase_add_test(tc_core, test_policy_remove_rule);
    tcase_add_test(tc_core, test_policy_check);
    tcase_add_test(tc_core, test_policy_check_with_path);
    tcase_add_test(tc_core, test_policy_add_essential);
    tcase_add_test(tc_core, test_policy_generate_minimal);
    tcase_add_test(tc_core, test_policy_validate);
    tcase_add_test(tc_core, test_policy_to_json);
    tcase_add_test(tc_core, test_policy_from_json);
    tcase_add_test(tc_core, test_policy_to_text);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}
