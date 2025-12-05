/*
 * Auris - JSON Utils Tests
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "trace_store.h"
#include "profiler.h"
#include "graph.h"
#include "policy.h"
#include "dataflow.h"

START_TEST(test_event_to_json)
{
    sg_syscall_event_t event = {0};
    event.id = 1;
    event.pid = 1234;
    event.syscall_nr = 63;
    strcpy(event.syscall_name, "read");
    event.ret_value = 100;
    
    char *json = sg_event_to_json(&event);
    ck_assert_ptr_nonnull(json);
    ck_assert(strstr(json, "\"id\":1") != NULL);
    ck_assert(strstr(json, "\"pid\":1234") != NULL);
    ck_assert(strstr(json, "\"syscall_name\":\"read\"") != NULL);
    
    free(json);
}
END_TEST

START_TEST(test_trace_meta_to_json)
{
    sg_trace_meta_t meta = {0};
    strcpy(meta.trace_id, "test-trace-id");
    strcpy(meta.binary_path, "/bin/test");
    meta.root_pid = 1234;
    
    char *json = sg_trace_meta_to_json(&meta);
    ck_assert_ptr_nonnull(json);
    ck_assert(strstr(json, "test-trace-id") != NULL);
    ck_assert(strstr(json, "/bin/test") != NULL);
    
    free(json);
}
END_TEST

START_TEST(test_comparison_to_json)
{
    sg_comparison_t result = {0};
    strcpy(result.trace_id, "trace-1");
    strcpy(result.profile_id, "profile-1");
    result.overall_deviation = 0.5;
    result.risk_score = 0.7;
    result.is_anomalous = true;
    
    result.anomalies = calloc(1, sizeof(sg_anomaly_t));
    result.anomaly_count = 1;
    result.anomalies[0].type = ANOMALY_NEW_SYSCALL;
    strcpy(result.anomalies[0].description, "New syscall detected");
    result.anomalies[0].severity = 0.8;
    
    char *json = sg_comparison_to_json(&result);
    ck_assert_ptr_nonnull(json);
    ck_assert(strstr(json, "trace-1") != NULL);
    ck_assert(strstr(json, "profile-1") != NULL);
    ck_assert(strstr(json, "anomalies") != NULL);
    
    free(json);
    free(result.anomalies);
}
END_TEST

START_TEST(test_dataflow_result_to_json)
{
    sg_dataflow_result_t result = {0};
    result.overall_risk = 0.6;
    result.has_high_risk_flows = true;
    
    result.flows = calloc(1, sizeof(sg_exfil_flow_t));
    result.flow_count = 1;
    strcpy(result.flows[0].source_path, "/etc/passwd");
    result.flows[0].sensitivity = SENSITIVITY_MEDIUM;
    result.flows[0].bytes_transferred = 1024;
    
    char *json = sg_dataflow_result_to_json(&result);
    ck_assert_ptr_nonnull(json);
    ck_assert(strstr(json, "overall_risk") != NULL);
    ck_assert(strstr(json, "flows") != NULL);
    
    free(json);
    free(result.flows);
}
END_TEST

Suite *json_utils_suite(void)
{
    Suite *s;
    TCase *tc_core;
    
    s = suite_create("JsonUtils");
    tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_event_to_json);
    tcase_add_test(tc_core, test_trace_meta_to_json);
    tcase_add_test(tc_core, test_comparison_to_json);
    tcase_add_test(tc_core, test_dataflow_result_to_json);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}
