/*
 * Auris - Profiler Tests
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "profiler.h"
#include "trace_store.h"
#include "syscall_table.h"

static void setup(void)
{
    sg_syscall_table_init();
}

static void teardown(void)
{
    sg_syscall_table_cleanup();
}

static sg_trace_t *create_test_trace(void)
{
    sg_trace_t *trace = sg_trace_alloc();
    strcpy(trace->meta.binary_path, "/bin/test");
    strcpy(trace->meta.trace_id, "test-trace");
    
    /* Add some events */
    sg_syscall_event_t events[] = {
        {.syscall_nr = SYS_read, .syscall_name = "read"},
        {.syscall_nr = SYS_read, .syscall_name = "read"},
        {.syscall_nr = SYS_write, .syscall_name = "write"},
        {.syscall_nr = SYS_openat, .syscall_name = "openat"},
        {.syscall_nr = SYS_close, .syscall_name = "close"},
    };
    
    for (size_t i = 0; i < sizeof(events)/sizeof(events[0]); i++) {
        events[i].id = i;
        sg_trace_add_event(trace, &events[i]);
    }
    
    sg_trace_finalize(trace);
    return trace;
}

START_TEST(test_profile_alloc_free)
{
    sg_profile_t *profile = sg_profile_alloc();
    ck_assert_ptr_nonnull(profile);
    sg_profile_free(profile);
}
END_TEST

START_TEST(test_calc_syscall_stats)
{
    sg_trace_t *trace = create_test_trace();
    
    sg_syscall_stats_t *stats = NULL;
    size_t count = 0;
    
    sg_error_t err = sg_calc_syscall_stats(trace, &stats, &count);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_ptr_nonnull(stats);
    ck_assert_int_eq(count, 4);  /* read, write, openat, close */
    
    /* Find read stats */
    bool found_read = false;
    for (size_t i = 0; i < count; i++) {
        if (stats[i].syscall_nr == SYS_read) {
            ck_assert_int_eq(stats[i].count, 2);
            found_read = true;
        }
    }
    ck_assert(found_read);
    
    free(stats);
    sg_trace_free(trace);
}
END_TEST

START_TEST(test_profile_build_from_trace)
{
    sg_trace_t *trace = create_test_trace();
    
    sg_profile_t *profile = NULL;
    sg_error_t err = sg_profile_build_from_trace(trace, &profile);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_ptr_nonnull(profile);
    
    ck_assert_str_eq(profile->binary_path, "/bin/test");
    ck_assert_int_eq(profile->total_syscalls, 5);
    ck_assert_int_eq(profile->unique_count, 4);
    ck_assert(profile->does_file_io);
    
    sg_profile_free(profile);
    sg_trace_free(trace);
}
END_TEST

START_TEST(test_profile_compare)
{
    sg_trace_t *trace1 = create_test_trace();
    
    sg_profile_t *baseline = NULL;
    sg_profile_build_from_trace(trace1, &baseline);
    
    /* Create a different trace with new syscall */
    sg_trace_t *trace2 = sg_trace_alloc();
    strcpy(trace2->meta.binary_path, "/bin/test");
    
    sg_syscall_event_t events[] = {
        {.syscall_nr = SYS_read, .syscall_name = "read"},
        {.syscall_nr = SYS_socket, .syscall_name = "socket"},  /* New! */
        {.syscall_nr = SYS_connect, .syscall_name = "connect"},  /* New! */
    };
    
    for (size_t i = 0; i < sizeof(events)/sizeof(events[0]); i++) {
        events[i].id = i;
        sg_trace_add_event(trace2, &events[i]);
    }
    sg_trace_finalize(trace2);
    
    sg_comparison_t *result = NULL;
    sg_error_t err = sg_profile_compare(baseline, trace2, &result);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_ptr_nonnull(result);
    
    ck_assert(result->is_anomalous);
    ck_assert_int_gt(result->anomaly_count, 0);
    
    sg_comparison_free(result);
    sg_profile_free(baseline);
    sg_trace_free(trace1);
    sg_trace_free(trace2);
}
END_TEST

START_TEST(test_profile_to_json)
{
    sg_trace_t *trace = create_test_trace();
    
    sg_profile_t *profile = NULL;
    sg_profile_build_from_trace(trace, &profile);
    
    char *json = sg_profile_to_json(profile);
    ck_assert_ptr_nonnull(json);
    ck_assert(strstr(json, "profile_id") != NULL);
    ck_assert(strstr(json, "syscall_stats") != NULL);
    
    free(json);
    sg_profile_free(profile);
    sg_trace_free(trace);
}
END_TEST

Suite *profiler_suite(void)
{
    Suite *s;
    TCase *tc_core;
    
    s = suite_create("Profiler");
    tc_core = tcase_create("Core");
    
    tcase_add_checked_fixture(tc_core, setup, teardown);
    
    tcase_add_test(tc_core, test_profile_alloc_free);
    tcase_add_test(tc_core, test_calc_syscall_stats);
    tcase_add_test(tc_core, test_profile_build_from_trace);
    tcase_add_test(tc_core, test_profile_compare);
    tcase_add_test(tc_core, test_profile_to_json);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}
