/*
 * Auris - Trace Store Tests
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "auris.h"
#include "trace_store.h"

static sg_trace_store_t store;
static char test_dir[] = "/tmp/auris_test_XXXXXX";

static void setup(void)
{
    mkdtemp(test_dir);
    sg_trace_store_init(&store, test_dir);
}

static void teardown(void)
{
    sg_trace_store_cleanup(&store);
    /* Clean up test directory */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
    system(cmd);
}

START_TEST(test_trace_alloc_free)
{
    sg_trace_t *trace = sg_trace_alloc();
    ck_assert_ptr_nonnull(trace);
    ck_assert_ptr_nonnull(trace->events);
    ck_assert_int_eq(trace->event_count, 0);
    ck_assert_int_gt(trace->event_capacity, 0);
    
    sg_trace_free(trace);
}
END_TEST

START_TEST(test_trace_add_event)
{
    sg_trace_t *trace = sg_trace_alloc();
    
    sg_syscall_event_t event = {0};
    event.id = 1;
    event.pid = 1234;
    event.syscall_nr = 63;  /* read */
    strcpy(event.syscall_name, "read");
    
    sg_error_t err = sg_trace_add_event(trace, &event);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_int_eq(trace->event_count, 1);
    ck_assert_int_eq(trace->events[0].pid, 1234);
    
    sg_trace_free(trace);
}
END_TEST

START_TEST(test_trace_save_load)
{
    sg_trace_t *trace = sg_trace_alloc();
    
    strcpy(trace->meta.binary_path, "/bin/test");
    strcpy(trace->meta.binary_hash, "abc123");
    
    sg_syscall_event_t event = {0};
    event.id = 0;
    event.pid = 1234;
    event.syscall_nr = 63;
    strcpy(event.syscall_name, "read");
    sg_trace_add_event(trace, &event);
    
    sg_trace_finalize(trace);
    
    /* Save */
    sg_error_t err = sg_trace_store_save(&store, trace, "test-trace-1");
    ck_assert_int_eq(err, SG_OK);
    
    /* Check exists */
    ck_assert(sg_trace_store_exists(&store, "test-trace-1"));
    
    /* Load */
    sg_trace_t *loaded = NULL;
    err = sg_trace_store_load(&store, "test-trace-1", &loaded);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_ptr_nonnull(loaded);
    
    ck_assert_str_eq(loaded->meta.binary_path, "/bin/test");
    ck_assert_int_eq(loaded->event_count, 1);
    ck_assert_int_eq(loaded->events[0].pid, 1234);
    
    sg_trace_free(trace);
    sg_trace_free(loaded);
}
END_TEST

START_TEST(test_trace_to_json)
{
    sg_trace_t *trace = sg_trace_alloc();
    
    strcpy(trace->meta.trace_id, "test-id");
    strcpy(trace->meta.binary_path, "/bin/test");
    
    char *json = sg_trace_to_json(trace);
    ck_assert_ptr_nonnull(json);
    ck_assert(strstr(json, "test-id") != NULL);
    ck_assert(strstr(json, "/bin/test") != NULL);
    
    free(json);
    sg_trace_free(trace);
}
END_TEST

START_TEST(test_trace_from_json)
{
    const char *json = "{"
        "\"format_version\":1,"
        "\"metadata\":{"
            "\"trace_id\":\"test-123\","
            "\"binary_path\":\"/bin/ls\","
            "\"binary_hash\":\"abc\","
            "\"total_syscalls\":0"
        "},"
        "\"events\":[]"
    "}";
    
    sg_trace_t *trace = NULL;
    sg_error_t err = sg_trace_from_json(json, &trace);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_ptr_nonnull(trace);
    ck_assert_str_eq(trace->meta.trace_id, "test-123");
    ck_assert_str_eq(trace->meta.binary_path, "/bin/ls");
    
    sg_trace_free(trace);
}
END_TEST

Suite *trace_store_suite(void)
{
    Suite *s;
    TCase *tc_core;
    
    s = suite_create("TraceStore");
    tc_core = tcase_create("Core");
    
    tcase_add_checked_fixture(tc_core, setup, teardown);
    
    tcase_add_test(tc_core, test_trace_alloc_free);
    tcase_add_test(tc_core, test_trace_add_event);
    tcase_add_test(tc_core, test_trace_save_load);
    tcase_add_test(tc_core, test_trace_to_json);
    tcase_add_test(tc_core, test_trace_from_json);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}
