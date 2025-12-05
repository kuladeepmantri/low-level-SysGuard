/*
 * Auris - Pattern Match Tests
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

START_TEST(test_extract_patterns)
{
    sg_trace_t *trace = sg_trace_alloc();
    
    /* Create a trace with repeated pattern: read, write, read, write */
    sg_syscall_event_t events[] = {
        {.syscall_nr = SYS_read},
        {.syscall_nr = SYS_write},
        {.syscall_nr = SYS_read},
        {.syscall_nr = SYS_write},
        {.syscall_nr = SYS_read},
        {.syscall_nr = SYS_write},
    };
    
    for (size_t i = 0; i < sizeof(events)/sizeof(events[0]); i++) {
        events[i].id = i;
        sg_trace_add_event(trace, &events[i]);
    }
    
    sg_pattern_t *patterns = NULL;
    size_t count = 0;
    
    sg_error_t err = sg_extract_patterns(trace, &patterns, &count, 2, 4, 2);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_ptr_nonnull(patterns);
    ck_assert_int_gt(count, 0);
    
    /* Should find read-write pattern */
    bool found = false;
    for (size_t i = 0; i < count; i++) {
        if (patterns[i].length == 2 &&
            patterns[i].pattern[0] == SYS_read &&
            patterns[i].pattern[1] == SYS_write) {
            found = true;
            ck_assert_int_ge(patterns[i].occurrences, 2);
        }
    }
    ck_assert(found);
    
    free(patterns);
    sg_trace_free(trace);
}
END_TEST

START_TEST(test_pattern_exists)
{
    sg_trace_t *trace = sg_trace_alloc();
    
    sg_syscall_event_t events[] = {
        {.syscall_nr = SYS_openat},
        {.syscall_nr = SYS_read},
        {.syscall_nr = SYS_close},
    };
    
    for (size_t i = 0; i < sizeof(events)/sizeof(events[0]); i++) {
        events[i].id = i;
        sg_trace_add_event(trace, &events[i]);
    }
    
    sg_pattern_t pattern = {0};
    pattern.pattern[0] = SYS_openat;
    pattern.pattern[1] = SYS_read;
    pattern.length = 2;
    
    ck_assert(sg_pattern_exists(trace, &pattern));
    
    pattern.pattern[0] = SYS_write;
    pattern.pattern[1] = SYS_socket;
    ck_assert(!sg_pattern_exists(trace, &pattern));
    
    sg_trace_free(trace);
}
END_TEST

START_TEST(test_find_suspicious_patterns)
{
    sg_trace_t *trace = sg_trace_alloc();
    
    /* Create a potential reverse shell pattern */
    sg_syscall_event_t events[] = {
        {.syscall_nr = SYS_socket},
        {.syscall_nr = SYS_connect},
        {.syscall_nr = SYS_dup3},
        {.syscall_nr = SYS_dup3},
        {.syscall_nr = SYS_execve},
    };
    
    for (size_t i = 0; i < sizeof(events)/sizeof(events[0]); i++) {
        events[i].id = i;
        sg_trace_add_event(trace, &events[i]);
    }
    
    sg_pattern_t *patterns = NULL;
    size_t count = 0;
    
    sg_error_t err = sg_find_suspicious_patterns(trace, &patterns, &count);
    ck_assert_int_eq(err, SG_OK);
    ck_assert_ptr_nonnull(patterns);
    ck_assert_int_gt(count, 0);  /* Should detect reverse shell pattern */
    
    free(patterns);
    sg_trace_free(trace);
}
END_TEST

Suite *pattern_match_suite(void)
{
    Suite *s;
    TCase *tc_core;
    
    s = suite_create("PatternMatch");
    tc_core = tcase_create("Core");
    
    tcase_add_checked_fixture(tc_core, setup, teardown);
    
    tcase_add_test(tc_core, test_extract_patterns);
    tcase_add_test(tc_core, test_pattern_exists);
    tcase_add_test(tc_core, test_find_suspicious_patterns);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}
