/*
 * Auris - Syscall Table Tests
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "syscall_table.h"

static void setup(void)
{
    sg_syscall_table_init();
}

static void teardown(void)
{
    sg_syscall_table_cleanup();
}

START_TEST(test_syscall_lookup)
{
    const sg_syscall_desc_t *desc;
    
    desc = sg_syscall_lookup(SYS_read);
    ck_assert_ptr_nonnull(desc);
    ck_assert_str_eq(desc->name, "read");
    ck_assert_int_eq(desc->category, SYSCALL_CAT_FILE);
    
    desc = sg_syscall_lookup(SYS_write);
    ck_assert_ptr_nonnull(desc);
    ck_assert_str_eq(desc->name, "write");
    
    desc = sg_syscall_lookup(SYS_openat);
    ck_assert_ptr_nonnull(desc);
    ck_assert_str_eq(desc->name, "openat");
}
END_TEST

START_TEST(test_syscall_lookup_by_name)
{
    const sg_syscall_desc_t *desc;
    
    desc = sg_syscall_lookup_by_name("read");
    ck_assert_ptr_nonnull(desc);
    ck_assert_int_eq(desc->nr, SYS_read);
    
    desc = sg_syscall_lookup_by_name("nonexistent");
    ck_assert_ptr_null(desc);
}
END_TEST

START_TEST(test_syscall_name)
{
    const char *name;
    
    name = sg_syscall_name(SYS_read);
    ck_assert_str_eq(name, "read");
    
    name = sg_syscall_name(SYS_clone);
    ck_assert_str_eq(name, "clone");
    
    name = sg_syscall_name(9999);
    ck_assert_str_eq(name, "unknown");
}
END_TEST

START_TEST(test_syscall_nr)
{
    int nr;
    
    nr = sg_syscall_nr("read");
    ck_assert_int_eq(nr, SYS_read);
    
    nr = sg_syscall_nr("write");
    ck_assert_int_eq(nr, SYS_write);
    
    nr = sg_syscall_nr("nonexistent");
    ck_assert_int_eq(nr, -1);
}
END_TEST

START_TEST(test_syscall_is_essential)
{
    ck_assert(sg_syscall_is_essential(SYS_read));
    ck_assert(sg_syscall_is_essential(SYS_write));
    ck_assert(sg_syscall_is_essential(SYS_exit));
    ck_assert(sg_syscall_is_essential(SYS_brk));
    ck_assert(sg_syscall_is_essential(SYS_mmap));
}
END_TEST

START_TEST(test_syscall_is_sensitive)
{
    ck_assert(sg_syscall_is_sensitive(SYS_execve));
    ck_assert(sg_syscall_is_sensitive(SYS_setuid));
    ck_assert(sg_syscall_is_sensitive(SYS_ptrace));
    ck_assert(!sg_syscall_is_sensitive(SYS_read));
}
END_TEST

START_TEST(test_syscall_category)
{
    ck_assert(sg_syscall_is_category(SYS_read, SYSCALL_CAT_FILE));
    ck_assert(sg_syscall_is_category(SYS_socket, SYSCALL_CAT_NETWORK));
    ck_assert(sg_syscall_is_category(SYS_clone, SYSCALL_CAT_PROCESS));
    ck_assert(sg_syscall_is_category(SYS_mmap, SYSCALL_CAT_MEMORY));
}
END_TEST

START_TEST(test_get_essential)
{
    uint32_t essential[64];
    size_t count = sg_syscall_get_essential(essential, 64);
    
    ck_assert_int_gt(count, 0);
    ck_assert_int_le(count, 64);
    
    /* Check that read is in the list */
    bool found_read = false;
    for (size_t i = 0; i < count; i++) {
        if (essential[i] == SYS_read) {
            found_read = true;
            break;
        }
    }
    ck_assert(found_read);
}
END_TEST

Suite *syscall_table_suite(void)
{
    Suite *s;
    TCase *tc_core;
    
    s = suite_create("SyscallTable");
    tc_core = tcase_create("Core");
    
    tcase_add_checked_fixture(tc_core, setup, teardown);
    
    tcase_add_test(tc_core, test_syscall_lookup);
    tcase_add_test(tc_core, test_syscall_lookup_by_name);
    tcase_add_test(tc_core, test_syscall_name);
    tcase_add_test(tc_core, test_syscall_nr);
    tcase_add_test(tc_core, test_syscall_is_essential);
    tcase_add_test(tc_core, test_syscall_is_sensitive);
    tcase_add_test(tc_core, test_syscall_category);
    tcase_add_test(tc_core, test_get_essential);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}
