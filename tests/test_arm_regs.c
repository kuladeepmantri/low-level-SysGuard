/*
 * Auris - ARM Registers Tests
 * Note: Most tests require running on ARM64 Linux with ptrace
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "tracer.h"

/* These tests are mostly stubs since they require actual ptrace */

START_TEST(test_sockaddr_decode_ipv4)
{
    /* Test IPv4 sockaddr decoding */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = htonl(0x7F000001);  /* 127.0.0.1 */
    
    sg_netaddr_t result;
    sg_decode_sockaddr((struct sockaddr *)&addr, sizeof(addr), &result);
    
    ck_assert_int_eq(result.family, AF_INET);
    ck_assert_int_eq(result.port, 8080);
    ck_assert(strstr(result.str, "127.0.0.1") != NULL);
}
END_TEST

START_TEST(test_sockaddr_decode_ipv6)
{
    /* Test IPv6 sockaddr decoding */
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(443);
    /* ::1 */
    addr.sin6_addr.s6_addr[15] = 1;
    
    sg_netaddr_t result;
    sg_decode_sockaddr((struct sockaddr *)&addr, sizeof(addr), &result);
    
    ck_assert_int_eq(result.family, AF_INET6);
    ck_assert_int_eq(result.port, 443);
}
END_TEST

Suite *arm_regs_suite(void)
{
    Suite *s;
    TCase *tc_core;
    
    s = suite_create("ArmRegs");
    tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_sockaddr_decode_ipv4);
    tcase_add_test(tc_core, test_sockaddr_decode_ipv6);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}
