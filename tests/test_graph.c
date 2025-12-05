/*
 * Auris - Graph Tests
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "graph.h"

START_TEST(test_graph_alloc_free)
{
    sg_graph_t *graph = sg_graph_alloc();
    ck_assert_ptr_nonnull(graph);
    ck_assert_int_eq(graph->node_count, 0);
    ck_assert_int_eq(graph->edge_count, 0);
    
    sg_graph_free(graph);
}
END_TEST

START_TEST(test_graph_add_node)
{
    sg_graph_t *graph = sg_graph_alloc();
    
    int32_t id = sg_graph_add_node(graph, NODE_TYPE_PROCESS, "process:1234",
                                    1234, NULL, SENSITIVITY_NONE);
    ck_assert_int_ge(id, 0);
    ck_assert_int_eq(graph->node_count, 1);
    
    const sg_graph_node_t *node = sg_graph_get_node(graph, id);
    ck_assert_ptr_nonnull(node);
    ck_assert_int_eq(node->type, NODE_TYPE_PROCESS);
    ck_assert_int_eq(node->pid, 1234);
    
    sg_graph_free(graph);
}
END_TEST

START_TEST(test_graph_add_edge)
{
    sg_graph_t *graph = sg_graph_alloc();
    
    int32_t n1 = sg_graph_add_node(graph, NODE_TYPE_PROCESS, "proc", 1, NULL, SENSITIVITY_NONE);
    int32_t n2 = sg_graph_add_node(graph, NODE_TYPE_FILE, "/tmp/file", 0, NULL, SENSITIVITY_NONE);
    
    sg_timestamp_t ts = {0, 0};
    int32_t e = sg_graph_add_edge(graph, n1, n2, EDGE_TYPE_OPEN, 1, ts, 0);
    ck_assert_int_ge(e, 0);
    ck_assert_int_eq(graph->edge_count, 1);
    
    const sg_graph_edge_t *edge = sg_graph_get_edge(graph, e);
    ck_assert_ptr_nonnull(edge);
    ck_assert_int_eq(edge->source, n1);
    ck_assert_int_eq(edge->target, n2);
    ck_assert_int_eq(edge->type, EDGE_TYPE_OPEN);
    
    sg_graph_free(graph);
}
END_TEST

START_TEST(test_graph_find_node)
{
    sg_graph_t *graph = sg_graph_alloc();
    
    sg_graph_add_node(graph, NODE_TYPE_FILE, "/etc/passwd", 0, NULL, SENSITIVITY_MEDIUM);
    sg_graph_add_node(graph, NODE_TYPE_FILE, "/tmp/test", 0, NULL, SENSITIVITY_NONE);
    
    int32_t id = sg_graph_find_node(graph, "/etc/passwd");
    ck_assert_int_ge(id, 0);
    
    id = sg_graph_find_node(graph, "nonexistent");
    ck_assert_int_eq(id, -1);
    
    sg_graph_free(graph);
}
END_TEST

START_TEST(test_graph_stats)
{
    sg_graph_t *graph = sg_graph_alloc();
    
    sg_graph_add_node(graph, NODE_TYPE_PROCESS, "proc1", 1, NULL, SENSITIVITY_NONE);
    sg_graph_add_node(graph, NODE_TYPE_PROCESS, "proc2", 2, NULL, SENSITIVITY_NONE);
    sg_graph_add_node(graph, NODE_TYPE_FILE, "/tmp/file", 0, NULL, SENSITIVITY_HIGH);
    
    sg_timestamp_t ts = {0, 0};
    sg_graph_add_edge(graph, 0, 2, EDGE_TYPE_OPEN, 1, ts, 0);
    sg_graph_add_edge(graph, 1, 2, EDGE_TYPE_READ, 2, ts, 100);
    
    sg_graph_stats_t stats;
    sg_error_t err = sg_graph_stats(graph, &stats);
    ck_assert_int_eq(err, SG_OK);
    
    ck_assert_int_eq(stats.node_count, 3);
    ck_assert_int_eq(stats.edge_count, 2);
    ck_assert_int_eq(stats.process_count, 2);
    ck_assert_int_eq(stats.file_count, 1);
    ck_assert_int_eq(stats.sensitive_node_count, 1);
    
    sg_graph_free(graph);
}
END_TEST

START_TEST(test_graph_to_json)
{
    sg_graph_t *graph = sg_graph_alloc();
    
    sg_graph_add_node(graph, NODE_TYPE_PROCESS, "test", 1, NULL, SENSITIVITY_NONE);
    
    char *json = sg_graph_to_json(graph);
    ck_assert_ptr_nonnull(json);
    ck_assert(strstr(json, "nodes") != NULL);
    ck_assert(strstr(json, "edges") != NULL);
    
    free(json);
    sg_graph_free(graph);
}
END_TEST

START_TEST(test_graph_to_dot)
{
    sg_graph_t *graph = sg_graph_alloc();
    
    int32_t n1 = sg_graph_add_node(graph, NODE_TYPE_PROCESS, "proc", 1, NULL, SENSITIVITY_NONE);
    int32_t n2 = sg_graph_add_node(graph, NODE_TYPE_FILE, "file", 0, NULL, SENSITIVITY_NONE);
    
    sg_timestamp_t ts = {0, 0};
    sg_graph_add_edge(graph, n1, n2, EDGE_TYPE_READ, 1, ts, 0);
    
    char *dot = sg_graph_to_dot(graph);
    ck_assert_ptr_nonnull(dot);
    ck_assert(strstr(dot, "digraph") != NULL);
    ck_assert(strstr(dot, "->") != NULL);
    
    free(dot);
    sg_graph_free(graph);
}
END_TEST

Suite *graph_suite(void)
{
    Suite *s;
    TCase *tc_core;
    
    s = suite_create("Graph");
    tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_graph_alloc_free);
    tcase_add_test(tc_core, test_graph_add_node);
    tcase_add_test(tc_core, test_graph_add_edge);
    tcase_add_test(tc_core, test_graph_find_node);
    tcase_add_test(tc_core, test_graph_stats);
    tcase_add_test(tc_core, test_graph_to_json);
    tcase_add_test(tc_core, test_graph_to_dot);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}
