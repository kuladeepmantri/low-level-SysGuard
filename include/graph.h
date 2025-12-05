/*
 * Auris - Activity Graph
 * Graph-based representation of process, file, and network activity
 */

#ifndef AURIS_GRAPH_H
#define AURIS_GRAPH_H

#include "auris.h"

/* Forward declaration */
struct sg_trace;

/*
 * Allocate a new graph
 */
sg_graph_t *sg_graph_alloc(void);

/*
 * Free a graph and all its contents
 */
void sg_graph_free(sg_graph_t *graph);

/*
 * Build a graph from a trace
 */
sg_error_t sg_graph_build(const struct sg_trace *trace, sg_graph_t **graph_out);

/*
 * Merge multiple graphs into a summary graph
 */
sg_error_t sg_graph_merge(const sg_graph_t **graphs, 
                           size_t count,
                           sg_graph_t **merged_out);

/*
 * Add a node to the graph
 * Returns node ID, or negative error code
 */
int32_t sg_graph_add_node(sg_graph_t *graph,
                           sg_node_type_t type,
                           const char *label,
                           pid_t pid,
                           const sg_netaddr_t *addr,
                           sg_sensitivity_t sensitivity);

/*
 * Add an edge to the graph
 * Returns edge ID, or negative error code
 */
int32_t sg_graph_add_edge(sg_graph_t *graph,
                           uint32_t source,
                           uint32_t target,
                           sg_edge_type_t type,
                           uint64_t event_id,
                           sg_timestamp_t timestamp,
                           uint64_t bytes);

/*
 * Find node by label
 * Returns node ID, or -1 if not found
 */
int32_t sg_graph_find_node(const sg_graph_t *graph, const char *label);

/*
 * Find node by PID (for process nodes)
 */
int32_t sg_graph_find_process(const sg_graph_t *graph, pid_t pid);

/*
 * Get node by ID
 */
const sg_graph_node_t *sg_graph_get_node(const sg_graph_t *graph, uint32_t id);

/*
 * Get edge by ID
 */
const sg_graph_edge_t *sg_graph_get_edge(const sg_graph_t *graph, uint32_t id);

/*
 * Get all edges from a node
 */
sg_error_t sg_graph_get_outgoing(const sg_graph_t *graph,
                                  uint32_t node_id,
                                  uint32_t **edge_ids_out,
                                  size_t *count_out);

/*
 * Get all edges to a node
 */
sg_error_t sg_graph_get_incoming(const sg_graph_t *graph,
                                  uint32_t node_id,
                                  uint32_t **edge_ids_out,
                                  size_t *count_out);

/* Graph analysis */

/*
 * Find all paths between two nodes
 * Returns array of paths (each path is array of node IDs)
 */
sg_error_t sg_graph_find_paths(const sg_graph_t *graph,
                                uint32_t source,
                                uint32_t target,
                                size_t max_depth,
                                uint32_t ***paths_out,
                                size_t **path_lengths_out,
                                size_t *path_count_out);

/*
 * Find sensitive data flow paths
 * Paths from high-sensitivity nodes to network endpoints
 */
sg_error_t sg_graph_find_sensitive_flows(const sg_graph_t *graph,
                                          uint32_t ***paths_out,
                                          size_t **path_lengths_out,
                                          size_t *path_count_out);

/*
 * Calculate node centrality (how connected a node is)
 */
double sg_graph_node_centrality(const sg_graph_t *graph, uint32_t node_id);

/*
 * Find nodes with high fan-out (many outgoing edges)
 */
sg_error_t sg_graph_find_high_fanout(const sg_graph_t *graph,
                                      size_t threshold,
                                      uint32_t **node_ids_out,
                                      size_t *count_out);

/*
 * Find isolated subgraphs (connected components)
 */
sg_error_t sg_graph_find_components(const sg_graph_t *graph,
                                     uint32_t ***components_out,
                                     size_t **component_sizes_out,
                                     size_t *component_count_out);

/*
 * Detect cycles in the graph
 */
bool sg_graph_has_cycles(const sg_graph_t *graph);

/*
 * Get graph statistics
 */
typedef struct {
    size_t node_count;
    size_t edge_count;
    size_t process_count;
    size_t file_count;
    size_t socket_count;
    size_t remote_count;
    size_t sensitive_node_count;
    double avg_degree;
    uint32_t max_in_degree;
    uint32_t max_out_degree;
} sg_graph_stats_t;

sg_error_t sg_graph_stats(const sg_graph_t *graph, sg_graph_stats_t *stats_out);

/* Graph serialization */

/*
 * Serialize graph to JSON
 */
char *sg_graph_to_json(const sg_graph_t *graph);

/*
 * Parse graph from JSON
 */
sg_error_t sg_graph_from_json(const char *json, sg_graph_t **graph_out);

/*
 * Export graph to DOT format (for visualization)
 */
char *sg_graph_to_dot(const sg_graph_t *graph);

/*
 * Export graph summary (for AI analysis)
 * Includes key metrics and notable patterns
 */
char *sg_graph_summary(const sg_graph_t *graph);

/* Graph persistence */

/*
 * Save graph to file
 */
sg_error_t sg_graph_save(const sg_graph_t *graph, const char *path);

/*
 * Load graph from file
 */
sg_error_t sg_graph_load(const char *path, sg_graph_t **graph_out);

#endif /* AURIS_GRAPH_H */
