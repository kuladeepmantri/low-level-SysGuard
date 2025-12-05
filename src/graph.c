/*
 * Auris - Activity Graph
 * Graph-based representation of process/file/network activity
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "graph.h"
#include "trace_store.h"
#include "syscall_table.h"
#include "dataflow.h"

/* Initial capacities */
#define INITIAL_NODE_CAPACITY 256
#define INITIAL_EDGE_CAPACITY 512

/*
 * Allocate a new graph
 */
sg_graph_t *sg_graph_alloc(void)
{
    sg_graph_t *graph = calloc(1, sizeof(sg_graph_t));
    if (graph == NULL) {
        return NULL;
    }
    
    graph->nodes = calloc(INITIAL_NODE_CAPACITY, sizeof(sg_graph_node_t));
    if (graph->nodes == NULL) {
        free(graph);
        return NULL;
    }
    graph->node_capacity = INITIAL_NODE_CAPACITY;
    
    graph->edges = calloc(INITIAL_EDGE_CAPACITY, sizeof(sg_graph_edge_t));
    if (graph->edges == NULL) {
        free(graph->nodes);
        free(graph);
        return NULL;
    }
    graph->edge_capacity = INITIAL_EDGE_CAPACITY;
    
    sg_generate_id(graph->graph_id, sizeof(graph->graph_id));
    
    return graph;
}

/*
 * Free a graph
 */
void sg_graph_free(sg_graph_t *graph)
{
    if (graph == NULL) {
        return;
    }
    
    if (graph->nodes != NULL) {
        free(graph->nodes);
    }
    if (graph->edges != NULL) {
        free(graph->edges);
    }
    if (graph->adj_list != NULL) {
        for (size_t i = 0; i < graph->node_count; i++) {
            if (graph->adj_list[i] != NULL) {
                free(graph->adj_list[i]);
            }
        }
        free(graph->adj_list);
    }
    if (graph->adj_sizes != NULL) {
        free(graph->adj_sizes);
    }
    
    free(graph);
}

/*
 * Add a node to the graph
 */
int32_t sg_graph_add_node(sg_graph_t *graph,
                           sg_node_type_t type,
                           const char *label,
                           pid_t pid,
                           const sg_netaddr_t *addr,
                           sg_sensitivity_t sensitivity)
{
    if (graph == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Check for existing node with same label */
    int32_t existing = sg_graph_find_node(graph, label);
    if (existing >= 0) {
        return existing;
    }
    
    /* Expand if needed */
    if (graph->node_count >= graph->node_capacity) {
        size_t new_capacity = graph->node_capacity * 2;
        if (new_capacity > MAX_GRAPH_NODES) {
            new_capacity = MAX_GRAPH_NODES;
        }
        if (graph->node_count >= new_capacity) {
            return SG_ERR_LIMIT;
        }
        
        sg_graph_node_t *new_nodes = realloc(graph->nodes,
                                              new_capacity * sizeof(sg_graph_node_t));
        if (new_nodes == NULL) {
            return SG_ERR_NOMEM;
        }
        graph->nodes = new_nodes;
        graph->node_capacity = new_capacity;
    }
    
    /* Add node */
    sg_graph_node_t *node = &graph->nodes[graph->node_count];
    memset(node, 0, sizeof(*node));
    
    node->id = (uint32_t)graph->node_count;
    node->type = type;
    if (label != NULL) {
        sg_safe_strncpy(node->label, label, sizeof(node->label));
    }
    node->pid = pid;
    if (addr != NULL) {
        node->addr = *addr;
    }
    node->sensitivity = sensitivity;
    
    graph->node_count++;
    
    return (int32_t)node->id;
}

/*
 * Add an edge to the graph
 */
int32_t sg_graph_add_edge(sg_graph_t *graph,
                           uint32_t source,
                           uint32_t target,
                           sg_edge_type_t type,
                           uint64_t event_id,
                           sg_timestamp_t timestamp,
                           uint64_t bytes)
{
    if (graph == NULL || source >= graph->node_count || target >= graph->node_count) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Expand if needed */
    if (graph->edge_count >= graph->edge_capacity) {
        size_t new_capacity = graph->edge_capacity * 2;
        if (new_capacity > MAX_GRAPH_EDGES) {
            new_capacity = MAX_GRAPH_EDGES;
        }
        if (graph->edge_count >= new_capacity) {
            return SG_ERR_LIMIT;
        }
        
        sg_graph_edge_t *new_edges = realloc(graph->edges,
                                              new_capacity * sizeof(sg_graph_edge_t));
        if (new_edges == NULL) {
            return SG_ERR_NOMEM;
        }
        graph->edges = new_edges;
        graph->edge_capacity = new_capacity;
    }
    
    /* Add edge */
    sg_graph_edge_t *edge = &graph->edges[graph->edge_count];
    memset(edge, 0, sizeof(*edge));
    
    edge->id = (uint32_t)graph->edge_count;
    edge->source = source;
    edge->target = target;
    edge->type = type;
    edge->event_id = event_id;
    edge->timestamp = timestamp;
    edge->bytes = bytes;
    
    /* Update node degrees */
    graph->nodes[source].out_degree++;
    graph->nodes[target].in_degree++;
    
    graph->edge_count++;
    
    return (int32_t)edge->id;
}

/*
 * Find node by label
 */
int32_t sg_graph_find_node(const sg_graph_t *graph, const char *label)
{
    if (graph == NULL || label == NULL) {
        return -1;
    }
    
    for (size_t i = 0; i < graph->node_count; i++) {
        if (strcmp(graph->nodes[i].label, label) == 0) {
            return (int32_t)i;
        }
    }
    
    return -1;
}

/*
 * Find process node by PID
 */
int32_t sg_graph_find_process(const sg_graph_t *graph, pid_t pid)
{
    if (graph == NULL) {
        return -1;
    }
    
    for (size_t i = 0; i < graph->node_count; i++) {
        if (graph->nodes[i].type == NODE_TYPE_PROCESS &&
            graph->nodes[i].pid == pid) {
            return (int32_t)i;
        }
    }
    
    return -1;
}

/*
 * Get node by ID
 */
const sg_graph_node_t *sg_graph_get_node(const sg_graph_t *graph, uint32_t id)
{
    if (graph == NULL || id >= graph->node_count) {
        return NULL;
    }
    return &graph->nodes[id];
}

/*
 * Get edge by ID
 */
const sg_graph_edge_t *sg_graph_get_edge(const sg_graph_t *graph, uint32_t id)
{
    if (graph == NULL || id >= graph->edge_count) {
        return NULL;
    }
    return &graph->edges[id];
}

/*
 * Build graph from trace
 */
sg_error_t sg_graph_build(const sg_trace_t *trace, sg_graph_t **graph_out)
{
    if (trace == NULL || graph_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_graph_t *graph = sg_graph_alloc();
    if (graph == NULL) {
        return SG_ERR_NOMEM;
    }
    
    sg_safe_strncpy(graph->trace_id, trace->meta.trace_id, sizeof(graph->trace_id));
    
    /* Track FD to node mapping */
    int32_t fd_nodes[MAX_FD_TABLE_SIZE];
    for (int i = 0; i < MAX_FD_TABLE_SIZE; i++) {
        fd_nodes[i] = -1;
    }
    
    /* Process each event */
    for (size_t i = 0; i < trace->event_count; i++) {
        const sg_syscall_event_t *event = &trace->events[i];
        uint32_t nr = event->syscall_nr;
        
        /* Ensure process node exists */
        char proc_label[64];
        snprintf(proc_label, sizeof(proc_label), "process:%d", event->pid);
        int32_t proc_node = sg_graph_add_node(graph, NODE_TYPE_PROCESS,
                                               proc_label, event->pid, NULL,
                                               SENSITIVITY_NONE);
        if (proc_node < 0) continue;
        
        /* Handle file open */
        if (nr == SYS_openat && event->ret_value >= 0) {
            int fd = (int)event->ret_value;
            const char *path = NULL;
            
            if (event->args[1].type == ARG_TYPE_PATH && event->args[1].valid) {
                path = event->args[1].value.str;
            }
            
            if (path != NULL && fd < MAX_FD_TABLE_SIZE) {
                sg_sensitivity_t sens = sg_path_sensitivity(path);
                int32_t file_node = sg_graph_add_node(graph, NODE_TYPE_FILE,
                                                       path, 0, NULL, sens);
                if (file_node >= 0) {
                    fd_nodes[fd] = file_node;
                    sg_graph_add_edge(graph, proc_node, file_node, EDGE_TYPE_OPEN,
                                      event->id, event->entry_time, 0);
                }
            }
        }
        /* Handle read */
        else if ((nr == SYS_read || nr == SYS_pread64) && event->ret_value > 0) {
            if (event->args[0].valid) {
                int fd = (int)event->args[0].value.i64;
                if (fd >= 0 && fd < MAX_FD_TABLE_SIZE && fd_nodes[fd] >= 0) {
                    sg_graph_add_edge(graph, fd_nodes[fd], proc_node, EDGE_TYPE_READ,
                                      event->id, event->entry_time, event->ret_value);
                }
            }
        }
        /* Handle write */
        else if ((nr == SYS_write || nr == SYS_pwrite64) && event->ret_value > 0) {
            if (event->args[0].valid) {
                int fd = (int)event->args[0].value.i64;
                if (fd >= 0 && fd < MAX_FD_TABLE_SIZE && fd_nodes[fd] >= 0) {
                    sg_graph_add_edge(graph, proc_node, fd_nodes[fd], EDGE_TYPE_WRITE,
                                      event->id, event->entry_time, event->ret_value);
                }
            }
        }
        /* Handle socket */
        else if (nr == SYS_socket && event->ret_value >= 0) {
            int fd = (int)event->ret_value;
            if (fd < MAX_FD_TABLE_SIZE) {
                char sock_label[64];
                snprintf(sock_label, sizeof(sock_label), "socket:%d:%d", event->pid, fd);
                int32_t sock_node = sg_graph_add_node(graph, NODE_TYPE_SOCKET,
                                                       sock_label, 0, NULL,
                                                       SENSITIVITY_NONE);
                if (sock_node >= 0) {
                    fd_nodes[fd] = sock_node;
                }
            }
        }
        /* Handle connect */
        else if (nr == SYS_connect && event->ret_value == 0) {
            if (event->args[0].valid && event->args[1].type == ARG_TYPE_SOCKADDR &&
                event->args[1].valid) {
                int fd = (int)event->args[0].value.i64;
                const sg_netaddr_t *addr = &event->args[1].value.addr;
                
                /* Create remote endpoint node */
                int32_t remote_node = sg_graph_add_node(graph, NODE_TYPE_REMOTE_ENDPOINT,
                                                         addr->str, 0, addr,
                                                         SENSITIVITY_NONE);
                if (remote_node >= 0) {
                    sg_graph_add_edge(graph, proc_node, remote_node, EDGE_TYPE_CONNECT,
                                      event->id, event->entry_time, 0);
                    
                    if (fd >= 0 && fd < MAX_FD_TABLE_SIZE) {
                        fd_nodes[fd] = remote_node;
                    }
                }
            }
        }
        /* Handle sendto */
        else if (nr == SYS_sendto && event->ret_value > 0) {
            if (event->args[0].valid) {
                int fd = (int)event->args[0].value.i64;
                int32_t target = -1;
                
                if (event->args[4].type == ARG_TYPE_SOCKADDR && event->args[4].valid) {
                    const sg_netaddr_t *addr = &event->args[4].value.addr;
                    target = sg_graph_add_node(graph, NODE_TYPE_REMOTE_ENDPOINT,
                                                addr->str, 0, addr, SENSITIVITY_NONE);
                } else if (fd >= 0 && fd < MAX_FD_TABLE_SIZE && fd_nodes[fd] >= 0) {
                    target = fd_nodes[fd];
                }
                
                if (target >= 0) {
                    sg_graph_add_edge(graph, proc_node, target, EDGE_TYPE_SEND,
                                      event->id, event->entry_time, event->ret_value);
                }
            }
        }
        /* Handle clone/fork */
        else if ((nr == SYS_clone || nr == SYS_clone3) && event->ret_value > 0) {
            pid_t child_pid = (pid_t)event->ret_value;
            char child_label[64];
            snprintf(child_label, sizeof(child_label), "process:%d", child_pid);
            int32_t child_node = sg_graph_add_node(graph, NODE_TYPE_PROCESS,
                                                    child_label, child_pid, NULL,
                                                    SENSITIVITY_NONE);
            if (child_node >= 0) {
                sg_graph_add_edge(graph, proc_node, child_node, EDGE_TYPE_FORK,
                                  event->id, event->entry_time, 0);
            }
        }
        /* Handle close */
        else if (nr == SYS_close) {
            if (event->args[0].valid) {
                int fd = (int)event->args[0].value.i64;
                if (fd >= 0 && fd < MAX_FD_TABLE_SIZE && fd_nodes[fd] >= 0) {
                    sg_graph_add_edge(graph, proc_node, fd_nodes[fd], EDGE_TYPE_CLOSE,
                                      event->id, event->entry_time, 0);
                    fd_nodes[fd] = -1;
                }
            }
        }
    }
    
    *graph_out = graph;
    return SG_OK;
}

/*
 * Get graph statistics
 */
sg_error_t sg_graph_stats(const sg_graph_t *graph, sg_graph_stats_t *stats_out)
{
    if (graph == NULL || stats_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(stats_out, 0, sizeof(*stats_out));
    
    stats_out->node_count = graph->node_count;
    stats_out->edge_count = graph->edge_count;
    
    uint64_t total_degree = 0;
    
    for (size_t i = 0; i < graph->node_count; i++) {
        const sg_graph_node_t *node = &graph->nodes[i];
        
        switch (node->type) {
            case NODE_TYPE_PROCESS:
                stats_out->process_count++;
                break;
            case NODE_TYPE_FILE:
                stats_out->file_count++;
                break;
            case NODE_TYPE_SOCKET:
                stats_out->socket_count++;
                break;
            case NODE_TYPE_REMOTE_ENDPOINT:
                stats_out->remote_count++;
                break;
            default:
                break;
        }
        
        if (node->sensitivity > SENSITIVITY_NONE) {
            stats_out->sensitive_node_count++;
        }
        
        total_degree += node->in_degree + node->out_degree;
        
        if (node->in_degree > stats_out->max_in_degree) {
            stats_out->max_in_degree = node->in_degree;
        }
        if (node->out_degree > stats_out->max_out_degree) {
            stats_out->max_out_degree = node->out_degree;
        }
    }
    
    if (graph->node_count > 0) {
        stats_out->avg_degree = (double)total_degree / (double)graph->node_count;
    }
    
    return SG_OK;
}

/*
 * Export graph to DOT format
 */
char *sg_graph_to_dot(const sg_graph_t *graph)
{
    if (graph == NULL) {
        return NULL;
    }
    
    /* Estimate size */
    size_t buf_size = 1024 + graph->node_count * 256 + graph->edge_count * 128;
    char *buf = malloc(buf_size);
    if (buf == NULL) {
        return NULL;
    }
    
    int pos = 0;
    pos += snprintf(buf + pos, buf_size - pos, "digraph auris {\n");
    pos += snprintf(buf + pos, buf_size - pos, "  rankdir=LR;\n");
    pos += snprintf(buf + pos, buf_size - pos, "  node [shape=box];\n\n");
    
    /* Node type colors */
    const char *node_colors[] = {
        "lightblue",   /* PROCESS */
        "lightgreen",  /* FILE */
        "lightyellow", /* SOCKET */
        "lightgray",   /* PIPE */
        "lightcoral",  /* REMOTE */
    };
    
    /* Nodes */
    for (size_t i = 0; i < graph->node_count; i++) {
        const sg_graph_node_t *node = &graph->nodes[i];
        const char *color = node_colors[node->type % 5];
        
        if (node->sensitivity >= SENSITIVITY_HIGH) {
            color = "red";
        } else if (node->sensitivity >= SENSITIVITY_MEDIUM) {
            color = "orange";
        }
        
        pos += snprintf(buf + pos, buf_size - pos,
                        "  n%u [label=\"%s\" style=filled fillcolor=%s];\n",
                        node->id, node->label, color);
    }
    
    pos += snprintf(buf + pos, buf_size - pos, "\n");
    
    /* Edge type labels */
    const char *edge_labels[] = {
        "read", "write", "open", "close", "connect",
        "accept", "send", "recv", "fork", "exec", "pipe", "dup"
    };
    
    /* Edges */
    for (size_t i = 0; i < graph->edge_count; i++) {
        const sg_graph_edge_t *edge = &graph->edges[i];
        const char *label = edge_labels[edge->type % 12];
        
        pos += snprintf(buf + pos, buf_size - pos,
                        "  n%u -> n%u [label=\"%s\"];\n",
                        edge->source, edge->target, label);
    }
    
    pos += snprintf(buf + pos, buf_size - pos, "}\n");
    
    return buf;
}

/*
 * Generate graph summary for AI
 */
char *sg_graph_summary(const sg_graph_t *graph)
{
    if (graph == NULL) {
        return NULL;
    }
    
    sg_graph_stats_t stats;
    sg_graph_stats(graph, &stats);
    
    size_t buf_size = 4096;
    char *buf = malloc(buf_size);
    if (buf == NULL) {
        return NULL;
    }
    
    int pos = 0;
    pos += snprintf(buf + pos, buf_size - pos,
                    "Graph Summary:\n"
                    "- Total nodes: %zu\n"
                    "- Total edges: %zu\n"
                    "- Processes: %zu\n"
                    "- Files: %zu\n"
                    "- Sockets: %zu\n"
                    "- Remote endpoints: %zu\n"
                    "- Sensitive nodes: %zu\n"
                    "- Average degree: %.2f\n"
                    "- Max in-degree: %u\n"
                    "- Max out-degree: %u\n\n",
                    stats.node_count, stats.edge_count,
                    stats.process_count, stats.file_count,
                    stats.socket_count, stats.remote_count,
                    stats.sensitive_node_count, stats.avg_degree,
                    stats.max_in_degree, stats.max_out_degree);
    
    /* List sensitive nodes */
    if (stats.sensitive_node_count > 0) {
        pos += snprintf(buf + pos, buf_size - pos, "Sensitive nodes:\n");
        for (size_t i = 0; i < graph->node_count && (size_t)pos < buf_size - 100; i++) {
            if (graph->nodes[i].sensitivity >= SENSITIVITY_MEDIUM) {
                pos += snprintf(buf + pos, buf_size - pos, "- %s (level %d)\n",
                                graph->nodes[i].label, graph->nodes[i].sensitivity);
            }
        }
    }
    
    /* List remote endpoints */
    if (stats.remote_count > 0) {
        pos += snprintf(buf + pos, buf_size - pos, "\nRemote endpoints:\n");
        for (size_t i = 0; i < graph->node_count && (size_t)pos < buf_size - 100; i++) {
            if (graph->nodes[i].type == NODE_TYPE_REMOTE_ENDPOINT) {
                pos += snprintf(buf + pos, buf_size - pos, "- %s\n",
                                graph->nodes[i].label);
            }
        }
    }
    
    return buf;
}

/*
 * Save graph to file
 */
sg_error_t sg_graph_save(const sg_graph_t *graph, const char *path)
{
    if (graph == NULL || path == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    char *json = sg_graph_to_json(graph);
    if (json == NULL) {
        return SG_ERR_NOMEM;
    }
    
    sg_error_t err = sg_write_file(path, json, strlen(json));
    free(json);
    
    return err;
}
