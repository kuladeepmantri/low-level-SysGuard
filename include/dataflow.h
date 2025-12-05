/*
 * Auris - Data Flow Analyzer
 * Track data flow through file descriptors and detect potential exfiltration
 */

#ifndef AURIS_DATAFLOW_H
#define AURIS_DATAFLOW_H

#include "auris.h"
#include "trace_store.h"
#include "graph.h"

/* Data flow tracking context */
typedef struct {
    /* File descriptor to source mapping */
    struct {
        int fd;
        char source_path[MAX_PATH_LEN];
        sg_sensitivity_t sensitivity;
        uint64_t bytes_read;
        bool tainted;
    } fd_sources[MAX_FD_TABLE_SIZE];
    
    /* Tracked sensitive reads */
    struct {
        uint64_t event_id;
        int fd;
        char path[MAX_PATH_LEN];
        sg_sensitivity_t sensitivity;
        size_t bytes;
    } *sensitive_reads;
    size_t read_count;
    size_t read_capacity;
    
    /* Tracked network writes */
    struct {
        uint64_t event_id;
        int fd;
        sg_netaddr_t remote;
        size_t bytes;
        bool from_sensitive;
    } *network_writes;
    size_t write_count;
    size_t write_capacity;
    
} sg_dataflow_ctx_t;

/*
 * Initialize data flow analysis context
 */
sg_error_t sg_dataflow_init(sg_dataflow_ctx_t *ctx);

/*
 * Clean up data flow context
 */
void sg_dataflow_cleanup(sg_dataflow_ctx_t *ctx);

/*
 * Analyze a trace for potential data exfiltration
 */
sg_error_t sg_dataflow_analyze(const sg_trace_t *trace,
                                sg_dataflow_result_t **result_out);

/*
 * Free data flow result
 */
void sg_dataflow_result_free(sg_dataflow_result_t *result);

/*
 * Process a single syscall event for data flow tracking
 */
sg_error_t sg_dataflow_process_event(sg_dataflow_ctx_t *ctx,
                                      const sg_syscall_event_t *event);

/*
 * Check if a file descriptor is tainted (contains sensitive data)
 */
bool sg_dataflow_is_tainted(sg_dataflow_ctx_t *ctx, int fd);

/*
 * Get sensitivity level of a file descriptor
 */
sg_sensitivity_t sg_dataflow_get_sensitivity(sg_dataflow_ctx_t *ctx, int fd);

/*
 * Mark a file descriptor as tainted
 */
void sg_dataflow_mark_tainted(sg_dataflow_ctx_t *ctx, 
                               int fd, 
                               const char *source,
                               sg_sensitivity_t level);

/*
 * Handle FD duplication (dup, dup2, dup3)
 */
void sg_dataflow_handle_dup(sg_dataflow_ctx_t *ctx, int old_fd, int new_fd);

/*
 * Handle FD close
 */
void sg_dataflow_handle_close(sg_dataflow_ctx_t *ctx, int fd);

/*
 * Detect potential exfiltration flows
 * Correlates sensitive reads with network writes
 */
sg_error_t sg_dataflow_detect_exfil(sg_dataflow_ctx_t *ctx,
                                     const sg_trace_t *trace,
                                     sg_exfil_flow_t **flows_out,
                                     size_t *count_out);

/*
 * Calculate exfiltration risk score
 */
double sg_dataflow_risk_score(const sg_dataflow_result_t *result);

/*
 * Serialize data flow result to JSON
 */
char *sg_dataflow_result_to_json(const sg_dataflow_result_t *result);

/* Sensitive path detection */

/*
 * Check if a path is sensitive
 */
sg_sensitivity_t sg_path_sensitivity(const char *path);

/*
 * Check if path matches any sensitive pattern
 */
bool sg_is_sensitive_path(const char *path);

/*
 * Get description of why a path is sensitive
 */
const char *sg_sensitive_path_reason(const char *path);

/*
 * Add custom sensitive path pattern
 */
sg_error_t sg_add_sensitive_pattern(const char *pattern, 
                                     sg_sensitivity_t level,
                                     const char *reason);

/*
 * Load sensitive patterns from config file
 */
sg_error_t sg_load_sensitive_patterns(const char *config_path);

/*
 * Clean up custom sensitive patterns
 * Should be called at program exit to free memory
 */
void sg_sensitive_patterns_cleanup(void);

#endif /* AURIS_DATAFLOW_H */
