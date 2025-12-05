/*
 * Auris - Data Flow Analyzer
 * Track data flow and detect potential exfiltration
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "dataflow.h"
#include "syscall_table.h"

/* Initial capacities */
#define INITIAL_READ_CAPACITY 256
#define INITIAL_WRITE_CAPACITY 256

/*
 * Initialize data flow context
 */
sg_error_t sg_dataflow_init(sg_dataflow_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(ctx, 0, sizeof(*ctx));
    
    /* Initialize FD sources */
    for (int i = 0; i < MAX_FD_TABLE_SIZE; i++) {
        ctx->fd_sources[i].fd = -1;
        ctx->fd_sources[i].sensitivity = SENSITIVITY_NONE;
        ctx->fd_sources[i].tainted = false;
    }
    
    /* Allocate tracking arrays */
    ctx->sensitive_reads = calloc(INITIAL_READ_CAPACITY, sizeof(*ctx->sensitive_reads));
    if (ctx->sensitive_reads == NULL) {
        return SG_ERR_NOMEM;
    }
    ctx->read_capacity = INITIAL_READ_CAPACITY;
    
    ctx->network_writes = calloc(INITIAL_WRITE_CAPACITY, sizeof(*ctx->network_writes));
    if (ctx->network_writes == NULL) {
        free(ctx->sensitive_reads);
        return SG_ERR_NOMEM;
    }
    ctx->write_capacity = INITIAL_WRITE_CAPACITY;
    
    return SG_OK;
}

/*
 * Clean up data flow context
 */
void sg_dataflow_cleanup(sg_dataflow_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    if (ctx->sensitive_reads != NULL) {
        free(ctx->sensitive_reads);
    }
    if (ctx->network_writes != NULL) {
        free(ctx->network_writes);
    }
    
    memset(ctx, 0, sizeof(*ctx));
}

/*
 * Check if FD is tainted
 */
bool sg_dataflow_is_tainted(sg_dataflow_ctx_t *ctx, int fd)
{
    if (ctx == NULL || fd < 0 || fd >= MAX_FD_TABLE_SIZE) {
        return false;
    }
    return ctx->fd_sources[fd].tainted;
}

/*
 * Get sensitivity of FD
 */
sg_sensitivity_t sg_dataflow_get_sensitivity(sg_dataflow_ctx_t *ctx, int fd)
{
    if (ctx == NULL || fd < 0 || fd >= MAX_FD_TABLE_SIZE) {
        return SENSITIVITY_NONE;
    }
    return ctx->fd_sources[fd].sensitivity;
}

/*
 * Mark FD as tainted
 */
void sg_dataflow_mark_tainted(sg_dataflow_ctx_t *ctx,
                               int fd,
                               const char *source,
                               sg_sensitivity_t level)
{
    if (ctx == NULL || fd < 0 || fd >= MAX_FD_TABLE_SIZE) {
        return;
    }
    
    ctx->fd_sources[fd].fd = fd;
    ctx->fd_sources[fd].tainted = true;
    ctx->fd_sources[fd].sensitivity = level;
    if (source != NULL) {
        sg_safe_strncpy(ctx->fd_sources[fd].source_path, source,
                        sizeof(ctx->fd_sources[fd].source_path));
    }
}

/*
 * Handle FD duplication
 */
void sg_dataflow_handle_dup(sg_dataflow_ctx_t *ctx, int old_fd, int new_fd)
{
    if (ctx == NULL || old_fd < 0 || old_fd >= MAX_FD_TABLE_SIZE ||
        new_fd < 0 || new_fd >= MAX_FD_TABLE_SIZE) {
        return;
    }
    
    /* Copy taint from old to new */
    ctx->fd_sources[new_fd] = ctx->fd_sources[old_fd];
    ctx->fd_sources[new_fd].fd = new_fd;
}

/*
 * Handle FD close
 */
void sg_dataflow_handle_close(sg_dataflow_ctx_t *ctx, int fd)
{
    if (ctx == NULL || fd < 0 || fd >= MAX_FD_TABLE_SIZE) {
        return;
    }
    
    ctx->fd_sources[fd].fd = -1;
    ctx->fd_sources[fd].tainted = false;
    ctx->fd_sources[fd].sensitivity = SENSITIVITY_NONE;
    ctx->fd_sources[fd].source_path[0] = '\0';
    ctx->fd_sources[fd].bytes_read = 0;
}

/*
 * Process a single syscall event
 */
sg_error_t sg_dataflow_process_event(sg_dataflow_ctx_t *ctx,
                                      const sg_syscall_event_t *event)
{
    if (ctx == NULL || event == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    uint32_t nr = event->syscall_nr;
    
    /* Handle file open */
    if (nr == SYS_openat) {
        if (event->ret_value >= 0 && event->ret_value < MAX_FD_TABLE_SIZE) {
            int fd = (int)event->ret_value;
            const char *path = NULL;
            
            /* Get path from args */
            if (event->args[1].type == ARG_TYPE_PATH && event->args[1].valid) {
                path = event->args[1].value.str;
            }
            
            if (path != NULL) {
                sg_sensitivity_t sens = sg_path_sensitivity(path);
                if (sens > SENSITIVITY_NONE) {
                    sg_dataflow_mark_tainted(ctx, fd, path, sens);
                } else {
                    ctx->fd_sources[fd].fd = fd;
                    sg_safe_strncpy(ctx->fd_sources[fd].source_path, path,
                                    sizeof(ctx->fd_sources[fd].source_path));
                }
            }
        }
    }
    /* Handle read from sensitive file */
    else if (nr == SYS_read || nr == SYS_pread64) {
        if (event->args[0].valid && event->ret_value > 0) {
            int fd = (int)event->args[0].value.i64;
            
            if (fd >= 0 && fd < MAX_FD_TABLE_SIZE) {
                ctx->fd_sources[fd].bytes_read += event->ret_value;
                
                if (ctx->fd_sources[fd].sensitivity >= SENSITIVITY_MEDIUM) {
                    /* Record sensitive read */
                    if (ctx->read_count < ctx->read_capacity) {
                        ctx->sensitive_reads[ctx->read_count].event_id = event->id;
                        ctx->sensitive_reads[ctx->read_count].fd = fd;
                        sg_safe_strncpy(ctx->sensitive_reads[ctx->read_count].path,
                                        ctx->fd_sources[fd].source_path,
                                        sizeof(ctx->sensitive_reads[ctx->read_count].path));
                        ctx->sensitive_reads[ctx->read_count].sensitivity = 
                            ctx->fd_sources[fd].sensitivity;
                        ctx->sensitive_reads[ctx->read_count].bytes = event->ret_value;
                        ctx->read_count++;
                    }
                }
            }
        }
    }
    /* Handle network write */
    else if (nr == SYS_sendto || nr == SYS_write || nr == SYS_sendmsg) {
        if (event->args[0].valid && event->ret_value > 0) {
            int fd = (int)event->args[0].value.i64;
            
            /* Check if this is a socket (we track this based on prior connect/socket calls) */
            if (fd >= 0 && fd < MAX_FD_TABLE_SIZE) {
                /* For sendto, check if there's a destination address */
                bool is_network = false;
                sg_netaddr_t remote = {0};
                
                if (nr == SYS_sendto && event->args[4].type == ARG_TYPE_SOCKADDR &&
                    event->args[4].valid) {
                    is_network = true;
                    remote = event->args[4].value.addr;
                }
                
                /* Also consider any write to a socket FD as potential network */
                /* This is a simplification - in practice we'd track socket creation */
                
                if (is_network || ctx->fd_sources[fd].bytes_read > 0) {
                    if (ctx->write_count < ctx->write_capacity) {
                        ctx->network_writes[ctx->write_count].event_id = event->id;
                        ctx->network_writes[ctx->write_count].fd = fd;
                        ctx->network_writes[ctx->write_count].remote = remote;
                        ctx->network_writes[ctx->write_count].bytes = event->ret_value;
                        ctx->network_writes[ctx->write_count].from_sensitive = 
                            sg_dataflow_is_tainted(ctx, fd);
                        ctx->write_count++;
                    }
                }
            }
        }
    }
    /* Handle socket connect */
    else if (nr == SYS_connect) {
        if (event->args[0].valid && event->ret_value == 0) {
            int fd = (int)event->args[0].value.i64;
            
            if (fd >= 0 && fd < MAX_FD_TABLE_SIZE &&
                event->args[1].type == ARG_TYPE_SOCKADDR && event->args[1].valid) {
                ctx->fd_sources[fd].fd = fd;
                /* Mark as network socket by storing remote address */
                snprintf(ctx->fd_sources[fd].source_path,
                         sizeof(ctx->fd_sources[fd].source_path),
                         "socket:%s", event->args[1].value.addr.str);
            }
        }
    }
    /* Handle dup */
    else if (nr == SYS_dup || nr == SYS_dup3) {
        if (event->args[0].valid && event->ret_value >= 0) {
            int old_fd = (int)event->args[0].value.i64;
            int new_fd = (int)event->ret_value;
            sg_dataflow_handle_dup(ctx, old_fd, new_fd);
        }
    }
    /* Handle close */
    else if (nr == SYS_close) {
        if (event->args[0].valid) {
            int fd = (int)event->args[0].value.i64;
            sg_dataflow_handle_close(ctx, fd);
        }
    }
    
    return SG_OK;
}

/*
 * Detect potential exfiltration flows
 */
sg_error_t sg_dataflow_detect_exfil(sg_dataflow_ctx_t *ctx,
                                     const sg_trace_t *trace,
                                     sg_exfil_flow_t **flows_out,
                                     size_t *count_out)
{
    if (ctx == NULL || flows_out == NULL || count_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Simple heuristic: look for sensitive reads followed by network writes */
    size_t max_flows = ctx->read_count < MAX_EXFIL_FLOWS ? ctx->read_count : MAX_EXFIL_FLOWS;
    
    if (max_flows == 0) {
        *flows_out = NULL;
        *count_out = 0;
        return SG_OK;
    }
    
    sg_exfil_flow_t *flows = calloc(max_flows, sizeof(sg_exfil_flow_t));
    if (flows == NULL) {
        return SG_ERR_NOMEM;
    }
    
    size_t flow_count = 0;
    
    /* For each sensitive read, look for subsequent network writes */
    for (size_t i = 0; i < ctx->read_count && flow_count < max_flows; i++) {
        uint64_t read_event = ctx->sensitive_reads[i].event_id;
        
        for (size_t j = 0; j < ctx->write_count; j++) {
            /* Network write after sensitive read */
            if (ctx->network_writes[j].event_id > read_event) {
                sg_exfil_flow_t *flow = &flows[flow_count];
                
                sg_safe_strncpy(flow->source_path, ctx->sensitive_reads[i].path,
                                sizeof(flow->source_path));
                flow->sink_addr = ctx->network_writes[j].remote;
                flow->sensitivity = ctx->sensitive_reads[i].sensitivity;
                flow->bytes_transferred = ctx->network_writes[j].bytes;
                
                /* Calculate confidence based on timing and sensitivity */
                double time_factor = 1.0;
                if (trace != NULL && ctx->network_writes[j].event_id < trace->event_count &&
                    read_event < trace->event_count) {
                    /* Events closer together = higher confidence */
                    uint64_t event_gap = ctx->network_writes[j].event_id - read_event;
                    time_factor = 1.0 / (1.0 + (double)event_gap / 100.0);
                }
                
                flow->confidence = time_factor * 
                    ((double)flow->sensitivity / (double)SENSITIVITY_CRITICAL);
                
                flow_count++;
                break;  /* One flow per sensitive read */
            }
        }
    }
    
    *flows_out = flows;
    *count_out = flow_count;
    
    return SG_OK;
}

/*
 * Analyze trace for data flow
 */
sg_error_t sg_dataflow_analyze(const sg_trace_t *trace,
                                sg_dataflow_result_t **result_out)
{
    if (trace == NULL || result_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_dataflow_ctx_t ctx;
    sg_error_t err = sg_dataflow_init(&ctx);
    if (err != SG_OK) {
        return err;
    }
    
    /* Process all events */
    for (size_t i = 0; i < trace->event_count; i++) {
        sg_dataflow_process_event(&ctx, &trace->events[i]);
    }
    
    /* Allocate result */
    sg_dataflow_result_t *result = calloc(1, sizeof(sg_dataflow_result_t));
    if (result == NULL) {
        sg_dataflow_cleanup(&ctx);
        return SG_ERR_NOMEM;
    }
    
    /* Detect exfiltration flows */
    err = sg_dataflow_detect_exfil(&ctx, trace, &result->flows, &result->flow_count);
    if (err != SG_OK) {
        free(result);
        sg_dataflow_cleanup(&ctx);
        return err;
    }
    
    /* Calculate risk score */
    result->overall_risk = sg_dataflow_risk_score(result);
    result->has_high_risk_flows = false;
    
    for (size_t i = 0; i < result->flow_count; i++) {
        if (result->flows[i].sensitivity >= SENSITIVITY_HIGH) {
            result->has_high_risk_flows = true;
            break;
        }
    }
    
    sg_dataflow_cleanup(&ctx);
    
    *result_out = result;
    return SG_OK;
}

/*
 * Free data flow result
 */
void sg_dataflow_result_free(sg_dataflow_result_t *result)
{
    if (result == NULL) {
        return;
    }
    
    if (result->flows != NULL) {
        free(result->flows);
    }
    free(result);
}

/*
 * Calculate risk score
 */
double sg_dataflow_risk_score(const sg_dataflow_result_t *result)
{
    if (result == NULL || result->flow_count == 0) {
        return 0.0;
    }
    
    double max_risk = 0.0;
    double total_risk = 0.0;
    
    for (size_t i = 0; i < result->flow_count; i++) {
        double flow_risk = result->flows[i].confidence *
            ((double)result->flows[i].sensitivity / (double)SENSITIVITY_CRITICAL);
        
        total_risk += flow_risk;
        if (flow_risk > max_risk) {
            max_risk = flow_risk;
        }
    }
    
    /* Combine max and average */
    double avg_risk = total_risk / result->flow_count;
    return 0.7 * max_risk + 0.3 * avg_risk;
}
