/*
 * Auris - Policy Enforcer
 * Runtime enforcement of security policies via ptrace
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <linux/ptrace.h>

#include "auris.h"
#include "enforcer.h"
#include "syscall_table.h"

/* Initial violation capacity */
#define INITIAL_VIOLATION_CAPACITY 256

/*
 * Initialize enforcer context
 */
sg_error_t sg_enforcer_init(sg_enforcer_ctx_t *ctx,
                             sg_policy_t *policy,
                             sg_enforce_mode_t mode,
                             sg_config_t *config)
{
    if (ctx == NULL || policy == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(ctx, 0, sizeof(*ctx));
    
    ctx->policy = policy;
    ctx->mode = mode;
    ctx->terminate_on_block = (mode == ENFORCE_MODE_BLOCK);
    ctx->block_signal = SIGKILL;
    
    /* Initialize tracer */
    sg_error_t err = sg_tracer_init(&ctx->tracer, config);
    if (err != SG_OK) {
        return err;
    }
    
    /* Allocate violation log */
    ctx->violations = calloc(INITIAL_VIOLATION_CAPACITY, sizeof(sg_violation_t));
    if (ctx->violations == NULL) {
        sg_tracer_cleanup(&ctx->tracer);
        return SG_ERR_NOMEM;
    }
    ctx->violation_capacity = INITIAL_VIOLATION_CAPACITY;
    
    ctx->stats.start_time = sg_now();
    
    return SG_OK;
}

/*
 * Clean up enforcer context
 */
void sg_enforcer_cleanup(sg_enforcer_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    sg_tracer_cleanup(&ctx->tracer);
    
    if (ctx->violations != NULL) {
        free(ctx->violations);
        ctx->violations = NULL;
    }
}

/*
 * Record a violation
 */
static sg_error_t record_violation(sg_enforcer_ctx_t *ctx,
                                    const sg_syscall_event_t *event,
                                    sg_policy_action_t action,
                                    const char *path)
{
    if (ctx->violation_count >= ctx->violation_capacity) {
        size_t new_capacity = ctx->violation_capacity * 2;
        sg_violation_t *new_violations = realloc(ctx->violations,
                                                  new_capacity * sizeof(sg_violation_t));
        if (new_violations == NULL) {
            return SG_ERR_NOMEM;
        }
        ctx->violations = new_violations;
        ctx->violation_capacity = new_capacity;
    }
    
    sg_violation_t *v = &ctx->violations[ctx->violation_count];
    memset(v, 0, sizeof(*v));
    
    v->event_id = event->id;
    v->timestamp = event->entry_time;
    v->pid = event->pid;
    v->syscall_nr = event->syscall_nr;
    sg_safe_strncpy(v->syscall_name, event->syscall_name, sizeof(v->syscall_name));
    v->action_taken = action;
    
    if (path != NULL) {
        sg_safe_strncpy(v->path, path, sizeof(v->path));
    }
    
    const sg_policy_rule_t *rule = sg_policy_get_rule(ctx->policy, event->syscall_nr);
    if (rule != NULL && rule->reason[0] != '\0') {
        sg_safe_strncpy(v->reason, rule->reason, sizeof(v->reason));
    } else {
        snprintf(v->reason, sizeof(v->reason), "Syscall not in policy");
    }
    
    ctx->violation_count++;
    
    return SG_OK;
}

/*
 * Check syscall and take action
 */
sg_policy_action_t sg_enforcer_check_syscall(sg_enforcer_ctx_t *ctx,
                                              pid_t pid,
                                              uint32_t syscall_nr,
                                              const sg_arg_value_t args[6])
{
    if (ctx == NULL || ctx->policy == NULL) {
        return POLICY_ACTION_ALLOW;
    }
    
    /* Extract path if present */
    const char *path = NULL;
    for (int i = 0; i < MAX_SYSCALL_ARGS; i++) {
        if (args[i].type == ARG_TYPE_PATH && args[i].valid) {
            path = args[i].value.str;
            break;
        }
    }
    
    /* Check policy */
    sg_policy_action_t action = sg_policy_check(ctx->policy, syscall_nr, path);
    
    /* Update statistics */
    ctx->stats.total_syscalls++;
    
    switch (action) {
        case POLICY_ACTION_ALLOW:
            ctx->stats.allowed_syscalls++;
            break;
        case POLICY_ACTION_LOG:
            ctx->stats.logged_syscalls++;
            break;
        case POLICY_ACTION_ALERT:
            ctx->stats.alerted_syscalls++;
            break;
        case POLICY_ACTION_BLOCK:
            ctx->stats.blocked_syscalls++;
            break;
    }
    
    return action;
}

/*
 * Block a syscall by modifying return value
 * This makes the syscall return -EPERM
 */
sg_error_t sg_enforcer_block_syscall(sg_enforcer_ctx_t *ctx, pid_t pid)
{
    (void)ctx;
    
    /* On ARM64, we can modify x0 to set the return value to -EPERM
     * We need to use PTRACE_SETREGSET */
    
    struct {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    } user_regs;
    
    struct iovec iov = {
        .iov_base = &user_regs,
        .iov_len = sizeof(user_regs),
    };
    
    /* Read current registers */
    if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) < 0) {
        sg_log(SG_LOG_WARN, "Failed to get registers for blocking: %s",
               strerror(errno));
        return SG_ERR_PTRACE;
    }
    
    /* Set x0 to -EPERM (-1) */
    user_regs.regs[0] = (uint64_t)(-1);
    
    /* Also set x8 (syscall number) to -1 to prevent syscall execution */
    user_regs.regs[8] = (uint64_t)(-1);
    
    /* Write back */
    if (ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov) < 0) {
        sg_log(SG_LOG_WARN, "Failed to set registers for blocking: %s",
               strerror(errno));
        return SG_ERR_PTRACE;
    }
    
    return SG_OK;
}

/*
 * Terminate a traced process
 */
sg_error_t sg_enforcer_terminate(sg_enforcer_ctx_t *ctx, pid_t pid)
{
    if (ctx == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_log(SG_LOG_WARN, "Terminating process %d due to policy violation", pid);
    
    if (kill(pid, ctx->block_signal) < 0) {
        sg_log(SG_LOG_ERROR, "Failed to kill process %d: %s", pid, strerror(errno));
        return SG_ERR_SYSCALL;
    }
    
    return SG_OK;
}

/*
 * Syscall entry callback for enforcement
 */
static void enforce_syscall_entry(sg_tracer_ctx_t *tracer, sg_syscall_event_t *event)
{
    sg_enforcer_ctx_t *ctx = tracer->user_data;
    if (ctx == NULL) {
        return;
    }
    
    sg_policy_action_t action = sg_enforcer_check_syscall(ctx, event->pid,
                                                           event->syscall_nr,
                                                           event->args);
    
    if (action == POLICY_ACTION_BLOCK) {
        /* Record violation */
        const char *path = NULL;
        for (int i = 0; i < MAX_SYSCALL_ARGS; i++) {
            if (event->args[i].type == ARG_TYPE_PATH && event->args[i].valid) {
                path = event->args[i].value.str;
                break;
            }
        }
        record_violation(ctx, event, action, path);
        
        /* Call violation callback */
        if (ctx->on_violation != NULL) {
            ctx->on_violation(ctx, &ctx->violations[ctx->violation_count - 1]);
        }
        
        if (ctx->mode == ENFORCE_MODE_BLOCK) {
            /* Block the syscall */
            sg_enforcer_block_syscall(ctx, event->pid);
            
            if (ctx->terminate_on_block) {
                sg_enforcer_terminate(ctx, event->pid);
            }
            
            if (ctx->on_block != NULL) {
                ctx->on_block(ctx, &ctx->violations[ctx->violation_count - 1]);
            }
        }
        
        sg_log(SG_LOG_WARN, "[%d] BLOCKED: %s", event->pid, event->syscall_name);
    } else if (action == POLICY_ACTION_ALERT) {
        /* Record but don't block */
        const char *path = NULL;
        for (int i = 0; i < MAX_SYSCALL_ARGS; i++) {
            if (event->args[i].type == ARG_TYPE_PATH && event->args[i].valid) {
                path = event->args[i].value.str;
                break;
            }
        }
        record_violation(ctx, event, action, path);
        
        if (ctx->on_violation != NULL) {
            ctx->on_violation(ctx, &ctx->violations[ctx->violation_count - 1]);
        }
        
        sg_log(SG_LOG_WARN, "[%d] ALERT: %s", event->pid, event->syscall_name);
    } else if (action == POLICY_ACTION_LOG || ctx->log_allowed) {
        sg_log(SG_LOG_DEBUG, "[%d] ALLOW: %s", event->pid, event->syscall_name);
    }
}

/*
 * Run program under enforcement
 */
sg_error_t sg_enforcer_run(sg_enforcer_ctx_t *ctx,
                            const char *path,
                            char *const argv[],
                            char *const envp[])
{
    if (ctx == NULL || path == NULL || argv == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Set up callbacks */
    ctx->tracer.on_syscall_entry = enforce_syscall_entry;
    ctx->tracer.user_data = ctx;
    
    ctx->running = true;
    ctx->stats.start_time = sg_now();
    
    sg_log(SG_LOG_INFO, "Starting enforcement for %s (mode: %s)",
           path, ctx->mode == ENFORCE_MODE_BLOCK ? "block" : "alert");
    
    /* Run with tracing */
    sg_trace_t *trace = NULL;
    sg_error_t err = sg_tracer_run(&ctx->tracer, path, argv, envp, &trace);
    
    ctx->stats.end_time = sg_now();
    ctx->running = false;
    
    /* We don't need the trace for enforcement, just the side effects */
    if (trace != NULL) {
        sg_trace_free(trace);
    }
    
    sg_log(SG_LOG_INFO, "Enforcement complete: %lu syscalls, %zu violations",
           (unsigned long)ctx->stats.total_syscalls, ctx->violation_count);
    
    return err;
}

/*
 * Stop enforcement
 */
void sg_enforcer_stop(sg_enforcer_ctx_t *ctx)
{
    if (ctx != NULL) {
        ctx->interrupted = 1;
        ctx->running = false;
        sg_tracer_stop(&ctx->tracer);
    }
}

/*
 * Get enforcement statistics
 */
sg_error_t sg_enforcer_get_stats(const sg_enforcer_ctx_t *ctx,
                                  sg_enforce_stats_t *stats_out)
{
    if (ctx == NULL || stats_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    *stats_out = ctx->stats;
    return SG_OK;
}

/*
 * Get violations
 */
sg_error_t sg_enforcer_get_violations(const sg_enforcer_ctx_t *ctx,
                                       sg_violation_t **violations_out,
                                       size_t *count_out)
{
    if (ctx == NULL || violations_out == NULL || count_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (ctx->violation_count == 0) {
        *violations_out = NULL;
        *count_out = 0;
        return SG_OK;
    }
    
    sg_violation_t *copy = calloc(ctx->violation_count, sizeof(sg_violation_t));
    if (copy == NULL) {
        return SG_ERR_NOMEM;
    }
    
    memcpy(copy, ctx->violations, ctx->violation_count * sizeof(sg_violation_t));
    
    *violations_out = copy;
    *count_out = ctx->violation_count;
    
    return SG_OK;
}

/*
 * Clear violations
 */
void sg_enforcer_clear_violations(sg_enforcer_ctx_t *ctx)
{
    if (ctx != NULL) {
        ctx->violation_count = 0;
    }
}

/*
 * Serialize stats to JSON
 */
char *sg_enforce_stats_to_json(const sg_enforce_stats_t *stats)
{
    if (stats == NULL) {
        return NULL;
    }
    
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "{"
             "\"total_syscalls\":%lu,"
             "\"allowed\":%lu,"
             "\"logged\":%lu,"
             "\"alerted\":%lu,"
             "\"blocked\":%lu"
             "}",
             (unsigned long)stats->total_syscalls,
             (unsigned long)stats->allowed_syscalls,
             (unsigned long)stats->logged_syscalls,
             (unsigned long)stats->alerted_syscalls,
             (unsigned long)stats->blocked_syscalls);
    
    return strdup(buf);
}

/*
 * Escape a string for JSON output
 * Returns a newly allocated string that must be freed
 */
static char *json_escape_string(const char *str)
{
    if (str == NULL) {
        return strdup("");
    }
    
    /* Calculate required size */
    size_t len = 0;
    for (const char *p = str; *p; p++) {
        switch (*p) {
            case '"': case '\\': case '/':
                len += 2;
                break;
            case '\b': case '\f': case '\n': case '\r': case '\t':
                len += 2;
                break;
            default:
                if ((unsigned char)*p < 0x20) {
                    len += 6;  /* \uXXXX */
                } else {
                    len += 1;
                }
                break;
        }
    }
    
    char *escaped = malloc(len + 1);
    if (escaped == NULL) {
        return NULL;
    }
    
    char *out = escaped;
    for (const char *p = str; *p; p++) {
        switch (*p) {
            case '"':  *out++ = '\\'; *out++ = '"';  break;
            case '\\': *out++ = '\\'; *out++ = '\\'; break;
            case '/':  *out++ = '\\'; *out++ = '/';  break;
            case '\b': *out++ = '\\'; *out++ = 'b';  break;
            case '\f': *out++ = '\\'; *out++ = 'f';  break;
            case '\n': *out++ = '\\'; *out++ = 'n';  break;
            case '\r': *out++ = '\\'; *out++ = 'r';  break;
            case '\t': *out++ = '\\'; *out++ = 't';  break;
            default:
                if ((unsigned char)*p < 0x20) {
                    out += snprintf(out, 7, "\\u%04x", (unsigned char)*p);
                } else {
                    *out++ = *p;
                }
                break;
        }
    }
    *out = '\0';
    
    return escaped;
}

/*
 * Serialize violations to JSON
 */
char *sg_violations_to_json(const sg_violation_t *violations, size_t count)
{
    if (violations == NULL || count == 0) {
        return strdup("[]");
    }
    
    size_t buf_size = 256 + count * 1024;  /* Increased for escaped strings */
    char *buf = malloc(buf_size);
    if (buf == NULL) {
        return NULL;
    }
    
    int pos = 0;
    pos += snprintf(buf + pos, buf_size - pos, "[");
    
    for (size_t i = 0; i < count; i++) {
        if (i > 0) {
            pos += snprintf(buf + pos, buf_size - pos, ",");
        }
        
        /* Escape strings for safe JSON output */
        char *escaped_name = json_escape_string(violations[i].syscall_name);
        char *escaped_path = json_escape_string(violations[i].path);
        char *escaped_reason = json_escape_string(violations[i].reason);
        
        if (escaped_name && escaped_path && escaped_reason) {
            pos += snprintf(buf + pos, buf_size - pos,
                            "{"
                            "\"event_id\":%lu,"
                            "\"pid\":%d,"
                            "\"syscall_nr\":%u,"
                            "\"syscall_name\":\"%s\","
                            "\"action\":%d,"
                            "\"path\":\"%s\","
                            "\"reason\":\"%s\""
                            "}",
                            (unsigned long)violations[i].event_id,
                            violations[i].pid,
                            violations[i].syscall_nr,
                            escaped_name,
                            violations[i].action_taken,
                            escaped_path,
                            escaped_reason);
        }
        
        free(escaped_name);
        free(escaped_path);
        free(escaped_reason);
    }
    
    pos += snprintf(buf + pos, buf_size - pos, "]");
    
    return buf;
}

/*
 * Generate enforcement report
 */
char *sg_enforcer_report(const sg_enforcer_ctx_t *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    
    size_t buf_size = 4096 + ctx->violation_count * 256;
    char *buf = malloc(buf_size);
    if (buf == NULL) {
        return NULL;
    }
    
    int pos = 0;
    pos += snprintf(buf + pos, buf_size - pos,
                    "Enforcement Report\n"
                    "==================\n\n"
                    "Policy: %s\n"
                    "Mode: %s\n\n"
                    "Statistics:\n"
                    "  Total syscalls: %lu\n"
                    "  Allowed: %lu\n"
                    "  Logged: %lu\n"
                    "  Alerted: %lu\n"
                    "  Blocked: %lu\n\n",
                    ctx->policy->policy_id,
                    ctx->mode == ENFORCE_MODE_BLOCK ? "BLOCK" : "ALERT",
                    (unsigned long)ctx->stats.total_syscalls,
                    (unsigned long)ctx->stats.allowed_syscalls,
                    (unsigned long)ctx->stats.logged_syscalls,
                    (unsigned long)ctx->stats.alerted_syscalls,
                    (unsigned long)ctx->stats.blocked_syscalls);
    
    if (ctx->violation_count > 0) {
        pos += snprintf(buf + pos, buf_size - pos,
                        "Violations (%zu):\n", ctx->violation_count);
        
        for (size_t i = 0; i < ctx->violation_count && (size_t)pos < buf_size - 256; i++) {
            const sg_violation_t *v = &ctx->violations[i];
            pos += snprintf(buf + pos, buf_size - pos,
                            "  [%d] %s: %s\n",
                            v->pid, v->syscall_name, v->reason);
            if (v->path[0] != '\0') {
                pos += snprintf(buf + pos, buf_size - pos,
                                "       Path: %s\n", v->path);
            }
        }
    } else {
        pos += snprintf(buf + pos, buf_size - pos, "No violations detected.\n");
    }
    
    return buf;
}

/*
 * Export violations for policy tuning
 */
sg_error_t sg_enforcer_export_for_tuning(const sg_enforcer_ctx_t *ctx,
                                          sg_policy_t *policy)
{
    if (ctx == NULL || policy == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    for (size_t i = 0; i < ctx->violation_count; i++) {
        sg_policy_record_violation(policy, ctx->violations[i].syscall_nr,
                                    ctx->violations[i].path);
    }
    
    return SG_OK;
}

/*
 * Record violation in policy
 */
sg_error_t sg_policy_record_violation(sg_policy_t *policy,
                                       uint32_t syscall_nr,
                                       const char *path)
{
    if (policy == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Find or create rule */
    for (size_t i = 0; i < policy->rule_count; i++) {
        if (policy->rules[i].syscall_nr == syscall_nr) {
            policy->rules[i].hit_count++;
            return SG_OK;
        }
    }
    
    /* Add new rule as alert */
    return sg_policy_add_rule(policy, syscall_nr, POLICY_ACTION_ALERT,
                               path, "Recorded violation");
}
