/*
 * Auris - Policy Enforcer
 * Runtime enforcement of security policies via ptrace
 */

#ifndef AURIS_ENFORCER_H
#define AURIS_ENFORCER_H

#include "auris.h"
#include "policy.h"
#include "tracer.h"

/* Enforcement statistics */
typedef struct {
    uint64_t total_syscalls;
    uint64_t allowed_syscalls;
    uint64_t logged_syscalls;
    uint64_t alerted_syscalls;
    uint64_t blocked_syscalls;
    uint64_t unknown_syscalls;
    sg_timestamp_t start_time;
    sg_timestamp_t end_time;
} sg_enforce_stats_t;

/* Violation record */
typedef struct {
    uint64_t event_id;
    sg_timestamp_t timestamp;
    pid_t pid;
    uint32_t syscall_nr;
    char syscall_name[MAX_SYSCALL_NAME_LEN];
    sg_policy_action_t action_taken;
    char path[MAX_PATH_LEN];
    char reason[256];
} sg_violation_t;

/* Forward declaration for callbacks */
typedef struct sg_enforcer_ctx sg_enforcer_ctx_t;

/* Enforcer context */
struct sg_enforcer_ctx {
    sg_policy_t *policy;
    sg_enforce_mode_t mode;
    sg_tracer_ctx_t tracer;
    sg_enforce_stats_t stats;
    
    /* Violation log */
    sg_violation_t *violations;
    size_t violation_count;
    size_t violation_capacity;
    
    /* Configuration */
    bool log_allowed;                     /* Log allowed syscalls too */
    bool terminate_on_block;              /* Kill process on block */
    int block_signal;                     /* Signal to send on block (default SIGKILL) */
    
    /* Callbacks */
    void (*on_violation)(sg_enforcer_ctx_t *, const sg_violation_t *);
    void (*on_block)(sg_enforcer_ctx_t *, const sg_violation_t *);
    void *user_data;
    
    /* State */
    bool running;
    volatile sig_atomic_t interrupted;
};

/*
 * Initialize enforcer context
 */
sg_error_t sg_enforcer_init(sg_enforcer_ctx_t *ctx,
                             sg_policy_t *policy,
                             sg_enforce_mode_t mode,
                             sg_config_t *config);

/*
 * Clean up enforcer context
 */
void sg_enforcer_cleanup(sg_enforcer_ctx_t *ctx);

/*
 * Run a program under policy enforcement
 */
sg_error_t sg_enforcer_run(sg_enforcer_ctx_t *ctx,
                            const char *path,
                            char *const argv[],
                            char *const envp[]);

/*
 * Attach to existing process and enforce policy
 */
sg_error_t sg_enforcer_attach(sg_enforcer_ctx_t *ctx, pid_t pid);

/*
 * Stop enforcement
 */
void sg_enforcer_stop(sg_enforcer_ctx_t *ctx);

/*
 * Get enforcement statistics
 */
sg_error_t sg_enforcer_get_stats(const sg_enforcer_ctx_t *ctx,
                                  sg_enforce_stats_t *stats_out);

/*
 * Get recorded violations
 */
sg_error_t sg_enforcer_get_violations(const sg_enforcer_ctx_t *ctx,
                                       sg_violation_t **violations_out,
                                       size_t *count_out);

/*
 * Clear violation log
 */
void sg_enforcer_clear_violations(sg_enforcer_ctx_t *ctx);

/*
 * Check a syscall against policy and take action
 * Called internally by the enforcement loop
 */
sg_policy_action_t sg_enforcer_check_syscall(sg_enforcer_ctx_t *ctx,
                                              pid_t pid,
                                              uint32_t syscall_nr,
                                              const sg_arg_value_t args[6]);

/*
 * Block a syscall (make it fail with EPERM)
 */
sg_error_t sg_enforcer_block_syscall(sg_enforcer_ctx_t *ctx, pid_t pid);

/*
 * Terminate a traced process
 */
sg_error_t sg_enforcer_terminate(sg_enforcer_ctx_t *ctx, pid_t pid);

/* Enforcement result serialization */

/*
 * Serialize enforcement stats to JSON
 */
char *sg_enforce_stats_to_json(const sg_enforce_stats_t *stats);

/*
 * Serialize violations to JSON
 */
char *sg_violations_to_json(const sg_violation_t *violations, size_t count);

/*
 * Generate enforcement report
 */
char *sg_enforcer_report(const sg_enforcer_ctx_t *ctx);

/* Auto-tuning integration */

/*
 * Export violations for policy auto-tuning
 */
sg_error_t sg_enforcer_export_for_tuning(const sg_enforcer_ctx_t *ctx,
                                          sg_policy_t *policy);

/*
 * Apply tuning from enforcement session
 * Updates policy based on user-approved violations
 */
sg_error_t sg_enforcer_apply_tuning(sg_enforcer_ctx_t *ctx,
                                     const uint32_t *approved_syscalls,
                                     size_t count);

#endif /* AURIS_ENFORCER_H */
