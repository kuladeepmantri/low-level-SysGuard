/*
 * Auris - ARM Linux Syscall Tracer
 * Ptrace-based syscall interception for ARM64 Linux
 */

#ifndef AURIS_TRACER_H
#define AURIS_TRACER_H

#include "auris.h"
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <signal.h>

/* ARM64 register indices for syscall ABI */
#define ARM64_REG_SYSCALL_NR 8    /* x8 contains syscall number */
#define ARM64_REG_ARG0 0          /* x0 - first argument / return value */
#define ARM64_REG_ARG1 1          /* x1 */
#define ARM64_REG_ARG2 2          /* x2 */
#define ARM64_REG_ARG3 3          /* x3 */
#define ARM64_REG_ARG4 4          /* x4 */
#define ARM64_REG_ARG5 5          /* x5 */
#define ARM64_REG_PC 32           /* Program counter */
#define ARM64_REG_SP 31           /* Stack pointer */

/* Tracer state */
typedef enum {
    TRACER_STATE_INIT = 0,
    TRACER_STATE_RUNNING,
    TRACER_STATE_STOPPED,
    TRACER_STATE_SYSCALL_ENTRY,
    TRACER_STATE_SYSCALL_EXIT,
    TRACER_STATE_EXITED,
    TRACER_STATE_SIGNALED,
    TRACER_STATE_ERROR,
} sg_tracer_state_t;

/* Per-process tracing context */
typedef struct {
    pid_t pid;
    pid_t ppid;
    sg_tracer_state_t state;
    bool in_syscall;                      /* Currently inside syscall */
    uint32_t current_syscall;             /* Syscall number at entry */
    sg_syscall_event_t pending_event;     /* Event being built */
    int exit_code;
    int exit_signal;
    char comm[16];
} sg_proc_ctx_t;

/* Forward declaration for callbacks */
typedef struct sg_tracer_ctx sg_tracer_ctx_t;

/* Tracer context */
struct sg_tracer_ctx {
    sg_trace_t *trace;                    /* Current trace being built */
    sg_proc_ctx_t *procs;                 /* Tracked processes */
    size_t proc_count;
    size_t proc_capacity;
    pid_t root_pid;                       /* Initial traced process */
    bool follow_forks;
    bool running;
    volatile sig_atomic_t interrupted;
    sg_config_t *config;
    
    /* Callbacks */
    void (*on_syscall_entry)(sg_tracer_ctx_t *, sg_syscall_event_t *);
    void (*on_syscall_exit)(sg_tracer_ctx_t *, sg_syscall_event_t *);
    void (*on_process_exit)(sg_tracer_ctx_t *, pid_t, int);
    void *user_data;
};

/*
 * Initialize a new tracer context
 * Returns SG_OK on success, error code on failure
 */
sg_error_t sg_tracer_init(sg_tracer_ctx_t *ctx, sg_config_t *config);

/*
 * Clean up tracer context and free resources
 */
void sg_tracer_cleanup(sg_tracer_ctx_t *ctx);

/*
 * Execute and trace a target program
 * 
 * @param ctx       Initialized tracer context
 * @param path      Path to executable
 * @param argv      Argument vector (NULL-terminated)
 * @param envp      Environment vector (NULL-terminated), or NULL for inherited
 * @param trace_out Output trace structure (caller must free with sg_trace_free)
 * 
 * Returns SG_OK on success, error code on failure
 */
sg_error_t sg_tracer_run(sg_tracer_ctx_t *ctx, 
                         const char *path,
                         char *const argv[],
                         char *const envp[],
                         sg_trace_t **trace_out);

/*
 * Attach to an existing process and trace it
 * Note: Requires appropriate privileges
 */
sg_error_t sg_tracer_attach(sg_tracer_ctx_t *ctx, pid_t pid, sg_trace_t **trace_out);

/*
 * Detach from traced process(es) without killing them
 */
sg_error_t sg_tracer_detach(sg_tracer_ctx_t *ctx);

/*
 * Request tracer to stop (can be called from signal handler)
 */
void sg_tracer_stop(sg_tracer_ctx_t *ctx);

/*
 * Get process context by PID
 */
sg_proc_ctx_t *sg_tracer_get_proc(sg_tracer_ctx_t *ctx, pid_t pid);

/*
 * Add a new process to tracking
 */
sg_error_t sg_tracer_add_proc(sg_tracer_ctx_t *ctx, pid_t pid, pid_t ppid);

/*
 * Remove a process from tracking
 */
void sg_tracer_remove_proc(sg_tracer_ctx_t *ctx, pid_t pid);

/* ARM64 register access */

/*
 * Read ARM64 general-purpose registers
 */
sg_error_t sg_arm64_read_regs(pid_t pid, uint64_t regs[33]);

/*
 * Read a single register value
 */
sg_error_t sg_arm64_read_reg(pid_t pid, int reg_idx, uint64_t *value);

/*
 * Read syscall number from x8 register
 */
sg_error_t sg_arm64_read_syscall_nr(pid_t pid, uint32_t *nr);

/*
 * Read syscall arguments (x0-x5)
 */
sg_error_t sg_arm64_read_syscall_args(pid_t pid, uint64_t args[6]);

/*
 * Read syscall return value from x0
 */
sg_error_t sg_arm64_read_syscall_ret(pid_t pid, int64_t *ret);

/*
 * Read string from tracee memory
 * Returns number of bytes read, or negative error code
 */
ssize_t sg_read_string(pid_t pid, uint64_t addr, char *buf, size_t max_len);

/*
 * Read arbitrary data from tracee memory
 */
ssize_t sg_read_memory(pid_t pid, uint64_t addr, void *buf, size_t len);

/*
 * Read sockaddr structure from tracee memory
 */
sg_error_t sg_read_sockaddr(pid_t pid, uint64_t addr, size_t len, sg_netaddr_t *out);

#endif /* AURIS_TRACER_H */
