/*
 * Auris - ARM64 Syscall Tracer
 * Ptrace-based syscall interception for ARM64 Linux
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <linux/ptrace.h>

#include "auris.h"
#include "tracer.h"
#include "syscall_table.h"
#include "trace_store.h"

/* Initial capacity for process tracking */
#define INITIAL_PROC_CAPACITY 16

/* Ptrace options for syscall tracing */
#define PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD | \
                        PTRACE_O_TRACEFORK | \
                        PTRACE_O_TRACEVFORK | \
                        PTRACE_O_TRACECLONE | \
                        PTRACE_O_TRACEEXEC | \
                        PTRACE_O_TRACEEXIT)

/*
 * Initialize tracer context
 */
sg_error_t sg_tracer_init(sg_tracer_ctx_t *ctx, sg_config_t *config)
{
    if (ctx == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(ctx, 0, sizeof(*ctx));
    
    ctx->procs = calloc(INITIAL_PROC_CAPACITY, sizeof(sg_proc_ctx_t));
    if (ctx->procs == NULL) {
        return SG_ERR_NOMEM;
    }
    
    ctx->proc_capacity = INITIAL_PROC_CAPACITY;
    ctx->proc_count = 0;
    ctx->config = config;
    ctx->follow_forks = config ? config->follow_forks : true;
    ctx->running = false;
    ctx->interrupted = 0;
    
    return SG_OK;
}

/*
 * Clean up tracer context
 */
void sg_tracer_cleanup(sg_tracer_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    if (ctx->procs != NULL) {
        free(ctx->procs);
        ctx->procs = NULL;
    }
    
    ctx->proc_count = 0;
    ctx->proc_capacity = 0;
}

/*
 * Get process context by PID
 */
sg_proc_ctx_t *sg_tracer_get_proc(sg_tracer_ctx_t *ctx, pid_t pid)
{
    if (ctx == NULL || ctx->procs == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; i < ctx->proc_count; i++) {
        if (ctx->procs[i].pid == pid) {
            return &ctx->procs[i];
        }
    }
    
    return NULL;
}

/*
 * Add a new process to tracking
 */
sg_error_t sg_tracer_add_proc(sg_tracer_ctx_t *ctx, pid_t pid, pid_t ppid)
{
    if (ctx == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Check if already tracked */
    if (sg_tracer_get_proc(ctx, pid) != NULL) {
        return SG_OK;
    }
    
    /* Expand array if needed */
    if (ctx->proc_count >= ctx->proc_capacity) {
        size_t new_capacity = ctx->proc_capacity * 2;
        sg_proc_ctx_t *new_procs = realloc(ctx->procs,
                                            new_capacity * sizeof(sg_proc_ctx_t));
        if (new_procs == NULL) {
            return SG_ERR_NOMEM;
        }
        ctx->procs = new_procs;
        ctx->proc_capacity = new_capacity;
    }
    
    /* Initialize new process context */
    sg_proc_ctx_t *proc = &ctx->procs[ctx->proc_count];
    memset(proc, 0, sizeof(*proc));
    proc->pid = pid;
    proc->ppid = ppid;
    proc->state = TRACER_STATE_INIT;
    proc->in_syscall = false;
    
    /* Try to get process name */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f != NULL) {
        if (fgets(proc->comm, sizeof(proc->comm), f) != NULL) {
            /* Remove trailing newline */
            size_t len = strlen(proc->comm);
            if (len > 0 && proc->comm[len - 1] == '\n') {
                proc->comm[len - 1] = '\0';
            }
        }
        fclose(f);
    }
    
    ctx->proc_count++;
    
    sg_log(SG_LOG_DEBUG, "Added process %d (ppid=%d, comm=%s)",
           pid, ppid, proc->comm);
    
    return SG_OK;
}

/*
 * Remove a process from tracking
 */
void sg_tracer_remove_proc(sg_tracer_ctx_t *ctx, pid_t pid)
{
    if (ctx == NULL || ctx->procs == NULL) {
        return;
    }
    
    for (size_t i = 0; i < ctx->proc_count; i++) {
        if (ctx->procs[i].pid == pid) {
            /* Move last element to this position */
            if (i < ctx->proc_count - 1) {
                ctx->procs[i] = ctx->procs[ctx->proc_count - 1];
            }
            ctx->proc_count--;
            
            sg_log(SG_LOG_DEBUG, "Removed process %d", pid);
            return;
        }
    }
}

/*
 * Handle syscall entry
 */
static sg_error_t handle_syscall_entry(sg_tracer_ctx_t *ctx,
                                        sg_proc_ctx_t *proc)
{
    sg_error_t err;
    
    /* Read syscall number */
    err = sg_arm64_read_syscall_nr(proc->pid, &proc->current_syscall);
    if (err != SG_OK) {
        sg_log(SG_LOG_WARN, "Failed to read syscall number for pid %d",
               proc->pid);
        return err;
    }
    
    /* Read arguments */
    uint64_t raw_args[6];
    err = sg_arm64_read_syscall_args(proc->pid, raw_args);
    if (err != SG_OK) {
        sg_log(SG_LOG_WARN, "Failed to read syscall args for pid %d",
               proc->pid);
        return err;
    }
    
    /* Initialize pending event */
    sg_syscall_event_t *event = &proc->pending_event;
    memset(event, 0, sizeof(*event));
    
    event->pid = proc->pid;
    event->tid = proc->pid;  /* For now, same as pid */
    event->ppid = proc->ppid;
    event->syscall_nr = proc->current_syscall;
    event->entry_time = sg_now();
    event->is_entry = true;
    
    /* Get syscall name */
    sg_safe_strncpy(event->syscall_name, sg_syscall_name(proc->current_syscall),
                    sizeof(event->syscall_name));
    sg_safe_strncpy(event->comm, proc->comm, sizeof(event->comm));
    
    /* Decode arguments */
    size_t max_str_len = ctx->config ? ctx->config->max_string_len : 256;
    if (max_str_len == 0) {
        max_str_len = 256;
    }
    
    err = sg_syscall_decode_args(proc->pid, proc->current_syscall,
                                  raw_args, event->args, max_str_len);
    if (err != SG_OK) {
        sg_log(SG_LOG_DEBUG, "Failed to decode args for syscall %s",
               event->syscall_name);
    }
    
    proc->in_syscall = true;
    proc->state = TRACER_STATE_SYSCALL_ENTRY;
    
    /* Call entry callback if set */
    if (ctx->on_syscall_entry != NULL) {
        ctx->on_syscall_entry(ctx, event);
    }
    
    return SG_OK;
}

/*
 * Handle syscall exit
 */
static sg_error_t handle_syscall_exit(sg_tracer_ctx_t *ctx,
                                       sg_proc_ctx_t *proc)
{
    sg_error_t err;
    sg_syscall_event_t *event = &proc->pending_event;
    
    /* Read return value */
    err = sg_arm64_read_syscall_ret(proc->pid, &event->ret_value);
    if (err != SG_OK) {
        sg_log(SG_LOG_WARN, "Failed to read return value for pid %d",
               proc->pid);
        event->ret_value = -1;
    }
    
    /* Set errno if syscall failed */
    if (event->ret_value < 0 && event->ret_value >= -4095) {
        event->err_no = (int)(-event->ret_value);
    }
    
    event->exit_time = sg_now();
    event->duration_ns = sg_timestamp_diff_ns(event->exit_time, event->entry_time);
    event->is_entry = false;
    
    proc->in_syscall = false;
    proc->state = TRACER_STATE_SYSCALL_EXIT;
    
    /* Add event to trace */
    if (ctx->trace != NULL) {
        event->id = (uint32_t)ctx->trace->event_count;
        err = sg_trace_add_event(ctx->trace, event);
        if (err != SG_OK) {
            sg_log(SG_LOG_WARN, "Failed to add event to trace: %s",
                   sg_strerror(err));
        }
    }
    
    /* Call exit callback if set */
    if (ctx->on_syscall_exit != NULL) {
        ctx->on_syscall_exit(ctx, event);
    }
    
    sg_log(SG_LOG_TRACE, "[%d] %s", proc->pid, sg_syscall_format(event));
    
    return SG_OK;
}

/*
 * Handle new child process (fork/clone)
 */
static sg_error_t handle_new_child(sg_tracer_ctx_t *ctx, pid_t parent_pid,
                                    pid_t child_pid)
{
    sg_error_t err;
    
    if (!ctx->follow_forks) {
        /* Detach from child */
        ptrace(PTRACE_DETACH, child_pid, NULL, NULL);
        return SG_OK;
    }
    
    /* Add child to tracking */
    err = sg_tracer_add_proc(ctx, child_pid, parent_pid);
    if (err != SG_OK) {
        sg_log(SG_LOG_WARN, "Failed to add child process %d", child_pid);
        return err;
    }
    
    /* Set ptrace options on child */
    if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_OPTIONS) < 0) {
        sg_log(SG_LOG_WARN, "Failed to set ptrace options on child %d: %s",
               child_pid, strerror(errno));
    }
    
    sg_log(SG_LOG_DEBUG, "New child process %d from parent %d",
           child_pid, parent_pid);
    
    return SG_OK;
}

/*
 * Handle process exit
 */
static void handle_process_exit(sg_tracer_ctx_t *ctx, pid_t pid, int status)
{
    sg_proc_ctx_t *proc = sg_tracer_get_proc(ctx, pid);
    if (proc != NULL) {
        proc->state = TRACER_STATE_EXITED;
        proc->exit_code = WEXITSTATUS(status);
    }
    
    /* Call exit callback if set */
    if (ctx->on_process_exit != NULL) {
        ctx->on_process_exit(ctx, pid, status);
    }
    
    sg_log(SG_LOG_DEBUG, "Process %d exited with status %d", pid, status);
    
    sg_tracer_remove_proc(ctx, pid);
}

/*
 * Main tracing loop
 */
static sg_error_t trace_loop(sg_tracer_ctx_t *ctx)
{
    int status;
    pid_t pid;
    
    ctx->running = true;
    
    while (ctx->running && ctx->proc_count > 0 && !ctx->interrupted) {
        /* Wait for any traced process */
        pid = waitpid(-1, &status, __WALL);
        
        if (pid < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECHILD) {
                /* No more children */
                break;
            }
            sg_log(SG_LOG_ERROR, "waitpid failed: %s", strerror(errno));
            return SG_ERR_SYSCALL;
        }
        
        sg_proc_ctx_t *proc = sg_tracer_get_proc(ctx, pid);
        
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            /* Process terminated */
            handle_process_exit(ctx, pid, status);
            continue;
        }
        
        if (!WIFSTOPPED(status)) {
            continue;
        }
        
        int sig = WSTOPSIG(status);
        int event = (status >> 16) & 0xff;
        
        /* Handle ptrace events */
        if (event != 0) {
            switch (event) {
                case PTRACE_EVENT_FORK:
                case PTRACE_EVENT_VFORK:
                case PTRACE_EVENT_CLONE: {
                    unsigned long child_pid;
                    if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child_pid) == 0) {
                        handle_new_child(ctx, pid, (pid_t)child_pid);
                    }
                    break;
                }
                
                case PTRACE_EVENT_EXEC:
                    /* Process called exec - update comm */
                    if (proc != NULL) {
                        char path[64];
                        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
                        FILE *f = fopen(path, "r");
                        if (f != NULL) {
                            if (fgets(proc->comm, sizeof(proc->comm), f) != NULL) {
                                size_t len = strlen(proc->comm);
                                if (len > 0 && proc->comm[len - 1] == '\n') {
                                    proc->comm[len - 1] = '\0';
                                }
                            }
                            fclose(f);
                        }
                    }
                    break;
                
                case PTRACE_EVENT_EXIT:
                    /* Process is about to exit */
                    break;
            }
            
            /* Continue the process */
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }
        
        /* Handle syscall stop (SIGTRAP | 0x80) */
        if (sig == (SIGTRAP | 0x80)) {
            if (proc == NULL) {
                /* Unknown process, try to add it */
                sg_tracer_add_proc(ctx, pid, 0);
                proc = sg_tracer_get_proc(ctx, pid);
            }
            
            if (proc != NULL) {
                if (!proc->in_syscall) {
                    /* Syscall entry */
                    handle_syscall_entry(ctx, proc);
                } else {
                    /* Syscall exit */
                    handle_syscall_exit(ctx, proc);
                }
            }
            
            /* Continue to next syscall */
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }
        
        /* Handle other signals - deliver to tracee */
        if (sig != SIGTRAP) {
            sg_log(SG_LOG_DEBUG, "Delivering signal %d to pid %d", sig, pid);
            ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)sig);
        } else {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        }
    }
    
    ctx->running = false;
    return SG_OK;
}

/*
 * Execute and trace a target program
 */
sg_error_t sg_tracer_run(sg_tracer_ctx_t *ctx,
                          const char *path,
                          char *const argv[],
                          char *const envp[],
                          sg_trace_t **trace_out)
{
    if (ctx == NULL || path == NULL || argv == NULL || trace_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_error_t err;
    
    /* Allocate trace */
    sg_trace_t *trace = sg_trace_alloc();
    if (trace == NULL) {
        return SG_ERR_NOMEM;
    }
    
    ctx->trace = trace;
    
    /* Set up trace metadata */
    sg_generate_id(trace->meta.trace_id, sizeof(trace->meta.trace_id));
    sg_safe_strncpy(trace->meta.binary_path, path, sizeof(trace->meta.binary_path));
    sg_hash_file(path, trace->meta.binary_hash, sizeof(trace->meta.binary_hash));
    gethostname(trace->meta.hostname, sizeof(trace->meta.hostname));
    sg_safe_strncpy(trace->meta.auris_version, AURIS_VERSION_STRING,
                    sizeof(trace->meta.auris_version));
    trace->meta.start_time = sg_now();
    
    /* Copy argv */
    int argc = 0;
    while (argv[argc] != NULL) {
        argc++;
    }
    trace->meta.argc = argc;
    trace->meta.argv = calloc(argc + 1, sizeof(char *));
    if (trace->meta.argv != NULL) {
        for (int i = 0; i < argc; i++) {
            trace->meta.argv[i] = strdup(argv[i]);
        }
    }
    
    /* Fork child process */
    pid_t child = fork();
    
    if (child < 0) {
        sg_log(SG_LOG_ERROR, "fork failed: %s", strerror(errno));
        sg_trace_free(trace);
        return SG_ERR_FORK;
    }
    
    if (child == 0) {
        /* Child process */
        
        /* Request to be traced */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            _exit(127);
        }
        
        /* Stop ourselves so parent can set options */
        raise(SIGSTOP);
        
        /* Execute target */
        if (envp != NULL) {
            execve(path, argv, envp);
        } else {
            execv(path, argv);
        }
        
        /* exec failed */
        _exit(127);
    }
    
    /* Parent process */
    ctx->root_pid = child;
    trace->meta.root_pid = child;
    
    /* Wait for child to stop */
    int status;
    if (waitpid(child, &status, 0) < 0) {
        sg_log(SG_LOG_ERROR, "waitpid failed: %s", strerror(errno));
        kill(child, SIGKILL);
        sg_trace_free(trace);
        return SG_ERR_SYSCALL;
    }
    
    if (!WIFSTOPPED(status)) {
        sg_log(SG_LOG_ERROR, "Child did not stop as expected");
        kill(child, SIGKILL);
        sg_trace_free(trace);
        return SG_ERR_PTRACE;
    }
    
    /* Set ptrace options */
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_OPTIONS) < 0) {
        sg_log(SG_LOG_ERROR, "PTRACE_SETOPTIONS failed: %s", strerror(errno));
        kill(child, SIGKILL);
        sg_trace_free(trace);
        return SG_ERR_PTRACE;
    }
    
    /* Add child to tracking */
    err = sg_tracer_add_proc(ctx, child, getpid());
    if (err != SG_OK) {
        kill(child, SIGKILL);
        sg_trace_free(trace);
        return err;
    }
    
    /* Start tracing */
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
        sg_log(SG_LOG_ERROR, "PTRACE_SYSCALL failed: %s", strerror(errno));
        kill(child, SIGKILL);
        sg_trace_free(trace);
        return SG_ERR_PTRACE;
    }
    
    sg_log(SG_LOG_INFO, "Tracing process %d: %s", child, path);
    
    /* Run trace loop */
    err = trace_loop(ctx);
    
    /* Finalize trace */
    trace->meta.end_time = sg_now();
    
    /* Get exit code from root process */
    sg_proc_ctx_t *root_proc = sg_tracer_get_proc(ctx, child);
    if (root_proc != NULL) {
        trace->meta.exit_code = root_proc->exit_code;
    }
    
    err = sg_trace_finalize(trace);
    if (err != SG_OK) {
        sg_log(SG_LOG_WARN, "Failed to finalize trace: %s", sg_strerror(err));
    }
    
    sg_log(SG_LOG_INFO, "Trace complete: %lu syscalls captured",
           (unsigned long)trace->event_count);
    
    *trace_out = trace;
    ctx->trace = NULL;
    
    return SG_OK;
}

/*
 * Request tracer to stop
 */
void sg_tracer_stop(sg_tracer_ctx_t *ctx)
{
    if (ctx != NULL) {
        ctx->interrupted = 1;
        ctx->running = false;
    }
}

/*
 * Detach from traced processes
 */
sg_error_t sg_tracer_detach(sg_tracer_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    for (size_t i = 0; i < ctx->proc_count; i++) {
        pid_t pid = ctx->procs[i].pid;
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
            sg_log(SG_LOG_WARN, "Failed to detach from pid %d: %s",
                   pid, strerror(errno));
        }
    }
    
    ctx->proc_count = 0;
    ctx->running = false;
    
    return SG_OK;
}

/*
 * Attach to existing process
 */
sg_error_t sg_tracer_attach(sg_tracer_ctx_t *ctx, pid_t pid, sg_trace_t **trace_out)
{
    if (ctx == NULL || trace_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Attach to process */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        sg_log(SG_LOG_ERROR, "PTRACE_ATTACH failed for pid %d: %s",
               pid, strerror(errno));
        return SG_ERR_PTRACE;
    }
    
    /* Wait for process to stop */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        sg_log(SG_LOG_ERROR, "waitpid failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return SG_ERR_SYSCALL;
    }
    
    /* Allocate trace */
    sg_trace_t *trace = sg_trace_alloc();
    if (trace == NULL) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return SG_ERR_NOMEM;
    }
    
    ctx->trace = trace;
    ctx->root_pid = pid;
    
    /* Set up trace metadata */
    sg_generate_id(trace->meta.trace_id, sizeof(trace->meta.trace_id));
    
    /* Get binary path from /proc */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(proc_path, trace->meta.binary_path,
                           sizeof(trace->meta.binary_path) - 1);
    if (len > 0) {
        trace->meta.binary_path[len] = '\0';
        sg_hash_file(trace->meta.binary_path, trace->meta.binary_hash,
                     sizeof(trace->meta.binary_hash));
    }
    
    gethostname(trace->meta.hostname, sizeof(trace->meta.hostname));
    sg_safe_strncpy(trace->meta.auris_version, AURIS_VERSION_STRING,
                    sizeof(trace->meta.auris_version));
    trace->meta.start_time = sg_now();
    trace->meta.root_pid = pid;
    
    /* Set ptrace options */
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_OPTIONS) < 0) {
        sg_log(SG_LOG_WARN, "PTRACE_SETOPTIONS failed: %s", strerror(errno));
    }
    
    /* Add to tracking */
    sg_error_t err = sg_tracer_add_proc(ctx, pid, 0);
    if (err != SG_OK) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        sg_trace_free(trace);
        return err;
    }
    
    /* Start tracing */
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
        sg_log(SG_LOG_ERROR, "PTRACE_SYSCALL failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        sg_trace_free(trace);
        return SG_ERR_PTRACE;
    }
    
    sg_log(SG_LOG_INFO, "Attached to process %d", pid);
    
    /* Run trace loop */
    err = trace_loop(ctx);
    
    /* Finalize */
    trace->meta.end_time = sg_now();
    sg_trace_finalize(trace);
    
    *trace_out = trace;
    ctx->trace = NULL;
    
    return err;
}
