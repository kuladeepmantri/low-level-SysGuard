/*
 * Auris - Process Injection Framework
 * Core injection functionality for ARM64 Linux
 * 
 * WARNING: For authorized security research only.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <linux/elf.h>

#include "auris.h"
#include "inject.h"

/* Initial capacities */
#define INITIAL_REGION_CAPACITY 64
#define INITIAL_GADGET_CAPACITY 1024

/*
 * Find injectable processes
 * Returns processes we have permission to ptrace
 */
sg_error_t sg_inject_find_targets(pid_t **pids_out, size_t *count_out)
{
    if (pids_out == NULL || count_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    DIR *proc = opendir("/proc");
    if (proc == NULL) {
        return SG_ERR_IO;
    }
    
    pid_t *pids = NULL;
    size_t count = 0;
    size_t capacity = 64;
    
    pids = calloc(capacity, sizeof(pid_t));
    if (pids == NULL) {
        closedir(proc);
        return SG_ERR_NOMEM;
    }
    
    pid_t my_pid = getpid();
    struct dirent *entry;
    
    while ((entry = readdir(proc)) != NULL) {
        /* Skip non-numeric entries */
        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) {
            continue;
        }
        
        /* Skip ourselves */
        if ((pid_t)pid == my_pid) {
            continue;
        }
        
        /* Check if we can read the process info */
        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/status", pid);
        
        if (access(path, R_OK) == 0) {
            /* Expand array if needed */
            if (count >= capacity) {
                capacity *= 2;
                pid_t *new_pids = realloc(pids, capacity * sizeof(pid_t));
                if (new_pids == NULL) {
                    free(pids);
                    closedir(proc);
                    return SG_ERR_NOMEM;
                }
                pids = new_pids;
            }
            
            pids[count++] = (pid_t)pid;
        }
    }
    
    closedir(proc);
    
    *pids_out = pids;
    *count_out = count;
    
    return SG_OK;
}

/*
 * Get detailed target information
 */
sg_error_t sg_inject_get_target_info(pid_t pid, sg_inject_target_t *target_out)
{
    if (target_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(target_out, 0, sizeof(*target_out));
    target_out->pid = pid;
    
    /* Read comm (process name) */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f != NULL) {
        if (fgets(target_out->comm, sizeof(target_out->comm), f) != NULL) {
            size_t len = strlen(target_out->comm);
            if (len > 0 && target_out->comm[len - 1] == '\n') {
                target_out->comm[len - 1] = '\0';
            }
        }
        fclose(f);
    }
    
    /* Read exe path */
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, target_out->exe_path, 
                           sizeof(target_out->exe_path) - 1);
    if (len > 0) {
        target_out->exe_path[len] = '\0';
    }
    
    /* Read UID/GID from status */
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    f = fopen(path, "r");
    if (f != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), f) != NULL) {
            if (strncmp(line, "Uid:", 4) == 0) {
                sscanf(line + 4, "%u", &target_out->uid);
            } else if (strncmp(line, "Gid:", 4) == 0) {
                sscanf(line + 4, "%u", &target_out->gid);
            }
        }
        fclose(f);
    }
    
    return SG_OK;
}

/*
 * Check if we can inject into a process
 */
sg_error_t sg_inject_check_permissions(pid_t pid, bool *can_inject)
{
    if (can_inject == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    *can_inject = false;
    
    /* Check if we're root */
    if (geteuid() == 0) {
        *can_inject = true;
        return SG_OK;
    }
    
    /* Check if we own the process */
    char path[64];
    struct stat st;
    snprintf(path, sizeof(path), "/proc/%d", pid);
    
    if (stat(path, &st) == 0) {
        if (st.st_uid == geteuid()) {
            *can_inject = true;
        }
    }
    
    /* Check ptrace scope */
    FILE *f = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    if (f != NULL) {
        int scope = 0;
        if (fscanf(f, "%d", &scope) == 1) {
            if (scope >= 2) {
                /* Only root can ptrace */
                *can_inject = (geteuid() == 0);
            } else if (scope == 1) {
                /* Can only ptrace children (unless we're root) */
                /* For simplicity, we'll say no unless root */
                if (geteuid() != 0) {
                    *can_inject = false;
                }
            }
        }
        fclose(f);
    }
    
    return SG_OK;
}

/*
 * Parse /proc/pid/maps
 */
sg_error_t sg_inject_parse_maps(pid_t pid, sg_memory_map_t **map_out)
{
    if (map_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return SG_ERR_IO;
    }
    
    sg_memory_map_t *map = calloc(1, sizeof(sg_memory_map_t));
    if (map == NULL) {
        fclose(f);
        return SG_ERR_NOMEM;
    }
    
    map->regions = calloc(INITIAL_REGION_CAPACITY, sizeof(sg_memory_region_t));
    if (map->regions == NULL) {
        free(map);
        fclose(f);
        return SG_ERR_NOMEM;
    }
    map->region_capacity = INITIAL_REGION_CAPACITY;
    
    char line[512];
    while (fgets(line, sizeof(line), f) != NULL) {
        /* Expand if needed */
        if (map->region_count >= map->region_capacity) {
            size_t new_cap = map->region_capacity * 2;
            sg_memory_region_t *new_regions = realloc(map->regions,
                                                       new_cap * sizeof(sg_memory_region_t));
            if (new_regions == NULL) {
                sg_inject_free_maps(map);
                fclose(f);
                return SG_ERR_NOMEM;
            }
            map->regions = new_regions;
            map->region_capacity = new_cap;
        }
        
        sg_memory_region_t *region = &map->regions[map->region_count];
        memset(region, 0, sizeof(*region));
        
        /* Parse: start-end perms offset dev inode pathname */
        char perms[8] = {0};
        char dev[16] = {0};
        unsigned long inode = 0;
        
        int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %4095s",
                       &region->start, &region->end,
                       perms, &region->offset, dev, &inode,
                       region->pathname);
        
        if (n < 5) {
            continue;
        }
        
        /* Parse permissions */
        region->readable = (perms[0] == 'r');
        region->writable = (perms[1] == 'w');
        region->executable = (perms[2] == 'x');
        region->is_private = (perms[3] == 'p');
        
        /* Identify special regions */
        if (strstr(region->pathname, "[stack]") != NULL) {
            map->stack_region = region;
        } else if (strstr(region->pathname, "[heap]") != NULL) {
            map->heap_region = region;
        } else if (strstr(region->pathname, "[vdso]") != NULL) {
            map->vdso_region = region;
        } else if (strstr(region->pathname, "libc") != NULL && 
                   region->executable) {
            map->libc_region = region;
        }
        
        /* First executable region is likely .text */
        if (map->text_region == NULL && region->executable && 
            region->pathname[0] == '/') {
            map->text_region = region;
        }
        
        map->region_count++;
    }
    
    fclose(f);
    
    *map_out = map;
    return SG_OK;
}

/*
 * Free memory map
 */
void sg_inject_free_maps(sg_memory_map_t *map)
{
    if (map == NULL) {
        return;
    }
    
    if (map->regions != NULL) {
        free(map->regions);
    }
    free(map);
}

/*
 * Find a code cave (unused executable space)
 */
sg_error_t sg_inject_find_cave(sg_memory_map_t *map, size_t min_size,
                                uint64_t *addr_out)
{
    if (map == NULL || addr_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Look for executable regions with enough space */
    for (size_t i = 0; i < map->region_count; i++) {
        sg_memory_region_t *region = &map->regions[i];
        
        if (!region->executable) {
            continue;
        }
        
        size_t size = region->end - region->start;
        if (size >= min_size) {
            /* Use the end of the region (less likely to be used) */
            *addr_out = region->end - min_size;
            return SG_OK;
        }
    }
    
    return SG_ERR_NOT_FOUND;
}

/*
 * Find region containing address
 */
sg_memory_region_t *sg_inject_find_region(sg_memory_map_t *map, uint64_t addr)
{
    if (map == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; i < map->region_count; i++) {
        if (addr >= map->regions[i].start && addr < map->regions[i].end) {
            return &map->regions[i];
        }
    }
    
    return NULL;
}

/*
 * Initialize injection context
 */
sg_error_t sg_inject_init(sg_inject_ctx_t *ctx, pid_t target_pid)
{
    if (ctx == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(ctx, 0, sizeof(*ctx));
    
    sg_error_t err = sg_inject_get_target_info(target_pid, &ctx->target);
    if (err != SG_OK) {
        return err;
    }
    
    err = sg_inject_parse_maps(target_pid, &ctx->memory_map);
    if (err != SG_OK) {
        return err;
    }
    
    ctx->restore_on_cleanup = true;
    
    return SG_OK;
}

/*
 * Clean up injection context
 */
void sg_inject_cleanup(sg_inject_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    /* Restore original state if we modified anything */
    if (ctx->injection_active && ctx->restore_on_cleanup) {
        if (ctx->saved_code != NULL && ctx->saved_code_len > 0) {
            sg_inject_write_mem(ctx->target.pid, ctx->injection_addr,
                               ctx->saved_code, ctx->saved_code_len);
        }
        sg_inject_restore_regs(ctx);
    }
    
    /* Detach if still attached */
    if (ctx->target.is_attached) {
        sg_inject_detach(ctx);
    }
    
    /* Free resources */
    if (ctx->memory_map != NULL) {
        sg_inject_free_maps(ctx->memory_map);
    }
    if (ctx->saved_code != NULL) {
        free(ctx->saved_code);
    }
    
    memset(ctx, 0, sizeof(*ctx));
}

/*
 * Attach to target process
 */
sg_error_t sg_inject_attach(sg_inject_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (ctx->target.is_attached) {
        return SG_OK;  /* Already attached */
    }
    
    sg_log(SG_LOG_INFO, "Attaching to process %d (%s)",
           ctx->target.pid, ctx->target.comm);
    
    if (ptrace(PTRACE_ATTACH, ctx->target.pid, NULL, NULL) < 0) {
        sg_log(SG_LOG_ERROR, "PTRACE_ATTACH failed: %s", strerror(errno));
        return SG_ERR_PTRACE;
    }
    
    /* Wait for process to stop */
    int status;
    if (waitpid(ctx->target.pid, &status, 0) < 0) {
        sg_log(SG_LOG_ERROR, "waitpid failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, ctx->target.pid, NULL, NULL);
        return SG_ERR_SYSCALL;
    }
    
    if (!WIFSTOPPED(status)) {
        sg_log(SG_LOG_ERROR, "Process did not stop as expected");
        ptrace(PTRACE_DETACH, ctx->target.pid, NULL, NULL);
        return SG_ERR_PTRACE;
    }
    
    ctx->target.is_attached = true;
    ctx->target.was_stopped = (WSTOPSIG(status) == SIGSTOP);
    
    sg_log(SG_LOG_DEBUG, "Successfully attached to %d", ctx->target.pid);
    
    return SG_OK;
}

/*
 * Detach from target process
 */
sg_error_t sg_inject_detach(sg_inject_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (!ctx->target.is_attached) {
        return SG_OK;
    }
    
    sg_log(SG_LOG_DEBUG, "Detaching from process %d", ctx->target.pid);
    
    if (ptrace(PTRACE_DETACH, ctx->target.pid, NULL, NULL) < 0) {
        sg_log(SG_LOG_WARN, "PTRACE_DETACH failed: %s", strerror(errno));
        return SG_ERR_PTRACE;
    }
    
    ctx->target.is_attached = false;
    
    return SG_OK;
}

/*
 * Read registers from target
 */
sg_error_t sg_inject_read_regs(pid_t pid, sg_arm64_regs_t *regs)
{
    if (regs == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    struct iovec iov = {
        .iov_base = regs,
        .iov_len = sizeof(*regs),
    };
    
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        sg_log(SG_LOG_ERROR, "PTRACE_GETREGSET failed: %s", strerror(errno));
        return SG_ERR_PTRACE;
    }
    
    return SG_OK;
}

/*
 * Write registers to target
 */
sg_error_t sg_inject_write_regs(pid_t pid, const sg_arm64_regs_t *regs)
{
    if (regs == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    struct iovec iov = {
        .iov_base = (void *)regs,
        .iov_len = sizeof(*regs),
    };
    
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        sg_log(SG_LOG_ERROR, "PTRACE_SETREGSET failed: %s", strerror(errno));
        return SG_ERR_PTRACE;
    }
    
    return SG_OK;
}

/*
 * Save current register state
 */
sg_error_t sg_inject_save_regs(sg_inject_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    return sg_inject_read_regs(ctx->target.pid, &ctx->saved_regs);
}

/*
 * Restore saved register state
 */
sg_error_t sg_inject_restore_regs(sg_inject_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    return sg_inject_write_regs(ctx->target.pid, &ctx->saved_regs);
}

/*
 * Read memory from target process via ptrace
 */
ssize_t sg_inject_read_mem(pid_t pid, uint64_t addr, void *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return SG_ERR_INVALID_ARG;
    }
    
    unsigned char *dst = buf;
    size_t offset = 0;
    
    while (offset < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + offset), NULL);
        
        if (errno != 0) {
            if (offset == 0) {
                return SG_ERR_PTRACE;
            }
            break;
        }
        
        size_t to_copy = sizeof(long);
        if (offset + to_copy > len) {
            to_copy = len - offset;
        }
        
        memcpy(dst + offset, &word, to_copy);
        offset += sizeof(long);
    }
    
    return (ssize_t)(offset > len ? len : offset);
}

/*
 * Write memory to target process via ptrace
 */
ssize_t sg_inject_write_mem(pid_t pid, uint64_t addr, const void *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return SG_ERR_INVALID_ARG;
    }
    
    const unsigned char *src = buf;
    size_t offset = 0;
    
    while (offset < len) {
        long word = 0;
        size_t to_copy = sizeof(long);
        
        if (offset + to_copy > len) {
            /* Partial word - need to read first to preserve remaining bytes */
            to_copy = len - offset;
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + offset), NULL);
            if (errno != 0) {
                if (offset == 0) {
                    return SG_ERR_PTRACE;
                }
                break;
            }
        }
        
        memcpy(&word, src + offset, to_copy);
        
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + offset), (void *)word) < 0) {
            if (offset == 0) {
                return SG_ERR_PTRACE;
            }
            break;
        }
        
        offset += sizeof(long);
    }
    
    return (ssize_t)(offset > len ? len : offset);
}

/*
 * Write memory via /proc/pid/mem
 */
ssize_t sg_inject_write_mem_proc(pid_t pid, uint64_t addr, const void *buf, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return SG_ERR_IO;
    }
    
    if (lseek(fd, (off_t)addr, SEEK_SET) < 0) {
        close(fd);
        return SG_ERR_IO;
    }
    
    ssize_t written = write(fd, buf, len);
    close(fd);
    
    return written;
}

/*
 * Execute injected code and wait for completion
 */
sg_error_t sg_inject_execute(sg_inject_ctx_t *ctx, uint64_t addr,
                              sg_inject_result_t *result)
{
    if (ctx == NULL || result == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(result, 0, sizeof(*result));
    
    /* Set PC to our shellcode */
    sg_arm64_regs_t regs;
    sg_error_t err = sg_inject_read_regs(ctx->target.pid, &regs);
    if (err != SG_OK) {
        result->error = err;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to read registers");
        return err;
    }
    
    regs.pc = addr;
    
    err = sg_inject_write_regs(ctx->target.pid, &regs);
    if (err != SG_OK) {
        result->error = err;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to set PC to shellcode");
        return err;
    }
    
    sg_timestamp_t start = sg_now();
    
    /* Continue execution */
    if (ptrace(PTRACE_CONT, ctx->target.pid, NULL, NULL) < 0) {
        result->error = SG_ERR_PTRACE;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "PTRACE_CONT failed: %s", strerror(errno));
        return SG_ERR_PTRACE;
    }
    
    /* Wait for shellcode to complete (it should hit a breakpoint or trap) */
    int status;
    if (waitpid(ctx->target.pid, &status, 0) < 0) {
        result->error = SG_ERR_SYSCALL;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "waitpid failed: %s", strerror(errno));
        return SG_ERR_SYSCALL;
    }
    
    sg_timestamp_t end = sg_now();
    result->execution_time_ns = sg_timestamp_diff_ns(end, start);
    
    if (WIFSTOPPED(status)) {
        /* Read return value from x0 */
        err = sg_inject_read_regs(ctx->target.pid, &regs);
        if (err == SG_OK) {
            result->return_value = regs.regs[0];
        }
        
        result->success = true;
        result->injected_addr = addr;
    } else if (WIFSIGNALED(status)) {
        result->error = SG_ERR_SIGNAL;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Process killed by signal %d", WTERMSIG(status));
        return SG_ERR_SIGNAL;
    }
    
    return SG_OK;
}

/*
 * Inject and execute shellcode
 */
sg_error_t sg_inject_shellcode(sg_inject_ctx_t *ctx,
                                const sg_shellcode_t *shellcode,
                                sg_inject_result_t *result)
{
    if (ctx == NULL || shellcode == NULL || result == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(result, 0, sizeof(*result));
    
    /* Attach if not already attached */
    sg_error_t err = sg_inject_attach(ctx);
    if (err != SG_OK) {
        result->error = err;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to attach to target");
        return err;
    }
    
    /* Save registers */
    err = sg_inject_save_regs(ctx);
    if (err != SG_OK) {
        result->error = err;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to save registers");
        return err;
    }
    
    /* Find injection point - use current PC location */
    sg_arm64_regs_t regs;
    err = sg_inject_read_regs(ctx->target.pid, &regs);
    if (err != SG_OK) {
        result->error = err;
        return err;
    }
    
    uint64_t inject_addr = regs.pc;
    ctx->injection_addr = inject_addr;
    
    sg_log(SG_LOG_INFO, "Injecting %zu bytes at 0x%lx", 
           shellcode->length, inject_addr);
    
    /* Save original code */
    ctx->saved_code = malloc(shellcode->length);
    if (ctx->saved_code == NULL) {
        result->error = SG_ERR_NOMEM;
        return SG_ERR_NOMEM;
    }
    ctx->saved_code_len = shellcode->length;
    
    ssize_t n = sg_inject_read_mem(ctx->target.pid, inject_addr,
                                    ctx->saved_code, shellcode->length);
    if (n < 0) {
        result->error = SG_ERR_PTRACE;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to read original code");
        return SG_ERR_PTRACE;
    }
    
    /* Write shellcode */
    n = sg_inject_write_mem(ctx->target.pid, inject_addr,
                            shellcode->code, shellcode->length);
    if (n < (ssize_t)shellcode->length) {
        result->error = SG_ERR_PTRACE;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to write shellcode");
        return SG_ERR_PTRACE;
    }
    
    ctx->injection_active = true;
    
    /* Execute */
    err = sg_inject_execute(ctx, inject_addr, result);
    
    /* Restore original code */
    sg_inject_write_mem(ctx->target.pid, inject_addr,
                        ctx->saved_code, ctx->saved_code_len);
    
    /* Restore registers */
    sg_inject_restore_regs(ctx);
    
    ctx->injection_active = false;
    
    return err;
}

/*
 * Inject shellcode at specific address
 */
sg_error_t sg_inject_shellcode_at(sg_inject_ctx_t *ctx,
                                   uint64_t addr,
                                   const sg_shellcode_t *shellcode,
                                   sg_inject_result_t *result)
{
    if (ctx == NULL || shellcode == NULL || result == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(result, 0, sizeof(*result));
    
    /* Attach if not already attached */
    sg_error_t err = sg_inject_attach(ctx);
    if (err != SG_OK) {
        result->error = err;
        return err;
    }
    
    /* Save registers */
    err = sg_inject_save_regs(ctx);
    if (err != SG_OK) {
        result->error = err;
        return err;
    }
    
    ctx->injection_addr = addr;
    
    /* Save original code at target address */
    ctx->saved_code = malloc(shellcode->length);
    if (ctx->saved_code == NULL) {
        result->error = SG_ERR_NOMEM;
        return SG_ERR_NOMEM;
    }
    ctx->saved_code_len = shellcode->length;
    
    sg_inject_read_mem(ctx->target.pid, addr, ctx->saved_code, shellcode->length);
    
    /* Write shellcode */
    ssize_t n = sg_inject_write_mem(ctx->target.pid, addr,
                                     shellcode->code, shellcode->length);
    if (n < (ssize_t)shellcode->length) {
        result->error = SG_ERR_PTRACE;
        return SG_ERR_PTRACE;
    }
    
    ctx->injection_active = true;
    
    /* Execute */
    err = sg_inject_execute(ctx, addr, result);
    
    /* Restore */
    sg_inject_write_mem(ctx->target.pid, addr, ctx->saved_code, ctx->saved_code_len);
    sg_inject_restore_regs(ctx);
    
    ctx->injection_active = false;
    
    return err;
}

/*
 * Hexdump memory region
 */
void sg_inject_hexdump(const void *data, size_t len, uint64_t base_addr)
{
    const unsigned char *p = data;
    
    for (size_t i = 0; i < len; i += 16) {
        printf("%016lx  ", base_addr + i);
        
        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", p[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) {
                printf(" ");
            }
        }
        
        printf(" |");
        
        /* ASCII */
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = p[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        
        printf("|\n");
    }
}
