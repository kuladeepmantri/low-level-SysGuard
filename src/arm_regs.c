/*
 * Auris - ARM64 Register Access
 * Functions for reading ARM64 registers via ptrace
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <asm/ptrace.h>

#include "auris.h"
#include "tracer.h"

/*
 * ARM64 user_pt_regs structure (from Linux kernel headers)
 * This matches the layout used by PTRACE_GETREGSET with NT_PRSTATUS
 */
struct arm64_user_regs {
    uint64_t regs[31];    /* x0-x30 */
    uint64_t sp;          /* Stack pointer */
    uint64_t pc;          /* Program counter */
    uint64_t pstate;      /* Process state */
};

/*
 * Read all ARM64 general-purpose registers
 * Uses PTRACE_GETREGSET with NT_PRSTATUS for ARM64
 */
sg_error_t sg_arm64_read_regs(pid_t pid, uint64_t regs[33])
{
    if (regs == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    struct arm64_user_regs user_regs;
    struct iovec iov = {
        .iov_base = &user_regs,
        .iov_len = sizeof(user_regs),
    };
    
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0) {
        sg_log(SG_LOG_DEBUG, "PTRACE_GETREGSET failed for pid %d: %s",
               pid, strerror(errno));
        return SG_ERR_PTRACE;
    }
    
    /* Copy x0-x30 */
    for (int i = 0; i < 31; i++) {
        regs[i] = user_regs.regs[i];
    }
    
    /* SP and PC */
    regs[31] = user_regs.sp;
    regs[32] = user_regs.pc;
    
    return SG_OK;
}

/*
 * Read a single register value
 */
sg_error_t sg_arm64_read_reg(pid_t pid, int reg_idx, uint64_t *value)
{
    if (value == NULL || reg_idx < 0 || reg_idx > 32) {
        return SG_ERR_INVALID_ARG;
    }
    
    uint64_t regs[33];
    sg_error_t err = sg_arm64_read_regs(pid, regs);
    if (err != SG_OK) {
        return err;
    }
    
    *value = regs[reg_idx];
    return SG_OK;
}

/*
 * Read syscall number from x8 register
 * On ARM64, the syscall number is passed in x8
 */
sg_error_t sg_arm64_read_syscall_nr(pid_t pid, uint32_t *nr)
{
    if (nr == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    uint64_t x8;
    sg_error_t err = sg_arm64_read_reg(pid, ARM64_REG_SYSCALL_NR, &x8);
    if (err != SG_OK) {
        return err;
    }
    
    /* Syscall numbers fit in 32 bits */
    *nr = (uint32_t)x8;
    return SG_OK;
}

/*
 * Read syscall arguments (x0-x5)
 * ARM64 passes up to 6 syscall arguments in x0-x5
 */
sg_error_t sg_arm64_read_syscall_args(pid_t pid, uint64_t args[6])
{
    if (args == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    uint64_t regs[33];
    sg_error_t err = sg_arm64_read_regs(pid, regs);
    if (err != SG_OK) {
        return err;
    }
    
    /* Copy x0-x5 */
    for (int i = 0; i < 6; i++) {
        args[i] = regs[i];
    }
    
    return SG_OK;
}

/*
 * Read syscall return value from x0
 * On ARM64, the return value is in x0
 */
sg_error_t sg_arm64_read_syscall_ret(pid_t pid, int64_t *ret)
{
    if (ret == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    uint64_t x0;
    sg_error_t err = sg_arm64_read_reg(pid, ARM64_REG_ARG0, &x0);
    if (err != SG_OK) {
        return err;
    }
    
    /* Return value is signed */
    *ret = (int64_t)x0;
    return SG_OK;
}

/*
 * Read string from tracee memory using PTRACE_PEEKDATA
 * Returns number of bytes read (not including null terminator),
 * or negative error code
 */
ssize_t sg_read_string(pid_t pid, uint64_t addr, char *buf, size_t max_len)
{
    if (buf == NULL || max_len == 0) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (addr == 0) {
        buf[0] = '\0';
        return 0;
    }
    
    size_t offset = 0;
    bool found_null = false;
    
    while (offset < max_len - 1) {
        /* Read one word at a time */
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + offset), NULL);
        
        if (errno != 0) {
            if (offset == 0) {
                /* Failed to read anything */
                buf[0] = '\0';
                return SG_ERR_PTRACE;
            }
            /* Partial read is OK */
            break;
        }
        
        /* Copy bytes from word, checking for null */
        unsigned char *bytes = (unsigned char *)&word;
        for (size_t i = 0; i < sizeof(long) && offset + i < max_len - 1; i++) {
            buf[offset + i] = bytes[i];
            if (bytes[i] == '\0') {
                found_null = true;
                offset += i;
                goto done;
            }
        }
        
        offset += sizeof(long);
    }
    
done:
    buf[offset < max_len ? offset : max_len - 1] = '\0';
    
    /* If we didn't find a null and filled the buffer, truncate */
    if (!found_null && offset >= max_len - 1) {
        buf[max_len - 1] = '\0';
        offset = max_len - 1;
    }
    
    return (ssize_t)offset;
}

/*
 * Read arbitrary data from tracee memory
 */
ssize_t sg_read_memory(pid_t pid, uint64_t addr, void *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (addr == 0) {
        return 0;
    }
    
    unsigned char *dst = buf;
    size_t offset = 0;
    
    /* Handle unaligned start */
    size_t start_offset = addr % sizeof(long);
    if (start_offset != 0) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr - start_offset), NULL);
        if (errno != 0) {
            return SG_ERR_PTRACE;
        }
        
        unsigned char *bytes = (unsigned char *)&word;
        size_t to_copy = sizeof(long) - start_offset;
        if (to_copy > len) {
            to_copy = len;
        }
        
        memcpy(dst, bytes + start_offset, to_copy);
        offset += to_copy;
    }
    
    /* Read aligned words */
    while (offset + sizeof(long) <= len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + offset), NULL);
        if (errno != 0) {
            return (ssize_t)offset;
        }
        
        memcpy(dst + offset, &word, sizeof(long));
        offset += sizeof(long);
    }
    
    /* Handle remaining bytes */
    if (offset < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + offset), NULL);
        if (errno != 0) {
            return (ssize_t)offset;
        }
        
        memcpy(dst + offset, &word, len - offset);
        offset = len;
    }
    
    return (ssize_t)offset;
}

/*
 * Read sockaddr structure from tracee memory
 */
sg_error_t sg_read_sockaddr(pid_t pid, uint64_t addr, size_t len, sg_netaddr_t *out)
{
    if (out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(out, 0, sizeof(*out));
    
    if (addr == 0 || len == 0) {
        return SG_OK;
    }
    
    /* Read the sockaddr structure */
    unsigned char buf[128];
    if (len > sizeof(buf)) {
        len = sizeof(buf);
    }
    
    ssize_t n = sg_read_memory(pid, addr, buf, len);
    if (n < 2) {
        return SG_ERR_PTRACE;
    }
    
    /* Parse based on address family */
    uint16_t family = *(uint16_t *)buf;
    out->family = family;
    
    if (family == 2) {  /* AF_INET */
        if (n >= 8) {
            /* struct sockaddr_in: family(2) + port(2) + addr(4) */
            out->port = ntohs(*(uint16_t *)(buf + 2));
            out->addr.ipv4 = *(uint32_t *)(buf + 4);
            
            /* Format as string */
            unsigned char *ip = buf + 4;
            snprintf(out->str, sizeof(out->str), "%u.%u.%u.%u:%u",
                     ip[0], ip[1], ip[2], ip[3], out->port);
        }
    } else if (family == 10) {  /* AF_INET6 */
        if (n >= 28) {
            /* struct sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16) + scope(4) */
            out->port = ntohs(*(uint16_t *)(buf + 2));
            memcpy(out->addr.ipv6, buf + 8, 16);
            
            /* Format as string (simplified) */
            snprintf(out->str, sizeof(out->str), "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u",
                     out->addr.ipv6[0], out->addr.ipv6[1],
                     out->addr.ipv6[2], out->addr.ipv6[3],
                     out->addr.ipv6[4], out->addr.ipv6[5],
                     out->addr.ipv6[6], out->addr.ipv6[7],
                     out->addr.ipv6[8], out->addr.ipv6[9],
                     out->addr.ipv6[10], out->addr.ipv6[11],
                     out->addr.ipv6[12], out->addr.ipv6[13],
                     out->addr.ipv6[14], out->addr.ipv6[15],
                     out->port);
        }
    } else if (family == 1) {  /* AF_UNIX */
        /* struct sockaddr_un: family(2) + path(up to 108) */
        if (n > 2) {
            size_t path_len = n - 2;
            if (path_len > sizeof(out->str) - 1) {
                path_len = sizeof(out->str) - 1;
            }
            memcpy(out->str, buf + 2, path_len);
            out->str[path_len] = '\0';
        }
    }
    
    return SG_OK;
}
