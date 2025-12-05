/*
 * Auris - ARM Linux Syscall Tracer & Security Analyzer
 * Main entry point
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "auris.h"
#include "cli.h"
#include "syscall_table.h"
#include "logging.h"
#include "dataflow.h"
#include "inject.h"

/* Global for signal handling */
static volatile sig_atomic_t g_interrupted = 0;

/*
 * Signal handler for graceful shutdown
 */
static void signal_handler(int sig)
{
    (void)sig;
    g_interrupted = 1;
}

/*
 * Install signal handlers
 */
static void setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    /* Ignore SIGPIPE to handle broken pipes gracefully */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

/*
 * Initialize global subsystems
 */
static sg_error_t init_subsystems(sg_log_level_t log_level)
{
    sg_error_t err;
    
    /* Initialize logging first */
    sg_log_init(log_level, NULL);
    
    /* Initialize syscall table */
    err = sg_syscall_table_init();
    if (err != SG_OK) {
        sg_log(SG_LOG_ERROR, "Failed to initialize syscall table: %s",
               sg_strerror(err));
        return err;
    }
    
    sg_log(SG_LOG_DEBUG, "Auris %s initialized", AURIS_VERSION_STRING);
    
    return SG_OK;
}

/*
 * Clean up global subsystems
 */
static void cleanup_subsystems(void)
{
    sg_sensitive_patterns_cleanup();
    sg_syscall_table_cleanup();
    sg_log_cleanup();
}

int main(int argc, char *argv[])
{
    sg_cli_opts_t opts;
    sg_error_t err;
    int exit_code = EXIT_SUCCESS;
    
    /* Set up signal handlers */
    setup_signals();
    
    /* Initialize options to defaults */
    memset(&opts, 0, sizeof(opts));
    sg_cli_config_defaults(&opts.config);
    
    /* Parse command line */
    err = sg_cli_parse(argc, argv, &opts);
    if (err != SG_OK) {
        if (err == SG_ERR_INVALID_ARG) {
            /* Error already printed by parser */
            exit_code = EXIT_FAILURE;
            goto cleanup_opts;
        }
        fprintf(stderr, "Error parsing arguments: %s\n", sg_strerror(err));
        exit_code = EXIT_FAILURE;
        goto cleanup_opts;
    }
    
    /* Handle help and version early */
    if (opts.command == CMD_HELP) {
        sg_cli_usage(argv[0]);
        goto cleanup_opts;
    }
    
    if (opts.command == CMD_VERSION) {
        sg_cli_version();
        goto cleanup_opts;
    }
    
    /* Validate we have a command */
    if (opts.command == CMD_NONE) {
        sg_cli_usage(argv[0]);
        exit_code = EXIT_FAILURE;
        goto cleanup_opts;
    }
    
    /* Handle inject command specially - it has its own CLI parser */
    if (opts.command == CMD_INJECT) {
        /* Pass remaining args to inject subsystem */
        exit_code = sg_inject_main(argc - 1, argv + 1);
        goto cleanup_opts;
    }
    
    /* Initialize subsystems */
    sg_log_level_t log_level = opts.verbose ? SG_LOG_DEBUG : 
                                (opts.quiet ? SG_LOG_ERROR : SG_LOG_INFO);
    err = init_subsystems(log_level);
    if (err != SG_OK) {
        fprintf(stderr, "Failed to initialize: %s\n", sg_strerror(err));
        exit_code = EXIT_FAILURE;
        goto cleanup_opts;
    }
    
    /* Execute the command */
    err = sg_cli_execute(&opts);
    if (err != SG_OK) {
        if (!opts.quiet) {
            sg_cli_error("Command failed: %s", sg_strerror(err));
        }
        exit_code = EXIT_FAILURE;
    }
    
    /* Clean up */
    cleanup_subsystems();
    
cleanup_opts:
    sg_cli_opts_free(&opts);
    
    return exit_code;
}
