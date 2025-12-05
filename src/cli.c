/*
 * SysGuard - Command Line Interface
 * Argument parsing and command dispatch
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>

#include "sysguard.h"
#include "cli.h"
#include "tracer.h"
#include "trace_store.h"
#include "profiler.h"
#include "policy.h"
#include "enforcer.h"
#include "ai_client.h"
#include "dataflow.h"
#include "graph.h"

/* Default data directory */
#define DEFAULT_DATA_DIR "/data/sysguard"

/* Command names (for debugging/logging) */
__attribute__((unused))
static const char *command_names[] = {
    "none", "learn", "profile", "compare", "policy", "enforce", "analyze", "help", "version"
};

/* Long options */
static struct option long_options[] = {
    {"help",        no_argument,       NULL, 'h'},
    {"version",     no_argument,       NULL, 'V'},
    {"verbose",     no_argument,       NULL, 'v'},
    {"quiet",       no_argument,       NULL, 'q'},
    {"json",        no_argument,       NULL, 'j'},
    {"force",       no_argument,       NULL, 'f'},
    {"data-dir",    required_argument, NULL, 'd'},
    {"trace-id",    required_argument, NULL, 't'},
    {"profile-id",  required_argument, NULL, 'p'},
    {"policy-id",   required_argument, NULL, 'P'},
    {"output",      required_argument, NULL, 'o'},
    {"mode",        required_argument, NULL, 'm'},
    {"ai-endpoint", required_argument, NULL, 'a'},
    {"ai-model",    required_argument, NULL, 'M'},
    {NULL, 0, NULL, 0}
};

/*
 * Set default configuration
 */
void sg_cli_config_defaults(sg_config_t *config)
{
    if (config == NULL) {
        return;
    }
    
    memset(config, 0, sizeof(*config));
    sg_safe_strncpy(config->data_dir, DEFAULT_DATA_DIR, sizeof(config->data_dir));
    config->log_level = SG_LOG_INFO;
    config->follow_forks = true;
    config->decode_strings = true;
    config->max_string_len = 256;
    config->include_env = false;
    
    sg_ai_config_defaults(&config->ai);
}

/*
 * Print usage
 */
void sg_cli_usage(const char *program_name)
{
    printf("SysGuard %s - ARM Linux Syscall Tracer & Security Analyzer\n\n",
           SYSGUARD_VERSION_STRING);
    
    printf("Usage: %s <command> [options] [-- program [args...]]\n\n", program_name);
    
    printf("Commands:\n");
    printf("  learn     Trace a program and store the trace\n");
    printf("  profile   Build or update a behavioral profile from traces\n");
    printf("  compare   Compare a trace against a baseline profile\n");
    printf("  policy    Generate or manage security policies\n");
    printf("  enforce   Run a program under policy enforcement\n");
    printf("  analyze   Request AI analysis of traces or profiles\n");
    printf("  help      Show this help message\n");
    printf("  version   Show version information\n\n");
    
    printf("Options:\n");
    printf("  -h, --help            Show help message\n");
    printf("  -V, --version         Show version\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -q, --quiet           Quiet mode\n");
    printf("  -j, --json            Output in JSON format\n");
    printf("  -f, --force           Force overwrite existing files\n");
    printf("  -d, --data-dir DIR    Data directory (default: %s)\n", DEFAULT_DATA_DIR);
    printf("  -t, --trace-id ID     Trace ID to use\n");
    printf("  -p, --profile-id ID   Profile ID to use\n");
    printf("  -P, --policy-id ID    Policy ID to use\n");
    printf("  -o, --output FILE     Output file path\n");
    printf("  -m, --mode MODE       Enforcement mode: alert or block\n");
    printf("  -a, --ai-endpoint URL AI service endpoint\n");
    printf("  -M, --ai-model MODEL  AI model name\n\n");
    
    printf("Examples:\n");
    printf("  %s learn -- /bin/ls -la\n", program_name);
    printf("  %s profile -t <trace-id>\n", program_name);
    printf("  %s compare -p <profile-id> -- ./myapp\n", program_name);
    printf("  %s policy -p <profile-id>\n", program_name);
    printf("  %s enforce -P <policy-id> -m alert -- ./myapp\n", program_name);
    printf("  %s analyze -p <profile-id>\n", program_name);
}

/*
 * Print version
 */
void sg_cli_version(void)
{
    printf("SysGuard %s\n", SYSGUARD_VERSION_STRING);
    printf("ARM Linux Syscall Tracer & Security Analyzer\n");
    printf("Built for ARM64 Linux\n");
}

/*
 * Print help for specific command
 */
void sg_cli_help(sg_command_t cmd)
{
    switch (cmd) {
        case CMD_LEARN:
            printf("learn - Trace a program and store the syscall trace\n\n");
            printf("Usage: sysguard learn [options] -- program [args...]\n\n");
            printf("Options:\n");
            printf("  -t, --trace-id ID   Custom trace ID (auto-generated if not specified)\n");
            printf("  -o, --output FILE   Also save trace to specified file\n");
            break;
            
        case CMD_PROFILE:
            printf("profile - Build or update a behavioral profile\n\n");
            printf("Usage: sysguard profile [options]\n\n");
            printf("Options:\n");
            printf("  -t, --trace-id ID     Build profile from specific trace\n");
            printf("  -p, --profile-id ID   Update existing profile\n");
            printf("  --binary PATH         Build profile from all traces of binary\n");
            break;
            
        case CMD_COMPARE:
            printf("compare - Compare a trace against baseline\n\n");
            printf("Usage: sysguard compare [options] [-- program [args...]]\n\n");
            printf("Options:\n");
            printf("  -p, --profile-id ID   Baseline profile to compare against\n");
            printf("  -t, --trace-id ID     Compare existing trace (or run new trace)\n");
            break;
            
        case CMD_POLICY:
            printf("policy - Generate or manage security policies\n\n");
            printf("Usage: sysguard policy [options]\n\n");
            printf("Options:\n");
            printf("  -p, --profile-id ID   Generate policy from profile\n");
            printf("  -P, --policy-id ID    View or update existing policy\n");
            printf("  --minimal             Generate minimal policy\n");
            break;
            
        case CMD_ENFORCE:
            printf("enforce - Run program under policy enforcement\n\n");
            printf("Usage: sysguard enforce [options] -- program [args...]\n\n");
            printf("Options:\n");
            printf("  -P, --policy-id ID    Policy to enforce\n");
            printf("  -m, --mode MODE       alert (log only) or block (prevent)\n");
            break;
            
        case CMD_ANALYZE:
            printf("analyze - Request AI analysis\n\n");
            printf("Usage: sysguard analyze [options]\n\n");
            printf("Options:\n");
            printf("  -p, --profile-id ID   Analyze profile\n");
            printf("  -t, --trace-id ID     Analyze trace\n");
            printf("  -a, --ai-endpoint URL AI service endpoint\n");
            printf("  -M, --ai-model MODEL  AI model to use\n");
            break;
            
        default:
            sg_cli_usage("sysguard");
            break;
    }
}

/*
 * Parse command from string
 */
static sg_command_t parse_command(const char *cmd)
{
    if (cmd == NULL) {
        return CMD_NONE;
    }
    
    if (strcmp(cmd, "learn") == 0) return CMD_LEARN;
    if (strcmp(cmd, "profile") == 0) return CMD_PROFILE;
    if (strcmp(cmd, "compare") == 0) return CMD_COMPARE;
    if (strcmp(cmd, "policy") == 0) return CMD_POLICY;
    if (strcmp(cmd, "enforce") == 0) return CMD_ENFORCE;
    if (strcmp(cmd, "analyze") == 0) return CMD_ANALYZE;
    if (strcmp(cmd, "help") == 0) return CMD_HELP;
    if (strcmp(cmd, "version") == 0) return CMD_VERSION;
    
    return CMD_NONE;
}

/*
 * Parse command line arguments
 */
sg_error_t sg_cli_parse(int argc, char *argv[], sg_cli_opts_t *opts)
{
    if (opts == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(opts, 0, sizeof(*opts));
    sg_cli_config_defaults(&opts->config);
    
    if (argc < 2) {
        return SG_OK;  /* No command, will show usage */
    }
    
    /* First argument is the command */
    opts->command = parse_command(argv[1]);
    
    if (opts->command == CMD_NONE && argv[1][0] != '-') {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return SG_ERR_INVALID_ARG;
    }
    
    /* Parse options starting from argv[2] */
    optind = 2;
    int opt;
    
    while ((opt = getopt_long(argc, argv, "hVvqjfd:t:p:P:o:m:a:M:",
                               long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                opts->command = CMD_HELP;
                return SG_OK;
                
            case 'V':
                opts->command = CMD_VERSION;
                return SG_OK;
                
            case 'v':
                opts->verbose = true;
                break;
                
            case 'q':
                opts->quiet = true;
                break;
                
            case 'j':
                opts->json_output = true;
                break;
                
            case 'f':
                opts->force = true;
                break;
                
            case 'd':
                sg_safe_strncpy(opts->config.data_dir, optarg,
                                sizeof(opts->config.data_dir));
                break;
                
            case 't':
                sg_safe_strncpy(opts->trace_id, optarg, sizeof(opts->trace_id));
                break;
                
            case 'p':
                sg_safe_strncpy(opts->profile_id, optarg, sizeof(opts->profile_id));
                break;
                
            case 'P':
                sg_safe_strncpy(opts->policy_id, optarg, sizeof(opts->policy_id));
                break;
                
            case 'o':
                sg_safe_strncpy(opts->output_path, optarg, sizeof(opts->output_path));
                break;
                
            case 'm':
                if (strcmp(optarg, "alert") == 0) {
                    opts->enforce_mode = ENFORCE_MODE_ALERT;
                } else if (strcmp(optarg, "block") == 0) {
                    opts->enforce_mode = ENFORCE_MODE_BLOCK;
                } else {
                    fprintf(stderr, "Invalid mode: %s (use 'alert' or 'block')\n", optarg);
                    return SG_ERR_INVALID_ARG;
                }
                break;
                
            case 'a':
                sg_safe_strncpy(opts->config.ai.endpoint, optarg,
                                sizeof(opts->config.ai.endpoint));
                opts->config.ai.enabled = true;
                break;
                
            case 'M':
                sg_safe_strncpy(opts->config.ai.model, optarg,
                                sizeof(opts->config.ai.model));
                break;
                
            case '?':
                return SG_ERR_INVALID_ARG;
                
            default:
                break;
        }
    }
    
    /* Remaining arguments after -- are the program to run */
    if (optind < argc) {
        opts->binary_path[0] = '\0';
        sg_safe_strncpy(opts->binary_path, argv[optind], sizeof(opts->binary_path));
        opts->binary_argv = &argv[optind];
        opts->binary_argc = argc - optind;
    }
    
    return SG_OK;
}

/*
 * Free CLI options
 */
void sg_cli_opts_free(sg_cli_opts_t *opts)
{
    /* Currently no dynamic allocations in opts */
    (void)opts;
}

/*
 * Status message
 */
void sg_cli_status(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

/*
 * Error message
 */
void sg_cli_error(const char *fmt, ...)
{
    fprintf(stderr, "Error: ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

/*
 * Warning message
 */
void sg_cli_warn(const char *fmt, ...)
{
    fprintf(stderr, "Warning: ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

/*
 * Print trace summary
 */
void sg_cli_print_trace_summary(const sg_trace_t *trace)
{
    if (trace == NULL) {
        return;
    }
    
    printf("Trace Summary\n");
    printf("=============\n");
    printf("Trace ID:     %s\n", trace->meta.trace_id);
    printf("Binary:       %s\n", trace->meta.binary_path);
    printf("Hash:         %.16s...\n", trace->meta.binary_hash);
    printf("Syscalls:     %lu\n", (unsigned long)trace->event_count);
    printf("Exit code:    %d\n", trace->meta.exit_code);
}

/*
 * Print profile summary
 */
void sg_cli_print_profile_summary(const sg_profile_t *profile)
{
    if (profile == NULL) {
        return;
    }
    
    printf("Profile Summary\n");
    printf("===============\n");
    printf("Profile ID:   %s\n", profile->profile_id);
    printf("Binary:       %s\n", profile->binary_path);
    printf("Syscalls:     %lu total, %zu unique\n",
           (unsigned long)profile->total_syscalls, profile->unique_count);
    printf("Behavior:\n");
    printf("  Network I/O:      %s\n", profile->does_network_io ? "yes" : "no");
    printf("  File I/O:         %s\n", profile->does_file_io ? "yes" : "no");
    printf("  Spawns children:  %s\n", profile->spawns_children ? "yes" : "no");
    printf("  Changes privs:    %s\n", profile->changes_privileges ? "yes" : "no");
    printf("  Sensitive files:  %s\n", profile->accesses_sensitive_files ? "yes" : "no");
}

/*
 * Print comparison result
 */
void sg_cli_print_comparison(const sg_comparison_t *result)
{
    if (result == NULL) {
        return;
    }
    
    printf("Comparison Result\n");
    printf("=================\n");
    printf("Trace ID:     %s\n", result->trace_id);
    printf("Profile ID:   %s\n", result->profile_id);
    printf("Anomalous:    %s\n", result->is_anomalous ? "YES" : "no");
    printf("Deviation:    %.2f\n", result->overall_deviation);
    printf("Risk Score:   %.2f\n", result->risk_score);
    
    if (result->anomaly_count > 0) {
        printf("\nAnomalies (%zu):\n", result->anomaly_count);
        for (size_t i = 0; i < result->anomaly_count; i++) {
            printf("  - %s (severity: %.2f)\n",
                   result->anomalies[i].description,
                   result->anomalies[i].severity);
        }
    }
}

/*
 * Print policy summary
 */
void sg_cli_print_policy_summary(const sg_policy_t *policy)
{
    if (policy == NULL) {
        return;
    }
    
    printf("Policy Summary\n");
    printf("==============\n");
    printf("Policy ID:    %s\n", policy->policy_id);
    printf("Binary:       %s\n", policy->binary_path);
    printf("Rules:        %zu\n", policy->rule_count);
    printf("Default:      %s\n",
           policy->default_mode == ENFORCE_MODE_BLOCK ? "block" : "alert");
    printf("Allow unknown: %s\n", policy->allow_unknown ? "yes" : "no");
}

/*
 * Ask user if they want AI analysis (interactive prompt)
 */
bool sg_cli_ask_ai_analysis(void)
{
    char response[16];
    
    printf("\nWould you like AI analysis? (y/n): ");
    fflush(stdout);
    
    if (fgets(response, sizeof(response), stdin) == NULL) {
        return false;
    }
    
    /* Trim newline */
    size_t len = strlen(response);
    if (len > 0 && response[len - 1] == '\n') {
        response[len - 1] = '\0';
    }
    
    return (response[0] == 'y' || response[0] == 'Y');
}

/*
 * Perform optional AI analysis on a profile
 */
void sg_cli_optional_ai_analysis(const sg_profile_t *profile, const sg_config_t *config)
{
    if (profile == NULL || config == NULL) {
        return;
    }
    
    /* Ask user if they want AI analysis */
    if (!sg_cli_ask_ai_analysis()) {
        printf("Skipping AI analysis.\n");
        return;
    }
    
    /* Check if AI is configured */
    if (config->ai.endpoint[0] == '\0') {
        printf("\nAI endpoint not configured.\n");
        printf("To enable AI analysis, use: --ai-endpoint <URL> --ai-model <model>\n");
        printf("Example: --ai-endpoint http://localhost:11434/api/generate --ai-model llama2\n");
        return;
    }
    
    printf("\nConnecting to AI service...\n");
    
    sg_ai_client_t ai;
    sg_ai_config_t ai_config = config->ai;
    ai_config.enabled = true;
    
    sg_error_t err = sg_ai_client_init(&ai, &ai_config);
    if (err != SG_OK) {
        printf("Failed to initialize AI client: %s\n", sg_strerror(err));
        return;
    }
    
    sg_ai_response_t *response = NULL;
    err = sg_ai_analyze_profile(&ai, profile, &response);
    
    if (err == SG_OK && response != NULL) {
        sg_cli_print_ai_analysis(response);
    } else {
        printf("AI analysis failed: %s\n", sg_strerror(err));
        if (response != NULL && response->error[0] != '\0') {
            printf("Details: %s\n", response->error);
        }
    }
    
    sg_ai_response_free(response);
    sg_ai_client_cleanup(&ai);
}

/*
 * Print AI analysis
 */
void sg_cli_print_ai_analysis(const sg_ai_response_t *response)
{
    if (response == NULL) {
        return;
    }
    
    printf("AI Analysis\n");
    printf("===========\n");
    
    if (!response->success) {
        printf("Error: %s\n", response->error);
        return;
    }
    
    printf("Risk Score:   %.2f\n", response->risk_score);
    printf("Risk Level:   %s\n", response->risk_level);
    printf("\nAnalysis:\n%s\n", response->analysis ? response->analysis : "(none)");
}

/*
 * Execute command
 */
sg_error_t sg_cli_execute(const sg_cli_opts_t *opts)
{
    if (opts == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    switch (opts->command) {
        case CMD_LEARN:
            return sg_cmd_learn(opts);
        case CMD_PROFILE:
            return sg_cmd_profile(opts);
        case CMD_COMPARE:
            return sg_cmd_compare(opts);
        case CMD_POLICY:
            return sg_cmd_policy(opts);
        case CMD_ENFORCE:
            return sg_cmd_enforce(opts);
        case CMD_ANALYZE:
            return sg_cmd_analyze(opts);
        case CMD_HELP:
            sg_cli_usage("sysguard");
            return SG_OK;
        case CMD_VERSION:
            sg_cli_version();
            return SG_OK;
        default:
            sg_cli_usage("sysguard");
            return SG_ERR_INVALID_ARG;
    }
}

/*
 * Learn command
 */
sg_error_t sg_cmd_learn(const sg_cli_opts_t *opts)
{
    if (opts->binary_path[0] == '\0') {
        sg_cli_error("No program specified. Use: sysguard learn -- program [args...]");
        return SG_ERR_INVALID_ARG;
    }
    
    sg_error_t err;
    
    /* Initialize stores */
    sg_trace_store_t store;
    err = sg_trace_store_init(&store, opts->config.data_dir);
    if (err != SG_OK) {
        sg_cli_error("Failed to initialize trace store: %s", sg_strerror(err));
        return err;
    }
    
    /* Initialize tracer */
    sg_tracer_ctx_t tracer;
    err = sg_tracer_init(&tracer, (sg_config_t *)&opts->config);
    if (err != SG_OK) {
        sg_trace_store_cleanup(&store);
        sg_cli_error("Failed to initialize tracer: %s", sg_strerror(err));
        return err;
    }
    
    if (!opts->quiet) {
        sg_cli_status("Tracing: %s", opts->binary_path);
    }
    
    /* Run trace */
    sg_trace_t *trace = NULL;
    err = sg_tracer_run(&tracer, opts->binary_path, opts->binary_argv, NULL, &trace);
    
    sg_tracer_cleanup(&tracer);
    
    if (err != SG_OK) {
        sg_trace_store_cleanup(&store);
        sg_cli_error("Tracing failed: %s", sg_strerror(err));
        return err;
    }
    
    /* Save trace */
    const char *trace_id = opts->trace_id[0] != '\0' ? opts->trace_id : NULL;
    err = sg_trace_store_save(&store, trace, trace_id);
    
    if (err != SG_OK) {
        sg_cli_error("Failed to save trace: %s", sg_strerror(err));
    } else if (!opts->quiet) {
        if (opts->json_output) {
            char *json = sg_trace_meta_to_json(&trace->meta);
            if (json != NULL) {
                printf("%s\n", json);
                free(json);
            }
        } else {
            sg_cli_print_trace_summary(trace);
            sg_cli_status("\nTrace saved: %s", trace->meta.trace_id);
        }
    }
    
    sg_trace_free(trace);
    sg_trace_store_cleanup(&store);
    
    return err;
}

/*
 * Profile command
 */
sg_error_t sg_cmd_profile(const sg_cli_opts_t *opts)
{
    sg_error_t err;
    
    sg_trace_store_t trace_store;
    sg_profile_store_t profile_store;
    
    err = sg_trace_store_init(&trace_store, opts->config.data_dir);
    if (err != SG_OK) {
        return err;
    }
    
    err = sg_profile_store_init(&profile_store, opts->config.data_dir);
    if (err != SG_OK) {
        sg_trace_store_cleanup(&trace_store);
        return err;
    }
    
    sg_profile_t *profile = NULL;
    
    if (opts->trace_id[0] != '\0') {
        /* Build from specific trace */
        sg_trace_t *trace = NULL;
        err = sg_trace_store_load(&trace_store, opts->trace_id, &trace);
        if (err != SG_OK) {
            sg_cli_error("Failed to load trace %s: %s", opts->trace_id, sg_strerror(err));
            goto cleanup;
        }
        
        err = sg_profile_build_from_trace(trace, &profile);
        sg_trace_free(trace);
        
        if (err != SG_OK) {
            sg_cli_error("Failed to build profile: %s", sg_strerror(err));
            goto cleanup;
        }
    } else if (opts->profile_id[0] != '\0') {
        /* Load existing profile */
        err = sg_profile_store_load(&profile_store, opts->profile_id, &profile);
        if (err != SG_OK) {
            sg_cli_error("Failed to load profile %s: %s", opts->profile_id, sg_strerror(err));
            goto cleanup;
        }
    } else {
        sg_cli_error("Specify --trace-id or --profile-id");
        err = SG_ERR_INVALID_ARG;
        goto cleanup;
    }
    
    /* Save profile */
    err = sg_profile_store_save(&profile_store, profile, NULL);
    if (err != SG_OK) {
        sg_cli_error("Failed to save profile: %s", sg_strerror(err));
    } else if (!opts->quiet) {
        if (opts->json_output) {
            char *json = sg_profile_to_json(profile);
            if (json != NULL) {
                printf("%s\n", json);
                free(json);
            }
        } else {
            sg_cli_print_profile_summary(profile);
            sg_cli_status("\nProfile saved: %s", profile->profile_id);
            
            /* Offer optional AI analysis */
            sg_cli_optional_ai_analysis(profile, &opts->config);
        }
    }
    
    sg_profile_free(profile);
    
cleanup:
    sg_trace_store_cleanup(&trace_store);
    sg_profile_store_cleanup(&profile_store);
    return err;
}

/*
 * Compare command
 */
sg_error_t sg_cmd_compare(const sg_cli_opts_t *opts)
{
    if (opts->profile_id[0] == '\0') {
        sg_cli_error("Specify --profile-id for baseline");
        return SG_ERR_INVALID_ARG;
    }
    
    sg_error_t err;
    
    sg_trace_store_t trace_store;
    sg_profile_store_t profile_store;
    
    err = sg_trace_store_init(&trace_store, opts->config.data_dir);
    if (err != SG_OK) return err;
    
    err = sg_profile_store_init(&profile_store, opts->config.data_dir);
    if (err != SG_OK) {
        sg_trace_store_cleanup(&trace_store);
        return err;
    }
    
    /* Load baseline profile */
    sg_profile_t *profile = NULL;
    err = sg_profile_store_load(&profile_store, opts->profile_id, &profile);
    if (err != SG_OK) {
        sg_cli_error("Failed to load profile: %s", sg_strerror(err));
        goto cleanup;
    }
    
    sg_trace_t *trace = NULL;
    
    if (opts->trace_id[0] != '\0') {
        /* Use existing trace */
        err = sg_trace_store_load(&trace_store, opts->trace_id, &trace);
    } else if (opts->binary_path[0] != '\0') {
        /* Run new trace */
        sg_tracer_ctx_t tracer;
        err = sg_tracer_init(&tracer, (sg_config_t *)&opts->config);
        if (err == SG_OK) {
            err = sg_tracer_run(&tracer, opts->binary_path, opts->binary_argv, NULL, &trace);
            sg_tracer_cleanup(&tracer);
        }
    } else {
        sg_cli_error("Specify --trace-id or program to run");
        err = SG_ERR_INVALID_ARG;
        goto cleanup_profile;
    }
    
    if (err != SG_OK) {
        sg_cli_error("Failed to get trace: %s", sg_strerror(err));
        goto cleanup_profile;
    }
    
    /* Compare */
    sg_comparison_t *result = NULL;
    err = sg_profile_compare(profile, trace, &result);
    
    if (err != SG_OK) {
        sg_cli_error("Comparison failed: %s", sg_strerror(err));
    } else if (!opts->quiet) {
        if (opts->json_output) {
            char *json = sg_comparison_to_json(result);
            if (json != NULL) {
                printf("%s\n", json);
                free(json);
            }
        } else {
            sg_cli_print_comparison(result);
        }
    }
    
    sg_comparison_free(result);
    sg_trace_free(trace);
    
cleanup_profile:
    sg_profile_free(profile);
    
cleanup:
    sg_trace_store_cleanup(&trace_store);
    sg_profile_store_cleanup(&profile_store);
    return err;
}

/*
 * Policy command
 */
sg_error_t sg_cmd_policy(const sg_cli_opts_t *opts)
{
    sg_error_t err;
    
    sg_profile_store_t profile_store;
    sg_policy_store_t policy_store;
    
    err = sg_profile_store_init(&profile_store, opts->config.data_dir);
    if (err != SG_OK) return err;
    
    err = sg_policy_store_init(&policy_store, opts->config.data_dir);
    if (err != SG_OK) {
        sg_profile_store_cleanup(&profile_store);
        return err;
    }
    
    sg_policy_t *policy = NULL;
    
    if (opts->profile_id[0] != '\0') {
        /* Generate from profile */
        sg_profile_t *profile = NULL;
        err = sg_profile_store_load(&profile_store, opts->profile_id, &profile);
        if (err != SG_OK) {
            sg_cli_error("Failed to load profile: %s", sg_strerror(err));
            goto cleanup;
        }
        
        err = sg_policy_generate(profile, &policy);
        sg_profile_free(profile);
        
        if (err != SG_OK) {
            sg_cli_error("Failed to generate policy: %s", sg_strerror(err));
            goto cleanup;
        }
    } else if (opts->policy_id[0] != '\0') {
        /* Load existing */
        err = sg_policy_store_load(&policy_store, opts->policy_id, &policy);
        if (err != SG_OK) {
            sg_cli_error("Failed to load policy: %s", sg_strerror(err));
            goto cleanup;
        }
    } else {
        /* Generate minimal */
        err = sg_policy_generate_minimal(&policy);
        if (err != SG_OK) {
            sg_cli_error("Failed to generate policy: %s", sg_strerror(err));
            goto cleanup;
        }
    }
    
    /* Save policy */
    err = sg_policy_store_save(&policy_store, policy, NULL);
    if (err != SG_OK) {
        sg_cli_error("Failed to save policy: %s", sg_strerror(err));
    } else if (!opts->quiet) {
        if (opts->json_output) {
            char *json = sg_policy_to_json(policy);
            if (json != NULL) {
                printf("%s\n", json);
                free(json);
            }
        } else {
            sg_cli_print_policy_summary(policy);
            sg_cli_status("\nPolicy saved: %s", policy->policy_id);
        }
    }
    
    sg_policy_free(policy);
    
cleanup:
    sg_profile_store_cleanup(&profile_store);
    sg_policy_store_cleanup(&policy_store);
    return err;
}

/*
 * Enforce command
 */
sg_error_t sg_cmd_enforce(const sg_cli_opts_t *opts)
{
    if (opts->policy_id[0] == '\0') {
        sg_cli_error("Specify --policy-id");
        return SG_ERR_INVALID_ARG;
    }
    
    if (opts->binary_path[0] == '\0') {
        sg_cli_error("No program specified");
        return SG_ERR_INVALID_ARG;
    }
    
    sg_error_t err;
    
    sg_policy_store_t policy_store;
    err = sg_policy_store_init(&policy_store, opts->config.data_dir);
    if (err != SG_OK) return err;
    
    /* Load policy */
    sg_policy_t *policy = NULL;
    err = sg_policy_store_load(&policy_store, opts->policy_id, &policy);
    if (err != SG_OK) {
        sg_cli_error("Failed to load policy: %s", sg_strerror(err));
        sg_policy_store_cleanup(&policy_store);
        return err;
    }
    
    /* Initialize enforcer */
    sg_enforcer_ctx_t enforcer;
    err = sg_enforcer_init(&enforcer, policy, opts->enforce_mode,
                            (sg_config_t *)&opts->config);
    if (err != SG_OK) {
        sg_cli_error("Failed to initialize enforcer: %s", sg_strerror(err));
        sg_policy_free(policy);
        sg_policy_store_cleanup(&policy_store);
        return err;
    }
    
    if (!opts->quiet) {
        sg_cli_status("Enforcing policy %s on %s (mode: %s)",
                      opts->policy_id, opts->binary_path,
                      opts->enforce_mode == ENFORCE_MODE_BLOCK ? "block" : "alert");
    }
    
    /* Run with enforcement */
    err = sg_enforcer_run(&enforcer, opts->binary_path, opts->binary_argv, NULL);
    
    /* Print results */
    if (!opts->quiet) {
        char *report = sg_enforcer_report(&enforcer);
        if (report != NULL) {
            printf("\n%s", report);
            free(report);
        }
    }
    
    sg_enforcer_cleanup(&enforcer);
    sg_policy_free(policy);
    sg_policy_store_cleanup(&policy_store);
    
    return err;
}

/*
 * Analyze command - requires AI endpoint configuration
 */
sg_error_t sg_cmd_analyze(const sg_cli_opts_t *opts)
{
    /* Check if AI is configured */
    if (!opts->config.ai.enabled || opts->config.ai.endpoint[0] == '\0') {
        printf("AI Analysis requires an AI endpoint.\n");
        printf("Usage: sysguard analyze -p <profile-id> --ai-endpoint <URL> --ai-model <model>\n");
        printf("Example: sysguard analyze -p <profile-id> --ai-endpoint http://localhost:11434/api/generate --ai-model llama2\n");
        return SG_ERR_CONFIG;
    }
    
    if (opts->profile_id[0] == '\0' && opts->trace_id[0] == '\0') {
        sg_cli_error("Specify --profile-id or --trace-id");
        return SG_ERR_INVALID_ARG;
    }
    
    sg_error_t err;
    
    /* Initialize AI client */
    sg_ai_client_t ai;
    err = sg_ai_client_init(&ai, &opts->config.ai);
    if (err != SG_OK) {
        sg_cli_error("Failed to initialize AI client: %s", sg_strerror(err));
        return err;
    }
    
    printf("Connecting to AI service at %s...\n", opts->config.ai.endpoint);
    
    sg_ai_response_t *response = NULL;
    
    if (opts->profile_id[0] != '\0') {
        /* Analyze profile */
        sg_profile_store_t store;
        err = sg_profile_store_init(&store, opts->config.data_dir);
        if (err == SG_OK) {
            sg_profile_t *profile = NULL;
            err = sg_profile_store_load(&store, opts->profile_id, &profile);
            if (err == SG_OK) {
                printf("Analyzing profile %s...\n", opts->profile_id);
                err = sg_ai_analyze_profile(&ai, profile, &response);
                sg_profile_free(profile);
            }
            sg_profile_store_cleanup(&store);
        }
    } else {
        sg_cli_error("Specify --profile-id or --trace-id");
        err = SG_ERR_INVALID_ARG;
    }
    
    if (err == SG_OK && response != NULL) {
        if (opts->json_output) {
            char *json = sg_ai_response_to_json(response);
            if (json != NULL) {
                printf("%s\n", json);
                free(json);
            }
        } else {
            sg_cli_print_ai_analysis(response);
        }
    } else if (err != SG_OK) {
        sg_cli_error("Analysis failed: %s", sg_strerror(err));
    }
    
    sg_ai_response_free(response);
    sg_ai_client_cleanup(&ai);
    
    return err;
}
