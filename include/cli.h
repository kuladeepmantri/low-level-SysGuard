/*
 * Auris - Command Line Interface
 * Argument parsing and command dispatch
 */

#ifndef AURIS_CLI_H
#define AURIS_CLI_H

#include "auris.h"
#include "enforcer.h"

/*
 * Parse command line arguments
 */
sg_error_t sg_cli_parse(int argc, char *argv[], sg_cli_opts_t *opts);

/*
 * Free CLI options (allocated strings)
 */
void sg_cli_opts_free(sg_cli_opts_t *opts);

/*
 * Print usage information
 */
void sg_cli_usage(const char *program_name);

/*
 * Print help for a specific command
 */
void sg_cli_help(sg_command_t cmd);

/*
 * Print version information
 */
void sg_cli_version(void);

/*
 * Execute the parsed command
 */
sg_error_t sg_cli_execute(const sg_cli_opts_t *opts);

/* Individual command handlers */

/*
 * Learn mode: trace a program and store the trace
 */
sg_error_t sg_cmd_learn(const sg_cli_opts_t *opts);

/*
 * Profile mode: build/update baseline from traces
 */
sg_error_t sg_cmd_profile(const sg_cli_opts_t *opts);

/*
 * Compare mode: compare trace against baseline
 */
sg_error_t sg_cmd_compare(const sg_cli_opts_t *opts);

/*
 * Policy mode: generate/update policy from profile
 */
sg_error_t sg_cmd_policy(const sg_cli_opts_t *opts);

/*
 * Enforce mode: run program under policy enforcement
 */
sg_error_t sg_cmd_enforce(const sg_cli_opts_t *opts);

/*
 * Analyze mode: request AI analysis
 */
sg_error_t sg_cmd_analyze(const sg_cli_opts_t *opts);

/* Output formatting */

/*
 * Print trace summary
 */
void sg_cli_print_trace_summary(const sg_trace_t *trace);

/*
 * Print profile summary
 */
void sg_cli_print_profile_summary(const sg_profile_t *profile);

/*
 * Print comparison result
 */
void sg_cli_print_comparison(const sg_comparison_t *result);

/*
 * Print policy summary
 */
void sg_cli_print_policy_summary(const sg_policy_t *policy);

/*
 * Print enforcement result
 */
void sg_cli_print_enforcement_result(const sg_enforce_stats_t *stats,
                                      const sg_violation_t *violations,
                                      size_t violation_count);

/*
 * Print AI analysis result
 */
void sg_cli_print_ai_analysis(const sg_ai_response_t *response);

/*
 * Print data flow analysis
 */
void sg_cli_print_dataflow(const sg_dataflow_result_t *result);

/*
 * Print graph summary
 */
void sg_cli_print_graph_summary(const sg_graph_t *graph);

/* Progress and status */

/*
 * Print progress indicator
 */
void sg_cli_progress(const char *message, size_t current, size_t total);

/*
 * Print status message
 */
void sg_cli_status(const char *fmt, ...);

/*
 * Print error message
 */
void sg_cli_error(const char *fmt, ...);

/*
 * Print warning message
 */
void sg_cli_warn(const char *fmt, ...);

/* Configuration */

/*
 * Load configuration from file
 */
sg_error_t sg_cli_load_config(const char *path, sg_config_t *config);

/*
 * Save configuration to file
 */
sg_error_t sg_cli_save_config(const sg_config_t *config, const char *path);

/*
 * Set default configuration
 */
void sg_cli_config_defaults(sg_config_t *config);

/*
 * Validate configuration
 */
sg_error_t sg_cli_validate_config(const sg_config_t *config);

#endif /* AURIS_CLI_H */
