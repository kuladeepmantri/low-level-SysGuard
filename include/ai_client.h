/*
 * Auris - AI Analysis Client
 * Integration with local LLM service for security analysis
 */

#ifndef AURIS_AI_CLIENT_H
#define AURIS_AI_CLIENT_H

#include "auris.h"
#include "profiler.h"
#include "dataflow.h"
#include "graph.h"

/* AI client context */
typedef struct {
    sg_ai_config_t config;
    bool initialized;
    void *curl_handle;                    /* CURL handle for HTTP requests */
} sg_ai_client_t;

/*
 * Initialize AI client
 */
sg_error_t sg_ai_client_init(sg_ai_client_t *client, const sg_ai_config_t *config);

/*
 * Clean up AI client
 */
void sg_ai_client_cleanup(sg_ai_client_t *client);

/*
 * Check if AI service is available
 */
bool sg_ai_client_available(sg_ai_client_t *client);

/*
 * Test connection to AI service
 */
sg_error_t sg_ai_client_test(sg_ai_client_t *client);

/*
 * Request analysis of a profile
 */
sg_error_t sg_ai_analyze_profile(sg_ai_client_t *client,
                                  const sg_profile_t *profile,
                                  sg_ai_response_t **response_out);

/*
 * Request analysis of a trace
 */
sg_error_t sg_ai_analyze_trace(sg_ai_client_t *client,
                                const sg_trace_t *trace,
                                sg_ai_response_t **response_out);

/*
 * Request comparison analysis
 */
sg_error_t sg_ai_analyze_comparison(sg_ai_client_t *client,
                                     const sg_profile_t *baseline,
                                     const sg_trace_t *trace,
                                     const sg_comparison_t *comparison,
                                     sg_ai_response_t **response_out);

/*
 * Request data flow analysis
 */
sg_error_t sg_ai_analyze_dataflow(sg_ai_client_t *client,
                                   const sg_dataflow_result_t *dataflow,
                                   sg_ai_response_t **response_out);

/*
 * Request graph analysis
 */
sg_error_t sg_ai_analyze_graph(sg_ai_client_t *client,
                                const sg_graph_t *graph,
                                sg_ai_response_t **response_out);

/*
 * Request comprehensive analysis (all components)
 */
sg_error_t sg_ai_analyze_full(sg_ai_client_t *client,
                               const sg_profile_t *profile,
                               const sg_trace_t *trace,
                               const sg_comparison_t *comparison,
                               const sg_dataflow_result_t *dataflow,
                               const sg_graph_t *graph,
                               sg_ai_response_t **response_out);

/*
 * Free AI response
 */
void sg_ai_response_free(sg_ai_response_t *response);

/*
 * Serialize AI response to JSON
 */
char *sg_ai_response_to_json(const sg_ai_response_t *response);

/* Prompt generation */

/*
 * Generate analysis prompt for profile
 */
char *sg_ai_prompt_profile(const sg_profile_t *profile);

/*
 * Generate analysis prompt for trace
 */
char *sg_ai_prompt_trace(const sg_trace_t *trace);

/*
 * Generate analysis prompt for comparison
 */
char *sg_ai_prompt_comparison(const sg_profile_t *baseline,
                               const sg_trace_t *trace,
                               const sg_comparison_t *comparison);

/*
 * Generate analysis prompt for data flow
 */
char *sg_ai_prompt_dataflow(const sg_dataflow_result_t *dataflow);

/*
 * Generate comprehensive analysis prompt
 */
char *sg_ai_prompt_full(const sg_profile_t *profile,
                         const sg_trace_t *trace,
                         const sg_comparison_t *comparison,
                         const sg_dataflow_result_t *dataflow,
                         const sg_graph_t *graph);

/* Response parsing */

/*
 * Parse risk score from AI response
 */
double sg_ai_parse_risk_score(const char *response);

/*
 * Parse risk level from AI response
 */
const char *sg_ai_parse_risk_level(const char *response);

/*
 * Extract recommendations from AI response
 */
char *sg_ai_extract_recommendations(const char *response);

/* Configuration */

/*
 * Load AI configuration from file
 */
sg_error_t sg_ai_config_load(const char *path, sg_ai_config_t *config_out);

/*
 * Save AI configuration to file
 */
sg_error_t sg_ai_config_save(const sg_ai_config_t *config, const char *path);

/*
 * Set default AI configuration
 */
void sg_ai_config_defaults(sg_ai_config_t *config);

/* Rate limiting and retry */

/*
 * Check if we should retry after an error
 */
bool sg_ai_should_retry(sg_error_t err, int attempt);

/*
 * Get retry delay in milliseconds
 */
int sg_ai_retry_delay(int attempt);

#endif /* AURIS_AI_CLIENT_H */
