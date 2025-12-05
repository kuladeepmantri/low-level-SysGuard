/*
 * Auris - JSON Utilities Header
 * Serialization and deserialization helpers
 */

#ifndef AURIS_JSON_UTILS_H
#define AURIS_JSON_UTILS_H

#include "auris.h"

/* Forward declarations */
struct sg_trace;
struct sg_trace_meta;
struct sg_syscall_event;
struct sg_profile;
struct sg_comparison;
struct sg_policy;
struct sg_graph;
struct sg_dataflow_result;
struct sg_ai_response;

/*
 * Event serialization
 */
char *sg_event_to_json(const sg_syscall_event_t *event);

/*
 * Trace metadata serialization
 */
char *sg_trace_meta_to_json(const sg_trace_meta_t *meta);

/*
 * Full trace serialization
 */
char *sg_trace_to_json(const sg_trace_t *trace);

/*
 * Trace deserialization
 */
sg_error_t sg_trace_from_json(const char *json, sg_trace_t **trace_out);

/*
 * Profile serialization
 */
char *sg_profile_to_json(const sg_profile_t *profile);

/*
 * Comparison result serialization
 */
char *sg_comparison_to_json(const sg_comparison_t *result);

/*
 * Policy serialization
 */
char *sg_policy_to_json(const sg_policy_t *policy);

/*
 * Policy deserialization
 */
sg_error_t sg_policy_from_json(const char *json, sg_policy_t **policy_out);

/*
 * Graph serialization
 */
char *sg_graph_to_json(const sg_graph_t *graph);

/*
 * Data flow result serialization
 */
char *sg_dataflow_result_to_json(const sg_dataflow_result_t *result);

/*
 * AI response serialization
 */
char *sg_ai_response_to_json(const sg_ai_response_t *response);

#endif /* AURIS_JSON_UTILS_H */
