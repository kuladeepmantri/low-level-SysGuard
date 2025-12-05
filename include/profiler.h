/*
 * Auris - Behavioral Profiler
 * Build and compare behavioral profiles from syscall traces
 */

#ifndef AURIS_PROFILER_H
#define AURIS_PROFILER_H

#include "auris.h"
#include "trace_store.h"

/* Profile storage context */
typedef struct {
    char base_dir[MAX_PATH_LEN];
    bool initialized;
} sg_profile_store_t;

/*
 * Initialize profile storage
 */
sg_error_t sg_profile_store_init(sg_profile_store_t *store, const char *base_dir);

/*
 * Clean up profile storage
 */
void sg_profile_store_cleanup(sg_profile_store_t *store);

/*
 * Allocate a new profile structure
 */
sg_profile_t *sg_profile_alloc(void);

/*
 * Free a profile structure
 */
void sg_profile_free(sg_profile_t *profile);

/*
 * Build a profile from a single trace
 */
sg_error_t sg_profile_build_from_trace(const sg_trace_t *trace,
                                        sg_profile_t **profile_out);

/*
 * Build a baseline profile from multiple traces
 * Aggregates statistics across all traces
 */
sg_error_t sg_profile_build_baseline(const sg_trace_t **traces,
                                      size_t trace_count,
                                      sg_profile_t **profile_out);

/*
 * Update an existing profile with a new trace
 * Merges new observations into the baseline
 */
sg_error_t sg_profile_update(sg_profile_t *profile, const sg_trace_t *trace);

/*
 * Compare a trace against a baseline profile
 * Detects anomalies and deviations
 */
sg_error_t sg_profile_compare(const sg_profile_t *baseline,
                               const sg_trace_t *trace,
                               sg_comparison_t **result_out);

/*
 * Free comparison result
 */
void sg_comparison_free(sg_comparison_t *result);

/*
 * Calculate overall deviation score (0.0 - 1.0)
 */
double sg_profile_deviation_score(const sg_comparison_t *result);

/*
 * Calculate risk score based on anomalies (0.0 - 1.0)
 */
double sg_profile_risk_score(const sg_comparison_t *result);

/* Profile persistence */

/*
 * Save profile to disk
 */
sg_error_t sg_profile_store_save(sg_profile_store_t *store,
                                  sg_profile_t *profile,
                                  const char *profile_id);

/*
 * Load profile from disk
 */
sg_error_t sg_profile_store_load(sg_profile_store_t *store,
                                  const char *profile_id,
                                  sg_profile_t **profile_out);

/*
 * Delete a profile
 */
sg_error_t sg_profile_store_delete(sg_profile_store_t *store,
                                    const char *profile_id);

/*
 * List profiles for a binary
 */
sg_error_t sg_profile_store_list(sg_profile_store_t *store,
                                  const char *binary_path,
                                  char ***profile_ids_out,
                                  size_t *count_out);

/*
 * Check if profile exists
 */
bool sg_profile_store_exists(sg_profile_store_t *store, const char *profile_id);

/* Profile serialization */

/*
 * Serialize profile to JSON
 */
char *sg_profile_to_json(const sg_profile_t *profile);

/*
 * Parse profile from JSON
 */
sg_error_t sg_profile_from_json(const char *json, sg_profile_t **profile_out);

/*
 * Serialize comparison result to JSON
 */
char *sg_comparison_to_json(const sg_comparison_t *result);

/* Pattern detection */

/*
 * Extract common syscall patterns from a trace
 */
sg_error_t sg_extract_patterns(const sg_trace_t *trace,
                                sg_pattern_t **patterns_out,
                                size_t *count_out,
                                size_t min_length,
                                size_t max_length,
                                size_t min_occurrences);

/*
 * Check if a pattern exists in a trace
 */
bool sg_pattern_exists(const sg_trace_t *trace, const sg_pattern_t *pattern);

/*
 * Find suspicious patterns (known malicious sequences)
 */
sg_error_t sg_find_suspicious_patterns(const sg_trace_t *trace,
                                        sg_pattern_t **patterns_out,
                                        size_t *count_out);

/* Statistical analysis */

/*
 * Calculate syscall frequency distribution
 */
sg_error_t sg_calc_syscall_stats(const sg_trace_t *trace,
                                  sg_syscall_stats_t **stats_out,
                                  size_t *count_out);

/*
 * Calculate entropy of syscall distribution
 */
double sg_calc_syscall_entropy(const sg_syscall_stats_t *stats, size_t count);

/*
 * Compare two frequency distributions (KL divergence)
 */
double sg_compare_distributions(const sg_syscall_stats_t *baseline,
                                 size_t baseline_count,
                                 const sg_syscall_stats_t *observed,
                                 size_t observed_count);

#endif /* AURIS_PROFILER_H */
