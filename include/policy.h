/*
 * Auris - Security Policy Engine
 * Policy generation, storage, and enforcement
 */

#ifndef AURIS_POLICY_H
#define AURIS_POLICY_H

#include "auris.h"
#include "profiler.h"

/* Policy storage context */
typedef struct {
    char base_dir[MAX_PATH_LEN];
    bool initialized;
} sg_policy_store_t;

/*
 * Initialize policy storage
 */
sg_error_t sg_policy_store_init(sg_policy_store_t *store, const char *base_dir);

/*
 * Clean up policy storage
 */
void sg_policy_store_cleanup(sg_policy_store_t *store);

/*
 * Allocate a new policy
 */
sg_policy_t *sg_policy_alloc(void);

/*
 * Free a policy
 */
void sg_policy_free(sg_policy_t *policy);

/*
 * Generate a policy from a behavioral profile
 * Creates restrictive policy allowing only observed syscalls
 */
sg_error_t sg_policy_generate(const sg_profile_t *profile,
                               sg_policy_t **policy_out);

/*
 * Generate a minimal policy with only essential syscalls
 */
sg_error_t sg_policy_generate_minimal(sg_policy_t **policy_out);

/*
 * Add essential syscalls to a policy
 * These are syscalls required for basic process operation
 */
sg_error_t sg_policy_add_essential(sg_policy_t *policy);

/*
 * Add a rule to a policy
 */
sg_error_t sg_policy_add_rule(sg_policy_t *policy,
                               uint32_t syscall_nr,
                               sg_policy_action_t action,
                               const char *path_pattern,
                               const char *reason);

/*
 * Remove a rule from a policy
 */
sg_error_t sg_policy_remove_rule(sg_policy_t *policy, uint32_t syscall_nr);

/*
 * Update a rule's action
 */
sg_error_t sg_policy_update_rule(sg_policy_t *policy,
                                  uint32_t syscall_nr,
                                  sg_policy_action_t new_action);

/*
 * Check if a syscall is allowed by the policy
 */
sg_policy_action_t sg_policy_check(const sg_policy_t *policy,
                                    uint32_t syscall_nr,
                                    const char *path);

/*
 * Get the rule for a specific syscall
 */
const sg_policy_rule_t *sg_policy_get_rule(const sg_policy_t *policy,
                                            uint32_t syscall_nr);

/*
 * Merge two policies (union of allowed syscalls)
 */
sg_error_t sg_policy_merge(const sg_policy_t *a,
                            const sg_policy_t *b,
                            sg_policy_t **merged_out);

/*
 * Diff two policies (find differences)
 */
sg_error_t sg_policy_diff(const sg_policy_t *a,
                           const sg_policy_t *b,
                           sg_policy_t **diff_out);

/* Auto-tuning */

/*
 * Record a policy violation for auto-tuning
 */
sg_error_t sg_policy_record_violation(sg_policy_t *policy,
                                       uint32_t syscall_nr,
                                       const char *path);

/*
 * Mark a violation as benign (update policy to allow)
 */
sg_error_t sg_policy_mark_benign(sg_policy_t *policy,
                                  uint32_t syscall_nr,
                                  const char *path);

/*
 * Get list of recorded violations
 */
sg_error_t sg_policy_get_violations(const sg_policy_t *policy,
                                     sg_policy_rule_t **violations_out,
                                     size_t *count_out);

/*
 * Apply auto-tuning based on recorded violations
 * Adds frequently violated syscalls to allow list
 */
sg_error_t sg_policy_auto_tune(sg_policy_t *policy,
                                size_t min_occurrences);

/* Policy persistence */

/*
 * Save policy to disk
 */
sg_error_t sg_policy_store_save(sg_policy_store_t *store,
                                 sg_policy_t *policy,
                                 const char *policy_id);

/*
 * Load policy from disk
 */
sg_error_t sg_policy_store_load(sg_policy_store_t *store,
                                 const char *policy_id,
                                 sg_policy_t **policy_out);

/*
 * Delete a policy
 */
sg_error_t sg_policy_store_delete(sg_policy_store_t *store,
                                   const char *policy_id);

/*
 * List all policies
 */
sg_error_t sg_policy_store_list(sg_policy_store_t *store,
                                 char ***policy_ids_out,
                                 size_t *count_out);

/*
 * Check if policy exists
 */
bool sg_policy_store_exists(sg_policy_store_t *store, const char *policy_id);

/* Policy serialization */

/*
 * Serialize policy to JSON
 */
char *sg_policy_to_json(const sg_policy_t *policy);

/*
 * Parse policy from JSON
 */
sg_error_t sg_policy_from_json(const char *json, sg_policy_t **policy_out);

/*
 * Export policy as human-readable text
 */
char *sg_policy_to_text(const sg_policy_t *policy);

/* Policy validation */

/*
 * Validate policy structure
 */
sg_error_t sg_policy_validate(const sg_policy_t *policy);

/*
 * Check policy for common issues
 */
typedef struct {
    bool has_essential_syscalls;
    bool allows_exit;
    bool allows_memory;
    size_t total_rules;
    size_t allow_rules;
    size_t block_rules;
    char warnings[10][256];
    size_t warning_count;
} sg_policy_check_result_t;

sg_error_t sg_policy_check_sanity(const sg_policy_t *policy,
                                   sg_policy_check_result_t *result);

#endif /* AURIS_POLICY_H */
