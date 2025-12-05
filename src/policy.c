/*
 * Auris - Security Policy Engine
 * Policy generation, storage, and validation
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <dirent.h>
#include <json-c/json.h>

#include "auris.h"
#include "policy.h"
#include "syscall_table.h"

/* Policy storage subdirectory */
#define POLICIES_SUBDIR "policies"

/*
 * Initialize policy storage
 */
sg_error_t sg_policy_store_init(sg_policy_store_t *store, const char *base_dir)
{
    if (store == NULL || base_dir == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(store, 0, sizeof(*store));
    sg_safe_strncpy(store->base_dir, base_dir, sizeof(store->base_dir));
    
    char policies_dir[MAX_PATH_LEN];
    snprintf(policies_dir, sizeof(policies_dir), "%s/%s", base_dir, POLICIES_SUBDIR);
    
    sg_error_t err = sg_mkdir_p(policies_dir, 0755);
    if (err != SG_OK) {
        return err;
    }
    
    store->initialized = true;
    return SG_OK;
}

/*
 * Clean up policy storage
 */
void sg_policy_store_cleanup(sg_policy_store_t *store)
{
    if (store != NULL) {
        store->initialized = false;
    }
}

/*
 * Allocate a new policy
 */
sg_policy_t *sg_policy_alloc(void)
{
    sg_policy_t *policy = calloc(1, sizeof(sg_policy_t));
    if (policy == NULL) {
        return NULL;
    }
    
    policy->rules = calloc(MAX_POLICY_RULES, sizeof(sg_policy_rule_t));
    if (policy->rules == NULL) {
        free(policy);
        return NULL;
    }
    
    sg_generate_id(policy->policy_id, sizeof(policy->policy_id));
    policy->created = sg_now();
    policy->updated = policy->created;
    policy->default_mode = ENFORCE_MODE_ALERT;
    policy->allow_unknown = false;
    
    return policy;
}

/*
 * Free a policy
 */
void sg_policy_free(sg_policy_t *policy)
{
    if (policy == NULL) {
        return;
    }
    
    if (policy->rules != NULL) {
        free(policy->rules);
    }
    free(policy);
}

/*
 * Add essential syscalls to policy
 */
sg_error_t sg_policy_add_essential(sg_policy_t *policy)
{
    if (policy == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    uint32_t essential[64];
    size_t count = sg_syscall_get_essential(essential, 64);
    
    for (size_t i = 0; i < count; i++) {
        sg_policy_add_rule(policy, essential[i], POLICY_ACTION_ALLOW,
                           NULL, "Essential syscall");
    }
    
    return SG_OK;
}

/*
 * Add a rule to policy
 */
sg_error_t sg_policy_add_rule(sg_policy_t *policy,
                               uint32_t syscall_nr,
                               sg_policy_action_t action,
                               const char *path_pattern,
                               const char *reason)
{
    if (policy == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Check if rule already exists */
    for (size_t i = 0; i < policy->rule_count; i++) {
        if (policy->rules[i].syscall_nr == syscall_nr) {
            /* Update existing rule */
            policy->rules[i].action = action;
            policy->rules[i].enabled = true;
            if (path_pattern != NULL) {
                sg_safe_strncpy(policy->rules[i].path_pattern, path_pattern,
                                sizeof(policy->rules[i].path_pattern));
            }
            if (reason != NULL) {
                sg_safe_strncpy(policy->rules[i].reason, reason,
                                sizeof(policy->rules[i].reason));
            }
            policy->updated = sg_now();
            return SG_OK;
        }
    }
    
    /* Add new rule */
    if (policy->rule_count >= MAX_POLICY_RULES) {
        return SG_ERR_LIMIT;
    }
    
    sg_policy_rule_t *rule = &policy->rules[policy->rule_count];
    memset(rule, 0, sizeof(*rule));
    
    rule->syscall_nr = syscall_nr;
    sg_safe_strncpy(rule->syscall_name, sg_syscall_name(syscall_nr),
                    sizeof(rule->syscall_name));
    rule->action = action;
    rule->enabled = true;
    
    if (path_pattern != NULL) {
        sg_safe_strncpy(rule->path_pattern, path_pattern, sizeof(rule->path_pattern));
    }
    if (reason != NULL) {
        sg_safe_strncpy(rule->reason, reason, sizeof(rule->reason));
    }
    
    policy->rule_count++;
    policy->updated = sg_now();
    
    return SG_OK;
}

/*
 * Remove a rule
 */
sg_error_t sg_policy_remove_rule(sg_policy_t *policy, uint32_t syscall_nr)
{
    if (policy == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    for (size_t i = 0; i < policy->rule_count; i++) {
        if (policy->rules[i].syscall_nr == syscall_nr) {
            /* Move last rule to this position */
            if (i < policy->rule_count - 1) {
                policy->rules[i] = policy->rules[policy->rule_count - 1];
            }
            policy->rule_count--;
            policy->updated = sg_now();
            return SG_OK;
        }
    }
    
    return SG_ERR_NOT_FOUND;
}

/*
 * Update rule action
 */
sg_error_t sg_policy_update_rule(sg_policy_t *policy,
                                  uint32_t syscall_nr,
                                  sg_policy_action_t new_action)
{
    if (policy == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    for (size_t i = 0; i < policy->rule_count; i++) {
        if (policy->rules[i].syscall_nr == syscall_nr) {
            policy->rules[i].action = new_action;
            policy->updated = sg_now();
            return SG_OK;
        }
    }
    
    return SG_ERR_NOT_FOUND;
}

/*
 * Check syscall against policy
 */
sg_policy_action_t sg_policy_check(const sg_policy_t *policy,
                                    uint32_t syscall_nr,
                                    const char *path)
{
    if (policy == NULL) {
        return POLICY_ACTION_ALLOW;
    }
    
    /* Find matching rule */
    for (size_t i = 0; i < policy->rule_count; i++) {
        if (!policy->rules[i].enabled) {
            continue;
        }
        
        if (policy->rules[i].syscall_nr == syscall_nr) {
            /* Check path pattern if specified */
            if (policy->rules[i].path_pattern[0] != '\0' && path != NULL) {
                if (fnmatch(policy->rules[i].path_pattern, path, 0) != 0) {
                    continue;  /* Path doesn't match, try next rule */
                }
            }
            
            return policy->rules[i].action;
        }
    }
    
    /* No matching rule - use default behavior */
    if (policy->allow_unknown) {
        return POLICY_ACTION_ALLOW;
    }
    
    /* Default to alert for unknown syscalls */
    return POLICY_ACTION_ALERT;
}

/*
 * Get rule for syscall
 */
const sg_policy_rule_t *sg_policy_get_rule(const sg_policy_t *policy,
                                            uint32_t syscall_nr)
{
    if (policy == NULL) {
        return NULL;
    }
    
    for (size_t i = 0; i < policy->rule_count; i++) {
        if (policy->rules[i].syscall_nr == syscall_nr) {
            return &policy->rules[i];
        }
    }
    
    return NULL;
}

/*
 * Generate policy from profile
 */
sg_error_t sg_policy_generate(const sg_profile_t *profile,
                               sg_policy_t **policy_out)
{
    if (profile == NULL || policy_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_policy_t *policy = sg_policy_alloc();
    if (policy == NULL) {
        return SG_ERR_NOMEM;
    }
    
    sg_safe_strncpy(policy->profile_id, profile->profile_id,
                    sizeof(policy->profile_id));
    sg_safe_strncpy(policy->binary_path, profile->binary_path,
                    sizeof(policy->binary_path));
    snprintf(policy->description, sizeof(policy->description),
             "Auto-generated policy from profile %s", profile->profile_id);
    
    /* Add essential syscalls first */
    sg_policy_add_essential(policy);
    
    /* Add all observed syscalls as allowed */
    for (size_t i = 0; i < profile->unique_count; i++) {
        uint32_t nr = profile->unique_syscalls[i];
        
        /* Check if already added (essential) */
        bool exists = false;
        for (size_t j = 0; j < policy->rule_count; j++) {
            if (policy->rules[j].syscall_nr == nr) {
                exists = true;
                break;
            }
        }
        
        if (!exists) {
            sg_policy_add_rule(policy, nr, POLICY_ACTION_ALLOW,
                               NULL, "Observed in baseline");
        }
    }
    
    /* Set default to alert unknown syscalls */
    policy->default_mode = ENFORCE_MODE_ALERT;
    policy->allow_unknown = false;
    
    *policy_out = policy;
    return SG_OK;
}

/*
 * Generate minimal policy
 */
sg_error_t sg_policy_generate_minimal(sg_policy_t **policy_out)
{
    if (policy_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_policy_t *policy = sg_policy_alloc();
    if (policy == NULL) {
        return SG_ERR_NOMEM;
    }
    
    snprintf(policy->description, sizeof(policy->description),
             "Minimal policy with essential syscalls only");
    
    sg_policy_add_essential(policy);
    
    policy->default_mode = ENFORCE_MODE_BLOCK;
    policy->allow_unknown = false;
    
    *policy_out = policy;
    return SG_OK;
}

/*
 * Mark violation as benign
 */
sg_error_t sg_policy_mark_benign(sg_policy_t *policy,
                                  uint32_t syscall_nr,
                                  const char *path)
{
    if (policy == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Add or update rule to allow */
    return sg_policy_add_rule(policy, syscall_nr, POLICY_ACTION_ALLOW,
                               path, "Marked benign by user");
}

/*
 * Validate policy
 */
sg_error_t sg_policy_validate(const sg_policy_t *policy)
{
    if (policy == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (policy->policy_id[0] == '\0') {
        return SG_ERR_POLICY;
    }
    
    /* Check for duplicate rules */
    for (size_t i = 0; i < policy->rule_count; i++) {
        for (size_t j = i + 1; j < policy->rule_count; j++) {
            if (policy->rules[i].syscall_nr == policy->rules[j].syscall_nr &&
                strcmp(policy->rules[i].path_pattern, policy->rules[j].path_pattern) == 0) {
                sg_log(SG_LOG_WARN, "Duplicate rule for syscall %s",
                       policy->rules[i].syscall_name);
            }
        }
    }
    
    return SG_OK;
}

/*
 * Check policy sanity
 */
sg_error_t sg_policy_check_sanity(const sg_policy_t *policy,
                                   sg_policy_check_result_t *result)
{
    if (policy == NULL || result == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(result, 0, sizeof(*result));
    
    result->total_rules = policy->rule_count;
    
    for (size_t i = 0; i < policy->rule_count; i++) {
        if (policy->rules[i].action == POLICY_ACTION_ALLOW) {
            result->allow_rules++;
        } else if (policy->rules[i].action == POLICY_ACTION_BLOCK) {
            result->block_rules++;
        }
        
        /* Check for essential syscalls */
        if (sg_syscall_is_essential(policy->rules[i].syscall_nr)) {
            result->has_essential_syscalls = true;
        }
        
        if (policy->rules[i].syscall_nr == SYS_exit ||
            policy->rules[i].syscall_nr == SYS_exit_group) {
            result->allows_exit = true;
        }
        
        if (policy->rules[i].syscall_nr == SYS_mmap ||
            policy->rules[i].syscall_nr == SYS_brk) {
            result->allows_memory = true;
        }
    }
    
    /* Generate warnings */
    if (!result->allows_exit) {
        snprintf(result->warnings[result->warning_count++], 256,
                 "Policy does not allow exit syscalls - process may hang");
    }
    
    if (!result->allows_memory) {
        snprintf(result->warnings[result->warning_count++], 256,
                 "Policy does not allow memory allocation - may cause crashes");
    }
    
    if (result->block_rules == 0 && !policy->allow_unknown) {
        snprintf(result->warnings[result->warning_count++], 256,
                 "Policy has no block rules but denies unknown syscalls");
    }
    
    return SG_OK;
}

/*
 * Export policy as text
 */
char *sg_policy_to_text(const sg_policy_t *policy)
{
    if (policy == NULL) {
        return NULL;
    }
    
    size_t buf_size = 4096 + policy->rule_count * 128;
    char *buf = malloc(buf_size);
    if (buf == NULL) {
        return NULL;
    }
    
    int pos = 0;
    pos += snprintf(buf + pos, buf_size - pos,
                    "Policy: %s\n"
                    "Binary: %s\n"
                    "Description: %s\n"
                    "Default mode: %s\n"
                    "Allow unknown: %s\n"
                    "Rules: %zu\n\n",
                    policy->policy_id,
                    policy->binary_path,
                    policy->description,
                    policy->default_mode == ENFORCE_MODE_BLOCK ? "block" : "alert",
                    policy->allow_unknown ? "yes" : "no",
                    policy->rule_count);
    
    const char *action_names[] = {"ALLOW", "LOG", "ALERT", "BLOCK"};
    
    for (size_t i = 0; i < policy->rule_count && (size_t)pos < buf_size - 128; i++) {
        const sg_policy_rule_t *rule = &policy->rules[i];
        pos += snprintf(buf + pos, buf_size - pos,
                        "  %s: %s",
                        action_names[rule->action % 4],
                        rule->syscall_name);
        
        if (rule->path_pattern[0] != '\0') {
            pos += snprintf(buf + pos, buf_size - pos, " [%s]", rule->path_pattern);
        }
        if (rule->reason[0] != '\0') {
            pos += snprintf(buf + pos, buf_size - pos, " (%s)", rule->reason);
        }
        pos += snprintf(buf + pos, buf_size - pos, "\n");
    }
    
    return buf;
}

/*
 * Save policy to disk
 */
sg_error_t sg_policy_store_save(sg_policy_store_t *store,
                                 sg_policy_t *policy,
                                 const char *policy_id)
{
    if (store == NULL || !store->initialized || policy == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (policy_id != NULL && policy_id[0] != '\0') {
        sg_safe_strncpy(policy->policy_id, policy_id, sizeof(policy->policy_id));
    }
    
    char *json = sg_policy_to_json(policy);
    if (json == NULL) {
        return SG_ERR_NOMEM;
    }
    
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s/%s.json",
             store->base_dir, POLICIES_SUBDIR, policy->policy_id);
    
    sg_error_t err = sg_write_file(path, json, strlen(json));
    free(json);
    
    return err;
}

/*
 * Load policy from disk
 */
sg_error_t sg_policy_store_load(sg_policy_store_t *store,
                                 const char *policy_id,
                                 sg_policy_t **policy_out)
{
    if (store == NULL || !store->initialized || policy_id == NULL || policy_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s/%s.json",
             store->base_dir, POLICIES_SUBDIR, policy_id);
    
    size_t len;
    char *json = sg_read_file(path, &len);
    if (json == NULL) {
        return SG_ERR_IO;
    }
    
    sg_error_t err = sg_policy_from_json(json, policy_out);
    free(json);
    
    return err;
}

/*
 * Parse policy from JSON
 */
sg_error_t sg_policy_from_json(const char *json, sg_policy_t **policy_out)
{
    if (json == NULL || policy_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    struct json_object *root = json_tokener_parse(json);
    if (root == NULL) {
        return SG_ERR_PARSE;
    }
    
    sg_policy_t *policy = sg_policy_alloc();
    if (policy == NULL) {
        json_object_put(root);
        return SG_ERR_NOMEM;
    }
    
    struct json_object *val;
    
    if (json_object_object_get_ex(root, "policy_id", &val)) {
        sg_safe_strncpy(policy->policy_id, json_object_get_string(val),
                        sizeof(policy->policy_id));
    }
    if (json_object_object_get_ex(root, "profile_id", &val)) {
        sg_safe_strncpy(policy->profile_id, json_object_get_string(val),
                        sizeof(policy->profile_id));
    }
    if (json_object_object_get_ex(root, "binary_path", &val)) {
        sg_safe_strncpy(policy->binary_path, json_object_get_string(val),
                        sizeof(policy->binary_path));
    }
    if (json_object_object_get_ex(root, "description", &val)) {
        sg_safe_strncpy(policy->description, json_object_get_string(val),
                        sizeof(policy->description));
    }
    if (json_object_object_get_ex(root, "default_mode", &val)) {
        policy->default_mode = json_object_get_int(val);
    }
    if (json_object_object_get_ex(root, "allow_unknown", &val)) {
        policy->allow_unknown = json_object_get_boolean(val);
    }
    
    /* Parse rules */
    struct json_object *rules;
    if (json_object_object_get_ex(root, "rules", &rules)) {
        size_t rule_count = json_object_array_length(rules);
        
        for (size_t i = 0; i < rule_count && policy->rule_count < MAX_POLICY_RULES; i++) {
            struct json_object *rule_obj = json_object_array_get_idx(rules, i);
            sg_policy_rule_t *rule = &policy->rules[policy->rule_count];
            
            if (json_object_object_get_ex(rule_obj, "syscall_nr", &val)) {
                rule->syscall_nr = json_object_get_int(val);
            }
            if (json_object_object_get_ex(rule_obj, "syscall_name", &val)) {
                sg_safe_strncpy(rule->syscall_name, json_object_get_string(val),
                                sizeof(rule->syscall_name));
            }
            if (json_object_object_get_ex(rule_obj, "action", &val)) {
                rule->action = json_object_get_int(val);
            }
            if (json_object_object_get_ex(rule_obj, "enabled", &val)) {
                rule->enabled = json_object_get_boolean(val);
            } else {
                rule->enabled = true;
            }
            if (json_object_object_get_ex(rule_obj, "path_pattern", &val)) {
                sg_safe_strncpy(rule->path_pattern, json_object_get_string(val),
                                sizeof(rule->path_pattern));
            }
            if (json_object_object_get_ex(rule_obj, "reason", &val)) {
                sg_safe_strncpy(rule->reason, json_object_get_string(val),
                                sizeof(rule->reason));
            }
            
            policy->rule_count++;
        }
    }
    
    json_object_put(root);
    
    *policy_out = policy;
    return SG_OK;
}

/*
 * Check if policy exists
 */
bool sg_policy_store_exists(sg_policy_store_t *store, const char *policy_id)
{
    if (store == NULL || !store->initialized || policy_id == NULL) {
        return false;
    }
    
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s/%s.json",
             store->base_dir, POLICIES_SUBDIR, policy_id);
    
    return sg_path_exists(path);
}
