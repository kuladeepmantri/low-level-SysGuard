/*
 * Auris - Behavioral Profiler
 * Build and compare behavioral profiles from syscall traces
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <dirent.h>
#include <json-c/json.h>

#include "auris.h"
#include "profiler.h"
#include "syscall_table.h"
#include "dataflow.h"

/* Profile storage subdirectory */
#define PROFILES_SUBDIR "profiles"

/* Thresholds for anomaly detection */
#define FREQ_SPIKE_THRESHOLD 3.0    /* 3x baseline frequency */
#define FREQ_DROP_THRESHOLD 0.1     /* 10% of baseline */
#define NEW_SYSCALL_SEVERITY 0.7
#define FREQ_ANOMALY_SEVERITY 0.5
#define SENSITIVE_ACCESS_SEVERITY 0.8

/*
 * Initialize profile storage
 */
sg_error_t sg_profile_store_init(sg_profile_store_t *store, const char *base_dir)
{
    if (store == NULL || base_dir == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(store, 0, sizeof(*store));
    sg_safe_strncpy(store->base_dir, base_dir, sizeof(store->base_dir));
    
    char profiles_dir[MAX_PATH_LEN];
    snprintf(profiles_dir, sizeof(profiles_dir), "%s/%s", base_dir, PROFILES_SUBDIR);
    
    sg_error_t err = sg_mkdir_p(profiles_dir, 0755);
    if (err != SG_OK) {
        return err;
    }
    
    store->initialized = true;
    return SG_OK;
}

/*
 * Clean up profile storage
 */
void sg_profile_store_cleanup(sg_profile_store_t *store)
{
    if (store != NULL) {
        store->initialized = false;
    }
}

/*
 * Allocate a new profile
 */
sg_profile_t *sg_profile_alloc(void)
{
    sg_profile_t *profile = calloc(1, sizeof(sg_profile_t));
    return profile;
}

/*
 * Free a profile
 */
void sg_profile_free(sg_profile_t *profile)
{
    if (profile == NULL) {
        return;
    }
    
    if (profile->syscall_stats != NULL) {
        free(profile->syscall_stats);
    }
    if (profile->unique_syscalls != NULL) {
        free(profile->unique_syscalls);
    }
    if (profile->patterns != NULL) {
        free(profile->patterns);
    }
    if (profile->accessed_files != NULL) {
        for (size_t i = 0; i < profile->file_count; i++) {
            free(profile->accessed_files[i]);
        }
        free(profile->accessed_files);
    }
    if (profile->network_endpoints != NULL) {
        free(profile->network_endpoints);
    }
    if (profile->baseline_trace_ids != NULL) {
        for (size_t i = 0; i < profile->baseline_count; i++) {
            free(profile->baseline_trace_ids[i]);
        }
        free(profile->baseline_trace_ids);
    }
    
    free(profile);
}

/*
 * Calculate syscall statistics from a trace
 */
sg_error_t sg_calc_syscall_stats(const sg_trace_t *trace,
                                  sg_syscall_stats_t **stats_out,
                                  size_t *count_out)
{
    if (trace == NULL || stats_out == NULL || count_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Count occurrences of each syscall */
    uint64_t counts[MAX_SYSCALL_NR] = {0};
    uint64_t durations[MAX_SYSCALL_NR] = {0};
    uint64_t min_dur[MAX_SYSCALL_NR];
    uint64_t max_dur[MAX_SYSCALL_NR];
    
    for (int i = 0; i < MAX_SYSCALL_NR; i++) {
        min_dur[i] = UINT64_MAX;
        max_dur[i] = 0;
    }
    
    for (size_t i = 0; i < trace->event_count; i++) {
        uint32_t nr = trace->events[i].syscall_nr;
        if (nr < MAX_SYSCALL_NR) {
            counts[nr]++;
            durations[nr] += trace->events[i].duration_ns;
            if (trace->events[i].duration_ns < min_dur[nr]) {
                min_dur[nr] = trace->events[i].duration_ns;
            }
            if (trace->events[i].duration_ns > max_dur[nr]) {
                max_dur[nr] = trace->events[i].duration_ns;
            }
        }
    }
    
    /* Count unique syscalls */
    size_t unique_count = 0;
    for (int i = 0; i < MAX_SYSCALL_NR; i++) {
        if (counts[i] > 0) {
            unique_count++;
        }
    }
    
    if (unique_count == 0) {
        *stats_out = NULL;
        *count_out = 0;
        return SG_OK;
    }
    
    /* Allocate stats array */
    sg_syscall_stats_t *stats = calloc(unique_count, sizeof(sg_syscall_stats_t));
    if (stats == NULL) {
        return SG_ERR_NOMEM;
    }
    
    /* Fill stats */
    size_t idx = 0;
    for (uint32_t i = 0; i < MAX_SYSCALL_NR && idx < unique_count; i++) {
        if (counts[i] > 0) {
            stats[idx].syscall_nr = i;
            sg_safe_strncpy(stats[idx].name, sg_syscall_name(i), sizeof(stats[idx].name));
            stats[idx].count = counts[i];
            stats[idx].frequency = (double)counts[i] / (double)trace->event_count;
            stats[idx].total_duration_ns = durations[i];
            stats[idx].min_duration_ns = min_dur[i];
            stats[idx].max_duration_ns = max_dur[i];
            stats[idx].avg_duration_ns = (double)durations[i] / (double)counts[i];
            idx++;
        }
    }
    
    *stats_out = stats;
    *count_out = unique_count;
    
    return SG_OK;
}

/*
 * Build a profile from a single trace
 */
sg_error_t sg_profile_build_from_trace(const sg_trace_t *trace,
                                        sg_profile_t **profile_out)
{
    if (trace == NULL || profile_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_profile_t *profile = sg_profile_alloc();
    if (profile == NULL) {
        return SG_ERR_NOMEM;
    }
    
    sg_error_t err;
    
    /* Generate profile ID */
    sg_generate_id(profile->profile_id, sizeof(profile->profile_id));
    
    /* Copy binary info */
    sg_safe_strncpy(profile->binary_path, trace->meta.binary_path,
                    sizeof(profile->binary_path));
    sg_safe_strncpy(profile->binary_hash, trace->meta.binary_hash,
                    sizeof(profile->binary_hash));
    
    profile->total_syscalls = trace->event_count;
    profile->created = sg_now();
    profile->updated = profile->created;
    
    /* Calculate syscall statistics */
    err = sg_calc_syscall_stats(trace, &profile->syscall_stats, &profile->syscall_count);
    if (err != SG_OK) {
        sg_profile_free(profile);
        return err;
    }
    
    /* Extract unique syscalls */
    profile->unique_syscalls = calloc(profile->syscall_count, sizeof(uint32_t));
    if (profile->unique_syscalls == NULL) {
        sg_profile_free(profile);
        return SG_ERR_NOMEM;
    }
    
    for (size_t i = 0; i < profile->syscall_count; i++) {
        profile->unique_syscalls[i] = profile->syscall_stats[i].syscall_nr;
    }
    profile->unique_count = profile->syscall_count;
    
    /* Analyze behavioral flags */
    for (size_t i = 0; i < trace->event_count; i++) {
        uint32_t nr = trace->events[i].syscall_nr;
        
        if (sg_syscall_is_category(nr, SYSCALL_CAT_NETWORK)) {
            profile->does_network_io = true;
        }
        if (sg_syscall_is_category(nr, SYSCALL_CAT_FILE)) {
            profile->does_file_io = true;
        }
        if (nr == SYS_clone || nr == SYS_clone3) {
            profile->spawns_children = true;
        }
        if (nr == SYS_setuid || nr == SYS_setgid || nr == SYS_setreuid ||
            nr == SYS_setregid || nr == SYS_setresuid || nr == SYS_setresgid) {
            profile->changes_privileges = true;
        }
        
        /* Check for sensitive file access */
        for (int j = 0; j < MAX_SYSCALL_ARGS; j++) {
            if (trace->events[i].args[j].type == ARG_TYPE_PATH &&
                trace->events[i].args[j].valid) {
                if (sg_is_sensitive_path(trace->events[i].args[j].value.str)) {
                    profile->accesses_sensitive_files = true;
                }
            }
        }
    }
    
    /* Store baseline trace ID */
    profile->baseline_trace_ids = calloc(1, sizeof(char *));
    if (profile->baseline_trace_ids != NULL) {
        profile->baseline_trace_ids[0] = strdup(trace->meta.trace_id);
        profile->baseline_count = 1;
    }
    
    *profile_out = profile;
    return SG_OK;
}

/*
 * Build baseline from multiple traces
 */
sg_error_t sg_profile_build_baseline(const sg_trace_t **traces,
                                      size_t trace_count,
                                      sg_profile_t **profile_out)
{
    if (traces == NULL || trace_count == 0 || profile_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Start with first trace */
    sg_profile_t *profile;
    sg_error_t err = sg_profile_build_from_trace(traces[0], &profile);
    if (err != SG_OK) {
        return err;
    }
    
    /* Merge additional traces */
    for (size_t i = 1; i < trace_count; i++) {
        err = sg_profile_update(profile, traces[i]);
        if (err != SG_OK) {
            sg_profile_free(profile);
            return err;
        }
    }
    
    *profile_out = profile;
    return SG_OK;
}

/*
 * Update profile with new trace
 */
sg_error_t sg_profile_update(sg_profile_t *profile, const sg_trace_t *trace)
{
    if (profile == NULL || trace == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Calculate stats for new trace */
    sg_syscall_stats_t *new_stats;
    size_t new_count;
    sg_error_t err = sg_calc_syscall_stats(trace, &new_stats, &new_count);
    if (err != SG_OK) {
        return err;
    }
    
    /* Merge statistics */
    uint64_t total_events = profile->total_syscalls + trace->event_count;
    
    for (size_t i = 0; i < new_count; i++) {
        bool found = false;
        for (size_t j = 0; j < profile->syscall_count; j++) {
            if (profile->syscall_stats[j].syscall_nr == new_stats[i].syscall_nr) {
                /* Update existing entry */
                profile->syscall_stats[j].count += new_stats[i].count;
                profile->syscall_stats[j].total_duration_ns += new_stats[i].total_duration_ns;
                if (new_stats[i].min_duration_ns < profile->syscall_stats[j].min_duration_ns) {
                    profile->syscall_stats[j].min_duration_ns = new_stats[i].min_duration_ns;
                }
                if (new_stats[i].max_duration_ns > profile->syscall_stats[j].max_duration_ns) {
                    profile->syscall_stats[j].max_duration_ns = new_stats[i].max_duration_ns;
                }
                found = true;
                break;
            }
        }
        
        if (!found) {
            /* Add new syscall */
            sg_syscall_stats_t *expanded = realloc(profile->syscall_stats,
                                                    (profile->syscall_count + 1) * sizeof(sg_syscall_stats_t));
            if (expanded == NULL) {
                free(new_stats);
                return SG_ERR_NOMEM;
            }
            profile->syscall_stats = expanded;
            profile->syscall_stats[profile->syscall_count] = new_stats[i];
            profile->syscall_count++;
            
            /* Update unique syscalls */
            uint32_t *expanded_unique = realloc(profile->unique_syscalls,
                                                 (profile->unique_count + 1) * sizeof(uint32_t));
            if (expanded_unique != NULL) {
                profile->unique_syscalls = expanded_unique;
                profile->unique_syscalls[profile->unique_count] = new_stats[i].syscall_nr;
                profile->unique_count++;
            }
        }
    }
    
    /* Recalculate frequencies */
    for (size_t i = 0; i < profile->syscall_count; i++) {
        profile->syscall_stats[i].frequency = 
            (double)profile->syscall_stats[i].count / (double)total_events;
        profile->syscall_stats[i].avg_duration_ns = 
            (double)profile->syscall_stats[i].total_duration_ns / 
            (double)profile->syscall_stats[i].count;
    }
    
    profile->total_syscalls = total_events;
    profile->updated = sg_now();
    
    /* Add trace ID to baseline list */
    char **expanded_ids = realloc(profile->baseline_trace_ids,
                                   (profile->baseline_count + 1) * sizeof(char *));
    if (expanded_ids != NULL) {
        profile->baseline_trace_ids = expanded_ids;
        profile->baseline_trace_ids[profile->baseline_count] = strdup(trace->meta.trace_id);
        profile->baseline_count++;
    }
    
    free(new_stats);
    
    return SG_OK;
}

/*
 * Compare trace against baseline
 */
sg_error_t sg_profile_compare(const sg_profile_t *baseline,
                               const sg_trace_t *trace,
                               sg_comparison_t **result_out)
{
    if (baseline == NULL || trace == NULL || result_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_comparison_t *result = calloc(1, sizeof(sg_comparison_t));
    if (result == NULL) {
        return SG_ERR_NOMEM;
    }
    
    sg_safe_strncpy(result->trace_id, trace->meta.trace_id, sizeof(result->trace_id));
    sg_safe_strncpy(result->profile_id, baseline->profile_id, sizeof(result->profile_id));
    
    /* Allocate anomaly array */
    result->anomalies = calloc(MAX_ANOMALIES, sizeof(sg_anomaly_t));
    if (result->anomalies == NULL) {
        free(result);
        return SG_ERR_NOMEM;
    }
    
    /* Calculate stats for trace */
    sg_syscall_stats_t *trace_stats;
    size_t trace_stat_count;
    sg_error_t err = sg_calc_syscall_stats(trace, &trace_stats, &trace_stat_count);
    if (err != SG_OK) {
        free(result->anomalies);
        free(result);
        return err;
    }
    
    double total_deviation = 0.0;
    int deviation_count = 0;
    
    /* Check for new syscalls and frequency changes */
    for (size_t i = 0; i < trace_stat_count; i++) {
        bool found = false;
        double baseline_freq = 0.0;
        
        for (size_t j = 0; j < baseline->syscall_count; j++) {
            if (baseline->syscall_stats[j].syscall_nr == trace_stats[i].syscall_nr) {
                found = true;
                baseline_freq = baseline->syscall_stats[j].frequency;
                break;
            }
        }
        
        if (!found && result->anomaly_count < MAX_ANOMALIES) {
            /* New syscall not in baseline */
            sg_anomaly_t *a = &result->anomalies[result->anomaly_count++];
            a->type = ANOMALY_NEW_SYSCALL;
            a->syscall_nr = trace_stats[i].syscall_nr;
            a->severity = NEW_SYSCALL_SEVERITY;
            a->observed_value = trace_stats[i].frequency;
            a->baseline_value = 0.0;
            snprintf(a->description, sizeof(a->description),
                     "New syscall '%s' not seen in baseline",
                     trace_stats[i].name);
            
            total_deviation += a->severity;
            deviation_count++;
        } else if (found && baseline_freq > 0) {
            double ratio = trace_stats[i].frequency / baseline_freq;
            
            if (ratio > FREQ_SPIKE_THRESHOLD && result->anomaly_count < MAX_ANOMALIES) {
                sg_anomaly_t *a = &result->anomalies[result->anomaly_count++];
                a->type = ANOMALY_FREQ_SPIKE;
                a->syscall_nr = trace_stats[i].syscall_nr;
                a->severity = FREQ_ANOMALY_SEVERITY * (ratio / FREQ_SPIKE_THRESHOLD);
                if (a->severity > 1.0) a->severity = 1.0;
                a->observed_value = trace_stats[i].frequency;
                a->baseline_value = baseline_freq;
                snprintf(a->description, sizeof(a->description),
                         "Syscall '%s' frequency %.1fx higher than baseline",
                         trace_stats[i].name, ratio);
                
                total_deviation += a->severity;
                deviation_count++;
            } else if (ratio < FREQ_DROP_THRESHOLD && result->anomaly_count < MAX_ANOMALIES) {
                sg_anomaly_t *a = &result->anomalies[result->anomaly_count++];
                a->type = ANOMALY_FREQ_DROP;
                a->syscall_nr = trace_stats[i].syscall_nr;
                a->severity = FREQ_ANOMALY_SEVERITY * 0.5;
                a->observed_value = trace_stats[i].frequency;
                a->baseline_value = baseline_freq;
                snprintf(a->description, sizeof(a->description),
                         "Syscall '%s' frequency significantly lower than baseline",
                         trace_stats[i].name);
                
                total_deviation += a->severity;
                deviation_count++;
            }
        }
    }
    
    /* Check for sensitive file access */
    for (size_t i = 0; i < trace->event_count && result->anomaly_count < MAX_ANOMALIES; i++) {
        for (int j = 0; j < MAX_SYSCALL_ARGS; j++) {
            if (trace->events[i].args[j].type == ARG_TYPE_PATH &&
                trace->events[i].args[j].valid) {
                sg_sensitivity_t sens = sg_path_sensitivity(trace->events[i].args[j].value.str);
                if (sens >= SENSITIVITY_HIGH) {
                    sg_anomaly_t *a = &result->anomalies[result->anomaly_count++];
                    a->type = ANOMALY_SENSITIVE_ACCESS;
                    a->syscall_nr = trace->events[i].syscall_nr;
                    a->severity = SENSITIVE_ACCESS_SEVERITY;
                    a->event_id = trace->events[i].id;
                    sg_safe_strncpy(a->related_path, trace->events[i].args[j].value.str,
                                    sizeof(a->related_path));
                    snprintf(a->description, sizeof(a->description),
                             "Access to sensitive file: %s",
                             trace->events[i].args[j].value.str);
                    
                    total_deviation += a->severity;
                    deviation_count++;
                    break;
                }
            }
        }
    }
    
    free(trace_stats);
    
    /* Calculate overall scores */
    if (deviation_count > 0) {
        result->overall_deviation = total_deviation / deviation_count;
    }
    result->risk_score = sg_profile_risk_score(result);
    result->is_anomalous = result->anomaly_count > 0;
    
    *result_out = result;
    return SG_OK;
}

/*
 * Free comparison result
 */
void sg_comparison_free(sg_comparison_t *result)
{
    if (result == NULL) {
        return;
    }
    
    if (result->anomalies != NULL) {
        free(result->anomalies);
    }
    free(result);
}

/*
 * Calculate deviation score
 */
double sg_profile_deviation_score(const sg_comparison_t *result)
{
    if (result == NULL) {
        return 0.0;
    }
    return result->overall_deviation;
}

/*
 * Calculate risk score
 */
double sg_profile_risk_score(const sg_comparison_t *result)
{
    if (result == NULL || result->anomaly_count == 0) {
        return 0.0;
    }
    
    double max_severity = 0.0;
    double total_severity = 0.0;
    
    for (size_t i = 0; i < result->anomaly_count; i++) {
        total_severity += result->anomalies[i].severity;
        if (result->anomalies[i].severity > max_severity) {
            max_severity = result->anomalies[i].severity;
        }
    }
    
    /* Weighted combination of max and average severity */
    double avg_severity = total_severity / result->anomaly_count;
    return 0.6 * max_severity + 0.4 * avg_severity;
}

/*
 * Calculate entropy of syscall distribution
 */
double sg_calc_syscall_entropy(const sg_syscall_stats_t *stats, size_t count)
{
    if (stats == NULL || count == 0) {
        return 0.0;
    }
    
    double entropy = 0.0;
    for (size_t i = 0; i < count; i++) {
        if (stats[i].frequency > 0.0) {
            entropy -= stats[i].frequency * log2(stats[i].frequency);
        }
    }
    
    return entropy;
}

/*
 * Compare distributions using KL divergence
 */
double sg_compare_distributions(const sg_syscall_stats_t *baseline,
                                 size_t baseline_count,
                                 const sg_syscall_stats_t *observed,
                                 size_t observed_count)
{
    if (baseline == NULL || observed == NULL) {
        return 0.0;
    }
    
    double kl_div = 0.0;
    
    for (size_t i = 0; i < observed_count; i++) {
        double p = observed[i].frequency;
        double q = 0.0;
        
        /* Find matching baseline frequency */
        for (size_t j = 0; j < baseline_count; j++) {
            if (baseline[j].syscall_nr == observed[i].syscall_nr) {
                q = baseline[j].frequency;
                break;
            }
        }
        
        /* Add small epsilon to avoid log(0) */
        if (q < 1e-10) q = 1e-10;
        if (p > 0.0) {
            kl_div += p * log2(p / q);
        }
    }
    
    return kl_div;
}

/*
 * Save profile to disk
 */
sg_error_t sg_profile_store_save(sg_profile_store_t *store,
                                  sg_profile_t *profile,
                                  const char *profile_id)
{
    if (store == NULL || !store->initialized || profile == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (profile_id != NULL && profile_id[0] != '\0') {
        sg_safe_strncpy(profile->profile_id, profile_id, sizeof(profile->profile_id));
    } else if (profile->profile_id[0] == '\0') {
        sg_generate_id(profile->profile_id, sizeof(profile->profile_id));
    }
    
    char *json = sg_profile_to_json(profile);
    if (json == NULL) {
        return SG_ERR_NOMEM;
    }
    
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s/%s.json",
             store->base_dir, PROFILES_SUBDIR, profile->profile_id);
    
    sg_error_t err = sg_write_file(path, json, strlen(json));
    free(json);
    
    return err;
}

/*
 * Check if profile exists
 */
bool sg_profile_store_exists(sg_profile_store_t *store, const char *profile_id)
{
    if (store == NULL || !store->initialized || profile_id == NULL) {
        return false;
    }
    
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s/%s.json",
             store->base_dir, PROFILES_SUBDIR, profile_id);
    
    return sg_path_exists(path);
}

/*
 * Load profile from disk
 */
sg_error_t sg_profile_store_load(sg_profile_store_t *store,
                                  const char *profile_id,
                                  sg_profile_t **profile_out)
{
    if (store == NULL || !store->initialized || profile_id == NULL || profile_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s/%s.json",
             store->base_dir, PROFILES_SUBDIR, profile_id);
    
    size_t len;
    char *json = sg_read_file(path, &len);
    if (json == NULL) {
        return SG_ERR_IO;
    }
    
    sg_error_t err = sg_profile_from_json(json, profile_out);
    free(json);
    
    return err;
}

/*
 * Parse profile from JSON
 */
sg_error_t sg_profile_from_json(const char *json, sg_profile_t **profile_out)
{
    if (json == NULL || profile_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    struct json_object *root = json_tokener_parse(json);
    if (root == NULL) {
        return SG_ERR_PARSE;
    }
    
    sg_profile_t *profile = sg_profile_alloc();
    if (profile == NULL) {
        json_object_put(root);
        return SG_ERR_NOMEM;
    }
    
    struct json_object *val;
    
    if (json_object_object_get_ex(root, "profile_id", &val)) {
        sg_safe_strncpy(profile->profile_id, json_object_get_string(val),
                        sizeof(profile->profile_id));
    }
    if (json_object_object_get_ex(root, "binary_path", &val)) {
        sg_safe_strncpy(profile->binary_path, json_object_get_string(val),
                        sizeof(profile->binary_path));
    }
    if (json_object_object_get_ex(root, "binary_hash", &val)) {
        sg_safe_strncpy(profile->binary_hash, json_object_get_string(val),
                        sizeof(profile->binary_hash));
    }
    if (json_object_object_get_ex(root, "total_syscalls", &val)) {
        profile->total_syscalls = json_object_get_int64(val);
    }
    
    /* Parse behavior flags */
    struct json_object *behavior;
    if (json_object_object_get_ex(root, "behavior", &behavior)) {
        if (json_object_object_get_ex(behavior, "network_io", &val)) {
            profile->does_network_io = json_object_get_boolean(val);
        }
        if (json_object_object_get_ex(behavior, "file_io", &val)) {
            profile->does_file_io = json_object_get_boolean(val);
        }
        if (json_object_object_get_ex(behavior, "spawns_children", &val)) {
            profile->spawns_children = json_object_get_boolean(val);
        }
        if (json_object_object_get_ex(behavior, "changes_privileges", &val)) {
            profile->changes_privileges = json_object_get_boolean(val);
        }
        if (json_object_object_get_ex(behavior, "accesses_sensitive", &val)) {
            profile->accesses_sensitive_files = json_object_get_boolean(val);
        }
    }
    
    /* Parse syscall stats */
    struct json_object *stats_arr;
    if (json_object_object_get_ex(root, "syscall_stats", &stats_arr)) {
        size_t count = json_object_array_length(stats_arr);
        profile->syscall_stats = calloc(count, sizeof(sg_syscall_stats_t));
        if (profile->syscall_stats != NULL) {
            profile->syscall_count = count;
            for (size_t i = 0; i < count; i++) {
                struct json_object *stat = json_object_array_get_idx(stats_arr, i);
                if (json_object_object_get_ex(stat, "syscall_nr", &val)) {
                    profile->syscall_stats[i].syscall_nr = json_object_get_int(val);
                }
                if (json_object_object_get_ex(stat, "name", &val)) {
                    sg_safe_strncpy(profile->syscall_stats[i].name,
                                    json_object_get_string(val),
                                    sizeof(profile->syscall_stats[i].name));
                }
                if (json_object_object_get_ex(stat, "count", &val)) {
                    profile->syscall_stats[i].count = json_object_get_int64(val);
                }
                if (json_object_object_get_ex(stat, "frequency", &val)) {
                    profile->syscall_stats[i].frequency = json_object_get_double(val);
                }
            }
        }
    }
    
    /* Parse unique syscalls */
    struct json_object *unique_arr;
    if (json_object_object_get_ex(root, "unique_syscalls", &unique_arr)) {
        size_t count = json_object_array_length(unique_arr);
        profile->unique_syscalls = calloc(count, sizeof(uint32_t));
        if (profile->unique_syscalls != NULL) {
            profile->unique_count = count;
            for (size_t i = 0; i < count; i++) {
                struct json_object *nr = json_object_array_get_idx(unique_arr, i);
                profile->unique_syscalls[i] = json_object_get_int(nr);
            }
        }
    }
    
    json_object_put(root);
    
    *profile_out = profile;
    return SG_OK;
}
