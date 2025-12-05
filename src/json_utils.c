/*
 * Auris - JSON Utilities
 * Serialization and deserialization helpers
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#include "auris.h"
#include "trace_store.h"
#include "profiler.h"
#include "graph.h"
#include "policy.h"
#include "dataflow.h"

/*
 * Serialize timestamp to JSON object
 */
static struct json_object *timestamp_to_json(sg_timestamp_t ts)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "sec", json_object_new_int64(ts.sec));
    json_object_object_add(obj, "nsec", json_object_new_int64(ts.nsec));
    return obj;
}

/*
 * Parse timestamp from JSON object
 */
static sg_timestamp_t timestamp_from_json(struct json_object *obj)
{
    sg_timestamp_t ts = {0, 0};
    struct json_object *val;
    
    if (json_object_object_get_ex(obj, "sec", &val)) {
        ts.sec = json_object_get_int64(val);
    }
    if (json_object_object_get_ex(obj, "nsec", &val)) {
        ts.nsec = json_object_get_int64(val);
    }
    
    return ts;
}

/*
 * Serialize network address to JSON
 */
static struct json_object *netaddr_to_json(const sg_netaddr_t *addr)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "family", json_object_new_int(addr->family));
    json_object_object_add(obj, "port", json_object_new_int(addr->port));
    json_object_object_add(obj, "str", json_object_new_string(addr->str));
    return obj;
}

/*
 * Serialize argument value to JSON
 */
static struct json_object *arg_to_json(const sg_arg_value_t *arg)
{
    struct json_object *obj = json_object_new_object();
    
    json_object_object_add(obj, "type", json_object_new_int(arg->type));
    json_object_object_add(obj, "valid", json_object_new_boolean(arg->valid));
    
    if (!arg->valid) {
        return obj;
    }
    
    switch (arg->type) {
        case ARG_TYPE_INT:
        case ARG_TYPE_LONG:
        case ARG_TYPE_PID:
        case ARG_TYPE_SIGNAL:
        case ARG_TYPE_FD:
            json_object_object_add(obj, "value", json_object_new_int64(arg->value.i64));
            break;
            
        case ARG_TYPE_UINT:
        case ARG_TYPE_ULONG:
        case ARG_TYPE_SIZE:
        case ARG_TYPE_PTR:
        case ARG_TYPE_FLAGS:
        case ARG_TYPE_MODE:
        case ARG_TYPE_UID:
        case ARG_TYPE_GID:
            json_object_object_add(obj, "value", json_object_new_int64((int64_t)arg->value.u64));
            break;
            
        case ARG_TYPE_STR:
        case ARG_TYPE_PATH:
            json_object_object_add(obj, "value", json_object_new_string(arg->value.str));
            break;
            
        case ARG_TYPE_SOCKADDR:
            json_object_object_add(obj, "value", netaddr_to_json(&arg->value.addr));
            break;
            
        default:
            json_object_object_add(obj, "value", json_object_new_int64((int64_t)arg->value.u64));
            break;
    }
    
    return obj;
}

/*
 * Serialize single event to JSON
 */
char *sg_event_to_json(const sg_syscall_event_t *event)
{
    if (event == NULL) {
        return NULL;
    }
    
    struct json_object *obj = json_object_new_object();
    
    json_object_object_add(obj, "id", json_object_new_int(event->id));
    json_object_object_add(obj, "pid", json_object_new_int(event->pid));
    json_object_object_add(obj, "tid", json_object_new_int(event->tid));
    json_object_object_add(obj, "ppid", json_object_new_int(event->ppid));
    json_object_object_add(obj, "syscall_nr", json_object_new_int(event->syscall_nr));
    json_object_object_add(obj, "syscall_name", json_object_new_string(event->syscall_name));
    json_object_object_add(obj, "ret_value", json_object_new_int64(event->ret_value));
    json_object_object_add(obj, "errno", json_object_new_int(event->err_no));
    json_object_object_add(obj, "entry_time", timestamp_to_json(event->entry_time));
    json_object_object_add(obj, "exit_time", timestamp_to_json(event->exit_time));
    json_object_object_add(obj, "duration_ns", json_object_new_int64((int64_t)event->duration_ns));
    json_object_object_add(obj, "comm", json_object_new_string(event->comm));
    
    /* Arguments */
    struct json_object *args = json_object_new_array();
    for (int i = 0; i < MAX_SYSCALL_ARGS; i++) {
        json_object_array_add(args, arg_to_json(&event->args[i]));
    }
    json_object_object_add(obj, "args", args);
    
    const char *json_str = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    char *result = strdup(json_str);
    
    json_object_put(obj);
    
    return result;
}

/*
 * Serialize trace metadata to JSON
 */
char *sg_trace_meta_to_json(const sg_trace_meta_t *meta)
{
    if (meta == NULL) {
        return NULL;
    }
    
    struct json_object *obj = json_object_new_object();
    
    json_object_object_add(obj, "trace_id", json_object_new_string(meta->trace_id));
    json_object_object_add(obj, "binary_path", json_object_new_string(meta->binary_path));
    json_object_object_add(obj, "binary_hash", json_object_new_string(meta->binary_hash));
    json_object_object_add(obj, "hostname", json_object_new_string(meta->hostname));
    json_object_object_add(obj, "root_pid", json_object_new_int(meta->root_pid));
    json_object_object_add(obj, "exit_code", json_object_new_int(meta->exit_code));
    json_object_object_add(obj, "total_syscalls", json_object_new_int64((int64_t)meta->total_syscalls));
    json_object_object_add(obj, "auris_version", json_object_new_string(meta->auris_version));
    json_object_object_add(obj, "start_time", timestamp_to_json(meta->start_time));
    json_object_object_add(obj, "end_time", timestamp_to_json(meta->end_time));
    
    /* Command line arguments */
    if (meta->argv != NULL && meta->argc > 0) {
        struct json_object *argv = json_object_new_array();
        for (int i = 0; i < meta->argc; i++) {
            if (meta->argv[i] != NULL) {
                json_object_array_add(argv, json_object_new_string(meta->argv[i]));
            }
        }
        json_object_object_add(obj, "argv", argv);
    }
    
    const char *json_str = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    char *result = strdup(json_str);
    
    json_object_put(obj);
    
    return result;
}

/*
 * Serialize complete trace to JSON
 */
char *sg_trace_to_json(const sg_trace_t *trace)
{
    if (trace == NULL) {
        return NULL;
    }
    
    struct json_object *root = json_object_new_object();
    
    /* Format version */
    json_object_object_add(root, "format_version", json_object_new_int(TRACE_FORMAT_VERSION));
    
    /* Metadata */
    struct json_object *meta = json_object_new_object();
    json_object_object_add(meta, "trace_id", json_object_new_string(trace->meta.trace_id));
    json_object_object_add(meta, "binary_path", json_object_new_string(trace->meta.binary_path));
    json_object_object_add(meta, "binary_hash", json_object_new_string(trace->meta.binary_hash));
    json_object_object_add(meta, "hostname", json_object_new_string(trace->meta.hostname));
    json_object_object_add(meta, "root_pid", json_object_new_int(trace->meta.root_pid));
    json_object_object_add(meta, "exit_code", json_object_new_int(trace->meta.exit_code));
    json_object_object_add(meta, "total_syscalls", json_object_new_int64((int64_t)trace->meta.total_syscalls));
    json_object_object_add(meta, "auris_version", json_object_new_string(trace->meta.auris_version));
    json_object_object_add(meta, "start_time", timestamp_to_json(trace->meta.start_time));
    json_object_object_add(meta, "end_time", timestamp_to_json(trace->meta.end_time));
    
    if (trace->meta.argv != NULL) {
        struct json_object *argv = json_object_new_array();
        for (int i = 0; i < trace->meta.argc; i++) {
            if (trace->meta.argv[i] != NULL) {
                json_object_array_add(argv, json_object_new_string(trace->meta.argv[i]));
            }
        }
        json_object_object_add(meta, "argv", argv);
    }
    
    json_object_object_add(root, "metadata", meta);
    
    /* Events */
    struct json_object *events = json_object_new_array();
    for (size_t i = 0; i < trace->event_count; i++) {
        const sg_syscall_event_t *e = &trace->events[i];
        struct json_object *event = json_object_new_object();
        
        json_object_object_add(event, "id", json_object_new_int(e->id));
        json_object_object_add(event, "pid", json_object_new_int(e->pid));
        json_object_object_add(event, "syscall_nr", json_object_new_int(e->syscall_nr));
        json_object_object_add(event, "syscall_name", json_object_new_string(e->syscall_name));
        json_object_object_add(event, "ret", json_object_new_int64(e->ret_value));
        json_object_object_add(event, "duration_ns", json_object_new_int64((int64_t)e->duration_ns));
        
        /* Compact args - only include valid ones */
        struct json_object *args = json_object_new_array();
        for (int j = 0; j < MAX_SYSCALL_ARGS; j++) {
            if (e->args[j].valid) {
                json_object_array_add(args, arg_to_json(&e->args[j]));
            }
        }
        json_object_object_add(event, "args", args);
        
        json_object_array_add(events, event);
    }
    json_object_object_add(root, "events", events);
    
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    char *result = strdup(json_str);
    
    json_object_put(root);
    
    return result;
}

/*
 * Parse argument from JSON
 */
static void arg_from_json(struct json_object *obj, sg_arg_value_t *arg)
{
    struct json_object *val;
    
    memset(arg, 0, sizeof(*arg));
    
    if (json_object_object_get_ex(obj, "type", &val)) {
        arg->type = json_object_get_int(val);
    }
    if (json_object_object_get_ex(obj, "valid", &val)) {
        arg->valid = json_object_get_boolean(val);
    }
    
    if (!arg->valid) {
        return;
    }
    
    if (json_object_object_get_ex(obj, "value", &val)) {
        switch (arg->type) {
            case ARG_TYPE_STR:
            case ARG_TYPE_PATH:
                sg_safe_strncpy(arg->value.str, json_object_get_string(val),
                                sizeof(arg->value.str));
                break;
                
            case ARG_TYPE_SOCKADDR:
                if (json_object_is_type(val, json_type_object)) {
                    struct json_object *v;
                    if (json_object_object_get_ex(val, "family", &v)) {
                        arg->value.addr.family = json_object_get_int(v);
                    }
                    if (json_object_object_get_ex(val, "port", &v)) {
                        arg->value.addr.port = json_object_get_int(v);
                    }
                    if (json_object_object_get_ex(val, "str", &v)) {
                        sg_safe_strncpy(arg->value.addr.str, json_object_get_string(v),
                                        sizeof(arg->value.addr.str));
                    }
                }
                break;
                
            default:
                arg->value.i64 = json_object_get_int64(val);
                break;
        }
    }
}

/*
 * Parse trace from JSON
 */
sg_error_t sg_trace_from_json(const char *json, sg_trace_t **trace_out)
{
    if (json == NULL || trace_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    struct json_object *root = json_tokener_parse(json);
    if (root == NULL) {
        return SG_ERR_PARSE;
    }
    
    sg_trace_t *trace = sg_trace_alloc();
    if (trace == NULL) {
        json_object_put(root);
        return SG_ERR_NOMEM;
    }
    
    struct json_object *obj, *val;
    
    /* Parse metadata */
    if (json_object_object_get_ex(root, "metadata", &obj)) {
        if (json_object_object_get_ex(obj, "trace_id", &val)) {
            sg_safe_strncpy(trace->meta.trace_id, json_object_get_string(val),
                            sizeof(trace->meta.trace_id));
        }
        if (json_object_object_get_ex(obj, "binary_path", &val)) {
            sg_safe_strncpy(trace->meta.binary_path, json_object_get_string(val),
                            sizeof(trace->meta.binary_path));
        }
        if (json_object_object_get_ex(obj, "binary_hash", &val)) {
            sg_safe_strncpy(trace->meta.binary_hash, json_object_get_string(val),
                            sizeof(trace->meta.binary_hash));
        }
        if (json_object_object_get_ex(obj, "hostname", &val)) {
            sg_safe_strncpy(trace->meta.hostname, json_object_get_string(val),
                            sizeof(trace->meta.hostname));
        }
        if (json_object_object_get_ex(obj, "root_pid", &val)) {
            trace->meta.root_pid = json_object_get_int(val);
        }
        if (json_object_object_get_ex(obj, "exit_code", &val)) {
            trace->meta.exit_code = json_object_get_int(val);
        }
        if (json_object_object_get_ex(obj, "total_syscalls", &val)) {
            trace->meta.total_syscalls = json_object_get_int64(val);
        }
        if (json_object_object_get_ex(obj, "auris_version", &val)) {
            sg_safe_strncpy(trace->meta.auris_version, json_object_get_string(val),
                            sizeof(trace->meta.auris_version));
        }
        if (json_object_object_get_ex(obj, "start_time", &val)) {
            trace->meta.start_time = timestamp_from_json(val);
        }
        if (json_object_object_get_ex(obj, "end_time", &val)) {
            trace->meta.end_time = timestamp_from_json(val);
        }
        
        /* Parse argv */
        if (json_object_object_get_ex(obj, "argv", &val)) {
            size_t argc = json_object_array_length(val);
            trace->meta.argc = (int)argc;
            trace->meta.argv = calloc(argc + 1, sizeof(char *));
            if (trace->meta.argv != NULL) {
                for (size_t i = 0; i < argc; i++) {
                    struct json_object *arg = json_object_array_get_idx(val, i);
                    trace->meta.argv[i] = strdup(json_object_get_string(arg));
                }
            }
        }
    }
    
    /* Parse events */
    if (json_object_object_get_ex(root, "events", &obj)) {
        size_t event_count = json_object_array_length(obj);
        
        for (size_t i = 0; i < event_count; i++) {
            struct json_object *event_obj = json_object_array_get_idx(obj, i);
            sg_syscall_event_t event;
            memset(&event, 0, sizeof(event));
            
            if (json_object_object_get_ex(event_obj, "id", &val)) {
                event.id = json_object_get_int(val);
            }
            if (json_object_object_get_ex(event_obj, "pid", &val)) {
                event.pid = json_object_get_int(val);
            }
            if (json_object_object_get_ex(event_obj, "syscall_nr", &val)) {
                event.syscall_nr = json_object_get_int(val);
            }
            if (json_object_object_get_ex(event_obj, "syscall_name", &val)) {
                sg_safe_strncpy(event.syscall_name, json_object_get_string(val),
                                sizeof(event.syscall_name));
            }
            if (json_object_object_get_ex(event_obj, "ret", &val)) {
                event.ret_value = json_object_get_int64(val);
            }
            if (json_object_object_get_ex(event_obj, "duration_ns", &val)) {
                event.duration_ns = json_object_get_int64(val);
            }
            
            /* Parse args */
            if (json_object_object_get_ex(event_obj, "args", &val)) {
                size_t arg_count = json_object_array_length(val);
                for (size_t j = 0; j < arg_count && j < MAX_SYSCALL_ARGS; j++) {
                    struct json_object *arg_obj = json_object_array_get_idx(val, j);
                    arg_from_json(arg_obj, &event.args[j]);
                }
            }
            
            sg_trace_add_event(trace, &event);
        }
    }
    
    json_object_put(root);
    
    *trace_out = trace;
    return SG_OK;
}

/*
 * Serialize profile to JSON
 */
char *sg_profile_to_json(const sg_profile_t *profile)
{
    if (profile == NULL) {
        return NULL;
    }
    
    struct json_object *root = json_object_new_object();
    
    json_object_object_add(root, "profile_id", json_object_new_string(profile->profile_id));
    json_object_object_add(root, "binary_path", json_object_new_string(profile->binary_path));
    json_object_object_add(root, "binary_hash", json_object_new_string(profile->binary_hash));
    json_object_object_add(root, "total_syscalls", json_object_new_int64((int64_t)profile->total_syscalls));
    
    /* Behavioral flags */
    struct json_object *flags = json_object_new_object();
    json_object_object_add(flags, "network_io", json_object_new_boolean(profile->does_network_io));
    json_object_object_add(flags, "file_io", json_object_new_boolean(profile->does_file_io));
    json_object_object_add(flags, "spawns_children", json_object_new_boolean(profile->spawns_children));
    json_object_object_add(flags, "changes_privileges", json_object_new_boolean(profile->changes_privileges));
    json_object_object_add(flags, "accesses_sensitive", json_object_new_boolean(profile->accesses_sensitive_files));
    json_object_object_add(root, "behavior", flags);
    
    /* Syscall statistics */
    struct json_object *stats = json_object_new_array();
    for (size_t i = 0; i < profile->syscall_count; i++) {
        struct json_object *stat = json_object_new_object();
        json_object_object_add(stat, "syscall_nr", json_object_new_int(profile->syscall_stats[i].syscall_nr));
        json_object_object_add(stat, "name", json_object_new_string(profile->syscall_stats[i].name));
        json_object_object_add(stat, "count", json_object_new_int64((int64_t)profile->syscall_stats[i].count));
        json_object_object_add(stat, "frequency", json_object_new_double(profile->syscall_stats[i].frequency));
        json_object_array_add(stats, stat);
    }
    json_object_object_add(root, "syscall_stats", stats);
    
    /* Unique syscalls */
    struct json_object *unique = json_object_new_array();
    for (size_t i = 0; i < profile->unique_count; i++) {
        json_object_array_add(unique, json_object_new_int(profile->unique_syscalls[i]));
    }
    json_object_object_add(root, "unique_syscalls", unique);
    
    /* Timestamps */
    json_object_object_add(root, "created", timestamp_to_json(profile->created));
    json_object_object_add(root, "updated", timestamp_to_json(profile->updated));
    
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    char *result = strdup(json_str);
    
    json_object_put(root);
    
    return result;
}

/*
 * Serialize comparison result to JSON
 */
char *sg_comparison_to_json(const sg_comparison_t *result)
{
    if (result == NULL) {
        return NULL;
    }
    
    struct json_object *root = json_object_new_object();
    
    json_object_object_add(root, "trace_id", json_object_new_string(result->trace_id));
    json_object_object_add(root, "profile_id", json_object_new_string(result->profile_id));
    json_object_object_add(root, "overall_deviation", json_object_new_double(result->overall_deviation));
    json_object_object_add(root, "risk_score", json_object_new_double(result->risk_score));
    json_object_object_add(root, "is_anomalous", json_object_new_boolean(result->is_anomalous));
    
    /* Anomalies */
    struct json_object *anomalies = json_object_new_array();
    for (size_t i = 0; i < result->anomaly_count; i++) {
        struct json_object *a = json_object_new_object();
        json_object_object_add(a, "type", json_object_new_int(result->anomalies[i].type));
        json_object_object_add(a, "description", json_object_new_string(result->anomalies[i].description));
        json_object_object_add(a, "severity", json_object_new_double(result->anomalies[i].severity));
        json_object_object_add(a, "syscall_nr", json_object_new_int(result->anomalies[i].syscall_nr));
        json_object_array_add(anomalies, a);
    }
    json_object_object_add(root, "anomalies", anomalies);
    
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    char *result_str = strdup(json_str);
    
    json_object_put(root);
    
    return result_str;
}

/*
 * Serialize policy to JSON
 */
char *sg_policy_to_json(const sg_policy_t *policy)
{
    if (policy == NULL) {
        return NULL;
    }
    
    struct json_object *root = json_object_new_object();
    
    json_object_object_add(root, "policy_id", json_object_new_string(policy->policy_id));
    json_object_object_add(root, "profile_id", json_object_new_string(policy->profile_id));
    json_object_object_add(root, "binary_path", json_object_new_string(policy->binary_path));
    json_object_object_add(root, "default_mode", json_object_new_int(policy->default_mode));
    json_object_object_add(root, "allow_unknown", json_object_new_boolean(policy->allow_unknown));
    json_object_object_add(root, "description", json_object_new_string(policy->description));
    json_object_object_add(root, "created", timestamp_to_json(policy->created));
    json_object_object_add(root, "updated", timestamp_to_json(policy->updated));
    
    /* Rules */
    struct json_object *rules = json_object_new_array();
    for (size_t i = 0; i < policy->rule_count; i++) {
        struct json_object *rule = json_object_new_object();
        json_object_object_add(rule, "syscall_nr", json_object_new_int(policy->rules[i].syscall_nr));
        json_object_object_add(rule, "syscall_name", json_object_new_string(policy->rules[i].syscall_name));
        json_object_object_add(rule, "action", json_object_new_int(policy->rules[i].action));
        json_object_object_add(rule, "enabled", json_object_new_boolean(policy->rules[i].enabled));
        if (policy->rules[i].path_pattern[0] != '\0') {
            json_object_object_add(rule, "path_pattern", json_object_new_string(policy->rules[i].path_pattern));
        }
        if (policy->rules[i].reason[0] != '\0') {
            json_object_object_add(rule, "reason", json_object_new_string(policy->rules[i].reason));
        }
        json_object_array_add(rules, rule);
    }
    json_object_object_add(root, "rules", rules);
    
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    char *result = strdup(json_str);
    
    json_object_put(root);
    
    return result;
}

/*
 * Serialize graph to JSON
 */
char *sg_graph_to_json(const sg_graph_t *graph)
{
    if (graph == NULL) {
        return NULL;
    }
    
    struct json_object *root = json_object_new_object();
    
    json_object_object_add(root, "graph_id", json_object_new_string(graph->graph_id));
    json_object_object_add(root, "trace_id", json_object_new_string(graph->trace_id));
    
    /* Nodes */
    struct json_object *nodes = json_object_new_array();
    for (size_t i = 0; i < graph->node_count; i++) {
        struct json_object *node = json_object_new_object();
        json_object_object_add(node, "id", json_object_new_int(graph->nodes[i].id));
        json_object_object_add(node, "type", json_object_new_int(graph->nodes[i].type));
        json_object_object_add(node, "label", json_object_new_string(graph->nodes[i].label));
        json_object_object_add(node, "sensitivity", json_object_new_int(graph->nodes[i].sensitivity));
        json_object_array_add(nodes, node);
    }
    json_object_object_add(root, "nodes", nodes);
    
    /* Edges */
    struct json_object *edges = json_object_new_array();
    for (size_t i = 0; i < graph->edge_count; i++) {
        struct json_object *edge = json_object_new_object();
        json_object_object_add(edge, "id", json_object_new_int(graph->edges[i].id));
        json_object_object_add(edge, "source", json_object_new_int(graph->edges[i].source));
        json_object_object_add(edge, "target", json_object_new_int(graph->edges[i].target));
        json_object_object_add(edge, "type", json_object_new_int(graph->edges[i].type));
        json_object_object_add(edge, "bytes", json_object_new_int64((int64_t)graph->edges[i].bytes));
        json_object_array_add(edges, edge);
    }
    json_object_object_add(root, "edges", edges);
    
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    char *result = strdup(json_str);
    
    json_object_put(root);
    
    return result;
}

/*
 * Serialize data flow result to JSON
 */
char *sg_dataflow_result_to_json(const sg_dataflow_result_t *result)
{
    if (result == NULL) {
        return NULL;
    }
    
    struct json_object *root = json_object_new_object();
    
    json_object_object_add(root, "overall_risk", json_object_new_double(result->overall_risk));
    json_object_object_add(root, "has_high_risk", json_object_new_boolean(result->has_high_risk_flows));
    
    /* Flows */
    struct json_object *flows = json_object_new_array();
    for (size_t i = 0; i < result->flow_count; i++) {
        struct json_object *flow = json_object_new_object();
        json_object_object_add(flow, "source_path", json_object_new_string(result->flows[i].source_path));
        json_object_object_add(flow, "sink_addr", json_object_new_string(result->flows[i].sink_addr.str));
        json_object_object_add(flow, "sensitivity", json_object_new_int(result->flows[i].sensitivity));
        json_object_object_add(flow, "bytes", json_object_new_int64((int64_t)result->flows[i].bytes_transferred));
        json_object_object_add(flow, "confidence", json_object_new_double(result->flows[i].confidence));
        json_object_array_add(flows, flow);
    }
    json_object_object_add(root, "flows", flows);
    
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    char *result_str = strdup(json_str);
    
    json_object_put(root);
    
    return result_str;
}
