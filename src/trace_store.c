/*
 * Auris - Trace Storage
 * Persistent storage and retrieval of syscall traces as JSON
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <json-c/json.h>

#include "auris.h"
#include "trace_store.h"
#include "json_utils.h"

/* Initial event capacity */
#define INITIAL_EVENT_CAPACITY 1024

/* Subdirectory for traces */
#define TRACES_SUBDIR "traces"

/*
 * Initialize trace storage
 */
sg_error_t sg_trace_store_init(sg_trace_store_t *store, const char *base_dir)
{
    if (store == NULL || base_dir == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(store, 0, sizeof(*store));
    sg_safe_strncpy(store->base_dir, base_dir, sizeof(store->base_dir));
    
    /* Create traces subdirectory */
    char traces_dir[MAX_PATH_LEN];
    snprintf(traces_dir, sizeof(traces_dir), "%s/%s", base_dir, TRACES_SUBDIR);
    
    sg_error_t err = sg_mkdir_p(traces_dir, 0755);
    if (err != SG_OK) {
        sg_log(SG_LOG_ERROR, "Failed to create traces directory: %s", traces_dir);
        return err;
    }
    
    store->initialized = true;
    return SG_OK;
}

/*
 * Clean up trace storage
 */
void sg_trace_store_cleanup(sg_trace_store_t *store)
{
    if (store != NULL) {
        store->initialized = false;
    }
}

/*
 * Allocate a new trace structure
 */
sg_trace_t *sg_trace_alloc(void)
{
    sg_trace_t *trace = calloc(1, sizeof(sg_trace_t));
    if (trace == NULL) {
        return NULL;
    }
    
    trace->events = calloc(INITIAL_EVENT_CAPACITY, sizeof(sg_syscall_event_t));
    if (trace->events == NULL) {
        free(trace);
        return NULL;
    }
    
    trace->event_capacity = INITIAL_EVENT_CAPACITY;
    trace->event_count = 0;
    
    /* Initialize FD table */
    for (int i = 0; i < MAX_FD_TABLE_SIZE; i++) {
        trace->fd_table[i].fd = -1;
        trace->fd_table[i].is_open = false;
    }
    
    return trace;
}

/*
 * Free a trace structure
 */
void sg_trace_free(sg_trace_t *trace)
{
    if (trace == NULL) {
        return;
    }
    
    if (trace->events != NULL) {
        free(trace->events);
    }
    
    if (trace->meta.argv != NULL) {
        for (int i = 0; i < trace->meta.argc; i++) {
            free(trace->meta.argv[i]);
        }
        free(trace->meta.argv);
    }
    
    if (trace->meta.envp != NULL) {
        for (int i = 0; i < trace->meta.envc; i++) {
            free(trace->meta.envp[i]);
        }
        free(trace->meta.envp);
    }
    
    free(trace);
}

/*
 * Add an event to a trace
 */
sg_error_t sg_trace_add_event(sg_trace_t *trace, const sg_syscall_event_t *event)
{
    if (trace == NULL || event == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Check limit */
    if (trace->event_count >= MAX_TRACE_SYSCALLS) {
        return SG_ERR_LIMIT;
    }
    
    /* Expand array if needed */
    if (trace->event_count >= trace->event_capacity) {
        size_t new_capacity = trace->event_capacity * 2;
        if (new_capacity > MAX_TRACE_SYSCALLS) {
            new_capacity = MAX_TRACE_SYSCALLS;
        }
        
        sg_syscall_event_t *new_events = realloc(trace->events,
                                                  new_capacity * sizeof(sg_syscall_event_t));
        if (new_events == NULL) {
            return SG_ERR_NOMEM;
        }
        
        trace->events = new_events;
        trace->event_capacity = new_capacity;
    }
    
    /* Copy event */
    trace->events[trace->event_count] = *event;
    trace->event_count++;
    
    return SG_OK;
}

/*
 * Finalize a trace
 */
sg_error_t sg_trace_finalize(sg_trace_t *trace)
{
    if (trace == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    trace->meta.total_syscalls = trace->event_count;
    
    return SG_OK;
}

/*
 * Get path to trace file
 */
sg_error_t sg_trace_store_get_path(sg_trace_store_t *store,
                                    const char *trace_id,
                                    char *path_out,
                                    size_t path_len)
{
    if (store == NULL || trace_id == NULL || path_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    int n = snprintf(path_out, path_len, "%s/%s/%s.json",
                     store->base_dir, TRACES_SUBDIR, trace_id);
    
    if (n < 0 || (size_t)n >= path_len) {
        return SG_ERR_OVERFLOW;
    }
    
    return SG_OK;
}

/*
 * Save trace to disk
 */
sg_error_t sg_trace_store_save(sg_trace_store_t *store,
                                sg_trace_t *trace,
                                const char *trace_id)
{
    if (store == NULL || !store->initialized || trace == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Use provided ID or generate one */
    if (trace_id != NULL && trace_id[0] != '\0') {
        sg_safe_strncpy(trace->meta.trace_id, trace_id,
                        sizeof(trace->meta.trace_id));
    } else if (trace->meta.trace_id[0] == '\0') {
        sg_generate_id(trace->meta.trace_id, sizeof(trace->meta.trace_id));
    }
    
    /* Serialize to JSON */
    char *json = sg_trace_to_json(trace);
    if (json == NULL) {
        return SG_ERR_NOMEM;
    }
    
    /* Get file path */
    char path[MAX_PATH_LEN];
    sg_error_t err = sg_trace_store_get_path(store, trace->meta.trace_id,
                                              path, sizeof(path));
    if (err != SG_OK) {
        free(json);
        return err;
    }
    
    /* Write to file */
    err = sg_write_file(path, json, strlen(json));
    free(json);
    
    if (err != SG_OK) {
        sg_log(SG_LOG_ERROR, "Failed to write trace to %s", path);
        return err;
    }
    
    sg_log(SG_LOG_INFO, "Saved trace %s to %s", trace->meta.trace_id, path);
    
    return SG_OK;
}

/*
 * Load trace from disk
 */
sg_error_t sg_trace_store_load(sg_trace_store_t *store,
                                const char *trace_id,
                                sg_trace_t **trace_out)
{
    if (store == NULL || !store->initialized || trace_id == NULL || trace_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Get file path */
    char path[MAX_PATH_LEN];
    sg_error_t err = sg_trace_store_get_path(store, trace_id, path, sizeof(path));
    if (err != SG_OK) {
        return err;
    }
    
    /* Read file */
    size_t len;
    char *json = sg_read_file(path, &len);
    if (json == NULL) {
        sg_log(SG_LOG_ERROR, "Failed to read trace from %s", path);
        return SG_ERR_IO;
    }
    
    /* Parse JSON */
    err = sg_trace_from_json(json, trace_out);
    free(json);
    
    if (err != SG_OK) {
        sg_log(SG_LOG_ERROR, "Failed to parse trace %s", trace_id);
        return err;
    }
    
    return SG_OK;
}

/*
 * Delete a trace
 */
sg_error_t sg_trace_store_delete(sg_trace_store_t *store, const char *trace_id)
{
    if (store == NULL || !store->initialized || trace_id == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    char path[MAX_PATH_LEN];
    sg_error_t err = sg_trace_store_get_path(store, trace_id, path, sizeof(path));
    if (err != SG_OK) {
        return err;
    }
    
    if (unlink(path) != 0) {
        if (errno == ENOENT) {
            return SG_ERR_NOT_FOUND;
        }
        return SG_ERR_IO;
    }
    
    return SG_OK;
}

/*
 * Check if trace exists
 */
bool sg_trace_store_exists(sg_trace_store_t *store, const char *trace_id)
{
    if (store == NULL || !store->initialized || trace_id == NULL) {
        return false;
    }
    
    char path[MAX_PATH_LEN];
    if (sg_trace_store_get_path(store, trace_id, path, sizeof(path)) != SG_OK) {
        return false;
    }
    
    return sg_path_exists(path);
}

/*
 * List all traces
 */
sg_error_t sg_trace_store_list_all(sg_trace_store_t *store,
                                    char ***trace_ids_out,
                                    size_t *count_out)
{
    if (store == NULL || !store->initialized || trace_ids_out == NULL || count_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    char traces_dir[MAX_PATH_LEN];
    snprintf(traces_dir, sizeof(traces_dir), "%s/%s", store->base_dir, TRACES_SUBDIR);
    
    DIR *dir = opendir(traces_dir);
    if (dir == NULL) {
        *trace_ids_out = NULL;
        *count_out = 0;
        return SG_OK;
    }
    
    /* Count JSON files */
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t len = strlen(entry->d_name);
        if (len > 5 && strcmp(entry->d_name + len - 5, ".json") == 0) {
            count++;
        }
    }
    
    if (count == 0) {
        closedir(dir);
        *trace_ids_out = NULL;
        *count_out = 0;
        return SG_OK;
    }
    
    /* Allocate array */
    char **ids = calloc(count, sizeof(char *));
    if (ids == NULL) {
        closedir(dir);
        return SG_ERR_NOMEM;
    }
    
    /* Collect IDs */
    rewinddir(dir);
    size_t i = 0;
    while ((entry = readdir(dir)) != NULL && i < count) {
        size_t len = strlen(entry->d_name);
        if (len > 5 && strcmp(entry->d_name + len - 5, ".json") == 0) {
            /* Remove .json extension */
            ids[i] = strndup(entry->d_name, len - 5);
            if (ids[i] == NULL) {
                /* Clean up on error */
                for (size_t j = 0; j < i; j++) {
                    free(ids[j]);
                }
                free(ids);
                closedir(dir);
                return SG_ERR_NOMEM;
            }
            i++;
        }
    }
    
    closedir(dir);
    
    *trace_ids_out = ids;
    *count_out = i;
    
    return SG_OK;
}

/*
 * List traces for a specific binary
 */
sg_error_t sg_trace_store_list(sg_trace_store_t *store,
                                const char *binary_path,
                                const char *binary_hash,
                                char ***trace_ids_out,
                                size_t *count_out)
{
    if (store == NULL || trace_ids_out == NULL || count_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Get all traces first */
    char **all_ids;
    size_t all_count;
    sg_error_t err = sg_trace_store_list_all(store, &all_ids, &all_count);
    if (err != SG_OK) {
        return err;
    }
    
    if (all_count == 0) {
        *trace_ids_out = NULL;
        *count_out = 0;
        return SG_OK;
    }
    
    /* Filter by binary */
    char **filtered = calloc(all_count, sizeof(char *));
    if (filtered == NULL) {
        for (size_t i = 0; i < all_count; i++) {
            free(all_ids[i]);
        }
        free(all_ids);
        return SG_ERR_NOMEM;
    }
    
    size_t filtered_count = 0;
    for (size_t i = 0; i < all_count; i++) {
        sg_trace_meta_t meta;
        err = sg_trace_store_get_meta(store, all_ids[i], &meta);
        if (err == SG_OK) {
            bool match = false;
            
            if (binary_hash != NULL && binary_hash[0] != '\0') {
                match = (strcmp(meta.binary_hash, binary_hash) == 0);
            } else if (binary_path != NULL && binary_path[0] != '\0') {
                match = (strcmp(meta.binary_path, binary_path) == 0);
            } else {
                match = true;
            }
            
            if (match) {
                filtered[filtered_count++] = all_ids[i];
                all_ids[i] = NULL;
            }
        }
    }
    
    /* Clean up unmatched */
    for (size_t i = 0; i < all_count; i++) {
        if (all_ids[i] != NULL) {
            free(all_ids[i]);
        }
    }
    free(all_ids);
    
    *trace_ids_out = filtered;
    *count_out = filtered_count;
    
    return SG_OK;
}

/*
 * Get trace metadata without loading full trace
 */
sg_error_t sg_trace_store_get_meta(sg_trace_store_t *store,
                                    const char *trace_id,
                                    sg_trace_meta_t *meta_out)
{
    if (store == NULL || trace_id == NULL || meta_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    char path[MAX_PATH_LEN];
    sg_error_t err = sg_trace_store_get_path(store, trace_id, path, sizeof(path));
    if (err != SG_OK) {
        return err;
    }
    
    /* Read file */
    size_t len;
    char *json = sg_read_file(path, &len);
    if (json == NULL) {
        return SG_ERR_IO;
    }
    
    /* Parse just the metadata */
    struct json_object *root = json_tokener_parse(json);
    free(json);
    
    if (root == NULL) {
        return SG_ERR_PARSE;
    }
    
    memset(meta_out, 0, sizeof(*meta_out));
    
    struct json_object *meta_obj;
    if (json_object_object_get_ex(root, "metadata", &meta_obj)) {
        struct json_object *val;
        
        if (json_object_object_get_ex(meta_obj, "trace_id", &val)) {
            sg_safe_strncpy(meta_out->trace_id, json_object_get_string(val),
                            sizeof(meta_out->trace_id));
        }
        if (json_object_object_get_ex(meta_obj, "binary_path", &val)) {
            sg_safe_strncpy(meta_out->binary_path, json_object_get_string(val),
                            sizeof(meta_out->binary_path));
        }
        if (json_object_object_get_ex(meta_obj, "binary_hash", &val)) {
            sg_safe_strncpy(meta_out->binary_hash, json_object_get_string(val),
                            sizeof(meta_out->binary_hash));
        }
        if (json_object_object_get_ex(meta_obj, "hostname", &val)) {
            sg_safe_strncpy(meta_out->hostname, json_object_get_string(val),
                            sizeof(meta_out->hostname));
        }
        if (json_object_object_get_ex(meta_obj, "total_syscalls", &val)) {
            meta_out->total_syscalls = json_object_get_int64(val);
        }
        if (json_object_object_get_ex(meta_obj, "exit_code", &val)) {
            meta_out->exit_code = json_object_get_int(val);
        }
        if (json_object_object_get_ex(meta_obj, "root_pid", &val)) {
            meta_out->root_pid = json_object_get_int(val);
        }
    }
    
    json_object_put(root);
    
    return SG_OK;
}
