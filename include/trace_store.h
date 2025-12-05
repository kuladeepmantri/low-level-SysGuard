/*
 * Auris - Trace Storage
 * Persistent storage and retrieval of syscall traces
 */

#ifndef AURIS_TRACE_STORE_H
#define AURIS_TRACE_STORE_H

#include "auris.h"

/* Trace file format version */
#define TRACE_FORMAT_VERSION 1

/* Trace storage context */
typedef struct {
    char base_dir[MAX_PATH_LEN];
    bool initialized;
} sg_trace_store_t;

/*
 * Initialize trace storage
 * Creates directory structure if needed
 */
sg_error_t sg_trace_store_init(sg_trace_store_t *store, const char *base_dir);

/*
 * Clean up trace storage
 */
void sg_trace_store_cleanup(sg_trace_store_t *store);

/*
 * Allocate a new trace structure
 */
sg_trace_t *sg_trace_alloc(void);

/*
 * Free a trace structure and all its contents
 */
void sg_trace_free(sg_trace_t *trace);

/*
 * Add an event to a trace
 * Returns SG_OK on success, SG_ERR_LIMIT if max events reached
 */
sg_error_t sg_trace_add_event(sg_trace_t *trace, const sg_syscall_event_t *event);

/*
 * Finalize a trace (compute final metadata)
 */
sg_error_t sg_trace_finalize(sg_trace_t *trace);

/*
 * Save trace to disk as JSON
 * If trace_id is NULL, generates a new ID
 */
sg_error_t sg_trace_store_save(sg_trace_store_t *store, 
                                sg_trace_t *trace,
                                const char *trace_id);

/*
 * Load trace from disk by ID
 */
sg_error_t sg_trace_store_load(sg_trace_store_t *store,
                                const char *trace_id,
                                sg_trace_t **trace_out);

/*
 * Delete a trace from disk
 */
sg_error_t sg_trace_store_delete(sg_trace_store_t *store, const char *trace_id);

/*
 * List all traces for a binary (by path or hash)
 * Returns array of trace IDs (caller must free each and the array)
 */
sg_error_t sg_trace_store_list(sg_trace_store_t *store,
                                const char *binary_path,
                                const char *binary_hash,
                                char ***trace_ids_out,
                                size_t *count_out);

/*
 * List all traces in the store
 */
sg_error_t sg_trace_store_list_all(sg_trace_store_t *store,
                                    char ***trace_ids_out,
                                    size_t *count_out);

/*
 * Get trace metadata without loading full trace
 */
sg_error_t sg_trace_store_get_meta(sg_trace_store_t *store,
                                    const char *trace_id,
                                    sg_trace_meta_t *meta_out);

/*
 * Check if a trace exists
 */
bool sg_trace_store_exists(sg_trace_store_t *store, const char *trace_id);

/*
 * Get path to trace file
 */
sg_error_t sg_trace_store_get_path(sg_trace_store_t *store,
                                    const char *trace_id,
                                    char *path_out,
                                    size_t path_len);

/* Trace serialization */

/*
 * Serialize trace to JSON string
 * Caller must free returned string
 */
char *sg_trace_to_json(const sg_trace_t *trace);

/*
 * Parse trace from JSON string
 */
sg_error_t sg_trace_from_json(const char *json, sg_trace_t **trace_out);

/*
 * Serialize trace metadata to JSON
 */
char *sg_trace_meta_to_json(const sg_trace_meta_t *meta);

/*
 * Serialize single event to JSON
 */
char *sg_event_to_json(const sg_syscall_event_t *event);

/*
 * Export trace to compact binary format (for large traces)
 */
sg_error_t sg_trace_export_binary(const sg_trace_t *trace, 
                                   const char *path);

/*
 * Import trace from binary format
 */
sg_error_t sg_trace_import_binary(const char *path, 
                                   sg_trace_t **trace_out);

#endif /* AURIS_TRACE_STORE_H */
