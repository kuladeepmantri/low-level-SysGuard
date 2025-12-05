/*
 * Auris - Pattern Matching
 * Syscall sequence pattern detection
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auris.h"
#include "profiler.h"
#include "syscall_table.h"

/* Known suspicious patterns */
static const struct {
    uint32_t pattern[MAX_PATTERN_LENGTH];
    size_t length;
    const char *description;
    double severity;
} suspicious_patterns[] = {
    /* Potential reverse shell */
    {{SYS_socket, SYS_connect, SYS_dup3, SYS_dup3, SYS_execve}, 5,
     "Potential reverse shell (socket->connect->dup->exec)", 0.9},
    
    /* Credential access followed by network */
    {{SYS_openat, SYS_read, SYS_socket, SYS_connect, SYS_sendto}, 5,
     "File read followed by network send", 0.7},
    
    /* Privilege escalation attempt */
    {{SYS_setuid, SYS_setgid, SYS_execve}, 3,
     "Privilege change before exec", 0.8},
    
    /* Process injection pattern */
    {{SYS_ptrace, SYS_mmap, SYS_write}, 3,
     "Potential process injection", 0.9},
    
    /* Sentinel */
    {{0}, 0, NULL, 0.0}
};

/*
 * Check if pattern matches at position
 */
static bool pattern_matches_at(const sg_trace_t *trace,
                                size_t pos,
                                const uint32_t *pattern,
                                size_t pattern_len)
{
    if (pos + pattern_len > trace->event_count) {
        return false;
    }
    
    for (size_t i = 0; i < pattern_len; i++) {
        if (trace->events[pos + i].syscall_nr != pattern[i]) {
            return false;
        }
    }
    
    return true;
}

/*
 * Count pattern occurrences
 */
static uint64_t count_pattern(const sg_trace_t *trace,
                               const uint32_t *pattern,
                               size_t pattern_len)
{
    uint64_t count = 0;
    
    for (size_t i = 0; i + pattern_len <= trace->event_count; i++) {
        if (pattern_matches_at(trace, i, pattern, pattern_len)) {
            count++;
            i += pattern_len - 1;  /* Skip matched portion */
        }
    }
    
    return count;
}

/*
 * Extract common patterns from trace
 */
sg_error_t sg_extract_patterns(const sg_trace_t *trace,
                                sg_pattern_t **patterns_out,
                                size_t *count_out,
                                size_t min_length,
                                size_t max_length,
                                size_t min_occurrences)
{
    if (trace == NULL || patterns_out == NULL || count_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (min_length < 2) min_length = 2;
    if (max_length > MAX_PATTERN_LENGTH) max_length = MAX_PATTERN_LENGTH;
    if (min_occurrences < 2) min_occurrences = 2;
    
    /* Simple approach: look for repeated subsequences */
    sg_pattern_t *patterns = calloc(MAX_PATTERNS, sizeof(sg_pattern_t));
    if (patterns == NULL) {
        return SG_ERR_NOMEM;
    }
    
    size_t pattern_count = 0;
    
    /* For each starting position */
    for (size_t i = 0; i + min_length <= trace->event_count && pattern_count < MAX_PATTERNS; i++) {
        /* For each pattern length */
        for (size_t len = min_length; len <= max_length && i + len <= trace->event_count; len++) {
            /* Extract candidate pattern */
            uint32_t candidate[MAX_PATTERN_LENGTH];
            for (size_t j = 0; j < len; j++) {
                candidate[j] = trace->events[i + j].syscall_nr;
            }
            
            /* Check if we already have this pattern */
            bool exists = false;
            for (size_t p = 0; p < pattern_count; p++) {
                if (patterns[p].length == len) {
                    bool match = true;
                    for (size_t j = 0; j < len; j++) {
                        if (patterns[p].pattern[j] != candidate[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        exists = true;
                        break;
                    }
                }
            }
            
            if (!exists) {
                /* Count occurrences */
                uint64_t occurrences = count_pattern(trace, candidate, len);
                
                if (occurrences >= min_occurrences) {
                    sg_pattern_t *p = &patterns[pattern_count];
                    memcpy(p->pattern, candidate, len * sizeof(uint32_t));
                    p->length = len;
                    p->occurrences = occurrences;
                    p->frequency = (double)occurrences / (double)trace->event_count;
                    pattern_count++;
                }
            }
        }
    }
    
    *patterns_out = patterns;
    *count_out = pattern_count;
    
    return SG_OK;
}

/*
 * Check if pattern exists in trace
 */
bool sg_pattern_exists(const sg_trace_t *trace, const sg_pattern_t *pattern)
{
    if (trace == NULL || pattern == NULL || pattern->length == 0) {
        return false;
    }
    
    return count_pattern(trace, pattern->pattern, pattern->length) > 0;
}

/*
 * Find suspicious patterns
 */
sg_error_t sg_find_suspicious_patterns(const sg_trace_t *trace,
                                        sg_pattern_t **patterns_out,
                                        size_t *count_out)
{
    if (trace == NULL || patterns_out == NULL || count_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    sg_pattern_t *patterns = calloc(MAX_PATTERNS, sizeof(sg_pattern_t));
    if (patterns == NULL) {
        return SG_ERR_NOMEM;
    }
    
    size_t pattern_count = 0;
    
    /* Check each known suspicious pattern */
    for (size_t i = 0; suspicious_patterns[i].length > 0 && pattern_count < MAX_PATTERNS; i++) {
        uint64_t occurrences = count_pattern(trace,
                                              suspicious_patterns[i].pattern,
                                              suspicious_patterns[i].length);
        
        if (occurrences > 0) {
            sg_pattern_t *p = &patterns[pattern_count];
            memcpy(p->pattern, suspicious_patterns[i].pattern,
                   suspicious_patterns[i].length * sizeof(uint32_t));
            p->length = suspicious_patterns[i].length;
            p->occurrences = occurrences;
            p->frequency = suspicious_patterns[i].severity;  /* Use severity as frequency */
            pattern_count++;
            
            sg_log(SG_LOG_WARN, "Suspicious pattern detected: %s (%lu occurrences)",
                   suspicious_patterns[i].description, (unsigned long)occurrences);
        }
    }
    
    *patterns_out = patterns;
    *count_out = pattern_count;
    
    return SG_OK;
}
