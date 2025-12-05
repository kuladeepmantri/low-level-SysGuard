/*
 * Auris - Logging System
 * Thread-safe logging with multiple output targets
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include "auris.h"

/* Logging state */
static struct {
    sg_log_level_t level;
    FILE *file;
    bool to_file;
    bool initialized;
    pthread_mutex_t mutex;
} g_log = {
    .level = SG_LOG_INFO,
    .file = NULL,
    .to_file = false,
    .initialized = false,
};

/* Level names */
static const char *level_names[] = {
    "TRACE",
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL",
};

/* Level colors (ANSI) */
static const char *level_colors[] = {
    "\033[90m",    /* TRACE: gray */
    "\033[36m",    /* DEBUG: cyan */
    "\033[32m",    /* INFO: green */
    "\033[33m",    /* WARN: yellow */
    "\033[31m",    /* ERROR: red */
    "\033[35m",    /* FATAL: magenta */
};

static const char *color_reset = "\033[0m";

/*
 * Check if output is a terminal
 */
static bool is_tty(FILE *f)
{
    return isatty(fileno(f)) != 0;
}

/*
 * Get current timestamp string
 */
static void get_timestamp(char *buf, size_t len)
{
    struct timespec ts;
    struct tm tm;
    
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    
    snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             ts.tv_nsec / 1000000);
}

void sg_log_init(sg_log_level_t level, const char *file)
{
    if (g_log.initialized) {
        sg_log_cleanup();
    }
    
    pthread_mutex_init(&g_log.mutex, NULL);
    g_log.level = level;
    g_log.to_file = false;
    g_log.file = NULL;
    
    if (file != NULL && file[0] != '\0') {
        g_log.file = fopen(file, "a");
        if (g_log.file != NULL) {
            g_log.to_file = true;
            /* Set line buffering */
            setvbuf(g_log.file, NULL, _IOLBF, 0);
        }
    }
    
    g_log.initialized = true;
}

void sg_log_cleanup(void)
{
    if (!g_log.initialized) {
        return;
    }
    
    pthread_mutex_lock(&g_log.mutex);
    
    if (g_log.file != NULL) {
        fclose(g_log.file);
        g_log.file = NULL;
    }
    g_log.to_file = false;
    
    pthread_mutex_unlock(&g_log.mutex);
    pthread_mutex_destroy(&g_log.mutex);
    
    g_log.initialized = false;
}

void sg_log(sg_log_level_t level, const char *fmt, ...)
{
    if (!g_log.initialized || level < g_log.level) {
        return;
    }
    
    if (level < 0 || level > SG_LOG_FATAL) {
        level = SG_LOG_INFO;
    }
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    pthread_mutex_lock(&g_log.mutex);
    
    /* Output to stderr */
    FILE *out = stderr;
    bool use_color = is_tty(out);
    
    if (use_color) {
        fprintf(out, "%s[%s]%s %s%-5s%s ",
                "\033[90m", timestamp, color_reset,
                level_colors[level], level_names[level], color_reset);
    } else {
        fprintf(out, "[%s] %-5s ", timestamp, level_names[level]);
    }
    
    va_list args;
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);
    
    fprintf(out, "\n");
    fflush(out);
    
    /* Also output to file if configured */
    if (g_log.to_file && g_log.file != NULL) {
        fprintf(g_log.file, "[%s] %-5s ", timestamp, level_names[level]);
        
        va_start(args, fmt);
        vfprintf(g_log.file, fmt, args);
        va_end(args);
        
        fprintf(g_log.file, "\n");
        fflush(g_log.file);
    }
    
    pthread_mutex_unlock(&g_log.mutex);
    
    /* Fatal errors should abort */
    if (level == SG_LOG_FATAL) {
        abort();
    }
}

const char *sg_strerror(sg_error_t err)
{
    switch (err) {
        case SG_OK:             return "Success";
        case SG_ERR_NOMEM:      return "Out of memory";
        case SG_ERR_INVALID_ARG: return "Invalid argument";
        case SG_ERR_IO:         return "I/O error";
        case SG_ERR_PARSE:      return "Parse error";
        case SG_ERR_SYSCALL:    return "System call failed";
        case SG_ERR_PTRACE:     return "Ptrace operation failed";
        case SG_ERR_FORK:       return "Fork failed";
        case SG_ERR_EXEC:       return "Exec failed";
        case SG_ERR_SIGNAL:     return "Signal error";
        case SG_ERR_POLICY:     return "Policy error";
        case SG_ERR_AI:         return "AI service error";
        case SG_ERR_OVERFLOW:   return "Buffer overflow";
        case SG_ERR_NOT_FOUND:  return "Not found";
        case SG_ERR_PERMISSION: return "Permission denied";
        case SG_ERR_TIMEOUT:    return "Operation timed out";
        case SG_ERR_INTERNAL:   return "Internal error";
        case SG_ERR_CONFIG:     return "Configuration error";
        case SG_ERR_LIMIT:      return "Limit exceeded";
        default:                return "Unknown error";
    }
}

void sg_perror(const char *prefix, sg_error_t err)
{
    if (prefix != NULL && prefix[0] != '\0') {
        sg_log(SG_LOG_ERROR, "%s: %s", prefix, sg_strerror(err));
    } else {
        sg_log(SG_LOG_ERROR, "%s", sg_strerror(err));
    }
    
    /* If it was a syscall error, also print errno */
    if (err == SG_ERR_SYSCALL || err == SG_ERR_IO) {
        sg_log(SG_LOG_ERROR, "  errno: %s", strerror(errno));
    }
}
