/*
 * Auris - Logging Header
 * Thread-safe logging with levels and optional file output
 */

#ifndef AURIS_LOGGING_H
#define AURIS_LOGGING_H

#include "auris.h"

/*
 * Initialize logging subsystem
 * @param level Minimum log level to output
 * @param file Optional file path for log output (NULL for stderr only)
 */
void sg_log_init(sg_log_level_t level, const char *file);

/*
 * Log a message at the specified level
 * @param level Log level
 * @param fmt Printf-style format string
 * @param ... Format arguments
 */
void sg_log(sg_log_level_t level, const char *fmt, ...);

/*
 * Clean up logging subsystem
 */
void sg_log_cleanup(void);

/*
 * Get string representation of error code
 */
const char *sg_strerror(sg_error_t err);

/*
 * Print error message with prefix
 */
void sg_perror(const char *prefix, sg_error_t err);

#endif /* AURIS_LOGGING_H */
