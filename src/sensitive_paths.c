/*
 * Auris - Sensitive Path Detection
 * Identify sensitive files and directories
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>

#include "auris.h"
#include "dataflow.h"

/* Sensitive path pattern */
typedef struct {
    char pattern[MAX_PATH_LEN];
    sg_sensitivity_t level;
    const char *reason;
} sensitive_pattern_t;

/* Built-in sensitive patterns */
static const sensitive_pattern_t builtin_patterns[] = {
    /* SSH keys and config */
    {"*/.ssh/id_*", SENSITIVITY_CRITICAL, "SSH private key"},
    {"*/.ssh/authorized_keys", SENSITIVITY_HIGH, "SSH authorized keys"},
    {"*/.ssh/known_hosts", SENSITIVITY_MEDIUM, "SSH known hosts"},
    {"*/.ssh/config", SENSITIVITY_MEDIUM, "SSH configuration"},
    {"/etc/ssh/ssh_host_*_key", SENSITIVITY_CRITICAL, "SSH host private key"},
    
    /* GPG keys */
    {"*/.gnupg/private-keys*", SENSITIVITY_CRITICAL, "GPG private key"},
    {"*/.gnupg/secring.gpg", SENSITIVITY_CRITICAL, "GPG secret keyring"},
    {"*/.gnupg/trustdb.gpg", SENSITIVITY_HIGH, "GPG trust database"},
    
    /* Password and shadow files */
    {"/etc/passwd", SENSITIVITY_MEDIUM, "User account information"},
    {"/etc/shadow", SENSITIVITY_CRITICAL, "Password hashes"},
    {"/etc/gshadow", SENSITIVITY_CRITICAL, "Group password hashes"},
    {"/etc/master.passwd", SENSITIVITY_CRITICAL, "BSD password file"},
    
    /* Credential stores */
    {"*/.netrc", SENSITIVITY_CRITICAL, "FTP/network credentials"},
    {"*/.pgpass", SENSITIVITY_CRITICAL, "PostgreSQL credentials"},
    {"*/.my.cnf", SENSITIVITY_HIGH, "MySQL configuration/credentials"},
    {"*/.docker/config.json", SENSITIVITY_HIGH, "Docker credentials"},
    {"*/.kube/config", SENSITIVITY_HIGH, "Kubernetes credentials"},
    {"*/.aws/credentials", SENSITIVITY_CRITICAL, "AWS credentials"},
    {"*/.aws/config", SENSITIVITY_MEDIUM, "AWS configuration"},
    {"*/.azure/*", SENSITIVITY_HIGH, "Azure credentials"},
    {"*/.gcloud/*", SENSITIVITY_HIGH, "Google Cloud credentials"},
    
    /* Browser data */
    {"*/.mozilla/firefox/*/logins.json", SENSITIVITY_CRITICAL, "Firefox passwords"},
    {"*/.mozilla/firefox/*/cookies.sqlite", SENSITIVITY_HIGH, "Firefox cookies"},
    {"*/.config/google-chrome/*/Login Data", SENSITIVITY_CRITICAL, "Chrome passwords"},
    {"*/.config/google-chrome/*/Cookies", SENSITIVITY_HIGH, "Chrome cookies"},
    {"*/.config/chromium/*/Login Data", SENSITIVITY_CRITICAL, "Chromium passwords"},
    
    /* Application tokens */
    {"*/.npmrc", SENSITIVITY_HIGH, "NPM authentication token"},
    {"*/.pypirc", SENSITIVITY_HIGH, "PyPI credentials"},
    {"*/.gem/credentials", SENSITIVITY_HIGH, "RubyGems credentials"},
    {"*/.composer/auth.json", SENSITIVITY_HIGH, "Composer credentials"},
    {"*/.nuget/NuGet.Config", SENSITIVITY_MEDIUM, "NuGet configuration"},
    
    /* Git credentials */
    {"*/.git-credentials", SENSITIVITY_CRITICAL, "Git credentials"},
    {"*/.gitconfig", SENSITIVITY_LOW, "Git configuration"},
    
    /* Environment files */
    {"*/.env", SENSITIVITY_HIGH, "Environment variables"},
    {"*/.env.*", SENSITIVITY_HIGH, "Environment variables"},
    {"*.env", SENSITIVITY_MEDIUM, "Environment file"},
    
    /* Configuration with potential secrets */
    {"*/config.json", SENSITIVITY_MEDIUM, "Configuration file"},
    {"*/secrets.json", SENSITIVITY_CRITICAL, "Secrets file"},
    {"*/credentials.json", SENSITIVITY_CRITICAL, "Credentials file"},
    {"*/*secret*", SENSITIVITY_HIGH, "File with 'secret' in name"},
    {"*/*password*", SENSITIVITY_HIGH, "File with 'password' in name"},
    {"*/*credential*", SENSITIVITY_HIGH, "File with 'credential' in name"},
    {"*/*token*", SENSITIVITY_MEDIUM, "File with 'token' in name"},
    {"*/*apikey*", SENSITIVITY_HIGH, "File with 'apikey' in name"},
    {"*/*api_key*", SENSITIVITY_HIGH, "File with 'api_key' in name"},
    
    /* Certificate and key files */
    {"*.pem", SENSITIVITY_HIGH, "PEM certificate/key"},
    {"*.key", SENSITIVITY_CRITICAL, "Private key file"},
    {"*.p12", SENSITIVITY_CRITICAL, "PKCS#12 certificate"},
    {"*.pfx", SENSITIVITY_CRITICAL, "PFX certificate"},
    {"*.crt", SENSITIVITY_MEDIUM, "Certificate file"},
    {"*.cer", SENSITIVITY_MEDIUM, "Certificate file"},
    
    /* System configuration */
    {"/etc/sudoers", SENSITIVITY_HIGH, "Sudo configuration"},
    {"/etc/sudoers.d/*", SENSITIVITY_HIGH, "Sudo configuration"},
    {"/etc/pam.d/*", SENSITIVITY_MEDIUM, "PAM configuration"},
    {"/etc/security/*", SENSITIVITY_MEDIUM, "Security configuration"},
    
    /* Proc filesystem */
    {"/proc/*/environ", SENSITIVITY_HIGH, "Process environment"},
    {"/proc/*/cmdline", SENSITIVITY_MEDIUM, "Process command line"},
    {"/proc/*/mem", SENSITIVITY_CRITICAL, "Process memory"},
    {"/proc/*/maps", SENSITIVITY_MEDIUM, "Process memory maps"},
    
    /* Database files */
    {"*.sqlite", SENSITIVITY_MEDIUM, "SQLite database"},
    {"*.db", SENSITIVITY_MEDIUM, "Database file"},
    {"*.sql", SENSITIVITY_LOW, "SQL file"},
    
    /* Backup files that might contain secrets */
    {"*.bak", SENSITIVITY_LOW, "Backup file"},
    {"*.backup", SENSITIVITY_LOW, "Backup file"},
    {"*.old", SENSITIVITY_LOW, "Old file"},
    
    /* Sentinel */
    {"", SENSITIVITY_NONE, NULL}
};

/* Custom patterns (loaded at runtime) */
static sensitive_pattern_t *custom_patterns = NULL;
static size_t custom_pattern_count = 0;
static size_t custom_pattern_capacity = 0;

/*
 * Check if a path matches a pattern
 */
static bool path_matches(const char *path, const char *pattern)
{
    if (path == NULL || pattern == NULL) {
        return false;
    }
    
    return fnmatch(pattern, path, FNM_PATHNAME) == 0;
}

/*
 * Get sensitivity level for a path
 */
sg_sensitivity_t sg_path_sensitivity(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return SENSITIVITY_NONE;
    }
    
    sg_sensitivity_t max_level = SENSITIVITY_NONE;
    
    /* Check built-in patterns */
    for (size_t i = 0; builtin_patterns[i].pattern[0] != '\0'; i++) {
        if (path_matches(path, builtin_patterns[i].pattern)) {
            if (builtin_patterns[i].level > max_level) {
                max_level = builtin_patterns[i].level;
            }
        }
    }
    
    /* Check custom patterns */
    for (size_t i = 0; i < custom_pattern_count; i++) {
        if (path_matches(path, custom_patterns[i].pattern)) {
            if (custom_patterns[i].level > max_level) {
                max_level = custom_patterns[i].level;
            }
        }
    }
    
    return max_level;
}

/*
 * Check if path is sensitive
 */
bool sg_is_sensitive_path(const char *path)
{
    return sg_path_sensitivity(path) > SENSITIVITY_NONE;
}

/*
 * Get reason why a path is sensitive
 */
const char *sg_sensitive_path_reason(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return NULL;
    }
    
    sg_sensitivity_t max_level = SENSITIVITY_NONE;
    const char *reason = NULL;
    
    /* Check built-in patterns */
    for (size_t i = 0; builtin_patterns[i].pattern[0] != '\0'; i++) {
        if (path_matches(path, builtin_patterns[i].pattern)) {
            if (builtin_patterns[i].level > max_level) {
                max_level = builtin_patterns[i].level;
                reason = builtin_patterns[i].reason;
            }
        }
    }
    
    /* Check custom patterns */
    for (size_t i = 0; i < custom_pattern_count; i++) {
        if (path_matches(path, custom_patterns[i].pattern)) {
            if (custom_patterns[i].level > max_level) {
                max_level = custom_patterns[i].level;
                reason = custom_patterns[i].reason;
            }
        }
    }
    
    return reason;
}

/*
 * Add custom sensitive pattern
 */
sg_error_t sg_add_sensitive_pattern(const char *pattern,
                                     sg_sensitivity_t level,
                                     const char *reason)
{
    if (pattern == NULL || pattern[0] == '\0') {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Expand array if needed */
    if (custom_pattern_count >= custom_pattern_capacity) {
        size_t new_capacity = custom_pattern_capacity == 0 ? 16 : custom_pattern_capacity * 2;
        if (new_capacity > MAX_SENSITIVE_PATTERNS) {
            new_capacity = MAX_SENSITIVE_PATTERNS;
        }
        if (custom_pattern_count >= new_capacity) {
            return SG_ERR_LIMIT;
        }
        
        sensitive_pattern_t *new_patterns = realloc(custom_patterns,
                                                     new_capacity * sizeof(sensitive_pattern_t));
        if (new_patterns == NULL) {
            return SG_ERR_NOMEM;
        }
        
        custom_patterns = new_patterns;
        custom_pattern_capacity = new_capacity;
    }
    
    /* Add pattern */
    sensitive_pattern_t *p = &custom_patterns[custom_pattern_count];
    sg_safe_strncpy(p->pattern, pattern, sizeof(p->pattern));
    p->level = level;
    p->reason = reason ? strdup(reason) : NULL;
    
    custom_pattern_count++;
    
    return SG_OK;
}

/*
 * Load sensitive patterns from config file
 * Format: one pattern per line, with level and optional reason
 * Example: CRITICAL:HOME/.ssh/id_*:SSH private key
 */
sg_error_t sg_load_sensitive_patterns(const char *config_path)
{
    if (config_path == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    FILE *f = fopen(config_path, "r");
    if (f == NULL) {
        return SG_ERR_IO;
    }
    
    char line[MAX_PATH_LEN + 128];
    while (fgets(line, sizeof(line), f) != NULL) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        
        /* Parse level:pattern:reason */
        char *level_str = strtok(line, ":");
        char *pattern = strtok(NULL, ":");
        char *reason = strtok(NULL, "");
        
        if (level_str == NULL || pattern == NULL) {
            continue;
        }
        
        sg_sensitivity_t level = SENSITIVITY_MEDIUM;
        if (strcmp(level_str, "CRITICAL") == 0) {
            level = SENSITIVITY_CRITICAL;
        } else if (strcmp(level_str, "HIGH") == 0) {
            level = SENSITIVITY_HIGH;
        } else if (strcmp(level_str, "MEDIUM") == 0) {
            level = SENSITIVITY_MEDIUM;
        } else if (strcmp(level_str, "LOW") == 0) {
            level = SENSITIVITY_LOW;
        }
        
        sg_add_sensitive_pattern(pattern, level, reason);
    }
    
    fclose(f);
    
    return SG_OK;
}

/*
 * Clean up custom sensitive patterns
 * Should be called at program exit to free memory
 */
void sg_sensitive_patterns_cleanup(void)
{
    if (custom_patterns != NULL) {
        for (size_t i = 0; i < custom_pattern_count; i++) {
            /* Free the duplicated reason string */
            if (custom_patterns[i].reason != NULL) {
                free((void *)custom_patterns[i].reason);
            }
        }
        free(custom_patterns);
        custom_patterns = NULL;
    }
    custom_pattern_count = 0;
    custom_pattern_capacity = 0;
}
