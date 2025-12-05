/*
 * Auris - Utility Functions
 * Common helper functions used throughout the codebase
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>

#include "auris.h"

/*
 * Get current timestamp with nanosecond precision
 */
sg_timestamp_t sg_now(void)
{
    sg_timestamp_t ts;
    struct timespec spec;
    
    if (clock_gettime(CLOCK_REALTIME, &spec) == 0) {
        ts.sec = spec.tv_sec;
        ts.nsec = spec.tv_nsec;
    } else {
        ts.sec = time(NULL);
        ts.nsec = 0;
    }
    
    return ts;
}

/*
 * Calculate difference between timestamps in nanoseconds
 */
int64_t sg_timestamp_diff_ns(sg_timestamp_t a, sg_timestamp_t b)
{
    int64_t diff_sec = a.sec - b.sec;
    int64_t diff_nsec = a.nsec - b.nsec;
    
    return diff_sec * 1000000000LL + diff_nsec;
}

/*
 * Generate a unique ID (UUID-like)
 */
char *sg_generate_id(char *buf, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    
    if (buf == NULL || len < 37) {
        return NULL;
    }
    
    /* Read random bytes */
    unsigned char random[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        /* Fallback to time-based */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        memcpy(random, &ts, sizeof(ts) < 16 ? sizeof(ts) : 16);
        random[0] ^= (unsigned char)getpid();
    } else {
        ssize_t n = read(fd, random, sizeof(random));
        close(fd);
        if (n != sizeof(random)) {
            /* Partial read, mix with time */
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            for (size_t i = 0; i < sizeof(ts) && i < 16; i++) {
                random[i] ^= ((unsigned char *)&ts)[i];
            }
        }
    }
    
    /* Set version (4) and variant bits */
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    
    /* Format as UUID */
    int pos = 0;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            buf[pos++] = '-';
        }
        buf[pos++] = hex[(random[i] >> 4) & 0x0f];
        buf[pos++] = hex[random[i] & 0x0f];
    }
    buf[pos] = '\0';
    
    return buf;
}

/*
 * Compute SHA256 hash of a file using EVP API (OpenSSL 3.0+)
 */
int sg_hash_file(const char *path, char *hash_out, size_t hash_len)
{
    if (path == NULL || hash_out == NULL || hash_len < 65) {
        return SG_ERR_INVALID_ARG;
    }
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        /* File doesn't exist or can't be read - return empty hash */
        hash_out[0] = '\0';
        return SG_OK;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        close(fd);
        return SG_ERR_INTERNAL;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        return SG_ERR_INTERNAL;
    }
    
    unsigned char buffer[8192];
    ssize_t n;
    
    while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, (size_t)n) != 1) {
            EVP_MD_CTX_free(ctx);
            close(fd);
            return SG_ERR_INTERNAL;
        }
    }
    
    close(fd);
    
    if (n < 0) {
        EVP_MD_CTX_free(ctx);
        return SG_ERR_IO;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_size;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_size) != 1) {
        EVP_MD_CTX_free(ctx);
        return SG_ERR_INTERNAL;
    }
    
    EVP_MD_CTX_free(ctx);
    
    /* Convert to hex string */
    static const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < hash_size && i < 32; i++) {
        hash_out[i * 2] = hex[(hash[i] >> 4) & 0x0f];
        hash_out[i * 2 + 1] = hex[hash[i] & 0x0f];
    }
    hash_out[64] = '\0';
    
    return SG_OK;
}

/*
 * Check if a path exists
 */
bool sg_path_exists(const char *path)
{
    if (path == NULL) {
        return false;
    }
    
    struct stat st;
    return stat(path, &st) == 0;
}

/*
 * Check if a path is a directory
 */
bool sg_is_directory(const char *path)
{
    if (path == NULL) {
        return false;
    }
    
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    
    return S_ISDIR(st.st_mode);
}

/*
 * Create directory and all parent directories
 */
int sg_mkdir_p(const char *path, mode_t mode)
{
    if (path == NULL || path[0] == '\0') {
        return SG_ERR_INVALID_ARG;
    }
    
    /* Make a mutable copy */
    size_t len = strlen(path);
    if (len >= MAX_PATH_LEN) {
        return SG_ERR_OVERFLOW;
    }
    
    char tmp[MAX_PATH_LEN];
    memcpy(tmp, path, len + 1);
    
    /* Remove trailing slash */
    if (len > 1 && tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }
    
    /* Create each component */
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return SG_ERR_IO;
            }
            
            *p = '/';
        }
    }
    
    /* Create final directory */
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        return SG_ERR_IO;
    }
    
    return SG_OK;
}

/*
 * Read entire file into memory
 */
char *sg_read_file(const char *path, size_t *len)
{
    if (path == NULL) {
        return NULL;
    }
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }
    
    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return NULL;
    }
    
    size_t size = (size_t)st.st_size;
    
    /* Allocate buffer with space for null terminator */
    char *buf = malloc(size + 1);
    if (buf == NULL) {
        close(fd);
        return NULL;
    }
    
    /* Read file */
    size_t total = 0;
    while (total < size) {
        ssize_t n = read(fd, buf + total, size - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(buf);
            close(fd);
            return NULL;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }
    
    close(fd);
    
    buf[total] = '\0';
    
    if (len != NULL) {
        *len = total;
    }
    
    return buf;
}

/*
 * Write data to file
 */
int sg_write_file(const char *path, const void *data, size_t len)
{
    if (path == NULL || (data == NULL && len > 0)) {
        return SG_ERR_INVALID_ARG;
    }
    
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return SG_ERR_IO;
    }
    
    const char *ptr = data;
    size_t remaining = len;
    
    while (remaining > 0) {
        ssize_t n = write(fd, ptr, remaining);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return SG_ERR_IO;
        }
        ptr += n;
        remaining -= (size_t)n;
    }
    
    if (close(fd) != 0) {
        return SG_ERR_IO;
    }
    
    return SG_OK;
}

/*
 * Safe string copy with guaranteed null termination
 */
void sg_safe_strncpy(char *dst, const char *src, size_t n)
{
    if (dst == NULL || n == 0) {
        return;
    }
    
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    
    size_t i;
    for (i = 0; i < n - 1 && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}
