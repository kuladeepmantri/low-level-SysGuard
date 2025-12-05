/*
 * Auris - ARM Linux Syscall Tracer & Security Analyzer
 * Main header file with core type definitions and constants
 */

#ifndef AURIS_H
#define AURIS_H

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>

/* Version information */
#define AURIS_VERSION_MAJOR 2
#define AURIS_VERSION_MINOR 0
#define AURIS_VERSION_PATCH 0
#define AURIS_VERSION_STRING "2.0.0"

/* Limits and constants */
#define MAX_PATH_LEN 4096
#define MAX_SYSCALL_ARGS 6
#define MAX_SYSCALL_NAME_LEN 32
#define MAX_HOSTNAME_LEN 256
#define MAX_FD_TABLE_SIZE 1024
#define MAX_PROCESS_TREE_DEPTH 64
#define MAX_PATTERN_LENGTH 16
#define MAX_PATTERNS 256
#define MAX_GRAPH_NODES 10000
#define MAX_GRAPH_EDGES 50000
#define MAX_POLICY_RULES 1000
#define MAX_AI_RESPONSE_LEN (1024 * 1024)  /* 1MB */
#define MAX_TRACE_SYSCALLS (10 * 1000 * 1000)  /* 10M syscalls per trace */
#define MAX_SENSITIVE_PATTERNS 128
#define MAX_BASELINE_TRACES 100
#define MAX_ANOMALIES 1000
#define MAX_EXFIL_FLOWS 500

/* Error codes */
typedef enum {
    SG_OK = 0,
    SG_ERR_NOMEM = -1,
    SG_ERR_INVALID_ARG = -2,
    SG_ERR_IO = -3,
    SG_ERR_PARSE = -4,
    SG_ERR_SYSCALL = -5,
    SG_ERR_PTRACE = -6,
    SG_ERR_FORK = -7,
    SG_ERR_EXEC = -8,
    SG_ERR_SIGNAL = -9,
    SG_ERR_POLICY = -10,
    SG_ERR_AI = -11,
    SG_ERR_OVERFLOW = -12,
    SG_ERR_NOT_FOUND = -13,
    SG_ERR_PERMISSION = -14,
    SG_ERR_TIMEOUT = -15,
    SG_ERR_INTERNAL = -16,
    SG_ERR_CONFIG = -17,
    SG_ERR_LIMIT = -18,
} sg_error_t;

/* Log levels */
typedef enum {
    SG_LOG_TRACE = 0,
    SG_LOG_DEBUG = 1,
    SG_LOG_INFO = 2,
    SG_LOG_WARN = 3,
    SG_LOG_ERROR = 4,
    SG_LOG_FATAL = 5,
} sg_log_level_t;

/* Syscall argument types for decoding */
typedef enum {
    ARG_TYPE_NONE = 0,
    ARG_TYPE_INT,
    ARG_TYPE_UINT,
    ARG_TYPE_LONG,
    ARG_TYPE_ULONG,
    ARG_TYPE_PTR,
    ARG_TYPE_STR,
    ARG_TYPE_FD,
    ARG_TYPE_PATH,
    ARG_TYPE_SOCKADDR,
    ARG_TYPE_SIZE,
    ARG_TYPE_FLAGS,
    ARG_TYPE_MODE,
    ARG_TYPE_SIGNAL,
    ARG_TYPE_PID,
    ARG_TYPE_UID,
    ARG_TYPE_GID,
} sg_arg_type_t;

/* Sensitivity levels for files/data */
typedef enum {
    SENSITIVITY_NONE = 0,
    SENSITIVITY_LOW = 1,
    SENSITIVITY_MEDIUM = 2,
    SENSITIVITY_HIGH = 3,
    SENSITIVITY_CRITICAL = 4,
} sg_sensitivity_t;

/* Policy action types */
typedef enum {
    POLICY_ACTION_ALLOW = 0,
    POLICY_ACTION_LOG = 1,
    POLICY_ACTION_ALERT = 2,
    POLICY_ACTION_BLOCK = 3,
} sg_policy_action_t;

/* Enforcement modes */
typedef enum {
    ENFORCE_MODE_DISABLED = 0,
    ENFORCE_MODE_ALERT = 1,
    ENFORCE_MODE_BLOCK = 2,
} sg_enforce_mode_t;

/* Graph node types */
typedef enum {
    NODE_TYPE_PROCESS = 0,
    NODE_TYPE_FILE = 1,
    NODE_TYPE_SOCKET = 2,
    NODE_TYPE_PIPE = 3,
    NODE_TYPE_REMOTE_ENDPOINT = 4,
} sg_node_type_t;

/* Graph edge types */
typedef enum {
    EDGE_TYPE_READ = 0,
    EDGE_TYPE_WRITE = 1,
    EDGE_TYPE_OPEN = 2,
    EDGE_TYPE_CLOSE = 3,
    EDGE_TYPE_CONNECT = 4,
    EDGE_TYPE_ACCEPT = 5,
    EDGE_TYPE_SEND = 6,
    EDGE_TYPE_RECV = 7,
    EDGE_TYPE_FORK = 8,
    EDGE_TYPE_EXEC = 9,
    EDGE_TYPE_PIPE = 10,
    EDGE_TYPE_DUP = 11,
} sg_edge_type_t;

/* Anomaly types */
typedef enum {
    ANOMALY_NEW_SYSCALL = 0,
    ANOMALY_FREQ_SPIKE = 1,
    ANOMALY_FREQ_DROP = 2,
    ANOMALY_NEW_FILE = 3,
    ANOMALY_NEW_NETWORK = 4,
    ANOMALY_SENSITIVE_ACCESS = 5,
    ANOMALY_PRIVILEGE_CHANGE = 6,
    ANOMALY_SUSPICIOUS_SEQUENCE = 7,
    ANOMALY_EXFILTRATION = 8,
} sg_anomaly_type_t;

/* Forward declarations */
struct sg_syscall_event;
struct sg_trace;
struct sg_profile;
struct sg_policy;
struct sg_graph;
struct sg_ai_response;

/* Timestamp with nanosecond precision */
typedef struct {
    int64_t sec;
    int64_t nsec;
} sg_timestamp_t;

/* Network address (IPv4/IPv6) */
typedef struct {
    int family;  /* AF_INET or AF_INET6 */
    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    } addr;
    uint16_t port;
    char str[64];  /* String representation */
} sg_netaddr_t;

/* File descriptor info */
typedef struct {
    int fd;
    char path[MAX_PATH_LEN];
    sg_node_type_t type;
    sg_sensitivity_t sensitivity;
    sg_netaddr_t remote;  /* For sockets */
    bool is_open;
    uint64_t bytes_read;
    uint64_t bytes_written;
} sg_fd_info_t;

/* Syscall argument value */
typedef struct {
    sg_arg_type_t type;
    union {
        int64_t i64;
        uint64_t u64;
        void *ptr;
        char str[MAX_PATH_LEN];
        sg_netaddr_t addr;
    } value;
    bool valid;
} sg_arg_value_t;

/* Single syscall event */
typedef struct sg_syscall_event {
    uint32_t id;                          /* Event sequence number */
    pid_t pid;                            /* Process ID */
    pid_t tid;                            /* Thread ID */
    pid_t ppid;                           /* Parent process ID */
    uint32_t syscall_nr;                  /* ARM64 syscall number */
    char syscall_name[MAX_SYSCALL_NAME_LEN];
    sg_arg_value_t args[MAX_SYSCALL_ARGS];
    int64_t ret_value;                    /* Return value */
    int err_no;                           /* errno if failed */
    sg_timestamp_t entry_time;            /* Syscall entry timestamp */
    sg_timestamp_t exit_time;             /* Syscall exit timestamp */
    uint64_t duration_ns;                 /* Duration in nanoseconds */
    bool is_entry;                        /* Entry or exit event */
    sg_sensitivity_t sensitivity;         /* Sensitivity of accessed resource */
    char comm[16];                        /* Process name */
} sg_syscall_event_t;

/* Trace metadata */
typedef struct {
    char trace_id[64];                    /* Unique trace identifier */
    char binary_path[MAX_PATH_LEN];       /* Path to traced binary */
    char binary_hash[65];                 /* SHA256 of binary */
    char hostname[MAX_HOSTNAME_LEN];
    char **argv;                          /* Command line arguments */
    int argc;
    char **envp;                          /* Environment (filtered) */
    int envc;
    sg_timestamp_t start_time;
    sg_timestamp_t end_time;
    pid_t root_pid;
    int exit_code;
    uint64_t total_syscalls;
    char auris_version[16];
} sg_trace_meta_t;

/* Complete trace */
typedef struct sg_trace {
    sg_trace_meta_t meta;
    sg_syscall_event_t *events;
    size_t event_count;
    size_t event_capacity;
    sg_fd_info_t fd_table[MAX_FD_TABLE_SIZE];
} sg_trace_t;

/* Syscall frequency statistics */
typedef struct {
    uint32_t syscall_nr;
    char name[MAX_SYSCALL_NAME_LEN];
    uint64_t count;
    double frequency;                     /* Percentage of total */
    uint64_t total_duration_ns;
    uint64_t min_duration_ns;
    uint64_t max_duration_ns;
    double avg_duration_ns;
} sg_syscall_stats_t;

/* Syscall sequence pattern */
typedef struct {
    uint32_t pattern[MAX_PATTERN_LENGTH];
    size_t length;
    uint64_t occurrences;
    double frequency;
} sg_pattern_t;

/* Behavioral profile */
typedef struct sg_profile {
    char profile_id[64];
    char binary_path[MAX_PATH_LEN];
    char binary_hash[65];
    
    /* Syscall statistics */
    sg_syscall_stats_t *syscall_stats;
    size_t syscall_count;
    uint64_t total_syscalls;
    
    /* Unique syscalls observed */
    uint32_t *unique_syscalls;
    size_t unique_count;
    
    /* Temporal patterns */
    sg_pattern_t *patterns;
    size_t pattern_count;
    
    /* High-level behavioral flags */
    bool does_network_io;
    bool does_file_io;
    bool spawns_children;
    bool changes_privileges;
    bool accesses_sensitive_files;
    bool uses_crypto;
    
    /* File access patterns */
    char **accessed_files;
    size_t file_count;
    
    /* Network endpoints */
    sg_netaddr_t *network_endpoints;
    size_t endpoint_count;
    
    /* Baseline traces used */
    char **baseline_trace_ids;
    size_t baseline_count;
    
    /* Timestamps */
    sg_timestamp_t created;
    sg_timestamp_t updated;
} sg_profile_t;

/* Anomaly detection result */
typedef struct {
    sg_anomaly_type_t type;
    char description[256];
    double severity;                      /* 0.0 - 1.0 */
    uint32_t syscall_nr;                  /* Related syscall if applicable */
    char related_path[MAX_PATH_LEN];      /* Related file/endpoint */
    uint64_t event_id;                    /* Related event ID */
    double baseline_value;                /* Expected value */
    double observed_value;                /* Actual value */
} sg_anomaly_t;

/* Comparison result */
typedef struct {
    char trace_id[64];
    char profile_id[64];
    sg_anomaly_t *anomalies;
    size_t anomaly_count;
    double overall_deviation;             /* 0.0 - 1.0 */
    double risk_score;                    /* 0.0 - 1.0 */
    bool is_anomalous;
} sg_comparison_t;

/* Policy rule */
typedef struct {
    uint32_t syscall_nr;
    char syscall_name[MAX_SYSCALL_NAME_LEN];
    sg_policy_action_t action;
    char path_pattern[MAX_PATH_LEN];      /* Optional path filter */
    bool enabled;
    uint64_t hit_count;
    char reason[128];
} sg_policy_rule_t;

/* Security policy */
typedef struct sg_policy {
    char policy_id[64];
    char profile_id[64];
    char binary_path[MAX_PATH_LEN];
    sg_policy_rule_t *rules;
    size_t rule_count;
    sg_enforce_mode_t default_mode;
    bool allow_unknown;                   /* Allow syscalls not in policy */
    sg_timestamp_t created;
    sg_timestamp_t updated;
    char description[256];
} sg_policy_t;

/* Graph node */
typedef struct {
    uint32_t id;
    sg_node_type_t type;
    char label[MAX_PATH_LEN];
    pid_t pid;                            /* For process nodes */
    sg_netaddr_t addr;                    /* For network nodes */
    sg_sensitivity_t sensitivity;
    uint64_t first_seen;                  /* Event ID */
    uint64_t last_seen;
    uint32_t in_degree;
    uint32_t out_degree;
} sg_graph_node_t;

/* Graph edge */
typedef struct {
    uint32_t id;
    uint32_t source;                      /* Node ID */
    uint32_t target;                      /* Node ID */
    sg_edge_type_t type;
    uint64_t event_id;                    /* Related syscall event */
    sg_timestamp_t timestamp;
    uint64_t bytes;                       /* Data transferred */
    char label[64];
} sg_graph_edge_t;

/* Activity graph */
typedef struct sg_graph {
    char graph_id[64];
    char trace_id[64];
    sg_graph_node_t *nodes;
    size_t node_count;
    size_t node_capacity;
    sg_graph_edge_t *edges;
    size_t edge_count;
    size_t edge_capacity;
    /* Adjacency list for efficient traversal */
    uint32_t **adj_list;
    size_t *adj_sizes;
} sg_graph_t;

/* Potential exfiltration flow */
typedef struct {
    uint32_t source_node;                 /* Sensitive file node */
    uint32_t sink_node;                   /* Network endpoint node */
    char source_path[MAX_PATH_LEN];
    sg_netaddr_t sink_addr;
    sg_sensitivity_t sensitivity;
    uint64_t bytes_transferred;
    uint64_t *event_chain;                /* Sequence of event IDs */
    size_t chain_length;
    double confidence;                    /* 0.0 - 1.0 */
} sg_exfil_flow_t;

/* Data flow analysis result */
typedef struct {
    sg_exfil_flow_t *flows;
    size_t flow_count;
    double overall_risk;
    bool has_high_risk_flows;
} sg_dataflow_result_t;

/* AI analysis request */
typedef struct {
    char *profile_json;
    char *trace_json;
    char *graph_json;
    char *anomalies_json;
    char *dataflow_json;
    char prompt_template[1024];
} sg_ai_request_t;

/* AI analysis response */
typedef struct sg_ai_response {
    char *analysis;                       /* Natural language analysis */
    double risk_score;                    /* 0.0 - 1.0 */
    char risk_level[16];                  /* low/medium/high/critical */
    char *recommendations;
    bool success;
    char error[256];
} sg_ai_response_t;

/* AI client configuration */
typedef struct {
    char endpoint[512];
    char api_key[256];
    char model[64];
    int timeout_sec;
    int max_retries;
    bool enabled;
} sg_ai_config_t;

/* Global configuration */
typedef struct {
    char data_dir[MAX_PATH_LEN];          /* Directory for traces/profiles */
    char config_file[MAX_PATH_LEN];
    sg_log_level_t log_level;
    bool log_to_file;
    char log_file[MAX_PATH_LEN];
    sg_ai_config_t ai;
    bool follow_forks;
    bool decode_strings;
    size_t max_string_len;
    bool include_env;
    char **env_filter;                    /* Env vars to exclude */
    size_t env_filter_count;
} sg_config_t;

/* CLI command types */
typedef enum {
    CMD_NONE = 0,
    CMD_LEARN,
    CMD_PROFILE,
    CMD_COMPARE,
    CMD_POLICY,
    CMD_ENFORCE,
    CMD_ANALYZE,
    CMD_INJECT,      /* v2: Process injection framework */
    CMD_HELP,
    CMD_VERSION,
} sg_command_t;

/* CLI options */
typedef struct {
    sg_command_t command;
    char binary_path[MAX_PATH_LEN];
    char **binary_argv;
    int binary_argc;
    char trace_id[64];
    char profile_id[64];
    char policy_id[64];
    char output_path[MAX_PATH_LEN];
    sg_enforce_mode_t enforce_mode;
    bool verbose;
    bool quiet;
    bool json_output;
    bool force;
    sg_config_t config;
} sg_cli_opts_t;

/* Function declarations - see individual headers for details */

/* Error handling */
const char *sg_strerror(sg_error_t err);
void sg_perror(const char *prefix, sg_error_t err);

/* Logging */
void sg_log_init(sg_log_level_t level, const char *file);
void sg_log(sg_log_level_t level, const char *fmt, ...);
void sg_log_cleanup(void);

/* Utility functions */
sg_timestamp_t sg_now(void);
int64_t sg_timestamp_diff_ns(sg_timestamp_t a, sg_timestamp_t b);
char *sg_generate_id(char *buf, size_t len);
int sg_hash_file(const char *path, char *hash_out, size_t hash_len);
bool sg_path_exists(const char *path);
bool sg_is_directory(const char *path);
int sg_mkdir_p(const char *path, mode_t mode);
char *sg_read_file(const char *path, size_t *len);
int sg_write_file(const char *path, const void *data, size_t len);
void sg_safe_strncpy(char *dst, const char *src, size_t n);

#endif /* AURIS_H */
