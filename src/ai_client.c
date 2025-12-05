/*
 * Auris - AI Analysis Client
 * Integration with local LLM service for security analysis
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>

#include "auris.h"
#include "ai_client.h"

/* Response buffer for CURL */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} response_buffer_t;

/*
 * CURL write callback
 */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    response_buffer_t *buf = (response_buffer_t *)userp;
    
    /* Check for integer overflow in size calculation */
    if (size > 0 && nmemb > SIZE_MAX / size) {
        return 0;  /* Overflow would occur */
    }
    size_t realsize = size * nmemb;
    
    /* Check for overflow in buffer size calculation */
    if (buf->size > SIZE_MAX - realsize - 1) {
        return 0;  /* Overflow would occur */
    }
    
    /* Expand buffer if needed */
    if (buf->size + realsize + 1 > buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        if (new_capacity < buf->size + realsize + 1) {
            new_capacity = buf->size + realsize + 1;
        }
        if (new_capacity > MAX_AI_RESPONSE_LEN) {
            return 0;  /* Response too large */
        }
        
        char *new_data = realloc(buf->data, new_capacity);
        if (new_data == NULL) {
            return 0;
        }
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    
    memcpy(buf->data + buf->size, contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = '\0';
    
    return realsize;
}

/*
 * Set default AI configuration
 */
void sg_ai_config_defaults(sg_ai_config_t *config)
{
    if (config == NULL) {
        return;
    }
    
    memset(config, 0, sizeof(*config));
    sg_safe_strncpy(config->endpoint, "http://localhost:11434/api/generate",
                    sizeof(config->endpoint));
    sg_safe_strncpy(config->model, "llama2", sizeof(config->model));
    config->timeout_sec = 60;
    config->max_retries = 3;
    config->enabled = false;  /* Disabled by default */
}

/*
 * Initialize AI client
 */
sg_error_t sg_ai_client_init(sg_ai_client_t *client, const sg_ai_config_t *config)
{
    if (client == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    memset(client, 0, sizeof(*client));
    
    if (config != NULL) {
        client->config = *config;
    } else {
        sg_ai_config_defaults(&client->config);
    }
    
    if (!client->config.enabled) {
        client->initialized = true;
        return SG_OK;
    }
    
    /* Initialize CURL */
    client->curl_handle = curl_easy_init();
    if (client->curl_handle == NULL) {
        sg_log(SG_LOG_ERROR, "Failed to initialize CURL");
        return SG_ERR_AI;
    }
    
    client->initialized = true;
    
    return SG_OK;
}

/*
 * Clean up AI client
 */
void sg_ai_client_cleanup(sg_ai_client_t *client)
{
    if (client == NULL) {
        return;
    }
    
    if (client->curl_handle != NULL) {
        curl_easy_cleanup(client->curl_handle);
        client->curl_handle = NULL;
    }
    
    client->initialized = false;
}

/*
 * Check if AI service is available
 */
bool sg_ai_client_available(sg_ai_client_t *client)
{
    if (client == NULL || !client->initialized || !client->config.enabled) {
        return false;
    }
    
    return client->curl_handle != NULL;
}

/*
 * Test connection to AI service
 */
sg_error_t sg_ai_client_test(sg_ai_client_t *client)
{
    if (client == NULL || !client->initialized) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (!client->config.enabled) {
        return SG_ERR_AI;
    }
    
    /* Simple test request */
    CURL *curl = client->curl_handle;
    if (curl == NULL) {
        return SG_ERR_AI;
    }
    
    response_buffer_t response = {0};
    response.data = malloc(1024);
    if (response.data == NULL) {
        return SG_ERR_NOMEM;
    }
    response.capacity = 1024;
    
    /* Build test request */
    struct json_object *req = json_object_new_object();
    json_object_object_add(req, "model", json_object_new_string(client->config.model));
    json_object_object_add(req, "prompt", json_object_new_string("Hello"));
    json_object_object_add(req, "stream", json_object_new_boolean(false));
    
    const char *req_str = json_object_to_json_string(req);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, client->config.endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    json_object_put(req);
    free(response.data);
    
    if (res != CURLE_OK) {
        sg_log(SG_LOG_DEBUG, "AI service test failed: %s", curl_easy_strerror(res));
        return SG_ERR_AI;
    }
    
    return SG_OK;
}

/*
 * Send request to AI service
 */
static sg_error_t send_ai_request(sg_ai_client_t *client,
                                   const char *prompt,
                                   sg_ai_response_t **response_out)
{
    if (client == NULL || prompt == NULL || response_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    if (!client->config.enabled || client->curl_handle == NULL) {
        sg_ai_response_t *resp = calloc(1, sizeof(sg_ai_response_t));
        if (resp == NULL) {
            return SG_ERR_NOMEM;
        }
        resp->success = false;
        sg_safe_strncpy(resp->error, "AI service not enabled", sizeof(resp->error));
        *response_out = resp;
        return SG_ERR_AI;
    }
    
    CURL *curl = client->curl_handle;
    
    response_buffer_t response = {0};
    response.data = malloc(4096);
    if (response.data == NULL) {
        return SG_ERR_NOMEM;
    }
    response.capacity = 4096;
    
    /* Build request */
    struct json_object *req = json_object_new_object();
    json_object_object_add(req, "model", json_object_new_string(client->config.model));
    json_object_object_add(req, "prompt", json_object_new_string(prompt));
    json_object_object_add(req, "stream", json_object_new_boolean(false));
    
    const char *req_str = json_object_to_json_string(req);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    if (client->config.api_key[0] != '\0') {
        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s",
                 client->config.api_key);
        headers = curl_slist_append(headers, auth_header);
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, client->config.endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)client->config.timeout_sec);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    json_object_put(req);
    
    /* Allocate response */
    sg_ai_response_t *ai_resp = calloc(1, sizeof(sg_ai_response_t));
    if (ai_resp == NULL) {
        free(response.data);
        return SG_ERR_NOMEM;
    }
    
    if (res != CURLE_OK) {
        ai_resp->success = false;
        snprintf(ai_resp->error, sizeof(ai_resp->error),
                 "Request failed: %s", curl_easy_strerror(res));
        free(response.data);
        *response_out = ai_resp;
        return SG_ERR_AI;
    }
    
    /* Parse response */
    struct json_object *resp_json = json_tokener_parse(response.data);
    free(response.data);
    
    if (resp_json == NULL) {
        ai_resp->success = false;
        sg_safe_strncpy(ai_resp->error, "Failed to parse response", sizeof(ai_resp->error));
        *response_out = ai_resp;
        return SG_ERR_PARSE;
    }
    
    struct json_object *resp_text;
    if (json_object_object_get_ex(resp_json, "response", &resp_text)) {
        ai_resp->analysis = strdup(json_object_get_string(resp_text));
        ai_resp->success = true;
        
        /* Try to extract risk score from response */
        ai_resp->risk_score = sg_ai_parse_risk_score(ai_resp->analysis);
        sg_safe_strncpy(ai_resp->risk_level, sg_ai_parse_risk_level(ai_resp->analysis),
                        sizeof(ai_resp->risk_level));
    } else {
        ai_resp->success = false;
        sg_safe_strncpy(ai_resp->error, "No response field in reply", sizeof(ai_resp->error));
    }
    
    json_object_put(resp_json);
    
    *response_out = ai_resp;
    return ai_resp->success ? SG_OK : SG_ERR_AI;
}

/*
 * Generate profile analysis prompt
 */
char *sg_ai_prompt_profile(const sg_profile_t *profile)
{
    if (profile == NULL) {
        return NULL;
    }
    
    char *profile_json = sg_profile_to_json(profile);
    if (profile_json == NULL) {
        return NULL;
    }
    
    size_t prompt_size = strlen(profile_json) + 2048;
    char *prompt = malloc(prompt_size);
    if (prompt == NULL) {
        free(profile_json);
        return NULL;
    }
    
    snprintf(prompt, prompt_size,
             "You are a security analyst reviewing a behavioral profile of a Linux program. "
             "Analyze the following profile and provide:\n"
             "1. A brief description of what the program appears to do\n"
             "2. Any security concerns based on the syscalls used\n"
             "3. A risk assessment (low/medium/high/critical)\n"
             "4. Recommendations for security hardening\n\n"
             "Profile:\n%s\n\n"
             "Provide your analysis in a clear, structured format.",
             profile_json);
    
    free(profile_json);
    return prompt;
}

/*
 * Generate comparison analysis prompt
 */
char *sg_ai_prompt_comparison(const sg_profile_t *baseline,
                               const sg_trace_t *trace,
                               const sg_comparison_t *comparison)
{
    if (comparison == NULL) {
        return NULL;
    }
    
    char *comparison_json = sg_comparison_to_json(comparison);
    if (comparison_json == NULL) {
        return NULL;
    }
    
    size_t prompt_size = strlen(comparison_json) + 4096;
    char *prompt = malloc(prompt_size);
    if (prompt == NULL) {
        free(comparison_json);
        return NULL;
    }
    
    snprintf(prompt, prompt_size,
             "You are a security analyst comparing a program's current behavior against its baseline. "
             "Analyze the following comparison results and provide:\n"
             "1. Summary of behavioral changes detected\n"
             "2. Assessment of whether changes are suspicious\n"
             "3. Risk score (0.0-1.0) and risk level (low/medium/high/critical)\n"
             "4. Recommended actions\n\n"
             "Comparison Results:\n%s\n\n"
             "Binary: %s\n"
             "Provide your analysis in a clear, structured format. "
             "Include 'RISK_SCORE: X.X' and 'RISK_LEVEL: level' in your response.",
             comparison_json,
             baseline ? baseline->binary_path : "unknown");
    
    free(comparison_json);
    (void)trace;  /* May be used for additional context */
    return prompt;
}

/*
 * Analyze profile
 */
sg_error_t sg_ai_analyze_profile(sg_ai_client_t *client,
                                  const sg_profile_t *profile,
                                  sg_ai_response_t **response_out)
{
    if (client == NULL || profile == NULL || response_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    char *prompt = sg_ai_prompt_profile(profile);
    if (prompt == NULL) {
        return SG_ERR_NOMEM;
    }
    
    sg_error_t err = send_ai_request(client, prompt, response_out);
    free(prompt);
    
    return err;
}

/*
 * Analyze comparison
 */
sg_error_t sg_ai_analyze_comparison(sg_ai_client_t *client,
                                     const sg_profile_t *baseline,
                                     const sg_trace_t *trace,
                                     const sg_comparison_t *comparison,
                                     sg_ai_response_t **response_out)
{
    if (client == NULL || comparison == NULL || response_out == NULL) {
        return SG_ERR_INVALID_ARG;
    }
    
    char *prompt = sg_ai_prompt_comparison(baseline, trace, comparison);
    if (prompt == NULL) {
        return SG_ERR_NOMEM;
    }
    
    sg_error_t err = send_ai_request(client, prompt, response_out);
    free(prompt);
    
    return err;
}

/*
 * Free AI response
 */
void sg_ai_response_free(sg_ai_response_t *response)
{
    if (response == NULL) {
        return;
    }
    
    if (response->analysis != NULL) {
        free(response->analysis);
    }
    if (response->recommendations != NULL) {
        free(response->recommendations);
    }
    free(response);
}

/*
 * Parse risk score from response
 */
double sg_ai_parse_risk_score(const char *response)
{
    if (response == NULL) {
        return 0.0;
    }
    
    /* Look for "RISK_SCORE: X.X" pattern */
    const char *score_str = strstr(response, "RISK_SCORE:");
    if (score_str != NULL) {
        double score = 0.0;
        if (sscanf(score_str + 11, "%lf", &score) == 1) {
            if (score >= 0.0 && score <= 1.0) {
                return score;
            }
        }
    }
    
    /* Try alternative patterns */
    score_str = strstr(response, "risk score");
    if (score_str != NULL) {
        double score = 0.0;
        /* Look for number after "risk score" */
        const char *p = score_str + 10;
        while (*p && (*p < '0' || *p > '9') && *p != '.') p++;
        if (sscanf(p, "%lf", &score) == 1) {
            if (score >= 0.0 && score <= 1.0) {
                return score;
            }
        }
    }
    
    return 0.5;  /* Default to medium */
}

/*
 * Parse risk level from response
 */
const char *sg_ai_parse_risk_level(const char *response)
{
    if (response == NULL) {
        return "unknown";
    }
    
    /* Look for "RISK_LEVEL: level" pattern */
    const char *level_str = strstr(response, "RISK_LEVEL:");
    if (level_str != NULL) {
        level_str += 11;
        while (*level_str == ' ') level_str++;
        
        if (strncasecmp(level_str, "critical", 8) == 0) return "critical";
        if (strncasecmp(level_str, "high", 4) == 0) return "high";
        if (strncasecmp(level_str, "medium", 6) == 0) return "medium";
        if (strncasecmp(level_str, "low", 3) == 0) return "low";
    }
    
    /* Try to infer from content */
    if (strcasestr(response, "critical") != NULL) return "critical";
    if (strcasestr(response, "high risk") != NULL) return "high";
    if (strcasestr(response, "medium risk") != NULL) return "medium";
    if (strcasestr(response, "low risk") != NULL) return "low";
    
    return "unknown";
}

/*
 * Serialize AI response to JSON
 */
char *sg_ai_response_to_json(const sg_ai_response_t *response)
{
    if (response == NULL) {
        return NULL;
    }
    
    struct json_object *obj = json_object_new_object();
    
    json_object_object_add(obj, "success", json_object_new_boolean(response->success));
    json_object_object_add(obj, "risk_score", json_object_new_double(response->risk_score));
    json_object_object_add(obj, "risk_level", json_object_new_string(response->risk_level));
    
    if (response->analysis != NULL) {
        json_object_object_add(obj, "analysis", json_object_new_string(response->analysis));
    }
    if (response->error[0] != '\0') {
        json_object_object_add(obj, "error", json_object_new_string(response->error));
    }
    
    const char *json_str = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    char *result = strdup(json_str);
    
    json_object_put(obj);
    
    return result;
}
