#ifndef LIBINJECTION_HARNESS_H
#define LIBINJECTION_HARNESS_H

#include <stddef.h>

/**
 * Simplified C API for testing libinjection from Rust
 * These functions provide a stable interface for differential testing
 */

/**
 * SQL injection detection result
 */
typedef struct {
    int is_sqli;                    // 1 if SQL injection detected, 0 otherwise
    char fingerprint[16];           // Fingerprint string (null-terminated)
} sqli_result_t;

/**
 * XSS detection result  
 */
typedef struct {
    int is_xss;                     // 1 if XSS detected, 0 otherwise
} xss_result_t;

/**
 * Detect SQL injection in input
 * @param input Input string to test
 * @param input_len Length of input
 * @param flags Detection flags (0 for default)
 * @return Detection result
 */
sqli_result_t harness_detect_sqli(const char* input, size_t input_len, int flags);

/**
 * Detect XSS in input
 * @param input Input string to test
 * @param input_len Length of input
 * @param flags Detection flags (0 for default) 
 * @return Detection result
 */
xss_result_t harness_detect_xss(const char* input, size_t input_len, int flags);

/**
 * Get libinjection version string
 * @return Version string
 */
const char* harness_version(void);

#endif /* LIBINJECTION_HARNESS_H */