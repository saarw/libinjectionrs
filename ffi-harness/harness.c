#include "harness.h"
#include "libinjection.h"
#include "libinjection_sqli.h"
#include "libinjection_xss.h"
#include <string.h>

sqli_result_t harness_detect_sqli(const char* input, size_t input_len, int flags) {
    sqli_result_t result = {0};
    struct libinjection_sqli_state state;
    
    // Initialize state
    libinjection_sqli_init(&state, input, input_len, flags);
    
    // Detect SQL injection
    result.is_sqli = libinjection_is_sqli(&state);
    
    // Always get fingerprint from state, regardless of injection status
    // Copy fingerprint and ensure null termination
    memcpy(result.fingerprint, state.fingerprint, 8);
    result.fingerprint[8] = '\0';
    
    // Find actual end of fingerprint (remove trailing nulls)
    int end = 7;
    while (end >= 0 && result.fingerprint[end] == '\0') {
        end--;
    }
    if (end >= 0) {
        result.fingerprint[end + 1] = '\0';
    } else {
        result.fingerprint[0] = '\0';
    }
    
    return result;
}

xss_result_t harness_detect_xss(const char* input, size_t input_len, int flags) {
    xss_result_t result = {0};
    
    // Detect XSS
    result.is_xss = libinjection_xss(input, input_len);
    
    // Note: flags parameter currently unused but kept for API consistency
    (void)flags;
    
    return result;
}

const char* harness_version(void) {
    return libinjection_version();
}