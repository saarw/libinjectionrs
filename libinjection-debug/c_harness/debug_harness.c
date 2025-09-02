#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define LIBINJECTION_VERSION "dev"
#include "../../libinjection-c/src/libinjection.h"
#include "../../libinjection-c/src/libinjection_sqli.c"

const char *token_type_to_string(char type) {
    switch(type) {
        case TYPE_NONE: return "NONE";
        case TYPE_KEYWORD: return "KEYWORD"; 
        case TYPE_UNION: return "UNION";
        case TYPE_GROUP: return "GROUP";
        case TYPE_EXPRESSION: return "EXPRESSION";
        case TYPE_SQLTYPE: return "SQLTYPE";
        case TYPE_FUNCTION: return "FUNCTION";
        case TYPE_BAREWORD: return "BAREWORD";
        case TYPE_NUMBER: return "NUMBER";
        case TYPE_VARIABLE: return "VARIABLE";
        case TYPE_STRING: return "STRING";
        case TYPE_OPERATOR: return "OPERATOR";
        case TYPE_COMMENT: return "COMMENT";
        case TYPE_COLLATE: return "COLLATE";
        case TYPE_SEMICOLON: return "SEMICOLON";
        case TYPE_LEFTPARENS: return "LEFTPARENS";
        case TYPE_RIGHTPARENS: return "RIGHTPARENS";
        case TYPE_LEFTBRACE: return "LEFTBRACE";
        case TYPE_RIGHTBRACE: return "RIGHTBRACE";
        case TYPE_DOT: return "DOT";
        case TYPE_COMMA: return "COMMA";
        case TYPE_COLON: return "COLON";
        case TYPE_BACKSLASH: return "BACKSLASH";
        case TYPE_UNKNOWN: return "UNKNOWN";
        case TYPE_EVIL: return "EVIL";
        case TYPE_FINGERPRINT: return "FINGERPRINT";
        default: return "INVALID";
    }
}

const char *char_type_to_string(unsigned char ch) {
    // Use the actual libinjection character dispatch table
    extern const pt2Function char_parse_map[];
    pt2Function parser = char_parse_map[ch];
    
    // Map parser functions to human-readable names
    if (parser == &parse_white) return "WHITE";
    if (parser == &parse_hash) return "HASH";
    if (parser == &parse_string) return "STRING";
    if (parser == &parse_tick) return "TICK";
    if (parser == &parse_var) return "VARIABLE";
    if (parser == &parse_word) return "WORD";
    if (parser == &parse_bword) return "BWORD";
    if (parser == &parse_number) return "NUMBER";
    if (parser == &parse_operator1) return "OP1";
    if (parser == &parse_operator2) return "OP2";
    if (parser == &parse_char) return "LEFTPARENS";
    if (parser == &parse_dash) return "DASH";
    if (parser == &parse_slash) return "SLASH";
    if (parser == &parse_backslash) return "BACKSLASH";
    if (parser == &parse_money) return "MONEY";
    if (parser == &parse_ustring) return "USTRING";
    if (parser == &parse_qstring) return "QSTRING";
    if (parser == &parse_nqstring) return "NQSTRING";
    if (parser == &parse_xstring) return "XSTRING";
    if (parser == &parse_bstring) return "BSTRING";
    if (parser == &parse_estring) return "ESTRING";
    if (parser == &parse_other) return "OTHER";
    
    return "UNKNOWN";
}

void debug_raw_tokenization(const unsigned char* input, size_t len) {
    printf("RAW_TOKENIZATION_START\n");
    
    struct libinjection_sqli_state state;
    libinjection_sqli_init(&state, (const char*)input, len, FLAG_SQL_ANSI);
    
    // Character-by-character analysis
    printf("CHARACTER_ANALYSIS_START\n");
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = input[i];
        printf("CHAR_%zu: %u '%c' %s\n", i, ch, 
               (ch >= 32 && ch <= 126) ? ch : '?',
               char_type_to_string(ch));
    }
    printf("CHARACTER_ANALYSIS_END\n");
    
    // Raw tokenization - step by step
    printf("TOKENIZATION_START\n");
    size_t pos = 0;
    int token_count = 0;
    
    while (pos < len && token_count < 50) {
        struct libinjection_sqli_token token;
        memset(&token, 0, sizeof(token));
        
        // Set up temporary state for single token extraction
        struct libinjection_sqli_state temp_state = state;
        temp_state.pos = pos;
        temp_state.current = &token;
        
        // Get the character and call its parser
        unsigned char ch = input[pos];
        
        // Call the appropriate parser function
        typedef size_t (*pt2Function)(struct libinjection_sqli_state *sf);
        extern const pt2Function char_parse_map[];
        pt2Function parser = char_parse_map[ch];
        size_t new_pos = (*parser)(&temp_state);
        
        if (token.type != TYPE_NONE) {
            printf("RAW_TOKEN_%d: %s '%.*s' %zu %zu\n", 
                   token_count, 
                   token_type_to_string(token.type),
                   (int)token.len, token.val,
                   token.pos, token.len);
            token_count++;
        }
        
        // Advance position
        if (new_pos > pos) {
            pos = new_pos;
        } else {
            pos++; // Safety increment to avoid infinite loops
        }
    }
    printf("TOKENIZATION_END\n");
    printf("RAW_TOKENIZATION_END\n");
}

void analyze_input(const unsigned char* input, size_t len) {
    printf("INPUT_LENGTH: %zu\n", len);
    printf("INPUT_HEX: ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", input[i]);
    }
    printf("\n");
    
    // Raw tokenization debug
    debug_raw_tokenization(input, len);
    
    // Full processing
    struct libinjection_sqli_state state;
    libinjection_sqli_init(&state, (const char*)input, len, FLAG_SQL_ANSI);
    int result = libinjection_is_sqli(&state);
    
    printf("FINGERPRINT: %s\n", state.fingerprint);
    printf("STATS_TOKENS: %d\n", state.stats_tokens);
    printf("IS_SQLI: %d\n", result ? 1 : 0);
    
    // Final tokens (after folding)
    printf("FINAL_TOKEN_COUNT: %d\n", (int)strlen(state.fingerprint));
    
    // Note: The C implementation doesn't easily expose the final token array
    // We can only infer from the fingerprint for now
    // TODO: This would need modification to C library to expose tokens
    
    printf("ANALYSIS_COMPLETE\n");
}

int main(int argc, char *argv[]) {
    unsigned char buffer[8192];
    size_t total_read = 0;
    
    if (argc > 1) {
        // Input provided as command line argument
        const char* input_str = argv[1];
        analyze_input((const unsigned char*)input_str, strlen(input_str));
    } else {
        // Read from stdin
        size_t bytes_read;
        while ((bytes_read = fread(buffer + total_read, 1, 
                                  sizeof(buffer) - total_read - 1, stdin)) > 0) {
            total_read += bytes_read;
            if (total_read >= sizeof(buffer) - 1) break;
        }
        
        if (total_read > 0) {
            buffer[total_read] = '\0';
            analyze_input(buffer, total_read);
        } else {
            fprintf(stderr, "No input provided\n");
            return 1;
        }
    }
    
    return 0;
}