/// Character classification and lookup tables for SQL injection detection
/// 
/// This module contains the data tables used by the SQL tokenizer.
/// It is a direct transliteration from libinjection_sqli_data.h


/// SQL keyword lookup entry
#[derive(Debug, Clone)]
pub struct Keyword {
    pub word: &'static str,
    pub token_type: u8,
}

/// Function pointer type for parsing functions
pub type ParseFn = fn(&mut crate::sqli::SqliState) -> usize;

/// Character to parse function mapping table
/// Maps each byte value (0-255) to its corresponding parsing function
pub const CHAR_PARSE_MAP: [ParseFn; 256] = [
    parse_white,     // 0
    parse_white,     // 1
    parse_white,     // 2
    parse_white,     // 3
    parse_white,     // 4
    parse_white,     // 5
    parse_white,     // 6
    parse_white,     // 7
    parse_white,     // 8
    parse_white,     // 9
    parse_white,     // 10
    parse_white,     // 11
    parse_white,     // 12
    parse_white,     // 13
    parse_white,     // 14
    parse_white,     // 15
    parse_white,     // 16
    parse_white,     // 17
    parse_white,     // 18
    parse_white,     // 19
    parse_white,     // 20
    parse_white,     // 21
    parse_white,     // 22
    parse_white,     // 23
    parse_white,     // 24
    parse_white,     // 25
    parse_white,     // 26
    parse_white,     // 27
    parse_white,     // 28
    parse_white,     // 29
    parse_white,     // 30
    parse_white,     // 31
    parse_white,     // 32 ' '
    parse_operator2, // 33 '!'
    parse_string,    // 34 '"'
    parse_hash,      // 35 '#'
    parse_money,     // 36 '$'
    parse_operator1, // 37 '%'
    parse_operator2, // 38 '&'
    parse_string,    // 39 '\''
    parse_char,      // 40 '('
    parse_char,      // 41 ')'
    parse_operator2, // 42 '*'
    parse_operator1, // 43 '+'
    parse_char,      // 44 ','
    parse_dash,      // 45 '-'
    parse_number,    // 46 '.'
    parse_slash,     // 47 '/'
    parse_number,    // 48 '0'
    parse_number,    // 49 '1'
    parse_number,    // 50 '2'
    parse_number,    // 51 '3'
    parse_number,    // 52 '4'
    parse_number,    // 53 '5'
    parse_number,    // 54 '6'
    parse_number,    // 55 '7'
    parse_number,    // 56 '8'
    parse_number,    // 57 '9'
    parse_operator2, // 58 ':'
    parse_char,      // 59 ';'
    parse_operator2, // 60 '<'
    parse_operator2, // 61 '='
    parse_operator2, // 62 '>'
    parse_other,     // 63 '?'
    parse_var,       // 64 '@'
    parse_word,      // 65 'A'
    parse_bstring,   // 66 'B'
    parse_word,      // 67 'C'
    parse_word,      // 68 'D'
    parse_estring,   // 69 'E'
    parse_word,      // 70 'F'
    parse_word,      // 71 'G'
    parse_word,      // 72 'H'
    parse_word,      // 73 'I'
    parse_word,      // 74 'J'
    parse_word,      // 75 'K'
    parse_word,      // 76 'L'
    parse_word,      // 77 'M'
    parse_nqstring,  // 78 'N'
    parse_word,      // 79 'O'
    parse_word,      // 80 'P'
    parse_qstring,   // 81 'Q'
    parse_word,      // 82 'R'
    parse_word,      // 83 'S'
    parse_word,      // 84 'T'
    parse_ustring,   // 85 'U'
    parse_word,      // 86 'V'
    parse_word,      // 87 'W'
    parse_xstring,   // 88 'X'
    parse_word,      // 89 'Y'
    parse_word,      // 90 'Z'
    parse_bword,     // 91 '['
    parse_backslash, // 92 '\\'
    parse_other,     // 93 ']'
    parse_operator1, // 94 '^'
    parse_word,      // 95 '_'
    parse_tick,      // 96 '`'
    parse_word,      // 97 'a'
    parse_bstring,   // 98 'b'
    parse_word,      // 99 'c'
    parse_word,      // 100 'd'
    parse_estring,   // 101 'e'
    parse_word,      // 102 'f'
    parse_word,      // 103 'g'
    parse_word,      // 104 'h'
    parse_word,      // 105 'i'
    parse_word,      // 106 'j'
    parse_word,      // 107 'k'
    parse_word,      // 108 'l'
    parse_word,      // 109 'm'
    parse_nqstring,  // 110 'n'
    parse_word,      // 111 'o'
    parse_word,      // 112 'p'
    parse_qstring,   // 113 'q'
    parse_word,      // 114 'r'
    parse_word,      // 115 's'
    parse_word,      // 116 't'
    parse_ustring,   // 117 'u'
    parse_word,      // 118 'v'
    parse_word,      // 119 'w'
    parse_xstring,   // 120 'x'
    parse_word,      // 121 'y'
    parse_word,      // 122 'z'
    parse_char,      // 123 '{'
    parse_operator2, // 124 '|'
    parse_char,      // 125 '}'
    parse_operator1, // 126 '~'
    parse_white,     // 127
    parse_word,      // 128
    parse_word,      // 129
    parse_word,      // 130
    parse_word,      // 131
    parse_word,      // 132
    parse_word,      // 133
    parse_word,      // 134
    parse_word,      // 135
    parse_word,      // 136
    parse_word,      // 137
    parse_word,      // 138
    parse_word,      // 139
    parse_word,      // 140
    parse_word,      // 141
    parse_word,      // 142
    parse_word,      // 143
    parse_word,      // 144
    parse_word,      // 145
    parse_word,      // 146
    parse_word,      // 147
    parse_word,      // 148
    parse_word,      // 149
    parse_word,      // 150
    parse_word,      // 151
    parse_word,      // 152
    parse_word,      // 153
    parse_word,      // 154
    parse_word,      // 155
    parse_word,      // 156
    parse_word,      // 157
    parse_word,      // 158
    parse_word,      // 159
    parse_white,     // 160
    parse_word,      // 161
    parse_word,      // 162
    parse_word,      // 163
    parse_word,      // 164
    parse_word,      // 165
    parse_word,      // 166
    parse_word,      // 167
    parse_word,      // 168
    parse_word,      // 169
    parse_word,      // 170
    parse_word,      // 171
    parse_word,      // 172
    parse_word,      // 173
    parse_word,      // 174
    parse_word,      // 175
    parse_word,      // 176
    parse_word,      // 177
    parse_word,      // 178
    parse_word,      // 179
    parse_word,      // 180
    parse_word,      // 181
    parse_word,      // 182
    parse_word,      // 183
    parse_word,      // 184
    parse_word,      // 185
    parse_word,      // 186
    parse_word,      // 187
    parse_word,      // 188
    parse_word,      // 189
    parse_word,      // 190
    parse_word,      // 191
    parse_word,      // 192
    parse_word,      // 193
    parse_word,      // 194
    parse_word,      // 195
    parse_word,      // 196
    parse_word,      // 197
    parse_word,      // 198
    parse_word,      // 199
    parse_word,      // 200
    parse_word,      // 201
    parse_word,      // 202
    parse_word,      // 203
    parse_word,      // 204
    parse_word,      // 205
    parse_word,      // 206
    parse_word,      // 207
    parse_word,      // 208
    parse_word,      // 209
    parse_word,      // 210
    parse_word,      // 211
    parse_word,      // 212
    parse_word,      // 213
    parse_word,      // 214
    parse_word,      // 215
    parse_word,      // 216
    parse_word,      // 217
    parse_word,      // 218
    parse_word,      // 219
    parse_word,      // 220
    parse_word,      // 221
    parse_word,      // 222
    parse_word,      // 223
    parse_word,      // 224
    parse_word,      // 225
    parse_word,      // 226
    parse_word,      // 227
    parse_word,      // 228
    parse_word,      // 229
    parse_word,      // 230
    parse_word,      // 231
    parse_word,      // 232
    parse_word,      // 233
    parse_word,      // 234
    parse_word,      // 235
    parse_word,      // 236
    parse_word,      // 237
    parse_word,      // 238
    parse_word,      // 239
    parse_word,      // 240
    parse_word,      // 241
    parse_word,      // 242
    parse_word,      // 243
    parse_word,      // 244
    parse_word,      // 245
    parse_word,      // 246
    parse_word,      // 247
    parse_word,      // 248
    parse_word,      // 249
    parse_word,      // 250
    parse_word,      // 251
    parse_word,      // 252
    parse_word,      // 253
    parse_word,      // 254
    parse_word,      // 255
];

// Parsing functions from tokenizer module
use super::sqli_tokenizer::*;