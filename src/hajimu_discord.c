/**
 * hajimu_discord — はじむ言語用 Discord Bot 開発プラグイン
 *
 * Discord Gateway API v10 / REST API v10 対応
 * WebSocket + zlib-stream 圧縮ゲートウェイ
 *
 * 依存: libcurl, OpenSSL (libssl, libcrypto), zlib, pthread
 *
 * Copyright (c) 2026 はじむ開発チーム
 * MIT License
 *
 * v1.0.0 — 2026-02-12
 */

#define _GNU_SOURCE
#include "hajimu_plugin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <zlib.h>

/* =========================================================================
 * Section 1: Constants & Macros
 * ========================================================================= */

#define PLUGIN_NAME    "hajimu_discord"
#define PLUGIN_VERSION "1.0.0"

/* Discord API */
#define DISCORD_API_BASE    "https://discord.com/api/v10"
#define DISCORD_GATEWAY_HOST "gateway.discord.gg"
#define DISCORD_GATEWAY_PORT 443
#define DISCORD_GATEWAY_PATH "/?v=10&encoding=json&compress=zlib-stream"

/* Limits */
#define MAX_EVENTS            64
#define MAX_HANDLERS          16
#define MAX_COMMANDS          128
#define MAX_CMD_OPTIONS       25
#define MAX_EMBEDS_STORE      64
#define MAX_EMBED_FIELDS      25
#define MAX_TOKEN_LEN         256
#define MAX_SNOWFLAKE         24
#define MAX_URL_LEN           2048
#define MAX_MSG_LEN           2000
#define MAX_JSON_DEPTH        32
#define WS_READ_BUF           65536
#define REST_BUF_INIT         4096
#define ZLIB_CHUNK            65536

/* WebSocket opcodes */
#define WS_OP_TEXT   0x1
#define WS_OP_BIN    0x2
#define WS_OP_CLOSE  0x8
#define WS_OP_PING   0x9
#define WS_OP_PONG   0xA

/* Gateway opcodes */
#define GW_DISPATCH          0
#define GW_HEARTBEAT         1
#define GW_IDENTIFY          2
#define GW_PRESENCE_UPDATE   3
#define GW_VOICE_STATE       4
#define GW_RESUME            6
#define GW_RECONNECT         7
#define GW_REQ_MEMBERS       8
#define GW_INVALID_SESSION   9
#define GW_HELLO             10
#define GW_HEARTBEAT_ACK     11

/* Gateway Intents — Discord API v10 */
#define INTENT_GUILDS                   (1 << 0)
#define INTENT_GUILD_MEMBERS            (1 << 1)
#define INTENT_GUILD_MODERATION         (1 << 2)
#define INTENT_GUILD_EMOJIS             (1 << 3)
#define INTENT_GUILD_INTEGRATIONS       (1 << 4)
#define INTENT_GUILD_WEBHOOKS           (1 << 5)
#define INTENT_GUILD_INVITES            (1 << 6)
#define INTENT_GUILD_VOICE_STATES       (1 << 7)
#define INTENT_GUILD_PRESENCES          (1 << 8)
#define INTENT_GUILD_MESSAGES           (1 << 9)
#define INTENT_GUILD_MESSAGE_REACTIONS  (1 << 10)
#define INTENT_GUILD_MESSAGE_TYPING     (1 << 11)
#define INTENT_DIRECT_MESSAGES          (1 << 12)
#define INTENT_DIRECT_MESSAGE_REACTIONS (1 << 13)
#define INTENT_DIRECT_MESSAGE_TYPING    (1 << 14)
#define INTENT_MESSAGE_CONTENT          (1 << 15)
#define INTENT_GUILD_SCHEDULED_EVENTS   (1 << 16)
#define INTENT_AUTO_MODERATION_CONFIG   (1 << 20)
#define INTENT_AUTO_MODERATION_EXEC     (1 << 21)

/* Default intents (non-privileged) */
#define INTENT_DEFAULT  (INTENT_GUILDS | INTENT_GUILD_MESSAGES | \
                         INTENT_GUILD_MESSAGE_REACTIONS | INTENT_DIRECT_MESSAGES | \
                         INTENT_MESSAGE_CONTENT)

/* Log levels */
#define LOG_NONE   0
#define LOG_ERROR  1
#define LOG_WARN   2
#define LOG_INFO   3
#define LOG_DEBUG  4

/* =========================================================================
 * Section 2: Forward Declarations & Types
 * ========================================================================= */

/* --- JSON Node --- */
typedef enum {
    JSON_NULL, JSON_BOOL, JSON_NUMBER, JSON_STRING, JSON_ARRAY, JSON_OBJECT
} JsonType;

typedef struct JsonNode {
    JsonType type;
    union {
        bool boolean;
        double number;
        struct { char *data; int len; } str;
        struct { struct JsonNode *items; int count; int cap; } arr;
        struct { char **keys; struct JsonNode *vals; int count; int cap; } obj;
    };
} JsonNode;

/* --- String Buffer --- */
typedef struct {
    char *data;
    int   len;
    int   cap;
} StrBuf;

/* --- Embed --- */
typedef struct {
    char title[256];
    char description[4096];
    int  color;
    char footer_text[256];
    char footer_icon[MAX_URL_LEN];
    char thumbnail[MAX_URL_LEN];
    char image[MAX_URL_LEN];
    char author_name[256];
    char author_icon[MAX_URL_LEN];
    char author_url[MAX_URL_LEN];
    char timestamp[64];
    struct {
        char name[256];
        char value[1024];
        bool is_inline;
    } fields[MAX_EMBED_FIELDS];
    int field_count;
    bool active;
} Embed;

/* --- Slash Command --- */
typedef struct {
    char name[64];
    char description[128];
    Value callback;
    struct {
        char name[64];
        char description[128];
        int  type;          /* 3=STRING, 4=INTEGER, 5=BOOLEAN, 10=NUMBER */
        bool required;
    } options[MAX_CMD_OPTIONS];
    int option_count;
    char registered_id[MAX_SNOWFLAKE]; /* Discord 側 ID */
    bool registered;
} SlashCommand;

/* --- Event Handler --- */
typedef struct {
    char name[64];
    Value handlers[MAX_HANDLERS];
    int  handler_count;
} EventEntry;

/* --- WebSocket Connection --- */
typedef struct {
    int       fd;
    SSL_CTX  *ssl_ctx;
    SSL      *ssl;
    bool      connected;
    /* zlib inflate stream */
    z_stream  zstrm;
    bool      zlib_init;
    uint8_t   zbuf[ZLIB_CHUNK];
} WsConn;

/* --- Bot State --- */
typedef struct {
    /* Authentication */
    char token[MAX_TOKEN_LEN];
    bool token_set;

    /* Gateway */
    WsConn ws;
    int    heartbeat_interval;  /* ms */
    int    last_seq;            /* last sequence number */
    char   session_id[128];
    char   resume_url[MAX_URL_LEN];
    bool   gateway_ready;
    volatile bool running;
    volatile bool heartbeat_acked;

    /* Threads */
    pthread_t gateway_thread;
    pthread_t heartbeat_thread;
    pthread_mutex_t callback_mutex;
    pthread_mutex_t ws_write_mutex;
    pthread_mutex_t rest_mutex;

    /* Intents */
    int intents;

    /* Events */
    EventEntry events[MAX_EVENTS];
    int event_count;

    /* Slash Commands */
    SlashCommand commands[MAX_COMMANDS];
    int command_count;

    /* Embeds (pooled) */
    Embed embeds[MAX_EMBEDS_STORE];

    /* Bot user info */
    char bot_id[MAX_SNOWFLAKE];
    char bot_username[128];
    char bot_discriminator[8];

    /* Application ID for slash commands */
    char application_id[MAX_SNOWFLAKE];

    /* libcurl */
    CURL *curl;

    /* Log level */
    int log_level;
} BotState;

static BotState g_bot = {0};

/* Shutdown flag */
static volatile sig_atomic_t g_shutdown = 0;

/* =========================================================================
 * Section 3: Logging
 * ========================================================================= */

static void bot_log(int level, const char *fmt, ...) {
    if (level > g_bot.log_level) return;
    const char *prefix[] = {"", "[エラー]", "[警告]", "[情報]", "[デバッグ]"};
    fprintf(stderr, "[hajimu_discord] %s ", prefix[level]);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

#define LOG_E(...) bot_log(LOG_ERROR, __VA_ARGS__)
#define LOG_W(...) bot_log(LOG_WARN,  __VA_ARGS__)
#define LOG_I(...) bot_log(LOG_INFO,  __VA_ARGS__)
#define LOG_D(...) bot_log(LOG_DEBUG, __VA_ARGS__)

/* =========================================================================
 * Section 4: String Buffer
 * ========================================================================= */

static void sb_init(StrBuf *sb) {
    sb->cap = 256;
    sb->len = 0;
    sb->data = (char *)malloc(sb->cap);
    sb->data[0] = '\0';
}

static void sb_ensure(StrBuf *sb, int need) {
    if (sb->len + need + 1 > sb->cap) {
        while (sb->len + need + 1 > sb->cap) sb->cap *= 2;
        sb->data = (char *)realloc(sb->data, sb->cap);
    }
}

static void sb_append(StrBuf *sb, const char *s) {
    int slen = (int)strlen(s);
    sb_ensure(sb, slen);
    memcpy(sb->data + sb->len, s, slen);
    sb->len += slen;
    sb->data[sb->len] = '\0';
}

static void sb_appendn(StrBuf *sb, const char *s, int n) {
    sb_ensure(sb, n);
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
}

static void sb_appendf(StrBuf *sb, const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0) sb_appendn(sb, tmp, n < (int)sizeof(tmp) ? n : (int)sizeof(tmp) - 1);
}

static void sb_append_char(StrBuf *sb, char c) {
    sb_ensure(sb, 1);
    sb->data[sb->len++] = c;
    sb->data[sb->len] = '\0';
}

static char *sb_detach(StrBuf *sb) {
    char *r = sb->data;
    sb->data = NULL; sb->len = sb->cap = 0;
    return r;
}

static void sb_free(StrBuf *sb) {
    free(sb->data);
    sb->data = NULL; sb->len = sb->cap = 0;
}

/* =========================================================================
 * Section 5: JSON Parser (lightweight recursive descent)
 * ========================================================================= */

static JsonNode json_null_node(void) {
    JsonNode n; memset(&n, 0, sizeof(n)); n.type = JSON_NULL; return n;
}

static void json_free(JsonNode *n) {
    if (!n) return;
    switch (n->type) {
        case JSON_STRING: free(n->str.data); break;
        case JSON_ARRAY:
            for (int i = 0; i < n->arr.count; i++) json_free(&n->arr.items[i]);
            free(n->arr.items);
            break;
        case JSON_OBJECT:
            for (int i = 0; i < n->obj.count; i++) {
                free(n->obj.keys[i]);
                json_free(&n->obj.vals[i]);
            }
            free(n->obj.keys);
            free(n->obj.vals);
            break;
        default: break;
    }
    memset(n, 0, sizeof(*n));
}

/* Parser state */
typedef struct { const char *s; int pos; int len; } JParser;

static void jp_skip_ws(JParser *p) {
    while (p->pos < p->len) {
        char c = p->s[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') p->pos++;
        else break;
    }
}

__attribute__((unused))
static char jp_peek(JParser *p) {
    jp_skip_ws(p);
    return p->pos < p->len ? p->s[p->pos] : '\0';
}

__attribute__((unused))
static char jp_next(JParser *p) {
    jp_skip_ws(p);
    return p->pos < p->len ? p->s[p->pos++] : '\0';
}

static JsonNode jp_parse_value(JParser *p, int depth);

static JsonNode jp_parse_string(JParser *p) {
    JsonNode n = json_null_node();
    if (p->s[p->pos] != '"') return n;
    p->pos++; /* skip opening " */
    StrBuf sb; sb_init(&sb);
    while (p->pos < p->len && p->s[p->pos] != '"') {
        if (p->s[p->pos] == '\\' && p->pos + 1 < p->len) {
            p->pos++;
            switch (p->s[p->pos]) {
                case '"':  sb_append_char(&sb, '"'); break;
                case '\\': sb_append_char(&sb, '\\'); break;
                case '/':  sb_append_char(&sb, '/'); break;
                case 'b':  sb_append_char(&sb, '\b'); break;
                case 'f':  sb_append_char(&sb, '\f'); break;
                case 'n':  sb_append_char(&sb, '\n'); break;
                case 'r':  sb_append_char(&sb, '\r'); break;
                case 't':  sb_append_char(&sb, '\t'); break;
                case 'u': {
                    /* Parse \uXXXX */
                    if (p->pos + 4 < p->len) {
                        char hex[5] = {p->s[p->pos+1], p->s[p->pos+2],
                                       p->s[p->pos+3], p->s[p->pos+4], 0};
                        unsigned int cp = (unsigned int)strtoul(hex, NULL, 16);
                        p->pos += 4;
                        /* UTF-8 encode */
                        if (cp < 0x80) {
                            sb_append_char(&sb, (char)cp);
                        } else if (cp < 0x800) {
                            sb_append_char(&sb, (char)(0xC0 | (cp >> 6)));
                            sb_append_char(&sb, (char)(0x80 | (cp & 0x3F)));
                        } else {
                            sb_append_char(&sb, (char)(0xE0 | (cp >> 12)));
                            sb_append_char(&sb, (char)(0x80 | ((cp >> 6) & 0x3F)));
                            sb_append_char(&sb, (char)(0x80 | (cp & 0x3F)));
                        }
                    }
                    break;
                }
                default: sb_append_char(&sb, p->s[p->pos]); break;
            }
        } else {
            sb_append_char(&sb, p->s[p->pos]);
        }
        p->pos++;
    }
    if (p->pos < p->len) p->pos++; /* skip closing " */
    n.type = JSON_STRING;
    n.str.len = sb.len;
    n.str.data = sb_detach(&sb);
    return n;
}

static JsonNode jp_parse_number(JParser *p) {
    JsonNode n = json_null_node();
    const char *start = p->s + p->pos;
    char *end = NULL;
    double val = strtod(start, &end);
    if (end == start) return n;
    p->pos += (int)(end - start);
    n.type = JSON_NUMBER;
    n.number = val;
    return n;
}

static JsonNode jp_parse_array(JParser *p, int depth) {
    JsonNode n = json_null_node();
    n.type = JSON_ARRAY;
    n.arr.count = 0; n.arr.cap = 4;
    n.arr.items = (JsonNode *)calloc(n.arr.cap, sizeof(JsonNode));
    p->pos++; /* skip [ */
    jp_skip_ws(p);
    if (p->pos < p->len && p->s[p->pos] == ']') { p->pos++; return n; }
    while (p->pos < p->len) {
        JsonNode elem = jp_parse_value(p, depth + 1);
        if (n.arr.count >= n.arr.cap) {
            n.arr.cap *= 2;
            n.arr.items = (JsonNode *)realloc(n.arr.items, n.arr.cap * sizeof(JsonNode));
        }
        n.arr.items[n.arr.count++] = elem;
        jp_skip_ws(p);
        if (p->pos < p->len && p->s[p->pos] == ',') { p->pos++; continue; }
        break;
    }
    jp_skip_ws(p);
    if (p->pos < p->len && p->s[p->pos] == ']') p->pos++;
    return n;
}

static JsonNode jp_parse_object(JParser *p, int depth) {
    JsonNode n = json_null_node();
    n.type = JSON_OBJECT;
    n.obj.count = 0; n.obj.cap = 8;
    n.obj.keys = (char **)calloc(n.obj.cap, sizeof(char *));
    n.obj.vals = (JsonNode *)calloc(n.obj.cap, sizeof(JsonNode));
    p->pos++; /* skip { */
    jp_skip_ws(p);
    if (p->pos < p->len && p->s[p->pos] == '}') { p->pos++; return n; }
    while (p->pos < p->len) {
        jp_skip_ws(p);
        if (p->s[p->pos] != '"') break;
        JsonNode key = jp_parse_string(p);
        jp_skip_ws(p);
        if (p->pos < p->len && p->s[p->pos] == ':') p->pos++;
        JsonNode val = jp_parse_value(p, depth + 1);
        if (n.obj.count >= n.obj.cap) {
            n.obj.cap *= 2;
            n.obj.keys = (char **)realloc(n.obj.keys, n.obj.cap * sizeof(char *));
            n.obj.vals = (JsonNode *)realloc(n.obj.vals, n.obj.cap * sizeof(JsonNode));
        }
        n.obj.keys[n.obj.count] = key.str.data;
        n.obj.vals[n.obj.count] = val;
        n.obj.count++;
        jp_skip_ws(p);
        if (p->pos < p->len && p->s[p->pos] == ',') { p->pos++; continue; }
        break;
    }
    jp_skip_ws(p);
    if (p->pos < p->len && p->s[p->pos] == '}') p->pos++;
    return n;
}

static JsonNode jp_parse_value(JParser *p, int depth) {
    if (depth > MAX_JSON_DEPTH) return json_null_node();
    jp_skip_ws(p);
    if (p->pos >= p->len) return json_null_node();
    char c = p->s[p->pos];
    if (c == '"') return jp_parse_string(p);
    if (c == '{') return jp_parse_object(p, depth);
    if (c == '[') return jp_parse_array(p, depth);
    if (c == '-' || (c >= '0' && c <= '9')) return jp_parse_number(p);
    if (strncmp(p->s + p->pos, "true", 4) == 0) {
        p->pos += 4; JsonNode n = json_null_node(); n.type = JSON_BOOL; n.boolean = true; return n;
    }
    if (strncmp(p->s + p->pos, "false", 5) == 0) {
        p->pos += 5; JsonNode n = json_null_node(); n.type = JSON_BOOL; n.boolean = false; return n;
    }
    if (strncmp(p->s + p->pos, "null", 4) == 0) {
        p->pos += 4; return json_null_node();
    }
    return json_null_node();
}

static JsonNode *json_parse(const char *input) {
    if (!input) return NULL;
    JParser p = { .s = input, .pos = 0, .len = (int)strlen(input) };
    JsonNode *root = (JsonNode *)malloc(sizeof(JsonNode));
    *root = jp_parse_value(&p, 0);
    return root;
}

/* Accessor helpers */
static JsonNode *json_get(JsonNode *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT) return NULL;
    for (int i = 0; i < obj->obj.count; i++) {
        if (strcmp(obj->obj.keys[i], key) == 0) return &obj->obj.vals[i];
    }
    return NULL;
}

static const char *json_get_str(JsonNode *obj, const char *key) {
    JsonNode *n = json_get(obj, key);
    if (n && n->type == JSON_STRING) return n->str.data;
    return NULL;
}

static double json_get_num(JsonNode *obj, const char *key) {
    JsonNode *n = json_get(obj, key);
    if (n && n->type == JSON_NUMBER) return n->number;
    return 0;
}

__attribute__((unused))
static bool json_get_bool(JsonNode *obj, const char *key) {
    JsonNode *n = json_get(obj, key);
    if (n && n->type == JSON_BOOL) return n->boolean;
    return false;
}

__attribute__((unused))
static const char *json_str_val(JsonNode *n) {
    return (n && n->type == JSON_STRING) ? n->str.data : "";
}

/* =========================================================================
 * Section 6: JSON Builder
 * ========================================================================= */

static void json_escape_str(StrBuf *sb, const char *s) {
    sb_append_char(sb, '"');
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '"':  sb_append(sb, "\\\""); break;
            case '\\': sb_append(sb, "\\\\"); break;
            case '\n': sb_append(sb, "\\n"); break;
            case '\r': sb_append(sb, "\\r"); break;
            case '\t': sb_append(sb, "\\t"); break;
            case '\b': sb_append(sb, "\\b"); break;
            case '\f': sb_append(sb, "\\f"); break;
            default:
                if ((unsigned char)*p < 0x20) {
                    sb_appendf(sb, "\\u%04x", (unsigned char)*p);
                } else {
                    sb_append_char(sb, *p);
                }
                break;
        }
    }
    sb_append_char(sb, '"');
}

/* Fluent JSON builder helpers */
static void jb_obj_start(StrBuf *sb) { sb_append_char(sb, '{'); }
static void jb_obj_end(StrBuf *sb) {
    /* Remove trailing comma if present */
    if (sb->len > 0 && sb->data[sb->len - 1] == ',') sb->len--;
    sb->data[sb->len] = '\0';
    sb_append_char(sb, '}');
}
static void jb_arr_start(StrBuf *sb) { sb_append_char(sb, '['); }
static void jb_arr_end(StrBuf *sb) {
    if (sb->len > 0 && sb->data[sb->len - 1] == ',') sb->len--;
    sb->data[sb->len] = '\0';
    sb_append_char(sb, ']');
}
static void jb_key(StrBuf *sb, const char *k) {
    json_escape_str(sb, k);
    sb_append_char(sb, ':');
}
static void jb_str(StrBuf *sb, const char *k, const char *v) {
    jb_key(sb, k); json_escape_str(sb, v); sb_append_char(sb, ',');
}
static void jb_int(StrBuf *sb, const char *k, int64_t v) {
    jb_key(sb, k); sb_appendf(sb, "%lld,", (long long)v);
}
__attribute__((unused))
static void jb_num(StrBuf *sb, const char *k, double v) {
    jb_key(sb, k); sb_appendf(sb, "%g,", v);
}
static void jb_bool(StrBuf *sb, const char *k, bool v) {
    jb_key(sb, k); sb_append(sb, v ? "true," : "false,");
}
static void jb_null(StrBuf *sb, const char *k) {
    jb_key(sb, k); sb_append(sb, "null,");
}
__attribute__((unused))
static void jb_raw(StrBuf *sb, const char *k, const char *raw) {
    jb_key(sb, k); sb_append(sb, raw); sb_append_char(sb, ',');
}

/* =========================================================================
 * Section 7: Base64 Encoding (for WebSocket handshake)
 * ========================================================================= */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const uint8_t *data, int len) {
    int out_len = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(out_len + 1);
    int i = 0, j = 0;
    while (i < len) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > len) ? '=' : b64_table[triple & 0x3F];
    }
    out[j] = '\0';
    return out;
}

/* =========================================================================
 * Section 8: HTTP Client (libcurl wrapper)
 * ========================================================================= */

typedef struct {
    char *data;
    size_t len;
} CurlBuf;

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    CurlBuf *buf = (CurlBuf *)userdata;
    char *tmp = (char *)realloc(buf->data, buf->len + total + 1);
    if (!tmp) return 0;
    buf->data = tmp;
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

/* Generic REST API call. Returns JSON response (caller must free). */
static JsonNode *discord_rest(const char *method, const char *endpoint,
                              const char *body, long *http_code) {
    if (!g_bot.token_set) {
        LOG_E("トークンが設定されていません");
        return NULL;
    }

    pthread_mutex_lock(&g_bot.rest_mutex);

    if (!g_bot.curl) {
        g_bot.curl = curl_easy_init();
    }
    CURL *curl = g_bot.curl;
    if (!curl) {
        pthread_mutex_unlock(&g_bot.rest_mutex);
        return NULL;
    }

    char url[MAX_URL_LEN];
    snprintf(url, sizeof(url), "%s%s", DISCORD_API_BASE, endpoint);

    CurlBuf resp = {NULL, 0};
    resp.data = (char *)calloc(1, REST_BUF_INIT);

    /* Headers */
    struct curl_slist *hdrs = NULL;
    char auth[MAX_TOKEN_LEN + 32];
    snprintf(auth, sizeof(auth), "Authorization: Bot %s", g_bot.token);
    hdrs = curl_slist_append(hdrs, auth);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "User-Agent: DiscordBot (hajimu_discord, 1.0.0)");

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    } else if (strcmp(method, "PUT") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    } else if (strcmp(method, "PATCH") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
    } else if (strcmp(method, "DELETE") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
        if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    }
    /* GET is default */

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);

    if (http_code) *http_code = code;

    JsonNode *result = NULL;
    if (res == CURLE_OK && resp.data && resp.len > 0) {
        result = json_parse(resp.data);

        /* Rate limit handling */
        if (code == 429) {
            JsonNode *retry = json_get(result, "retry_after");
            double wait = retry ? retry->number : 1.0;
            LOG_W("レート制限中… %.1f秒待機します", wait);
            usleep((useconds_t)(wait * 1000000));
            json_free(result); free(result);
            free(resp.data);
            /* Retry once */
            resp.data = (char *)calloc(1, REST_BUF_INIT);
            resp.len = 0;
            hdrs = NULL;
            hdrs = curl_slist_append(hdrs, auth);
            hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
            hdrs = curl_slist_append(hdrs, "User-Agent: DiscordBot (hajimu_discord, 1.0.0)");
            curl_easy_reset(curl);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
            if (strcmp(method, "POST") == 0) {
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
            } else if (strcmp(method, "PUT") == 0) {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
            } else if (strcmp(method, "PATCH") == 0) {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
            } else if (strcmp(method, "DELETE") == 0) {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
                if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
            }
            res = curl_easy_perform(curl);
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            curl_slist_free_all(hdrs);
            if (http_code) *http_code = code;
            result = (res == CURLE_OK && resp.data) ? json_parse(resp.data) : NULL;
        }
    } else if (res != CURLE_OK) {
        LOG_E("REST APIエラー: %s", curl_easy_strerror(res));
    }

    free(resp.data);
    pthread_mutex_unlock(&g_bot.rest_mutex);
    return result;
}

/* =========================================================================
 * Section 9: WebSocket Client
 * ========================================================================= */

static int ws_connect(WsConn *ws, const char *host, int port, const char *path) {
    /* DNS resolve */
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        LOG_E("DNS解決失敗: %s", host);
        return -1;
    }

    ws->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (ws->fd < 0) {
        freeaddrinfo(res);
        LOG_E("ソケット作成失敗");
        return -1;
    }

    /* Connect with timeout */
    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(ws->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(ws->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(ws->fd, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        close(ws->fd); ws->fd = -1;
        LOG_E("接続失敗: %s:%d", host, port);
        return -1;
    }
    freeaddrinfo(res);

    /* TLS */
    ws->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ws->ssl_ctx) {
        close(ws->fd); ws->fd = -1;
        LOG_E("SSL_CTX作成失敗");
        return -1;
    }
    SSL_CTX_set_verify(ws->ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ws->ssl_ctx);

    ws->ssl = SSL_new(ws->ssl_ctx);
    SSL_set_fd(ws->ssl, ws->fd);
    SSL_set_tlsext_host_name(ws->ssl, host);

    if (SSL_connect(ws->ssl) <= 0) {
        LOG_E("TLSハンドシェイク失敗");
        SSL_free(ws->ssl); ws->ssl = NULL;
        SSL_CTX_free(ws->ssl_ctx); ws->ssl_ctx = NULL;
        close(ws->fd); ws->fd = -1;
        return -1;
    }

    /* WebSocket handshake */
    uint8_t nonce[16];
    RAND_bytes(nonce, 16);
    char *ws_key = base64_encode(nonce, 16);

    char req[2048];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        path, host, ws_key);
    free(ws_key);

    if (SSL_write(ws->ssl, req, req_len) <= 0) {
        LOG_E("WebSocketハンドシェイク送信失敗");
        goto ws_fail;
    }

    /* Read HTTP response */
    char resp_buf[4096];
    int resp_len = SSL_read(ws->ssl, resp_buf, sizeof(resp_buf) - 1);
    if (resp_len <= 0) {
        LOG_E("WebSocketハンドシェイク応答なし");
        goto ws_fail;
    }
    resp_buf[resp_len] = '\0';

    if (!strstr(resp_buf, "101")) {
        LOG_E("WebSocketアップグレード拒否: %.80s", resp_buf);
        goto ws_fail;
    }

    /* Init zlib inflate stream */
    memset(&ws->zstrm, 0, sizeof(ws->zstrm));
    if (inflateInit(&ws->zstrm) != Z_OK) {
        LOG_E("zlib初期化失敗");
        goto ws_fail;
    }
    ws->zlib_init = true;

    /* Set non-blocking read timeout for gateway */
    tv.tv_sec = 60;
    setsockopt(ws->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ws->connected = true;
    LOG_I("Gateway接続成功");
    return 0;

ws_fail:
    if (ws->ssl) { SSL_free(ws->ssl); ws->ssl = NULL; }
    if (ws->ssl_ctx) { SSL_CTX_free(ws->ssl_ctx); ws->ssl_ctx = NULL; }
    close(ws->fd); ws->fd = -1;
    return -1;
}

static void ws_close(WsConn *ws) {
    if (ws->zlib_init) { inflateEnd(&ws->zstrm); ws->zlib_init = false; }
    if (ws->ssl) { SSL_shutdown(ws->ssl); SSL_free(ws->ssl); ws->ssl = NULL; }
    if (ws->ssl_ctx) { SSL_CTX_free(ws->ssl_ctx); ws->ssl_ctx = NULL; }
    if (ws->fd >= 0) { close(ws->fd); ws->fd = -1; }
    ws->connected = false;
}

/* Write a WebSocket text frame (client must mask) */
static int ws_send_text(WsConn *ws, const char *data, int len) {
    if (!ws->connected || !ws->ssl) return -1;

    pthread_mutex_lock(&g_bot.ws_write_mutex);

    uint8_t header[14];
    int hlen = 0;
    header[0] = 0x80 | WS_OP_TEXT;  /* FIN + TEXT */

    /* Mask bit is set for client frames */
    if (len < 126) {
        header[1] = 0x80 | (uint8_t)len;
        hlen = 2;
    } else if (len < 65536) {
        header[1] = 0x80 | 126;
        header[2] = (uint8_t)(len >> 8);
        header[3] = (uint8_t)(len & 0xFF);
        hlen = 4;
    } else {
        header[1] = 0x80 | 127;
        memset(header + 2, 0, 4);
        header[6] = (uint8_t)(len >> 24);
        header[7] = (uint8_t)((len >> 16) & 0xFF);
        header[8] = (uint8_t)((len >> 8) & 0xFF);
        header[9] = (uint8_t)(len & 0xFF);
        hlen = 10;
    }

    /* Masking key */
    uint8_t mask[4];
    RAND_bytes(mask, 4);
    memcpy(header + hlen, mask, 4);
    hlen += 4;

    /* Masked payload */
    uint8_t *payload = (uint8_t *)malloc(len);
    for (int i = 0; i < len; i++) {
        payload[i] = (uint8_t)data[i] ^ mask[i & 3];
    }

    int ret = 0;
    if (SSL_write(ws->ssl, header, hlen) <= 0 ||
        SSL_write(ws->ssl, payload, len) <= 0) {
        ret = -1;
    }
    free(payload);

    pthread_mutex_unlock(&g_bot.ws_write_mutex);
    return ret;
}

/* Send pong frame */
static int ws_send_pong(WsConn *ws, const uint8_t *data, int len) {
    if (!ws->connected || !ws->ssl) return -1;
    pthread_mutex_lock(&g_bot.ws_write_mutex);
    uint8_t header[6];
    header[0] = 0x80 | WS_OP_PONG;
    header[1] = 0x80 | (uint8_t)(len < 125 ? len : 0);
    uint8_t mask[4];
    RAND_bytes(mask, 4);
    memcpy(header + 2, mask, 4);
    SSL_write(ws->ssl, header, 6);
    if (len > 0 && data) {
        uint8_t *masked = (uint8_t *)malloc(len);
        for (int i = 0; i < len; i++) masked[i] = data[i] ^ mask[i & 3];
        SSL_write(ws->ssl, masked, len);
        free(masked);
    }
    pthread_mutex_unlock(&g_bot.ws_write_mutex);
    return 0;
}

/**
 * Read one WebSocket frame. Returns decompressed text payload.
 * Caller must free() the returned string.
 * Returns NULL on error/close.
 */
static char *ws_read_message(WsConn *ws) {
    if (!ws->connected || !ws->ssl) return NULL;

    /* Accumulate fragments */
    StrBuf raw; sb_init(&raw);
    bool final = false;
    int msg_opcode = 0;

    while (!final) {
        /* Read header (2 bytes min) */
        uint8_t hdr[2];
        int r = SSL_read(ws->ssl, hdr, 2);
        if (r <= 0) { sb_free(&raw); return NULL; }

        final = (hdr[0] & 0x80) != 0;
        int opcode = hdr[0] & 0x0F;
        if (opcode != 0) msg_opcode = opcode;
        bool masked = (hdr[1] & 0x80) != 0;
        uint64_t payload_len = hdr[1] & 0x7F;

        if (payload_len == 126) {
            uint8_t ext[2];
            if (SSL_read(ws->ssl, ext, 2) < 2) { sb_free(&raw); return NULL; }
            payload_len = ((uint64_t)ext[0] << 8) | ext[1];
        } else if (payload_len == 127) {
            uint8_t ext[8];
            if (SSL_read(ws->ssl, ext, 8) < 8) { sb_free(&raw); return NULL; }
            payload_len = 0;
            for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | ext[i];
        }

        uint8_t mask_key[4] = {0};
        if (masked) {
            if (SSL_read(ws->ssl, mask_key, 4) < 4) { sb_free(&raw); return NULL; }
        }

        /* Read payload */
        if (payload_len > 0) {
            uint8_t *buf = (uint8_t *)malloc((size_t)payload_len);
            uint64_t read_total = 0;
            while (read_total < payload_len) {
                int chunk = (int)(payload_len - read_total);
                if (chunk > WS_READ_BUF) chunk = WS_READ_BUF;
                r = SSL_read(ws->ssl, buf + read_total, chunk);
                if (r <= 0) { free(buf); sb_free(&raw); return NULL; }
                read_total += r;
            }
            if (masked) {
                for (uint64_t i = 0; i < payload_len; i++)
                    buf[i] ^= mask_key[i & 3];
            }
            sb_appendn(&raw, (char *)buf, (int)payload_len);
            free(buf);
        }

        /* Handle control frames immediately */
        if (msg_opcode == WS_OP_PING) {
            ws_send_pong(ws, (uint8_t *)raw.data, raw.len);
            sb_free(&raw); sb_init(&raw);
            final = false;
            continue;
        }
        if (msg_opcode == WS_OP_CLOSE) {
            LOG_I("Gatewayからclose frameを受信");
            sb_free(&raw);
            return NULL;
        }
    }

    /* Decompress with zlib if zlib-stream is active */
    if (ws->zlib_init && raw.len >= 4 &&
        (uint8_t)raw.data[raw.len-1] == 0xFF &&
        (uint8_t)raw.data[raw.len-2] == 0xFF &&
        (uint8_t)raw.data[raw.len-3] == 0x00 &&
        (uint8_t)raw.data[raw.len-4] == 0x00) {
        /* This is a zlib-stream message */
        ws->zstrm.next_in = (uint8_t *)raw.data;
        ws->zstrm.avail_in = (uInt)raw.len;

        StrBuf decompressed; sb_init(&decompressed);
        do {
            ws->zstrm.next_out = ws->zbuf;
            ws->zstrm.avail_out = ZLIB_CHUNK;
            int ret = inflate(&ws->zstrm, Z_SYNC_FLUSH);
            if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                LOG_E("zlib展開エラー: %d", ret);
                sb_free(&raw); sb_free(&decompressed);
                return NULL;
            }
            int have = ZLIB_CHUNK - (int)ws->zstrm.avail_out;
            sb_appendn(&decompressed, (char *)ws->zbuf, have);
        } while (ws->zstrm.avail_out == 0);

        sb_free(&raw);
        sb_append_char(&decompressed, '\0');
        return sb_detach(&decompressed);
    }

    /* Non-compressed text: return as-is */
    return sb_detach(&raw);
}

/* =========================================================================
 * Section 10: Event System
 * ========================================================================= */

static EventEntry *event_find(const char *name) {
    for (int i = 0; i < g_bot.event_count; i++) {
        if (strcmp(g_bot.events[i].name, name) == 0)
            return &g_bot.events[i];
    }
    return NULL;
}

static int event_register(const char *name, Value handler) {
    EventEntry *e = event_find(name);
    if (!e) {
        if (g_bot.event_count >= MAX_EVENTS) {
            LOG_E("イベント登録上限に達しました");
            return -1;
        }
        e = &g_bot.events[g_bot.event_count++];
        memset(e, 0, sizeof(*e));
        snprintf(e->name, sizeof(e->name), "%s", name);
    }
    if (e->handler_count >= MAX_HANDLERS) {
        LOG_E("イベント '%s' のハンドラ上限です", name);
        return -1;
    }
    e->handlers[e->handler_count++] = handler;
    return 0;
}

static void event_fire(const char *name, int argc, Value *argv) {
    EventEntry *e = event_find(name);
    if (!e) return;

    pthread_mutex_lock(&g_bot.callback_mutex);
    for (int i = 0; i < e->handler_count; i++) {
        if (hajimu_runtime_available()) {
            hajimu_call(&e->handlers[i], argc, argv);
        }
    }
    pthread_mutex_unlock(&g_bot.callback_mutex);
}

/* =========================================================================
 * Section 11: Value Conversion Helpers
 * ========================================================================= */

/*
 * Convert a JSON node to a はじむ Value (dict/array/string/number/bool/null).
 * Dict keys are translated to Japanese where appropriate.
 */

/* Key translation table: Discord API → 日本語 */
typedef struct { const char *en; const char *ja; } KeyMap;

static const KeyMap key_map[] = {
    {"id",                "ID"},
    {"content",           "内容"},
    {"channel_id",        "チャンネルID"},
    {"guild_id",          "サーバーID"},
    {"author",            "著者"},
    {"username",          "ユーザー名"},
    {"global_name",       "表示名"},
    {"discriminator",     "識別子"},
    {"avatar",            "アバター"},
    {"bot",               "ボット"},
    {"timestamp",         "タイムスタンプ"},
    {"edited_timestamp",  "編集日時"},
    {"tts",               "TTS"},
    {"mention_everyone",  "全員メンション"},
    {"mentions",          "メンション"},
    {"pinned",            "ピン留め"},
    {"type",              "種類"},
    {"name",              "名前"},
    {"topic",             "トピック"},
    {"position",          "位置"},
    {"nsfw",              "NSFW"},
    {"permissions",       "権限"},
    {"roles",             "ロール"},
    {"members",           "メンバー"},
    {"member_count",      "メンバー数"},
    {"owner_id",          "オーナーID"},
    {"icon",              "アイコン"},
    {"banner",            "バナー"},
    {"description",       "説明"},
    {"user",              "ユーザー"},
    {"nick",              "ニックネーム"},
    {"joined_at",         "参加日時"},
    {"premium_since",     "ブースト開始"},
    {"deaf",              "サーバーミュート"},
    {"mute",              "マイクミュート"},
    {"emoji",             "絵文字"},
    {"message_id",        "メッセージID"},
    {"member",            "メンバー"},
    {"embeds",            "埋め込み"},
    {"attachments",       "添付ファイル"},
    {"reactions",         "リアクション"},
    {"referenced_message","返信元"},
    {"interaction",       "インタラクション"},
    {"token",             "トークン"},
    {"data",              "データ"},
    {"options",           "オプション"},
    {"value",             "値"},
    {"custom_id",         "カスタムID"},
    {"title",             "タイトル"},
    {"color",             "色"},
    {"footer",            "フッター"},
    {"image",             "画像"},
    {"thumbnail",         "サムネイル"},
    {"fields",            "フィールド"},
    {"inline",            "インライン"},
    {"url",               "URL"},
    {"text",              "テキスト"},
    {"icon_url",          "アイコンURL"},
    {"reason",            "理由"},
    {"count",             "数"},
    {"me",                "自分"},
    {NULL, NULL}
};

static const char *translate_key(const char *en) {
    for (int i = 0; key_map[i].en; i++) {
        if (strcmp(key_map[i].en, en) == 0) return key_map[i].ja;
    }
    return en; /* fallback: keep original */
}

static Value json_to_value(JsonNode *node) {
    if (!node) return hajimu_null();
    switch (node->type) {
        case JSON_NULL:   return hajimu_null();
        case JSON_BOOL:   return hajimu_bool(node->boolean);
        case JSON_NUMBER: return hajimu_number(node->number);
        case JSON_STRING: return hajimu_string(node->str.data);
        case JSON_ARRAY: {
            Value arr = hajimu_array();
            for (int i = 0; i < node->arr.count; i++) {
                hajimu_array_push(&arr, json_to_value(&node->arr.items[i]));
            }
            return arr;
        }
        case JSON_OBJECT: {
            Value dict;
            memset(&dict, 0, sizeof(dict));
            dict.type = VALUE_DICT;
            int count = node->obj.count;
            if (count > 0) {
                dict.dict.keys     = (char **)calloc(count, sizeof(char *));
                dict.dict.values   = (Value *)calloc(count, sizeof(Value));
                dict.dict.length   = count;
                dict.dict.capacity = count;
                for (int i = 0; i < count; i++) {
                    dict.dict.keys[i]   = strdup(translate_key(node->obj.keys[i]));
                    dict.dict.values[i] = json_to_value(&node->obj.vals[i]);
                }
            }
            return dict;
        }
    }
    return hajimu_null();
}

/* Extract snowflake (ID) string from a Value (accepts string or nested dict) */
static const char *value_get_str(Value *v, const char *key) {
    if (!v || v->type != VALUE_DICT) return NULL;
    for (int i = 0; i < v->dict.length; i++) {
        if (strcmp(v->dict.keys[i], key) == 0) {
            if (v->dict.values[i].type == VALUE_STRING)
                return v->dict.values[i].string.data;
        }
    }
    return NULL;
}

/* =========================================================================
 * Section 12: Embed Builder → JSON
 * ========================================================================= */

static int embed_alloc(void) {
    for (int i = 0; i < MAX_EMBEDS_STORE; i++) {
        if (!g_bot.embeds[i].active) {
            memset(&g_bot.embeds[i], 0, sizeof(Embed));
            g_bot.embeds[i].active = true;
            g_bot.embeds[i].color = -1;
            return i;
        }
    }
    LOG_E("埋め込みの上限に達しました");
    return -1;
}

static Embed *embed_get(int idx) {
    if (idx < 0 || idx >= MAX_EMBEDS_STORE || !g_bot.embeds[idx].active) return NULL;
    return &g_bot.embeds[idx];
}

/* Serialize embed to JSON string */
static char *embed_to_json(Embed *e) {
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    if (e->title[0])       jb_str(&sb, "title", e->title);
    if (e->description[0]) jb_str(&sb, "description", e->description);
    if (e->color >= 0)     jb_int(&sb, "color", e->color);
    if (e->timestamp[0])   jb_str(&sb, "timestamp", e->timestamp);
    if (e->footer_text[0]) {
        jb_key(&sb, "footer"); jb_obj_start(&sb);
        jb_str(&sb, "text", e->footer_text);
        if (e->footer_icon[0]) jb_str(&sb, "icon_url", e->footer_icon);
        jb_obj_end(&sb); sb_append_char(&sb, ',');
    }
    if (e->thumbnail[0]) {
        jb_key(&sb, "thumbnail"); jb_obj_start(&sb);
        jb_str(&sb, "url", e->thumbnail);
        jb_obj_end(&sb); sb_append_char(&sb, ',');
    }
    if (e->image[0]) {
        jb_key(&sb, "image"); jb_obj_start(&sb);
        jb_str(&sb, "url", e->image);
        jb_obj_end(&sb); sb_append_char(&sb, ',');
    }
    if (e->author_name[0]) {
        jb_key(&sb, "author"); jb_obj_start(&sb);
        jb_str(&sb, "name", e->author_name);
        if (e->author_icon[0]) jb_str(&sb, "icon_url", e->author_icon);
        if (e->author_url[0])  jb_str(&sb, "url", e->author_url);
        jb_obj_end(&sb); sb_append_char(&sb, ',');
    }
    if (e->field_count > 0) {
        jb_key(&sb, "fields"); jb_arr_start(&sb);
        for (int i = 0; i < e->field_count; i++) {
            jb_obj_start(&sb);
            jb_str(&sb, "name",  e->fields[i].name);
            jb_str(&sb, "value", e->fields[i].value);
            jb_bool(&sb, "inline", e->fields[i].is_inline);
            jb_obj_end(&sb); sb_append_char(&sb, ',');
        }
        jb_arr_end(&sb); sb_append_char(&sb, ',');
    }
    jb_obj_end(&sb);
    return sb_detach(&sb);
}

/* =========================================================================
 * Section 13: Discord Gateway Protocol
 * ========================================================================= */

static void gw_send_json(const char *json) {
    LOG_D("GW送信: %.200s", json);
    ws_send_text(&g_bot.ws, json, (int)strlen(json));
}

static void gw_send_heartbeat(void) {
    char buf[64];
    if (g_bot.last_seq > 0) {
        snprintf(buf, sizeof(buf), "{\"op\":1,\"d\":%d}", g_bot.last_seq);
    } else {
        snprintf(buf, sizeof(buf), "{\"op\":1,\"d\":null}");
    }
    gw_send_json(buf);
    g_bot.heartbeat_acked = false;
    LOG_D("Heartbeat送信 (seq=%d)", g_bot.last_seq);
}

static void gw_send_identify(void) {
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "op", GW_IDENTIFY);
    jb_key(&sb, "d"); jb_obj_start(&sb);
    jb_str(&sb, "token", g_bot.token);
    jb_int(&sb, "intents", g_bot.intents);
    jb_key(&sb, "properties"); jb_obj_start(&sb);
    jb_str(&sb, "os", "hajimu");
    jb_str(&sb, "browser", "hajimu_discord");
    jb_str(&sb, "device", "hajimu_discord");
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);
    gw_send_json(sb.data);
    sb_free(&sb);
    LOG_I("IDENTIFY送信");
}

static void gw_send_resume(void) {
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "op", GW_RESUME);
    jb_key(&sb, "d"); jb_obj_start(&sb);
    jb_str(&sb, "token", g_bot.token);
    jb_str(&sb, "session_id", g_bot.session_id);
    jb_int(&sb, "seq", g_bot.last_seq);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);
    gw_send_json(sb.data);
    sb_free(&sb);
    LOG_I("RESUME送信 (session=%s, seq=%d)", g_bot.session_id, g_bot.last_seq);
}

static void gw_send_presence(const char *status, const char *activity_name, int type) {
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "op", GW_PRESENCE_UPDATE);
    jb_key(&sb, "d"); jb_obj_start(&sb);
    jb_null(&sb, "since");
    jb_key(&sb, "activities"); jb_arr_start(&sb);
    if (activity_name && activity_name[0]) {
        jb_obj_start(&sb);
        jb_str(&sb, "name", activity_name);
        jb_int(&sb, "type", type);
        jb_obj_end(&sb);
    }
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    jb_str(&sb, "status", status);
    jb_bool(&sb, "afk", false);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);
    gw_send_json(sb.data);
    sb_free(&sb);
}

/* Process READY event */
static void gw_handle_ready(JsonNode *data) {
    const char *session = json_get_str(data, "session_id");
    if (session) snprintf(g_bot.session_id, sizeof(g_bot.session_id), "%s", session);

    const char *resume = json_get_str(data, "resume_gateway_url");
    if (resume) snprintf(g_bot.resume_url, sizeof(g_bot.resume_url), "%s", resume);

    /* Bot user info */
    JsonNode *user = json_get(data, "user");
    if (user) {
        const char *id = json_get_str(user, "id");
        if (id) snprintf(g_bot.bot_id, sizeof(g_bot.bot_id), "%s", id);
        const char *name = json_get_str(user, "username");
        if (name) snprintf(g_bot.bot_username, sizeof(g_bot.bot_username), "%s", name);
        const char *disc = json_get_str(user, "discriminator");
        if (disc) snprintf(g_bot.bot_discriminator, sizeof(g_bot.bot_discriminator), "%s", disc);
    }

    /* Application info */
    JsonNode *app = json_get(data, "application");
    if (app) {
        const char *app_id = json_get_str(app, "id");
        if (app_id) snprintf(g_bot.application_id, sizeof(g_bot.application_id), "%s", app_id);
    }

    g_bot.gateway_ready = true;
    LOG_I("準備完了！ ボット: %s (ID: %s)", g_bot.bot_username, g_bot.bot_id);

    /* Fire READY event */
    Value bot_info = hajimu_string(g_bot.bot_username);
    event_fire("READY", 1, &bot_info);
    event_fire("準備完了", 1, &bot_info);
}

/* Process INTERACTION_CREATE — slash commands */
static void gw_handle_interaction(JsonNode *data) {
    int type = (int)json_get_num(data, "type");

    /* Type 2 = APPLICATION_COMMAND */
    if (type == 2) {
        JsonNode *cmd_data = json_get(data, "data");
        if (!cmd_data) return;
        const char *cmd_name = json_get_str(cmd_data, "name");
        if (!cmd_name) return;

        /* Find registered command */
        for (int i = 0; i < g_bot.command_count; i++) {
            if (strcmp(g_bot.commands[i].name, cmd_name) == 0) {
                /* Build interaction value for the callback */
                Value interaction = json_to_value(data);
                event_fire("INTERACTION_CREATE", 1, &interaction);

                /* Call specific command handler */
                pthread_mutex_lock(&g_bot.callback_mutex);
                if (hajimu_runtime_available()) {
                    hajimu_call(&g_bot.commands[i].callback, 1, &interaction);
                }
                pthread_mutex_unlock(&g_bot.callback_mutex);
                return;
            }
        }

        /* Fire generic command event */
        Value interaction = json_to_value(data);
        event_fire("コマンド受信", 1, &interaction);
    }
}

/* Process a DISPATCH event (opcode 0) */
static void gw_handle_dispatch(const char *event_name, JsonNode *data) {
    if (!event_name || !data) return;

    LOG_D("イベント: %s", event_name);

    if (strcmp(event_name, "READY") == 0) {
        gw_handle_ready(data);
        return;
    }

    if (strcmp(event_name, "INTERACTION_CREATE") == 0) {
        gw_handle_interaction(data);
        return;
    }

    /* Convert data to はじむ Value and fire events */
    Value val = json_to_value(data);

    /* Fire English event name */
    event_fire(event_name, 1, &val);

    /* Fire Japanese event aliases */
    if (strcmp(event_name, "MESSAGE_CREATE") == 0) {
        event_fire("メッセージ受信", 1, &val);
    } else if (strcmp(event_name, "GUILD_MEMBER_ADD") == 0) {
        event_fire("メンバー参加", 1, &val);
    } else if (strcmp(event_name, "GUILD_MEMBER_REMOVE") == 0) {
        event_fire("メンバー退出", 1, &val);
    } else if (strcmp(event_name, "MESSAGE_REACTION_ADD") == 0) {
        event_fire("リアクション追加", 1, &val);
    } else if (strcmp(event_name, "MESSAGE_REACTION_REMOVE") == 0) {
        event_fire("リアクション削除", 1, &val);
    } else if (strcmp(event_name, "GUILD_CREATE") == 0) {
        event_fire("サーバー参加", 1, &val);
    } else if (strcmp(event_name, "GUILD_DELETE") == 0) {
        event_fire("サーバー退出", 1, &val);
    } else if (strcmp(event_name, "CHANNEL_CREATE") == 0) {
        event_fire("チャンネル作成", 1, &val);
    } else if (strcmp(event_name, "CHANNEL_DELETE") == 0) {
        event_fire("チャンネル削除", 1, &val);
    } else if (strcmp(event_name, "MESSAGE_UPDATE") == 0) {
        event_fire("メッセージ編集", 1, &val);
    } else if (strcmp(event_name, "MESSAGE_DELETE") == 0) {
        event_fire("メッセージ削除イベント", 1, &val);
    } else if (strcmp(event_name, "TYPING_START") == 0) {
        event_fire("入力中", 1, &val);
    } else if (strcmp(event_name, "PRESENCE_UPDATE") == 0) {
        event_fire("プレゼンス更新", 1, &val);
    } else if (strcmp(event_name, "VOICE_STATE_UPDATE") == 0) {
        event_fire("ボイス状態更新", 1, &val);
    } else if (strcmp(event_name, "RESUMED") == 0) {
        event_fire("再接続完了", 1, &val);
        LOG_I("セッション再開完了");
    }
}

/* Process one gateway message */
static void gw_process_message(const char *json_text) {
    if (!json_text) return;
    LOG_D("GW受信: %.200s", json_text);

    JsonNode *root = json_parse(json_text);
    if (!root) return;

    int op = (int)json_get_num(root, "op");
    JsonNode *d = json_get(root, "d");

    /* Update sequence number */
    JsonNode *s_node = json_get(root, "s");
    if (s_node && s_node->type == JSON_NUMBER) {
        g_bot.last_seq = (int)s_node->number;
    }

    switch (op) {
        case GW_DISPATCH: {
            const char *event_name = json_get_str(root, "t");
            gw_handle_dispatch(event_name, d);
            break;
        }

        case GW_HEARTBEAT:
            gw_send_heartbeat();
            break;

        case GW_RECONNECT:
            LOG_I("サーバーから再接続要求を受信");
            ws_close(&g_bot.ws);
            break;

        case GW_INVALID_SESSION: {
            bool resumable = (d && d->type == JSON_BOOL) ? d->boolean : false;
            LOG_W("セッション無効 (再開可能=%s)", resumable ? "はい" : "いいえ");
            if (!resumable) {
                g_bot.session_id[0] = '\0';
                g_bot.last_seq = 0;
            }
            usleep(3000000); /* Wait 3 seconds as Discord recommends */
            ws_close(&g_bot.ws);
            break;
        }

        case GW_HELLO: {
            g_bot.heartbeat_interval = (int)json_get_num(d, "heartbeat_interval");
            LOG_I("HELLO受信 (heartbeat: %dms)", g_bot.heartbeat_interval);
            g_bot.heartbeat_acked = true;

            /* Send RESUME if we have a session, otherwise IDENTIFY */
            if (g_bot.session_id[0]) {
                gw_send_resume();
            } else {
                gw_send_identify();
            }
            break;
        }

        case GW_HEARTBEAT_ACK:
            g_bot.heartbeat_acked = true;
            LOG_D("Heartbeat ACK受信");
            break;

        default:
            LOG_D("不明なopcode: %d", op);
            break;
    }

    json_free(root);
    free(root);
}

/* Heartbeat thread */
static void *heartbeat_thread_func(void *arg) {
    (void)arg;
    while (g_bot.running && !g_shutdown) {
        if (g_bot.heartbeat_interval <= 0) {
            usleep(100000);
            continue;
        }

        /* Jitter: first heartbeat at random fraction of interval */
        int wait_ms = g_bot.heartbeat_interval;
        struct timespec ts;
        ts.tv_sec = wait_ms / 1000;
        ts.tv_nsec = (wait_ms % 1000) * 1000000L;
        nanosleep(&ts, NULL);

        if (!g_bot.running || g_shutdown) break;

        if (!g_bot.heartbeat_acked && g_bot.ws.connected) {
            LOG_W("Heartbeat ACK未受信。接続が切断された可能性があります");
            ws_close(&g_bot.ws);
            continue;
        }

        if (g_bot.ws.connected) {
            gw_send_heartbeat();
        }
    }
    return NULL;
}

/* Register slash commands with Discord API */
static void register_slash_commands(void) {
    if (!g_bot.application_id[0]) {
        LOG_E("Application IDが不明です。スラッシュコマンドを登録できません");
        return;
    }

    for (int i = 0; i < g_bot.command_count; i++) {
        if (g_bot.commands[i].registered) continue;

        StrBuf sb; sb_init(&sb);
        jb_obj_start(&sb);
        jb_str(&sb, "name", g_bot.commands[i].name);
        jb_str(&sb, "description", g_bot.commands[i].description);
        jb_int(&sb, "type", 1); /* CHAT_INPUT */

        if (g_bot.commands[i].option_count > 0) {
            jb_key(&sb, "options"); jb_arr_start(&sb);
            for (int j = 0; j < g_bot.commands[i].option_count; j++) {
                jb_obj_start(&sb);
                jb_str(&sb, "name", g_bot.commands[i].options[j].name);
                jb_str(&sb, "description", g_bot.commands[i].options[j].description);
                jb_int(&sb, "type", g_bot.commands[i].options[j].type);
                jb_bool(&sb, "required", g_bot.commands[i].options[j].required);
                jb_obj_end(&sb); sb_append_char(&sb, ',');
            }
            jb_arr_end(&sb); sb_append_char(&sb, ',');
        }

        jb_obj_end(&sb);

        char endpoint[256];
        snprintf(endpoint, sizeof(endpoint), "/applications/%s/commands", g_bot.application_id);

        long code = 0;
        JsonNode *resp = discord_rest("POST", endpoint, sb.data, &code);
        if (resp && (code == 200 || code == 201)) {
            const char *cmd_id = json_get_str(resp, "id");
            if (cmd_id) {
                snprintf(g_bot.commands[i].registered_id, MAX_SNOWFLAKE, "%s", cmd_id);
            }
            g_bot.commands[i].registered = true;
            LOG_I("スラッシュコマンド登録: /%s", g_bot.commands[i].name);
        } else {
            LOG_E("スラッシュコマンド登録失敗: /%s (HTTP %ld)", g_bot.commands[i].name, code);
        }
        if (resp) { json_free(resp); free(resp); }
        sb_free(&sb);
    }
}

/* Main gateway loop */
static void *gateway_thread_func(void *arg) {
    (void)arg;

    while (g_bot.running && !g_shutdown) {
        /* Determine gateway host */
        const char *host = DISCORD_GATEWAY_HOST;
        const char *path = DISCORD_GATEWAY_PATH;
        int port = DISCORD_GATEWAY_PORT;

        /* Use resume URL if available */
        char resume_host[256] = {0};
        char resume_path[512] = {0};
        if (g_bot.resume_url[0]) {
            /* Parse wss://host/?... */
            const char *h = strstr(g_bot.resume_url, "wss://");
            if (h) {
                h += 6;
                const char *p = strchr(h, '/');
                if (p) {
                    int hlen = (int)(p - h);
                    snprintf(resume_host, sizeof(resume_host), "%.*s", hlen, h);
                    snprintf(resume_path, sizeof(resume_path), "%s", p);
                    host = resume_host;
                    path = resume_path;
                }
            }
        }

        LOG_I("Gatewayに接続中... (%s)", host);
        if (ws_connect(&g_bot.ws, host, port, path) < 0) {
            LOG_E("Gateway接続失敗。5秒後に再試行...");
            sleep(5);
            continue;
        }

        /* Read messages until disconnected */
        while (g_bot.running && !g_shutdown && g_bot.ws.connected) {
            char *msg = ws_read_message(&g_bot.ws);
            if (!msg) {
                if (g_bot.running && !g_shutdown) {
                    LOG_W("Gateway接続が切断されました。再接続します...");
                    ws_close(&g_bot.ws);
                }
                break;
            }
            gw_process_message(msg);
            free(msg);

            /* After READY, register slash commands */
            if (g_bot.gateway_ready && g_bot.command_count > 0) {
                static bool commands_registered = false;
                if (!commands_registered) {
                    register_slash_commands();
                    commands_registered = true;
                }
            }
        }

        if (g_bot.running && !g_shutdown) {
            LOG_I("2秒後にGateway再接続...");
            sleep(2);
        }
    }

    ws_close(&g_bot.ws);
    LOG_I("Gatewayスレッド終了");
    return NULL;
}

/* =========================================================================
 * Section 14: Plugin Functions (exposed to はじむ)
 * ========================================================================= */

/* --- ボット管理 --- */

/* ボット作成(トークン) */
static Value fn_bot_create(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("ボット作成: トークン(文字列)が必要です");
        return hajimu_bool(false);
    }
    snprintf(g_bot.token, MAX_TOKEN_LEN, "%s", argv[0].string.data);
    g_bot.token_set = true;
    if (g_bot.intents == 0) g_bot.intents = INTENT_DEFAULT;
    g_bot.log_level = LOG_INFO;

    /* Init mutexes */
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_bot.callback_mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    pthread_mutex_init(&g_bot.ws_write_mutex, NULL);
    pthread_mutex_init(&g_bot.rest_mutex, NULL);

    /* Init libcurl */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    LOG_I("ボット初期化完了");
    return hajimu_bool(true);
}

/* ボット起動() */
static Value fn_bot_start(int argc, Value *argv) {
    (void)argc; (void)argv;
    if (!g_bot.token_set) {
        LOG_E("先にボット作成(トークン)を呼んでください");
        return hajimu_bool(false);
    }
    if (g_bot.running) {
        LOG_W("ボットは既に起動中です");
        return hajimu_bool(true);
    }

    g_bot.running = true;

    /* Start gateway thread */
    if (pthread_create(&g_bot.gateway_thread, NULL, gateway_thread_func, NULL) != 0) {
        LOG_E("Gatewayスレッドの作成に失敗しました");
        g_bot.running = false;
        return hajimu_bool(false);
    }

    /* Start heartbeat thread */
    if (pthread_create(&g_bot.heartbeat_thread, NULL, heartbeat_thread_func, NULL) != 0) {
        LOG_E("Heartbeatスレッドの作成に失敗しました");
        g_bot.running = false;
        return hajimu_bool(false);
    }

    LOG_I("ボットを起動しました。Ctrl+C で停止します");

    /* Block main thread (like hajimu_web's サーバー起動) */
    signal(SIGINT, SIG_DFL);  /* Let default handler work */
    pthread_join(g_bot.gateway_thread, NULL);
    pthread_join(g_bot.heartbeat_thread, NULL);

    LOG_I("ボットが停止しました");
    return hajimu_bool(true);
}

/* ボット停止() */
static Value fn_bot_stop(int argc, Value *argv) {
    (void)argc; (void)argv;
    g_bot.running = false;
    g_shutdown = 1;
    ws_close(&g_bot.ws);
    LOG_I("ボットを停止します...");
    return hajimu_bool(true);
}

/* インテント設定(フラグ...) */
static Value fn_set_intents(int argc, Value *argv) {
    if (argc < 1) {
        LOG_E("インテント設定: 少なくとも1つのフラグが必要です");
        return hajimu_bool(false);
    }
    int intents = 0;
    for (int i = 0; i < argc; i++) {
        if (argv[i].type == VALUE_NUMBER) {
            intents |= (int)argv[i].number;
        } else if (argv[i].type == VALUE_STRING) {
            const char *s = argv[i].string.data;
            if (strcmp(s, "全て") == 0 || strcmp(s, "ALL") == 0)
                intents = 0x3FFFF;
            else if (strcmp(s, "サーバー") == 0) intents |= INTENT_GUILDS;
            else if (strcmp(s, "メンバー") == 0) intents |= INTENT_GUILD_MEMBERS;
            else if (strcmp(s, "モデレーション") == 0) intents |= INTENT_GUILD_MODERATION;
            else if (strcmp(s, "メッセージ") == 0) intents |= INTENT_GUILD_MESSAGES;
            else if (strcmp(s, "メッセージ内容") == 0) intents |= INTENT_MESSAGE_CONTENT;
            else if (strcmp(s, "リアクション") == 0) intents |= INTENT_GUILD_MESSAGE_REACTIONS;
            else if (strcmp(s, "DM") == 0) intents |= INTENT_DIRECT_MESSAGES;
            else if (strcmp(s, "プレゼンス") == 0) intents |= INTENT_GUILD_PRESENCES;
            else if (strcmp(s, "ボイス") == 0) intents |= INTENT_GUILD_VOICE_STATES;
            else if (strcmp(s, "デフォルト") == 0) intents |= INTENT_DEFAULT;
            else LOG_W("不明なインテント: %s", s);
        }
    }
    g_bot.intents = intents;
    LOG_D("インテント設定: 0x%X", intents);
    return hajimu_bool(true);
}

/* --- イベントハンドラ --- */

/* イベント(名前, コールバック) */
static Value fn_on_event(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        (argv[1].type != VALUE_FUNCTION && argv[1].type != VALUE_BUILTIN)) {
        LOG_E("イベント: (イベント名, コールバック関数) が必要です");
        return hajimu_bool(false);
    }
    event_register(argv[0].string.data, argv[1]);
    LOG_D("イベント登録: %s", argv[0].string.data);
    return hajimu_bool(true);
}

/* 準備完了時(コールバック) */
static Value fn_on_ready(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION && argv[0].type != VALUE_BUILTIN)) {
        LOG_E("準備完了時: コールバック関数が必要です");
        return hajimu_bool(false);
    }
    event_register("準備完了", argv[0]);
    event_register("READY", argv[0]);
    return hajimu_bool(true);
}

/* メッセージ受信時(コールバック) */
static Value fn_on_message(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION && argv[0].type != VALUE_BUILTIN)) {
        LOG_E("メッセージ受信時: コールバック関数が必要です");
        return hajimu_bool(false);
    }
    event_register("メッセージ受信", argv[0]);
    event_register("MESSAGE_CREATE", argv[0]);
    return hajimu_bool(true);
}

/* コマンド受信時(コールバック) */
static Value fn_on_command(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION && argv[0].type != VALUE_BUILTIN)) {
        LOG_E("コマンド受信時: コールバック関数が必要です");
        return hajimu_bool(false);
    }
    event_register("コマンド受信", argv[0]);
    event_register("INTERACTION_CREATE", argv[0]);
    return hajimu_bool(true);
}

/* 参加時(コールバック) */
static Value fn_on_join(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION && argv[0].type != VALUE_BUILTIN)) return hajimu_bool(false);
    event_register("メンバー参加", argv[0]);
    event_register("GUILD_MEMBER_ADD", argv[0]);
    return hajimu_bool(true);
}

/* 退出時(コールバック) */
static Value fn_on_leave(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION && argv[0].type != VALUE_BUILTIN)) return hajimu_bool(false);
    event_register("メンバー退出", argv[0]);
    event_register("GUILD_MEMBER_REMOVE", argv[0]);
    return hajimu_bool(true);
}

/* リアクション時(コールバック) */
static Value fn_on_reaction(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION && argv[0].type != VALUE_BUILTIN)) return hajimu_bool(false);
    event_register("リアクション追加", argv[0]);
    event_register("MESSAGE_REACTION_ADD", argv[0]);
    return hajimu_bool(true);
}

/* --- メッセージ送信 --- */

/* メッセージ送信(チャンネルID, 内容) */
static Value fn_send_message(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("メッセージ送信: (チャンネルID, 内容) が必要です");
        return hajimu_bool(false);
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "content", argv[1].string.data);
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/messages", argv[0].string.data);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);

    Value result = hajimu_bool(false);
    if (resp && (code == 200 || code == 201)) {
        result = json_to_value(resp);
    }
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* 返信(メッセージ, 内容) */
static Value fn_reply(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_DICT || argv[1].type != VALUE_STRING) {
        LOG_E("返信: (メッセージ辞書, 内容) が必要です");
        return hajimu_bool(false);
    }
    const char *channel_id = value_get_str(&argv[0], "チャンネルID");
    const char *msg_id = value_get_str(&argv[0], "ID");
    if (!channel_id || !msg_id) {
        LOG_E("返信: メッセージにチャンネルIDまたはIDがありません");
        return hajimu_bool(false);
    }

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "content", argv[1].string.data);
    jb_key(&sb, "message_reference"); jb_obj_start(&sb);
    jb_str(&sb, "message_id", msg_id);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/messages", channel_id);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);

    Value result = hajimu_bool(false);
    if (resp && (code == 200 || code == 201)) {
        result = json_to_value(resp);
    }
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* メッセージ編集(チャンネルID, メッセージID, 内容) */
static Value fn_edit_message(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING) {
        LOG_E("メッセージ編集: (チャンネルID, メッセージID, 新内容) が必要です");
        return hajimu_bool(false);
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "content", argv[2].string.data);
    jb_obj_end(&sb);

    char ep[160];
    snprintf(ep, sizeof(ep), "/channels/%s/messages/%s",
             argv[0].string.data, argv[1].string.data);

    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, sb.data, &code);
    sb_free(&sb);

    Value result = hajimu_bool(code == 200);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* メッセージ削除(チャンネルID, メッセージID) */
static Value fn_delete_message(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("メッセージ削除: (チャンネルID, メッセージID) が必要です");
        return hajimu_bool(false);
    }
    char ep[160];
    snprintf(ep, sizeof(ep), "/channels/%s/messages/%s",
             argv[0].string.data, argv[1].string.data);

    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* 一括削除(チャンネルID, メッセージID配列) */
static Value fn_bulk_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_ARRAY) {
        LOG_E("一括削除: (チャンネルID, メッセージID配列) が必要です");
        return hajimu_bool(false);
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_key(&sb, "messages"); jb_arr_start(&sb);
    for (int i = 0; i < argv[1].array.length; i++) {
        if (argv[1].array.elements[i].type == VALUE_STRING) {
            json_escape_str(&sb, argv[1].array.elements[i].string.data);
            sb_append_char(&sb, ',');
        }
    }
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/messages/bulk-delete", argv[0].string.data);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* --- 埋め込み (Embed) --- */

/* 埋め込み作成() */
static Value fn_embed_create(int argc, Value *argv) {
    (void)argc; (void)argv;
    int idx = embed_alloc();
    if (idx < 0) return hajimu_null();
    return hajimu_number(idx);
}

/* 埋め込みタイトル(e, text) */
static Value fn_embed_title(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    Embed *e = embed_get((int)argv[0].number);
    if (!e) return hajimu_bool(false);
    snprintf(e->title, sizeof(e->title), "%s", argv[1].string.data);
    return hajimu_number(argv[0].number);
}

/* 埋め込み説明(e, text) */
static Value fn_embed_desc(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    Embed *e = embed_get((int)argv[0].number);
    if (!e) return hajimu_bool(false);
    snprintf(e->description, sizeof(e->description), "%s", argv[1].string.data);
    return hajimu_number(argv[0].number);
}

/* 埋め込み色(e, color) — 16進数 0xRRGGBB */
static Value fn_embed_color(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_NUMBER)
        return hajimu_bool(false);
    Embed *e = embed_get((int)argv[0].number);
    if (!e) return hajimu_bool(false);
    e->color = (int)argv[1].number;
    return hajimu_number(argv[0].number);
}

/* 埋め込みフィールド(e, name, value) or (e, name, value, inline) */
static Value fn_embed_field(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_NUMBER ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);
    Embed *e = embed_get((int)argv[0].number);
    if (!e || e->field_count >= MAX_EMBED_FIELDS) return hajimu_bool(false);
    int fi = e->field_count++;
    snprintf(e->fields[fi].name, sizeof(e->fields[fi].name), "%s", argv[1].string.data);
    snprintf(e->fields[fi].value, sizeof(e->fields[fi].value), "%s", argv[2].string.data);
    e->fields[fi].is_inline = (argc >= 4 && argv[3].type == VALUE_BOOL) ? argv[3].boolean : false;
    return hajimu_number(argv[0].number);
}

/* 埋め込みフッター(e, text) or (e, text, icon_url) */
static Value fn_embed_footer(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    Embed *e = embed_get((int)argv[0].number);
    if (!e) return hajimu_bool(false);
    snprintf(e->footer_text, sizeof(e->footer_text), "%s", argv[1].string.data);
    if (argc >= 3 && argv[2].type == VALUE_STRING)
        snprintf(e->footer_icon, sizeof(e->footer_icon), "%s", argv[2].string.data);
    return hajimu_number(argv[0].number);
}

/* 埋め込みサムネイル(e, url) */
static Value fn_embed_thumbnail(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    Embed *e = embed_get((int)argv[0].number);
    if (!e) return hajimu_bool(false);
    snprintf(e->thumbnail, sizeof(e->thumbnail), "%s", argv[1].string.data);
    return hajimu_number(argv[0].number);
}

/* 埋め込み画像(e, url) */
static Value fn_embed_image(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    Embed *e = embed_get((int)argv[0].number);
    if (!e) return hajimu_bool(false);
    snprintf(e->image, sizeof(e->image), "%s", argv[1].string.data);
    return hajimu_number(argv[0].number);
}

/* 埋め込み著者(e, name) or (e, name, icon, url) */
static Value fn_embed_author(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    Embed *e = embed_get((int)argv[0].number);
    if (!e) return hajimu_bool(false);
    snprintf(e->author_name, sizeof(e->author_name), "%s", argv[1].string.data);
    if (argc >= 3 && argv[2].type == VALUE_STRING)
        snprintf(e->author_icon, sizeof(e->author_icon), "%s", argv[2].string.data);
    if (argc >= 4 && argv[3].type == VALUE_STRING)
        snprintf(e->author_url, sizeof(e->author_url), "%s", argv[3].string.data);
    return hajimu_number(argv[0].number);
}

/* 埋め込みタイムスタンプ(e) */
static Value fn_embed_timestamp(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_NUMBER) return hajimu_bool(false);
    Embed *e = embed_get((int)argv[0].number);
    if (!e) return hajimu_bool(false);
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(e->timestamp, sizeof(e->timestamp), "%Y-%m-%dT%H:%M:%SZ", tm);
    return hajimu_number(argv[0].number);
}

/* 埋め込み送信(チャンネルID, embed_id) */
static Value fn_embed_send(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_NUMBER) {
        LOG_E("埋め込み送信: (チャンネルID, 埋め込みID) が必要です");
        return hajimu_bool(false);
    }
    Embed *e = embed_get((int)argv[1].number);
    if (!e) return hajimu_bool(false);

    char *embed_json = embed_to_json(e);

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_key(&sb, "embeds"); jb_arr_start(&sb);
    sb_append(&sb, embed_json);
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    /* Optional content (3rd arg) */
    if (argc >= 3 && argv[2].type == VALUE_STRING) {
        jb_str(&sb, "content", argv[2].string.data);
    }
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/messages", argv[0].string.data);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);

    free(embed_json);
    sb_free(&sb);

    /* Free the embed slot */
    e->active = false;

    Value result = hajimu_bool(false);
    if (resp && (code == 200 || code == 201)) {
        result = json_to_value(resp);
    }
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- スラッシュコマンド --- */

/* コマンド登録(名前, 説明, コールバック) */
static Value fn_register_command(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        (argv[2].type != VALUE_FUNCTION && argv[2].type != VALUE_BUILTIN)) {
        LOG_E("コマンド登録: (名前, 説明, コールバック) が必要です");
        return hajimu_bool(false);
    }
    if (g_bot.command_count >= MAX_COMMANDS) {
        LOG_E("コマンド登録上限に達しました");
        return hajimu_bool(false);
    }
    int idx = g_bot.command_count++;
    SlashCommand *cmd = &g_bot.commands[idx];
    memset(cmd, 0, sizeof(*cmd));
    snprintf(cmd->name, sizeof(cmd->name), "%s", argv[0].string.data);
    snprintf(cmd->description, sizeof(cmd->description), "%s", argv[1].string.data);
    cmd->callback = argv[2];
    LOG_D("コマンド登録キュー: /%s", cmd->name);
    return hajimu_number(idx);
}

/* コマンドオプション(コマンドインデックス, 型, 名前, 説明, 必須) */
static Value fn_command_option(int argc, Value *argv) {
    if (argc < 4 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING || argv[3].type != VALUE_STRING) {
        LOG_E("コマンドオプション: (コマンドID, 型, 名前, 説明[, 必須]) が必要です");
        return hajimu_bool(false);
    }
    int idx = (int)argv[0].number;
    if (idx < 0 || idx >= g_bot.command_count) return hajimu_bool(false);
    SlashCommand *cmd = &g_bot.commands[idx];
    if (cmd->option_count >= MAX_CMD_OPTIONS) return hajimu_bool(false);

    int oi = cmd->option_count++;
    /* Parse type string */
    const char *type_str = argv[1].string.data;
    int type = 3; /* default STRING */
    if (strcmp(type_str, "文字列") == 0 || strcmp(type_str, "STRING") == 0) type = 3;
    else if (strcmp(type_str, "整数") == 0 || strcmp(type_str, "INTEGER") == 0) type = 4;
    else if (strcmp(type_str, "真偽値") == 0 || strcmp(type_str, "BOOLEAN") == 0) type = 5;
    else if (strcmp(type_str, "ユーザー") == 0 || strcmp(type_str, "USER") == 0) type = 6;
    else if (strcmp(type_str, "チャンネル") == 0 || strcmp(type_str, "CHANNEL") == 0) type = 7;
    else if (strcmp(type_str, "ロール") == 0 || strcmp(type_str, "ROLE") == 0) type = 8;
    else if (strcmp(type_str, "数値") == 0 || strcmp(type_str, "NUMBER") == 0) type = 10;

    cmd->options[oi].type = type;
    snprintf(cmd->options[oi].name, sizeof(cmd->options[oi].name), "%s", argv[2].string.data);
    snprintf(cmd->options[oi].description, sizeof(cmd->options[oi].description), "%s", argv[3].string.data);
    cmd->options[oi].required = (argc >= 5 && argv[4].type == VALUE_BOOL) ? argv[4].boolean : false;

    return hajimu_bool(true);
}

/* コマンド応答(インタラクション, 内容) */
static Value fn_command_respond(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_DICT || argv[1].type != VALUE_STRING) {
        LOG_E("コマンド応答: (インタラクション, 内容) が必要です");
        return hajimu_bool(false);
    }
    const char *interaction_id = value_get_str(&argv[0], "ID");
    const char *interaction_token = value_get_str(&argv[0], "トークン");
    if (!interaction_id || !interaction_token) {
        LOG_E("コマンド応答: インタラクションにIDまたはトークンがありません");
        return hajimu_bool(false);
    }

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 4); /* CHANNEL_MESSAGE_WITH_SOURCE */
    jb_key(&sb, "data"); jb_obj_start(&sb);
    jb_str(&sb, "content", argv[1].string.data);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);

    char ep[256];
    snprintf(ep, sizeof(ep), "/interactions/%s/%s/callback",
             interaction_id, interaction_token);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200 || code == 204);
}

/* コマンド遅延応答(インタラクション) */
static Value fn_command_defer(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_DICT) return hajimu_bool(false);
    const char *interaction_id = value_get_str(&argv[0], "ID");
    const char *interaction_token = value_get_str(&argv[0], "トークン");
    if (!interaction_id || !interaction_token) return hajimu_bool(false);

    char ep[256];
    snprintf(ep, sizeof(ep), "/interactions/%s/%s/callback",
             interaction_id, interaction_token);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, "{\"type\":5}", &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200 || code == 204);
}

/* コマンドフォローアップ(インタラクション, 内容) */
static Value fn_command_followup(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_DICT || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    const char *interaction_token = value_get_str(&argv[0], "トークン");
    if (!interaction_token) return hajimu_bool(false);

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "content", argv[1].string.data);
    jb_obj_end(&sb);

    char ep[256];
    snprintf(ep, sizeof(ep), "/webhooks/%s/%s", g_bot.application_id, interaction_token);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200 || code == 204);
}

/* --- チャンネル操作 --- */

/* チャンネル情報(ID) */
static Value fn_channel_info(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[64];
    snprintf(ep, sizeof(ep), "/channels/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* チャンネル一覧(サーバーID) */
static Value fn_channel_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/channels", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* タイピング表示(チャンネルID) */
static Value fn_typing(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char ep[64];
    snprintf(ep, sizeof(ep), "/channels/%s/typing", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* --- サーバー (Guild) 操作 --- */

/* サーバー情報(ID) */
static Value fn_guild_info(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s?with_counts=true", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* メンバー情報(サーバーID, ユーザーID) */
static Value fn_member_info(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/members/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* キック(サーバーID, ユーザーID[, 理由]) */
static Value fn_kick(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/members/%s",
             argv[0].string.data, argv[1].string.data);
    /* TODO: reason header via X-Audit-Log-Reason */
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* BAN(サーバーID, ユーザーID[, 理由]) */
static Value fn_ban(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/bans/%s",
             argv[0].string.data, argv[1].string.data);

    const char *body = "{}";
    StrBuf sb;
    if (argc >= 3 && argv[2].type == VALUE_STRING) {
        sb_init(&sb);
        jb_obj_start(&sb);
        jb_int(&sb, "delete_message_seconds", 0);
        jb_obj_end(&sb);
        body = sb.data;
    }

    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, body, &code);
    if (resp) { json_free(resp); free(resp); }
    if (argc >= 3) sb_free(&sb);
    return hajimu_bool(code == 204);
}

/* BAN解除(サーバーID, ユーザーID) */
static Value fn_unban(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/bans/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* --- ロール --- */

/* ロール付与(サーバーID, ユーザーID, ロールID) */
static Value fn_add_role(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[192];
    snprintf(ep, sizeof(ep), "/guilds/%s/members/%s/roles/%s",
             argv[0].string.data, argv[1].string.data, argv[2].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, "{}", &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* ロール剥奪(サーバーID, ユーザーID, ロールID) */
static Value fn_remove_role(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[192];
    snprintf(ep, sizeof(ep), "/guilds/%s/members/%s/roles/%s",
             argv[0].string.data, argv[1].string.data, argv[2].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* ロール一覧(サーバーID) */
static Value fn_role_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/roles", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- リアクション --- */

/* リアクション追加(チャンネルID, メッセージID, 絵文字) */
static Value fn_add_reaction(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);

    /* URL-encode the emoji */
    CURL *curl = curl_easy_init();
    char *encoded = curl_easy_escape(curl, argv[2].string.data, 0);
    curl_easy_cleanup(curl);

    char ep[256];
    snprintf(ep, sizeof(ep), "/channels/%s/messages/%s/reactions/%s/@me",
             argv[0].string.data, argv[1].string.data, encoded);
    curl_free(encoded);

    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, "{}", &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* リアクション削除(チャンネルID, メッセージID, 絵文字) */
static Value fn_remove_reaction(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);

    CURL *curl = curl_easy_init();
    char *encoded = curl_easy_escape(curl, argv[2].string.data, 0);
    curl_easy_cleanup(curl);

    char ep[256];
    snprintf(ep, sizeof(ep), "/channels/%s/messages/%s/reactions/%s/@me",
             argv[0].string.data, argv[1].string.data, encoded);
    curl_free(encoded);

    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* --- ステータス --- */

/* ステータス設定(状態, テキスト[, 種類]) */
static Value fn_set_status(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);

    const char *status_str = argv[0].string.data;
    const char *status = "online";
    if (strcmp(status_str, "オンライン") == 0) status = "online";
    else if (strcmp(status_str, "退席中") == 0) status = "idle";
    else if (strcmp(status_str, "取り込み中") == 0) status = "dnd";
    else if (strcmp(status_str, "オフライン") == 0) status = "invisible";
    else status = status_str; /* raw value */

    const char *activity = (argc >= 2 && argv[1].type == VALUE_STRING) ? argv[1].string.data : "";

    int type = 0; /* 0=Playing, 1=Streaming, 2=Listening, 3=Watching, 5=Competing */
    if (argc >= 3 && argv[2].type == VALUE_STRING) {
        const char *t = argv[2].string.data;
        if (strcmp(t, "プレイ中") == 0 || strcmp(t, "PLAYING") == 0) type = 0;
        else if (strcmp(t, "配信中") == 0 || strcmp(t, "STREAMING") == 0) type = 1;
        else if (strcmp(t, "再生中") == 0 || strcmp(t, "LISTENING") == 0) type = 2;
        else if (strcmp(t, "視聴中") == 0 || strcmp(t, "WATCHING") == 0) type = 3;
        else if (strcmp(t, "競争中") == 0 || strcmp(t, "COMPETING") == 0) type = 5;
    } else if (argc >= 3 && argv[2].type == VALUE_NUMBER) {
        type = (int)argv[2].number;
    }

    gw_send_presence(status, activity, type);
    return hajimu_bool(true);
}

/* --- ユーザー情報 --- */

/* 自分情報() */
static Value fn_me(int argc, Value *argv) {
    (void)argc; (void)argv;
    long code = 0;
    JsonNode *resp = discord_rest("GET", "/users/@me", NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ユーザー情報(ID) */
static Value fn_user_info(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[64];
    snprintf(ep, sizeof(ep), "/users/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- ピン留め --- */

/* ピン留め(チャンネルID, メッセージID) */
static Value fn_pin_message(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/pins/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, "{}", &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* --- DM --- */

/* DM作成(ユーザーID) → チャンネル情報を返す */
static Value fn_create_dm(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "recipient_id", argv[0].string.data);
    jb_obj_end(&sb);

    long code = 0;
    JsonNode *resp = discord_rest("POST", "/users/@me/channels", sb.data, &code);
    sb_free(&sb);

    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- ユーティリティ --- */

/* ログレベル設定(レベル) */
static Value fn_set_log_level(int argc, Value *argv) {
    if (argc < 1) return hajimu_bool(false);
    if (argv[0].type == VALUE_NUMBER) {
        g_bot.log_level = (int)argv[0].number;
    } else if (argv[0].type == VALUE_STRING) {
        const char *s = argv[0].string.data;
        if (strcmp(s, "なし") == 0 || strcmp(s, "NONE") == 0) g_bot.log_level = LOG_NONE;
        else if (strcmp(s, "エラー") == 0 || strcmp(s, "ERROR") == 0) g_bot.log_level = LOG_ERROR;
        else if (strcmp(s, "警告") == 0 || strcmp(s, "WARN") == 0) g_bot.log_level = LOG_WARN;
        else if (strcmp(s, "情報") == 0 || strcmp(s, "INFO") == 0) g_bot.log_level = LOG_INFO;
        else if (strcmp(s, "デバッグ") == 0 || strcmp(s, "DEBUG") == 0) g_bot.log_level = LOG_DEBUG;
    }
    return hajimu_bool(true);
}

/* インテント定数 — はじむから参照用 */
static Value fn_intent_value(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_number(0);
    const char *s = argv[0].string.data;
    if (strcmp(s, "サーバー") == 0)       return hajimu_number(INTENT_GUILDS);
    if (strcmp(s, "メンバー") == 0)       return hajimu_number(INTENT_GUILD_MEMBERS);
    if (strcmp(s, "モデレーション") == 0) return hajimu_number(INTENT_GUILD_MODERATION);
    if (strcmp(s, "メッセージ") == 0)     return hajimu_number(INTENT_GUILD_MESSAGES);
    if (strcmp(s, "メッセージ内容") == 0) return hajimu_number(INTENT_MESSAGE_CONTENT);
    if (strcmp(s, "リアクション") == 0)   return hajimu_number(INTENT_GUILD_MESSAGE_REACTIONS);
    if (strcmp(s, "DM") == 0)             return hajimu_number(INTENT_DIRECT_MESSAGES);
    if (strcmp(s, "プレゼンス") == 0)     return hajimu_number(INTENT_GUILD_PRESENCES);
    if (strcmp(s, "ボイス") == 0)         return hajimu_number(INTENT_GUILD_VOICE_STATES);
    if (strcmp(s, "全て") == 0)           return hajimu_number(0x3FFFF);
    if (strcmp(s, "デフォルト") == 0)     return hajimu_number(INTENT_DEFAULT);
    return hajimu_number(0);
}

/* バージョン情報 */
static Value fn_version(int argc, Value *argv) {
    (void)argc; (void)argv;
    return hajimu_string(PLUGIN_VERSION);
}

/* =========================================================================
 * Section 15: Plugin Registration
 * ========================================================================= */

HAJIMU_PLUGIN_EXPORT void hajimu_plugin_set_runtime(HajimuRuntime *rt) {
    __hajimu_runtime = rt;
}

static HajimuPluginFunc functions[] = {
    /* ボット管理 */
    {"ボット作成",           fn_bot_create,        1,  1},
    {"ボット起動",           fn_bot_start,         0,  0},
    {"ボット停止",           fn_bot_stop,          0,  0},
    {"インテント設定",       fn_set_intents,       1, -1},

    /* イベント */
    {"イベント",             fn_on_event,          2,  2},
    {"準備完了時",           fn_on_ready,          1,  1},
    {"メッセージ受信時",     fn_on_message,        1,  1},
    {"コマンド受信時",       fn_on_command,        1,  1},
    {"参加時",               fn_on_join,           1,  1},
    {"退出時",               fn_on_leave,          1,  1},
    {"リアクション時",       fn_on_reaction,       1,  1},

    /* メッセージ */
    {"メッセージ送信",       fn_send_message,      2,  2},
    {"返信",                 fn_reply,             2,  2},
    {"メッセージ編集",       fn_edit_message,      3,  3},
    {"メッセージ削除",       fn_delete_message,    2,  2},
    {"一括削除",             fn_bulk_delete,       2,  2},

    /* 埋め込み */
    {"埋め込み作成",         fn_embed_create,      0,  0},
    {"埋め込みタイトル",     fn_embed_title,       2,  2},
    {"埋め込み説明",         fn_embed_desc,        2,  2},
    {"埋め込み色",           fn_embed_color,       2,  2},
    {"埋め込みフィールド",   fn_embed_field,       3,  4},
    {"埋め込みフッター",     fn_embed_footer,      2,  3},
    {"埋め込みサムネイル",   fn_embed_thumbnail,   2,  2},
    {"埋め込み画像",         fn_embed_image,       2,  2},
    {"埋め込み著者",         fn_embed_author,      2,  4},
    {"埋め込みタイムスタンプ", fn_embed_timestamp, 1,  1},
    {"埋め込み送信",         fn_embed_send,        2,  3},

    /* スラッシュコマンド */
    {"コマンド登録",         fn_register_command,  3,  3},
    {"コマンドオプション",   fn_command_option,    4,  5},
    {"コマンド応答",         fn_command_respond,   2,  2},
    {"コマンド遅延応答",     fn_command_defer,     1,  1},
    {"コマンドフォローアップ", fn_command_followup, 2,  2},

    /* チャンネル */
    {"チャンネル情報",       fn_channel_info,      1,  1},
    {"チャンネル一覧",       fn_channel_list,      1,  1},
    {"タイピング表示",       fn_typing,            1,  1},

    /* サーバー */
    {"サーバー情報",         fn_guild_info,        1,  1},
    {"メンバー情報",         fn_member_info,       2,  2},
    {"キック",               fn_kick,              2,  3},
    {"BAN",                  fn_ban,               2,  3},
    {"BAN解除",              fn_unban,             2,  2},

    /* ロール */
    {"ロール付与",           fn_add_role,          3,  3},
    {"ロール剥奪",           fn_remove_role,       3,  3},
    {"ロール一覧",           fn_role_list,         1,  1},

    /* リアクション */
    {"リアクション追加",     fn_add_reaction,      3,  3},
    {"リアクション削除",     fn_remove_reaction,   3,  3},

    /* ステータス */
    {"ステータス設定",       fn_set_status,        1,  3},

    /* ユーザー */
    {"自分情報",             fn_me,                0,  0},
    {"ユーザー情報",         fn_user_info,         1,  1},

    /* その他 */
    {"ピン留め",             fn_pin_message,       2,  2},
    {"DM作成",               fn_create_dm,         1,  1},
    {"ログレベル設定",       fn_set_log_level,     1,  1},
    {"インテント値",         fn_intent_value,      1,  1},
    {"バージョン",           fn_version,           0,  0},
};

HAJIMU_PLUGIN_EXPORT HajimuPluginInfo *hajimu_plugin_init(void) {
    static HajimuPluginInfo info = {
        .name           = PLUGIN_NAME,
        .version        = PLUGIN_VERSION,
        .author         = "はじむ開発チーム",
        .description    = "Discord Bot開発プラグイン — Gateway v10 / REST v10 対応",
        .functions      = functions,
        .function_count = sizeof(functions) / sizeof(functions[0]),
    };
    return &info;
}
