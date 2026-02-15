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
 * v1.1.0 — 2026-02-14  メッセージ操作完全化・タイムアウト・エラー/切断イベント
 * v1.2.0 — 2026-02-14  ボタン・セレクトメニュー・コンポーネント・エフェメラル応答
 * v1.3.0 — 2026-02-14  モーダル・サブコマンド・コンテキストメニュー・オートコンプリート
 * v1.4.0 — 2026-02-14  チャンネル管理・スレッド・権限オーバーライド・招待
 * v1.5.0 — 2026-02-14  Webhook・ファイル添付
 * v1.6.0 — 2026-02-14  コレクター・メンバーキャッシュ・サーバー一覧
 * v1.7.0 — 2026-02-14  監査ログ・AutoModeration・絵文字・スケジュールイベント・投票
 * v1.7.1 — 2026-02-14  セキュリティ修正・バグ修正
 * v2.0.0 — 2026-02-14  ボイスチャンネル対応 (Opus/Sodium)
 * v2.1.0 — 2026-02-14  ステージチャンネル・スタンプ・サーバー編集・Markdownユーティリティ
 * v2.2.0 — 2026-02-14  Components V2・テンプレート・オンボーディング・サウンドボード・OAuth2・シャーディング
 * v2.2.1 — 2026-02-15  セキュリティ・バグ修正 (JSONパーサ境界チェック, User-Agent統一,
 *                       OAuth2メモリ安全性, pthread UB修正, 音声停止ロジック修正,
 *                       ffmpegコマンドインジェクション防止, シャード検証追加)
 * v2.3.0 — 2026-02-15  discord.js/discord.py互換性強化 — 自動選択メニュー(User/Role/
 *                       Channel/Mentionable), BAN一覧/一括, メンバー編集, ニックネーム,
 *                       Webhook編集/情報, スレッド一覧/アーカイブ/ロック/ピン, クロスポスト,
 *                       チャンネルフォロー, プルーン, サーバー削除/プレビュー/ウィジェット,
 *                       バニティURL, チャンネル/ロール位置変更, リアクションユーザー一覧,
 *                       コマンド管理(削除/一覧/権限), Snowflakeタイムスタンプ, 権限計算,
 *                       アプリ情報, Voice地域一覧, Gatewayイベント40種対応
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

/* v2.0.0: Voice — Opus encoding + Sodium encryption */
#include <opus.h>
#include <sodium.h>

/* =========================================================================
 * Section 1: Constants & Macros
 * ========================================================================= */

#define PLUGIN_NAME    "hajimu_discord"
#define PLUGIN_VERSION "2.3.0"

/* User-Agent (version auto-embedded) */
#define DISCORD_USER_AGENT "User-Agent: DiscordBot (hajimu_discord, " PLUGIN_VERSION ")"

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

/* v1.2.0: Component limits */
#define MAX_BUTTONS           128
#define MAX_ACTION_ROWS       64
#define MAX_ROW_COMPONENTS    5
#define MAX_SELECT_MENUS      64
#define MAX_MENU_OPTIONS      25
#define MAX_COMP_HANDLERS     128

/* v1.3.0: Modal limits */
#define MAX_MODALS            32
#define MAX_MODAL_INPUTS      5
#define MAX_CMD_CHOICES       25

/* v1.6.0: Collector limits */
#define MAX_COLLECTORS        16
#define MAX_COLLECTED         100

/* v2.0.0: Voice limits */
#define MAX_VOICE_CONNS       8     /* Max simultaneous voice connections */
#define VOICE_SAMPLE_RATE     48000
#define VOICE_CHANNELS        2     /* Stereo */
#define VOICE_FRAME_MS        20
#define VOICE_FRAME_SAMPLES   (VOICE_SAMPLE_RATE * VOICE_FRAME_MS / 1000) /* 960 */
#define VOICE_FRAME_SIZE      (VOICE_FRAME_SAMPLES * VOICE_CHANNELS)       /* 1920 */
#define VOICE_MAX_PACKET      4000
#define MAX_AUDIO_QUEUE       64
#define MAX_VOICE_STATE_CACHE 512

/* Discord component types */
#define COMP_ACTION_ROW       1
#define COMP_BUTTON           2
#define COMP_STRING_SELECT    3

/* Button styles */
#define BTN_PRIMARY           1
#define BTN_SECONDARY         2
#define BTN_SUCCESS           3
#define BTN_DANGER            4
#define BTN_LINK              5

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

/* --- v1.2.0: Button --- */
typedef struct {
    int  style;               /* BTN_PRIMARY ... BTN_LINK */
    char label[80];
    char custom_id[100];
    char url[MAX_URL_LEN];    /* link style only */
    char emoji_name[64];
    bool disabled;
    bool active;
} Button;

/* --- v1.2.0: Select Menu Option --- */
typedef struct {
    char label[100];
    char value[100];
    char description[100];
    char emoji_name[64];
    bool default_selected;
} MenuOption;

/* --- v1.2.0: Select Menu --- */
typedef struct {
    char custom_id[100];
    char placeholder[150];
    int  min_values;
    int  max_values;
    MenuOption options[MAX_MENU_OPTIONS];
    int  option_count;
    bool disabled;
    bool active;
} SelectMenu;

/* --- v1.2.0: Action Row --- */
typedef struct {
    int  comp_type[MAX_ROW_COMPONENTS];  /* COMP_BUTTON or COMP_STRING_SELECT */
    int  comp_idx[MAX_ROW_COMPONENTS];   /* index into buttons[] or menus[] */
    int  comp_count;
    bool active;
} ActionRow;

/* --- v1.2.0: Component Handler (maps custom_id → callback) --- */
typedef struct {
    char custom_id[100];
    Value callback;
    int type;  /* COMP_BUTTON or COMP_STRING_SELECT, -1=modal */
} ComponentHandler;

/* --- v1.3.0: Modal --- */
typedef struct {
    char custom_id[100];
    char title[128];
    struct {
        char custom_id[100];
        char label[128];
        int  style;          /* 1=Short, 2=Paragraph */
        char placeholder[256];
        char default_value[4096];
        int  min_length;
        int  max_length;
        bool required;
    } inputs[MAX_MODAL_INPUTS];
    int input_count;
    bool active;
} Modal;

/* --- v1.6.0: Collector --- */
typedef struct {
    int    type;              /* 0=message, 1=reaction, 2=interaction */
    char   channel_id[MAX_SNOWFLAKE];
    char   message_id[MAX_SNOWFLAKE]; /* for reaction collectors */
    Value  filter;            /* filter function (optional) */
    int    max_collect;       /* max items to collect (0=unlimited) */
    double timeout_sec;       /* timeout in seconds */
    struct timespec start_time;
    Value  collected[MAX_COLLECTED];
    int    collected_count;
    bool   active;
    bool   done;
} Collector;

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

/* --- v2.0.0: Voice Connection --- */
typedef struct {
    char path[256];       /* File/URL path */
} AudioQueueItem;

typedef struct {
    /* Identity */
    char guild_id[MAX_SNOWFLAKE];
    char channel_id[MAX_SNOWFLAKE];
    char session_id[128];
    char voice_token[128];
    char endpoint[256];
    bool active;

    /* Voice WebSocket */
    WsConn vws;
    uint32_t ssrc;
    char voice_ip[64];
    int  voice_port;
    unsigned char secret_key[32];
    bool ready;

    /* UDP */
    int udp_fd;
    struct sockaddr_in udp_addr;
    char external_ip[64];
    uint16_t external_port;

    /* Audio state */
    OpusEncoder *opus_enc;
    uint16_t rtp_seq;
    uint32_t rtp_timestamp;
    bool playing;
    bool paused;
    volatile bool stop_requested;

    /* Audio queue */
    AudioQueueItem queue[MAX_AUDIO_QUEUE];
    int queue_head;
    int queue_tail;
    int queue_count;
    bool loop_mode;

    /* Threads */
    pthread_t voice_ws_thread;
    pthread_t audio_thread;
    pthread_mutex_t voice_mutex;
    int voice_heartbeat_interval; /* ms */
    volatile bool voice_heartbeat_acked;

    /* Pending state (waiting for gateway events) */
    bool waiting_for_state;
    bool waiting_for_server;
    bool state_received;
    bool server_received;
} VoiceConn;

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

    /* Components (v1.2.0) */
    Button buttons[MAX_BUTTONS];
    SelectMenu menus[MAX_SELECT_MENUS];
    ActionRow rows[MAX_ACTION_ROWS];
    ComponentHandler comp_handlers[MAX_COMP_HANDLERS];
    int comp_handler_count;

    /* Modals (v1.3.0) */
    Modal modals[MAX_MODALS];

    /* Autocomplete handlers (v1.3.0) — maps command name → callback */
    struct {
        char command_name[64];
        Value callback;
    } autocomplete_handlers[MAX_COMMANDS];
    int autocomplete_count;

    /* Collectors (v1.6.0) */
    Collector collectors[MAX_COLLECTORS];
    pthread_mutex_t collector_mutex;

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

    /* Voice connections (v2.0.0) */
    VoiceConn voice_conns[MAX_VOICE_CONNS];
    int voice_conn_count;

    /* Voice state cache — maps (guild_id, user_id) → channel_id */
    struct {
        char guild_id[MAX_SNOWFLAKE];
        char user_id[MAX_SNOWFLAKE];
        char channel_id[MAX_SNOWFLAKE];
    } voice_states[MAX_VOICE_STATE_CACHE];
    int voice_state_count;

    /* Sharding (v2.2.0) */
    int shard_id;
    int shard_count;
    bool sharding_enabled;

    /* yt-dlp cookie option (v2.5.0) */
    char ytdlp_cookie_opt[512];
} BotState;

static BotState g_bot = {0};

/* Shutdown flag */
static volatile sig_atomic_t g_shutdown = 0;

/* Forward declarations for event system (used in REST and Gateway) */
static void event_fire(const char *name, int argc, Value *argv);

/* Forward declaration for collector feeding (v1.6.0) */
static void collector_feed(int type, const char *channel_id,
                           const char *message_id, Value *val);

/* Forward declarations for voice (v2.0.0) */
static VoiceConn *voice_find(const char *guild_id);
static VoiceConn *voice_alloc(const char *guild_id);
static void voice_free(VoiceConn *vc);
static int voice_ws_connect_raw(WsConn *ws, const char *host, int port, const char *path);
static void voice_check_ready(VoiceConn *vc);
static void *voice_ws_thread_func(void *arg);
static void *voice_audio_thread_func(void *arg);

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
    if (p->pos + 4 <= p->len && strncmp(p->s + p->pos, "true", 4) == 0) {
        p->pos += 4; JsonNode n = json_null_node(); n.type = JSON_BOOL; n.boolean = true; return n;
    }
    if (p->pos + 5 <= p->len && strncmp(p->s + p->pos, "false", 5) == 0) {
        p->pos += 5; JsonNode n = json_null_node(); n.type = JSON_BOOL; n.boolean = false; return n;
    }
    if (p->pos + 4 <= p->len && strncmp(p->s + p->pos, "null", 4) == 0) {
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
    if (!out) { LOG_E("base64メモリ確保失敗"); return NULL; }
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
    if (!resp.data) {
        pthread_mutex_unlock(&g_bot.rest_mutex);
        return NULL;
    }

    /* Headers */
    struct curl_slist *hdrs = NULL;
    char auth[MAX_TOKEN_LEN + 32];
    snprintf(auth, sizeof(auth), "Authorization: Bot %s", g_bot.token);
    hdrs = curl_slist_append(hdrs, auth);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, DISCORD_USER_AGENT);

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
            if (!resp.data) {
                pthread_mutex_unlock(&g_bot.rest_mutex);
                return NULL;
            }
            resp.len = 0;
            hdrs = NULL;
            hdrs = curl_slist_append(hdrs, auth);
            hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
            hdrs = curl_slist_append(hdrs, DISCORD_USER_AGENT);
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
        Value err_msg = hajimu_string(curl_easy_strerror(res));
        event_fire("エラー", 1, &err_msg);
        event_fire("ERROR", 1, &err_msg);
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
    if (!payload) {
        pthread_mutex_unlock(&g_bot.ws_write_mutex);
        return -1;
    }
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
            if (payload_len > 16 * 1024 * 1024) { /* 16MB max payload protection */
                LOG_E("異常なペイロードサイズ: %llu bytes", (unsigned long long)payload_len);
                sb_free(&raw);
                return NULL;
            }
            uint8_t *buf = (uint8_t *)malloc((size_t)payload_len);
            if (!buf) {
                LOG_E("ペイロードメモリ確保失敗");
                sb_free(&raw);
                return NULL;
            }            uint64_t read_total = 0;
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

/* v1.6.0: Feed a value to active collectors */
static void collector_feed(int type, const char *channel_id,
                           const char *message_id, Value *val) {
    pthread_mutex_lock(&g_bot.collector_mutex);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for (int i = 0; i < MAX_COLLECTORS; i++) {
        Collector *c = &g_bot.collectors[i];
        if (!c->active || c->done) continue;
        if (c->type != type) continue;

        /* Check timeout */
        double elapsed = (now.tv_sec - c->start_time.tv_sec) +
                         (now.tv_nsec - c->start_time.tv_nsec) / 1e9;
        if (c->timeout_sec > 0 && elapsed >= c->timeout_sec) {
            c->done = true;
            continue;
        }

        /* Channel filter */
        if (c->channel_id[0] && channel_id &&
            strcmp(c->channel_id, channel_id) != 0) continue;

        /* Message filter (for reaction collectors) */
        if (c->message_id[0] && message_id &&
            strcmp(c->message_id, message_id) != 0) continue;

        /* Optional user filter function */
        if (c->filter.type == VALUE_FUNCTION || c->filter.type == VALUE_BUILTIN) {
            pthread_mutex_lock(&g_bot.callback_mutex);
            Value result = hajimu_call(&c->filter, 1, val);
            pthread_mutex_unlock(&g_bot.callback_mutex);
            if (result.type == VALUE_BOOL && !result.boolean) continue;
        }

        /* Collect */
        if (c->collected_count < MAX_COLLECTED) {
            c->collected[c->collected_count++] = *val;
        }

        /* Check max */
        if (c->max_collect > 0 && c->collected_count >= c->max_collect) {
            c->done = true;
        }
    }
    pthread_mutex_unlock(&g_bot.collector_mutex);
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
    /* v1.7.0: 監査ログ / AutoMod / 絵文字 / イベント / 投票 */
    {"action_type",       "アクション種類"},
    {"target_id",         "対象ID"},
    {"changes",           "変更内容"},
    {"rule_id",           "ルールID"},
    {"rule_trigger_type", "トリガー種類"},
    {"matched_keyword",   "一致キーワード"},
    {"matched_content",   "一致内容"},
    {"alert_system_message_id", "アラートメッセージID"},
    {"keyword_filter",    "キーワードフィルタ"},
    {"trigger_type",      "トリガー種類"},
    {"trigger_metadata",  "トリガーメタ"},
    {"event_type",        "イベント種類"},
    {"actions",           "アクション"},
    {"enabled",           "有効"},
    {"exempt_roles",      "除外ロール"},
    {"exempt_channels",   "除外チャンネル"},
    {"animated",          "アニメーション"},
    {"available",         "利用可能"},
    {"managed",           "管理済み"},
    {"require_colons",    "コロン必要"},
    {"scheduled_start_time", "開始時刻"},
    {"scheduled_end_time","終了時刻"},
    {"entity_type",       "エンティティ種類"},
    {"privacy_level",     "プライバシー"},
    {"status",            "ステータス"},
    {"entity_metadata",   "エンティティメタ"},
    {"creator",           "作成者"},
    {"user_count",        "参加者数"},
    {"question",          "質問"},
    {"answers",           "回答"},
    {"expiry",            "期限"},
    {"allow_multiselect", "複数選択"},
    {"poll",              "投票"},
    {"results",           "結果"},
    {"layout_type",       "レイアウト"},
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
                if (!dict.dict.keys || !dict.dict.values) {
                    free(dict.dict.keys);
                    free(dict.dict.values);
                    return hajimu_null();
                }
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

/* Voice state cache helpers */
static void voice_state_cache_update(const char *guild_id, const char *user_id, const char *channel_id) {
    for (int i = 0; i < g_bot.voice_state_count; i++) {
        if (strcmp(g_bot.voice_states[i].guild_id, guild_id) == 0 &&
            strcmp(g_bot.voice_states[i].user_id, user_id) == 0) {
            if (channel_id && *channel_id) {
                snprintf(g_bot.voice_states[i].channel_id, MAX_SNOWFLAKE, "%s", channel_id);
            } else {
                g_bot.voice_states[i] = g_bot.voice_states[--g_bot.voice_state_count];
            }
            return;
        }
    }
    if (channel_id && *channel_id && g_bot.voice_state_count < MAX_VOICE_STATE_CACHE) {
        int idx = g_bot.voice_state_count++;
        snprintf(g_bot.voice_states[idx].guild_id, MAX_SNOWFLAKE, "%s", guild_id);
        snprintf(g_bot.voice_states[idx].user_id, MAX_SNOWFLAKE, "%s", user_id);
        snprintf(g_bot.voice_states[idx].channel_id, MAX_SNOWFLAKE, "%s", channel_id);
    }
}

static const char *voice_state_cache_get(const char *guild_id, const char *user_id) {
    if (!guild_id || !user_id) return NULL;
    for (int i = 0; i < g_bot.voice_state_count; i++) {
        if (strcmp(g_bot.voice_states[i].guild_id, guild_id) == 0 &&
            strcmp(g_bot.voice_states[i].user_id, user_id) == 0) {
            return g_bot.voice_states[i].channel_id;
        }
    }
    return NULL;
}

/* Helper to add a key-value pair to an existing Value dict */
static void value_dict_add(Value *dict, const char *key, Value v) {
    if (!dict || dict->type != VALUE_DICT) return;
    if (dict->dict.length >= dict->dict.capacity) {
        int new_cap = dict->dict.capacity ? dict->dict.capacity * 2 : 4;
        char **new_keys = (char **)realloc(dict->dict.keys, new_cap * sizeof(char *));
        Value *new_vals = (Value *)realloc(dict->dict.values, new_cap * sizeof(Value));
        if (!new_keys || !new_vals) return;
        dict->dict.keys = new_keys;
        dict->dict.values = new_vals;
        dict->dict.capacity = new_cap;
    }
    dict->dict.keys[dict->dict.length] = strdup(key);
    dict->dict.values[dict->dict.length] = v;
    dict->dict.length++;
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
    /* Sharding (v2.2.0) */
    if (g_bot.sharding_enabled) {
        jb_key(&sb, "shard");
        sb_appendf(&sb, "[%d,%d],", g_bot.shard_id, g_bot.shard_count);
    }
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
        if (app_id) {
            if (g_bot.application_id[0]) {
                /* 環境変数で既に設定済み — 一致確認のみ */
                if (strcmp(g_bot.application_id, app_id) != 0) {
                    LOG_W("CLIENT_ID 不一致: env=%s, READY=%s (READYの値を使用)",
                          g_bot.application_id, app_id);
                    snprintf(g_bot.application_id, sizeof(g_bot.application_id), "%s", app_id);
                }
            } else {
                snprintf(g_bot.application_id, sizeof(g_bot.application_id), "%s", app_id);
            }
        }
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
                LOG_I("CMD: '%s' コマンド一致 (idx=%d)", cmd_name, i);
                /* Build interaction value for the callback */
                Value interaction = json_to_value(data);

                /* Inject ボイスチャンネルID from voice state cache */
                {
                    const char *gid = json_get_str(data, "guild_id");
                    JsonNode *member = json_get(data, "member");
                    JsonNode *user = member ? json_get(member, "user") : NULL;
                    const char *uid = user ? json_get_str(user, "id") : NULL;
                    if (gid && uid) {
                        const char *vc_id = voice_state_cache_get(gid, uid);
                        if (vc_id) {
                            value_dict_add(&interaction, "ボイスチャンネルID", hajimu_string(vc_id));
                        }
                    }
                }

                event_fire("INTERACTION_CREATE", 1, &interaction);

                /* Call specific command handler */
                pthread_mutex_lock(&g_bot.callback_mutex);
                if (hajimu_runtime_available()) {
                    LOG_I("CMD: '%s' コールバック開始", cmd_name);
                    hajimu_call(&g_bot.commands[i].callback, 1, &interaction);
                    LOG_I("CMD: '%s' コールバック完了", cmd_name);
                }
                pthread_mutex_unlock(&g_bot.callback_mutex);
                return;
            }
        }

        /* Fire generic command event */
        Value interaction = json_to_value(data);
        event_fire("コマンド受信", 1, &interaction);
    }

    /* Type 3 = MESSAGE_COMPONENT (button click, select menu) */
    if (type == 3) {
        JsonNode *comp_data = json_get(data, "data");
        if (!comp_data) return;
        const char *custom_id = json_get_str(comp_data, "custom_id");
        int comp_type = (int)json_get_num(comp_data, "component_type");
        if (!custom_id) return;

        Value interaction = json_to_value(data);
        event_fire("INTERACTION_CREATE", 1, &interaction);

        /* v1.6.0: Feed interaction collectors */
        JsonNode *msg = json_get(data, "message");
        const char *msg_id = msg ? json_get_str(msg, "id") : NULL;
        JsonNode *ch = json_get(data, "channel_id");
        const char *ch_id = (ch && ch->type == JSON_STRING) ? ch->str.data : "";
        collector_feed(2, ch_id, msg_id ? msg_id : "", &interaction);

        /* Find registered component handler */
        for (int i = 0; i < g_bot.comp_handler_count; i++) {
            if (strcmp(g_bot.comp_handlers[i].custom_id, custom_id) == 0 &&
                (g_bot.comp_handlers[i].type == comp_type || g_bot.comp_handlers[i].type == 0)) {
                pthread_mutex_lock(&g_bot.callback_mutex);
                if (hajimu_runtime_available()) {
                    hajimu_call(&g_bot.comp_handlers[i].callback, 1, &interaction);
                }
                pthread_mutex_unlock(&g_bot.callback_mutex);
                return;
            }
        }

        /* Fire generic component events */
        if (comp_type == COMP_BUTTON) {
            event_fire("ボタンクリック", 1, &interaction);
            event_fire("BUTTON_CLICK", 1, &interaction);
        } else if (comp_type == COMP_STRING_SELECT) {
            event_fire("セレクト選択", 1, &interaction);
            event_fire("SELECT_MENU", 1, &interaction);
        }
    }

    /* Type 4 = APPLICATION_COMMAND_AUTOCOMPLETE */
    if (type == 4) {
        JsonNode *ac_data = json_get(data, "data");
        if (!ac_data) return;
        const char *cmd_name = json_get_str(ac_data, "name");
        if (!cmd_name) return;

        Value interaction = json_to_value(data);

        /* Find registered autocomplete handler */
        for (int i = 0; i < g_bot.autocomplete_count; i++) {
            if (strcmp(g_bot.autocomplete_handlers[i].command_name, cmd_name) == 0) {
                pthread_mutex_lock(&g_bot.callback_mutex);
                if (hajimu_runtime_available()) {
                    hajimu_call(&g_bot.autocomplete_handlers[i].callback, 1, &interaction);
                }
                pthread_mutex_unlock(&g_bot.callback_mutex);
                return;
            }
        }

        event_fire("オートコンプリート", 1, &interaction);
        event_fire("AUTOCOMPLETE", 1, &interaction);
    }

    /* Type 5 = MODAL_SUBMIT */
    if (type == 5) {
        JsonNode *modal_data = json_get(data, "data");
        if (!modal_data) return;
        const char *custom_id = json_get_str(modal_data, "custom_id");
        if (!custom_id) return;

        Value interaction = json_to_value(data);
        event_fire("INTERACTION_CREATE", 1, &interaction);

        /* Find registered modal handler */
        for (int i = 0; i < g_bot.comp_handler_count; i++) {
            if (strcmp(g_bot.comp_handlers[i].custom_id, custom_id) == 0 &&
                g_bot.comp_handlers[i].type == -1) { /* -1 = modal */
                pthread_mutex_lock(&g_bot.callback_mutex);
                if (hajimu_runtime_available()) {
                    hajimu_call(&g_bot.comp_handlers[i].callback, 1, &interaction);
                }
                pthread_mutex_unlock(&g_bot.callback_mutex);
                return;
            }
        }

        event_fire("モーダル送信", 1, &interaction);
        event_fire("MODAL_SUBMIT", 1, &interaction);
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
        /* Inject ボイスチャンネルID from voice state cache */
        {
            const char *gid = json_get_str(data, "guild_id");
            JsonNode *author = json_get(data, "author");
            const char *uid = author ? json_get_str(author, "id") : NULL;
            if (gid && uid) {
                const char *vc_id = voice_state_cache_get(gid, uid);
                if (vc_id) {
                    value_dict_add(&val, "ボイスチャンネルID", hajimu_string(vc_id));
                }
            }
        }
        event_fire("メッセージ受信", 1, &val);
        /* v1.6.0: Feed message collectors */
        JsonNode *ch = json_get(data, "channel_id");
        const char *ch_id = (ch && ch->type == JSON_STRING) ? ch->str.data : "";
        collector_feed(0, ch_id, NULL, &val);
    } else if (strcmp(event_name, "GUILD_MEMBER_ADD") == 0) {
        event_fire("メンバー参加", 1, &val);
    } else if (strcmp(event_name, "GUILD_MEMBER_REMOVE") == 0) {
        event_fire("メンバー退出", 1, &val);
    } else if (strcmp(event_name, "MESSAGE_REACTION_ADD") == 0) {
        event_fire("リアクション追加", 1, &val);
        /* v1.6.0: Feed reaction collectors */
        JsonNode *ch = json_get(data, "channel_id");
        JsonNode *msg = json_get(data, "message_id");
        const char *ch_id = (ch && ch->type == JSON_STRING) ? ch->str.data : "";
        const char *msg_id = (msg && msg->type == JSON_STRING) ? msg->str.data : "";
        collector_feed(1, ch_id, msg_id, &val);
    } else if (strcmp(event_name, "MESSAGE_REACTION_REMOVE") == 0) {
        event_fire("リアクション削除", 1, &val);
    } else if (strcmp(event_name, "GUILD_CREATE") == 0) {
        event_fire("サーバー参加", 1, &val);
        /* Populate voice state cache from guild data */
        {
            const char *gid = json_get_str(data, "id");
            JsonNode *vs = json_get(data, "voice_states");
            if (gid && vs && vs->type == JSON_ARRAY) {
                for (int vi = 0; vi < vs->arr.count; vi++) {
                    const char *uid = json_get_str(&vs->arr.items[vi], "user_id");
                    const char *cid = json_get_str(&vs->arr.items[vi], "channel_id");
                    if (uid) {
                        voice_state_cache_update(gid, uid, cid);
                    }
                }
            }
        }
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
        /* Cache voice states for all users */
        {
            const char *uid = json_get_str(data, "user_id");
            const char *gid = json_get_str(data, "guild_id");
            const char *cid = json_get_str(data, "channel_id");
            if (uid && gid) {
                voice_state_cache_update(gid, uid, cid);
            }
        }
        /* v2.0.0: Capture session_id for our voice connections */
        {
            const char *uid = json_get_str(data, "user_id");
            const char *gid = json_get_str(data, "guild_id");
            const char *sid = json_get_str(data, "session_id");
            if (uid && gid && sid && strcmp(uid, g_bot.bot_id) == 0) {
                VoiceConn *vc = voice_find(gid);
                if (vc && vc->waiting_for_state) {
                    snprintf(vc->session_id, sizeof(vc->session_id), "%s", sid);
                    vc->state_received = true;
                    vc->waiting_for_state = false;
                    LOG_I("Voice session_id取得: %.32s", sid);
                    voice_check_ready(vc);
                }
            }
        }
    } else if (strcmp(event_name, "VOICE_SERVER_UPDATE") == 0) {
        event_fire("ボイスサーバー更新", 1, &val);
        /* v2.0.0: Capture voice server info */
        {
            const char *gid = json_get_str(data, "guild_id");
            const char *token = json_get_str(data, "token");
            const char *endpoint = json_get_str(data, "endpoint");
            if (gid && token && endpoint) {
                VoiceConn *vc = voice_find(gid);
                if (vc && vc->waiting_for_server) {
                    snprintf(vc->voice_token, sizeof(vc->voice_token), "%s", token);
                    snprintf(vc->endpoint, sizeof(vc->endpoint), "%s", endpoint);
                    vc->server_received = true;
                    vc->waiting_for_server = false;
                    LOG_I("Voiceサーバー情報取得: %s", endpoint);
                    voice_check_ready(vc);
                }
            }
        }
    } else if (strcmp(event_name, "AUTO_MODERATION_ACTION_EXECUTION") == 0) {
        event_fire("自動モデレーション実行", 1, &val);
    } else if (strcmp(event_name, "GUILD_SCHEDULED_EVENT_CREATE") == 0) {
        event_fire("イベント作成", 1, &val);
    } else if (strcmp(event_name, "GUILD_SCHEDULED_EVENT_UPDATE") == 0) {
        event_fire("イベント更新", 1, &val);
    } else if (strcmp(event_name, "GUILD_SCHEDULED_EVENT_DELETE") == 0) {
        event_fire("イベント削除", 1, &val);
    } else if (strcmp(event_name, "RESUMED") == 0) {
        event_fire("再接続完了", 1, &val);
        LOG_I("セッション再開完了");
    }
    /* v2.3.0: 追加イベント — discord.js/discord.py 互換 */
    else if (strcmp(event_name, "CHANNEL_UPDATE") == 0) {
        event_fire("チャンネル更新", 1, &val);
    } else if (strcmp(event_name, "CHANNEL_PINS_UPDATE") == 0) {
        event_fire("ピン更新", 1, &val);
    } else if (strcmp(event_name, "GUILD_UPDATE") == 0) {
        event_fire("サーバー更新", 1, &val);
    } else if (strcmp(event_name, "GUILD_BAN_ADD") == 0) {
        event_fire("BAN追加", 1, &val);
    } else if (strcmp(event_name, "GUILD_BAN_REMOVE") == 0) {
        event_fire("BAN削除", 1, &val);
    } else if (strcmp(event_name, "GUILD_EMOJIS_UPDATE") == 0) {
        event_fire("絵文字更新", 1, &val);
    } else if (strcmp(event_name, "GUILD_STICKERS_UPDATE") == 0) {
        event_fire("スタンプ更新", 1, &val);
    } else if (strcmp(event_name, "GUILD_MEMBER_UPDATE") == 0) {
        event_fire("メンバー更新", 1, &val);
    } else if (strcmp(event_name, "GUILD_ROLE_CREATE") == 0) {
        event_fire("ロール作成", 1, &val);
    } else if (strcmp(event_name, "GUILD_ROLE_UPDATE") == 0) {
        event_fire("ロール更新", 1, &val);
    } else if (strcmp(event_name, "GUILD_ROLE_DELETE") == 0) {
        event_fire("ロール削除", 1, &val);
    } else if (strcmp(event_name, "GUILD_INTEGRATIONS_UPDATE") == 0) {
        event_fire("インテグレーション更新", 1, &val);
    } else if (strcmp(event_name, "INVITE_CREATE") == 0) {
        event_fire("招待作成", 1, &val);
    } else if (strcmp(event_name, "INVITE_DELETE") == 0) {
        event_fire("招待削除", 1, &val);
    } else if (strcmp(event_name, "MESSAGE_DELETE_BULK") == 0) {
        event_fire("メッセージ一括削除", 1, &val);
    } else if (strcmp(event_name, "THREAD_CREATE") == 0) {
        event_fire("スレッド作成", 1, &val);
    } else if (strcmp(event_name, "THREAD_UPDATE") == 0) {
        event_fire("スレッド更新", 1, &val);
    } else if (strcmp(event_name, "THREAD_DELETE") == 0) {
        event_fire("スレッド削除", 1, &val);
    } else if (strcmp(event_name, "THREAD_LIST_SYNC") == 0) {
        event_fire("スレッド同期", 1, &val);
    } else if (strcmp(event_name, "THREAD_MEMBER_UPDATE") == 0) {
        event_fire("スレッドメンバー更新", 1, &val);
    } else if (strcmp(event_name, "THREAD_MEMBERS_UPDATE") == 0) {
        event_fire("スレッドメンバーズ更新", 1, &val);
    } else if (strcmp(event_name, "WEBHOOKS_UPDATE") == 0) {
        event_fire("Webhook更新", 1, &val);
    } else if (strcmp(event_name, "STAGE_INSTANCE_CREATE") == 0) {
        event_fire("ステージ開始", 1, &val);
    } else if (strcmp(event_name, "STAGE_INSTANCE_UPDATE") == 0) {
        event_fire("ステージ更新", 1, &val);
    } else if (strcmp(event_name, "STAGE_INSTANCE_DELETE") == 0) {
        event_fire("ステージ終了", 1, &val);
    } else if (strcmp(event_name, "GUILD_SCHEDULED_EVENT_USER_ADD") == 0) {
        event_fire("イベント参加", 1, &val);
    } else if (strcmp(event_name, "GUILD_SCHEDULED_EVENT_USER_REMOVE") == 0) {
        event_fire("イベント退出", 1, &val);
    } else if (strcmp(event_name, "MESSAGE_POLL_VOTE_ADD") == 0) {
        event_fire("投票追加", 1, &val);
    } else if (strcmp(event_name, "MESSAGE_POLL_VOTE_REMOVE") == 0) {
        event_fire("投票削除", 1, &val);
    } else if (strcmp(event_name, "ENTITLEMENT_CREATE") == 0) {
        event_fire("エンタイトルメント作成", 1, &val);
    } else if (strcmp(event_name, "ENTITLEMENT_UPDATE") == 0) {
        event_fire("エンタイトルメント更新", 1, &val);
    } else if (strcmp(event_name, "ENTITLEMENT_DELETE") == 0) {
        event_fire("エンタイトルメント削除", 1, &val);
    } else if (strcmp(event_name, "AUTO_MODERATION_RULE_CREATE") == 0) {
        event_fire("自動モデレーションルール作成", 1, &val);
    } else if (strcmp(event_name, "AUTO_MODERATION_RULE_UPDATE") == 0) {
        event_fire("自動モデレーションルール更新", 1, &val);
    } else if (strcmp(event_name, "AUTO_MODERATION_RULE_DELETE") == 0) {
        event_fire("自動モデレーションルール削除", 1, &val);
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
            Value err_msg = hajimu_string("Heartbeat ACK未受信");
            event_fire("エラー", 1, &err_msg);
            event_fire("ERROR", 1, &err_msg);
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

        /* Skip subcommand entries (name contains '/') */
        if (strchr(g_bot.commands[i].name, '/')) {
            g_bot.commands[i].registered = true;
            continue;
        }

        StrBuf sb; sb_init(&sb);
        jb_obj_start(&sb);
        jb_str(&sb, "name", g_bot.commands[i].name);

        /* Determine command type */
        int cmd_type = 1; /* CHAT_INPUT */
        if (g_bot.commands[i].option_count == -2) cmd_type = 2; /* USER context menu */
        else if (g_bot.commands[i].option_count == -3) cmd_type = 3; /* MESSAGE context menu */
        jb_int(&sb, "type", cmd_type);

        /* Context menus don't need description */
        if (cmd_type == 1) {
            jb_str(&sb, "description", g_bot.commands[i].description);
        }

        if (cmd_type == 1 && g_bot.commands[i].option_count > 0) {
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
            const char *type_name = cmd_type == 1 ? "コマンド" :
                                    cmd_type == 2 ? "ユーザーメニュー" : "メッセージメニュー";
            LOG_I("%s登録: %s", type_name, g_bot.commands[i].name);
        } else {
            LOG_E("コマンド登録失敗: %s (HTTP %ld)", g_bot.commands[i].name, code);
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
            Value err_msg = hajimu_string("Gateway接続失敗");
            event_fire("エラー", 1, &err_msg);
            event_fire("ERROR", 1, &err_msg);
            sleep(5);
            continue;
        }

        /* Read messages until disconnected */
        while (g_bot.running && !g_shutdown && g_bot.ws.connected) {
            char *msg = ws_read_message(&g_bot.ws);
            if (!msg) {
                if (g_bot.running && !g_shutdown) {
                    LOG_W("Gateway接続が切断されました。再接続します...");
                    Value disc_msg = hajimu_string("Gateway切断");
                    event_fire("切断", 1, &disc_msg);
                    event_fire("DISCONNECT", 1, &disc_msg);
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
            Value reconn_msg = hajimu_string("再接続中");
            event_fire("再接続", 1, &reconn_msg);
            event_fire("RECONNECT", 1, &reconn_msg);
            sleep(2);
        }
    }

    ws_close(&g_bot.ws);
    LOG_I("Gatewayスレッド終了");
    return NULL;
}

/* =========================================================================
 * Section 13.5: Voice Channel System (v2.0.0)
 * ========================================================================= */

/* --- Voice Connection Management --- */

static VoiceConn *voice_find(const char *guild_id) {
    if (!guild_id) return NULL;
    for (int i = 0; i < g_bot.voice_conn_count; i++) {
        if (g_bot.voice_conns[i].active &&
            strcmp(g_bot.voice_conns[i].guild_id, guild_id) == 0)
            return &g_bot.voice_conns[i];
    }
    return NULL;
}

static VoiceConn *voice_alloc(const char *guild_id) {
    if (!guild_id) return NULL;
    /* Check existing */
    VoiceConn *vc = voice_find(guild_id);
    if (vc) return vc;
    /* Find free slot */
    if (g_bot.voice_conn_count >= MAX_VOICE_CONNS) {
        LOG_E("ボイス接続上限(%d)に達しました", MAX_VOICE_CONNS);
        return NULL;
    }
    vc = &g_bot.voice_conns[g_bot.voice_conn_count++];
    memset(vc, 0, sizeof(*vc));
    snprintf(vc->guild_id, sizeof(vc->guild_id), "%s", guild_id);
    vc->active = true;
    vc->vws.fd = -1;
    vc->udp_fd = -1;
    pthread_mutex_init(&vc->voice_mutex, NULL);
    return vc;
}

static void voice_free(VoiceConn *vc) {
    if (!vc || !vc->active) return;

    vc->stop_requested = true;
    vc->playing = false;

    /* Close voice WebSocket */
    if (vc->vws.connected) {
        ws_close(&vc->vws);
    }

    /* Close UDP socket */
    if (vc->udp_fd >= 0) {
        close(vc->udp_fd);
        vc->udp_fd = -1;
    }

    /* Destroy Opus encoder */
    if (vc->opus_enc) {
        opus_encoder_destroy(vc->opus_enc);
        vc->opus_enc = NULL;
    }

    /* Wait for threads */
    if (vc->voice_ws_thread) {
        pthread_join(vc->voice_ws_thread, NULL);
        vc->voice_ws_thread = 0;
    }
    if (vc->audio_thread) {
        pthread_join(vc->audio_thread, NULL);
        vc->audio_thread = 0;
    }

    pthread_mutex_destroy(&vc->voice_mutex);
    vc->active = false;

    /* Compact array */
    int idx = (int)(vc - g_bot.voice_conns);
    if (idx < g_bot.voice_conn_count - 1) {
        memmove(&g_bot.voice_conns[idx], &g_bot.voice_conns[idx + 1],
                (size_t)(g_bot.voice_conn_count - 1 - idx) * sizeof(VoiceConn));
    }
    g_bot.voice_conn_count--;
}

/* --- Voice WebSocket (separate from main Gateway) --- */

/* Connect to voice WebSocket (no zlib decompression needed) */
static int voice_ws_connect_raw(WsConn *ws, const char *host, int port, const char *path) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        LOG_E("Voice DNS解決失敗: %s", host);
        return -1;
    }

    ws->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (ws->fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    struct timeval tv = {.tv_sec = 10, .tv_usec = 0};
    setsockopt(ws->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(ws->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(ws->fd, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        close(ws->fd); ws->fd = -1;
        return -1;
    }
    freeaddrinfo(res);

    ws->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ws->ssl_ctx) { close(ws->fd); ws->fd = -1; return -1; }
    SSL_CTX_set_verify(ws->ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ws->ssl_ctx);

    ws->ssl = SSL_new(ws->ssl_ctx);
    SSL_set_fd(ws->ssl, ws->fd);
    SSL_set_tlsext_host_name(ws->ssl, host);

    if (SSL_connect(ws->ssl) <= 0) {
        SSL_free(ws->ssl); ws->ssl = NULL;
        SSL_CTX_free(ws->ssl_ctx); ws->ssl_ctx = NULL;
        close(ws->fd); ws->fd = -1;
        return -1;
    }

    /* WebSocket upgrade handshake */
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

    if (SSL_write(ws->ssl, req, req_len) <= 0) goto vws_fail;

    char resp[4096];
    int rlen = SSL_read(ws->ssl, resp, sizeof(resp) - 1);
    if (rlen <= 0) goto vws_fail;
    resp[rlen] = '\0';
    if (!strstr(resp, "101")) goto vws_fail;

    /* Voice WS does NOT use zlib */
    ws->zlib_init = false;
    ws->connected = true;
    LOG_I("Voice WebSocket接続成功: %s", host);
    return 0;

vws_fail:
    if (ws->ssl) { SSL_free(ws->ssl); ws->ssl = NULL; }
    if (ws->ssl_ctx) { SSL_CTX_free(ws->ssl_ctx); ws->ssl_ctx = NULL; }
    close(ws->fd); ws->fd = -1;
    return -1;
}

/* Read voice WS message (no zlib, plain text frames only) */
static char *voice_ws_read(WsConn *ws) {
    if (!ws->connected || !ws->ssl) return NULL;

    StrBuf raw; sb_init(&raw);
    bool final = false;
    int msg_opcode = 0;

    while (!final) {
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

        if (payload_len > 0) {
            if (payload_len > 16 * 1024 * 1024) { sb_free(&raw); return NULL; }
            uint8_t *buf = (uint8_t *)malloc((size_t)payload_len);
            if (!buf) { sb_free(&raw); return NULL; }
            uint64_t total = 0;
            while (total < payload_len) {
                int chunk = (int)(payload_len - total);
                if (chunk > 4096) chunk = 4096;
                r = SSL_read(ws->ssl, buf + total, chunk);
                if (r <= 0) { free(buf); sb_free(&raw); return NULL; }
                total += r;
            }
            if (masked) {
                for (uint64_t i = 0; i < payload_len; i++)
                    buf[i] ^= mask_key[i & 3];
            }
            sb_appendn(&raw, (char *)buf, (int)payload_len);
            free(buf);
        }

        if (msg_opcode == WS_OP_PING) {
            ws_send_pong(ws, (uint8_t *)raw.data, raw.len);
            sb_free(&raw); sb_init(&raw);
            final = false;
            continue;
        }
        if (msg_opcode == WS_OP_CLOSE) {
            sb_free(&raw);
            return NULL;
        }
    }

    sb_append_char(&raw, '\0');
    return sb_detach(&raw);
}

/* Send voice identify (op 0) */
static void voice_send_identify(VoiceConn *vc) {
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "op", 0);
    jb_key(&sb, "d"); jb_obj_start(&sb);
    jb_str(&sb, "server_id", vc->guild_id);
    jb_str(&sb, "user_id", g_bot.bot_id);
    jb_str(&sb, "session_id", vc->session_id);
    jb_str(&sb, "token", vc->voice_token);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);
    ws_send_text(&vc->vws, sb.data, sb.len);
    sb_free(&sb);
    LOG_I("Voice IDENTIFY送信 (guild=%s)", vc->guild_id);
}

/* Send voice select protocol (op 1) */
static void voice_send_select_protocol(VoiceConn *vc) {
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "op", 1);
    jb_key(&sb, "d"); jb_obj_start(&sb);
    jb_str(&sb, "protocol", "udp");
    jb_key(&sb, "data"); jb_obj_start(&sb);
    jb_str(&sb, "address", vc->external_ip);
    jb_int(&sb, "port", vc->external_port);
    jb_str(&sb, "mode", "xsalsa20_poly1305");
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);
    ws_send_text(&vc->vws, sb.data, sb.len);
    sb_free(&sb);
    LOG_I("Voice SELECT_PROTOCOL送信 (ip=%s, port=%d)", vc->external_ip, vc->external_port);
}

/* Send voice heartbeat (op 3) */
static void voice_send_heartbeat(VoiceConn *vc) {
    /* Voice heartbeat uses a nonce (timestamp) */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t nonce = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;

    char buf[64];
    snprintf(buf, sizeof(buf), "{\"op\":3,\"d\":%llu}", (unsigned long long)nonce);
    ws_send_text(&vc->vws, buf, (int)strlen(buf));
    vc->voice_heartbeat_acked = false;
}

/* Send voice speaking (op 5) */
static void voice_send_speaking(VoiceConn *vc, bool speaking) {
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "op", 5);
    jb_key(&sb, "d"); jb_obj_start(&sb);
    jb_int(&sb, "speaking", speaking ? 1 : 0);
    jb_int(&sb, "delay", 0);
    jb_int(&sb, "ssrc", (int64_t)vc->ssrc);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);
    ws_send_text(&vc->vws, sb.data, sb.len);
    sb_free(&sb);
}

/* --- UDP IP Discovery --- */

static int voice_ip_discovery(VoiceConn *vc) {
    /* Create UDP socket */
    vc->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (vc->udp_fd < 0) {
        LOG_E("Voice UDPソケット作成失敗");
        return -1;
    }

    memset(&vc->udp_addr, 0, sizeof(vc->udp_addr));
    vc->udp_addr.sin_family = AF_INET;
    vc->udp_addr.sin_port = htons((uint16_t)vc->voice_port);
    inet_pton(AF_INET, vc->voice_ip, &vc->udp_addr.sin_addr);

    /* Set timeout */
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(vc->udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Send 74-byte IP Discovery packet:
     * Type (2) = 0x0001, Length (2) = 70, SSRC (4), Address (64), Port (2) */
    uint8_t disc_pkt[74];
    memset(disc_pkt, 0, sizeof(disc_pkt));
    disc_pkt[0] = 0x00; disc_pkt[1] = 0x01; /* Type: Request */
    disc_pkt[2] = 0x00; disc_pkt[3] = 70;   /* Length: 70 */
    disc_pkt[4] = (vc->ssrc >> 24) & 0xFF;
    disc_pkt[5] = (vc->ssrc >> 16) & 0xFF;
    disc_pkt[6] = (vc->ssrc >> 8) & 0xFF;
    disc_pkt[7] = vc->ssrc & 0xFF;

    ssize_t sent = sendto(vc->udp_fd, disc_pkt, sizeof(disc_pkt), 0,
                          (struct sockaddr *)&vc->udp_addr, sizeof(vc->udp_addr));
    if (sent != sizeof(disc_pkt)) {
        LOG_E("Voice IP Discovery送信失敗");
        return -1;
    }

    /* Receive response: same 74-byte format with our external IP+port filled in */
    uint8_t resp[74];
    socklen_t addr_len = sizeof(vc->udp_addr);
    ssize_t rcvd = recvfrom(vc->udp_fd, resp, sizeof(resp), 0,
                            (struct sockaddr *)&vc->udp_addr, &addr_len);
    if (rcvd < 74) {
        LOG_E("Voice IP Discovery応答不正 (%zd bytes)", rcvd);
        return -1;
    }

    /* Extract IP (bytes 8-71) and port (bytes 72-73, big-endian) */
    snprintf(vc->external_ip, sizeof(vc->external_ip), "%s", (char *)&resp[8]);
    vc->external_port = ((uint16_t)resp[72] << 8) | resp[73];

    LOG_I("Voice IP Discovery完了: %s:%d", vc->external_ip, vc->external_port);
    return 0;
}

/* --- Voice WebSocket Thread --- */

static void *voice_ws_thread_func(void *arg) {
    VoiceConn *vc = (VoiceConn *)arg;

    /* Parse endpoint: remove port suffix, strip wss:// if present */
    char host[256] = {0};
    snprintf(host, sizeof(host), "%s", vc->endpoint);

    /* Remove :80 or trailing port */
    char *colon = strrchr(host, ':');
    if (colon) *colon = '\0';

    /* Build path */
    char path[512];
    snprintf(path, sizeof(path), "/?v=4");

    LOG_I("Voice WebSocketに接続中... (%s)", host);
    if (voice_ws_connect_raw(&vc->vws, host, 443, path) < 0) {
        LOG_E("Voice WebSocket接続失敗");
        return NULL;
    }

    /* Send IDENTIFY */
    voice_send_identify(vc);

    /* Read messages */
    time_t last_heartbeat = time(NULL);

    while (vc->active && vc->vws.connected && !g_shutdown) {
        /* Set short read timeout for heartbeating */
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        setsockopt(vc->vws.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char *msg = voice_ws_read(&vc->vws);
        if (!msg) {
            /* Check if it's just a timeout */
            if (vc->active && vc->vws.connected && !g_shutdown) {
                /* Send heartbeat if interval elapsed */
                if (vc->voice_heartbeat_interval > 0) {
                    time_t now = time(NULL);
                    if ((now - last_heartbeat) * 1000 >= vc->voice_heartbeat_interval) {
                        voice_send_heartbeat(vc);
                        last_heartbeat = now;
                    }
                }
                continue;
            }
            break;
        }

        JsonNode *root = json_parse(msg);
        if (!root) { free(msg); continue; }

        int op = (int)json_get_num(root, "op");
        JsonNode *d = json_get(root, "d");

        switch (op) {
        case 8: { /* HELLO — get heartbeat_interval */
            if (d) {
                double hb = json_get_num(d, "heartbeat_interval");
                vc->voice_heartbeat_interval = (int)hb;
                LOG_I("Voice Heartbeat間隔: %dms", vc->voice_heartbeat_interval);
                /* Send first heartbeat immediately */
                voice_send_heartbeat(vc);
                last_heartbeat = time(NULL);
            }
            break;
        }
        case 2: { /* READY — get SSRC, IP, port */
            if (d) {
                vc->ssrc = (uint32_t)json_get_num(d, "ssrc");
                const char *ip = json_get_str(d, "ip");
                int port = (int)json_get_num(d, "port");
                if (ip) snprintf(vc->voice_ip, sizeof(vc->voice_ip), "%s", ip);
                vc->voice_port = port;
                LOG_I("Voice READY: ssrc=%u, ip=%s, port=%d", vc->ssrc, vc->voice_ip, vc->voice_port);

                /* Perform IP Discovery */
                if (voice_ip_discovery(vc) == 0) {
                    /* Send SELECT_PROTOCOL */
                    voice_send_select_protocol(vc);
                } else {
                    LOG_E("Voice IP Discovery失敗");
                }
            }
            break;
        }
        case 4: { /* SESSION_DESCRIPTION — get secret_key */
            if (d) {
                JsonNode *key_arr = json_get(d, "secret_key");
                if (key_arr && key_arr->type == JSON_ARRAY) {
                    int ki = 0;
                    int kcount = key_arr->arr.count;
                    if (kcount > 32) kcount = 32;
                    for (ki = 0; ki < kcount; ki++) {
                        vc->secret_key[ki] = (unsigned char)(int)key_arr->arr.items[ki].number;
                    }
                    vc->ready = true;
                    LOG_I("Voice準備完了! (guild=%s)", vc->guild_id);

                    /* Initialize Opus encoder */
                    int err;
                    vc->opus_enc = opus_encoder_create(VOICE_SAMPLE_RATE, VOICE_CHANNELS,
                                                       OPUS_APPLICATION_AUDIO, &err);
                    if (err != OPUS_OK || !vc->opus_enc) {
                        LOG_E("Opusエンコーダー作成失敗: %s", opus_strerror(err));
                        vc->ready = false;
                    } else {
                        opus_encoder_ctl(vc->opus_enc, OPUS_SET_BITRATE(64000));
                        LOG_I("Opusエンコーダー初期化完了");
                    }

                    /* Fire voice ready event */
                    Value guild_val = hajimu_string(vc->guild_id);
                    event_fire("ボイス接続完了", 1, &guild_val);
                    event_fire("VOICE_CONNECTED", 1, &guild_val);
                }
            }
            break;
        }
        case 6: { /* HEARTBEAT_ACK */
            vc->voice_heartbeat_acked = true;
            break;
        }
        default:
            LOG_D("Voice WS未処理op: %d", op);
            break;
        }

        json_free(root);
        free(msg);

        /* Send heartbeat if needed */
        if (vc->voice_heartbeat_interval > 0) {
            time_t now = time(NULL);
            if ((now - last_heartbeat) * 1000 >= vc->voice_heartbeat_interval) {
                voice_send_heartbeat(vc);
                last_heartbeat = now;
            }
        }
    }

    LOG_I("Voice WebSocketスレッド終了 (guild=%s)", vc->guild_id);
    return NULL;
}

/* --- Kick off voice WS after both gateway events received --- */

static void voice_check_ready(VoiceConn *vc) {
    if (!vc->state_received || !vc->server_received) return;

    LOG_I("Voice両イベント受信完了。Voice WSに接続開始...");
    /* Start voice WebSocket thread */
    pthread_create(&vc->voice_ws_thread, NULL, voice_ws_thread_func, vc);
}

/* --- Audio Playback Thread --- */

/* Read WAV file header, return number of channels and sample rate */
static bool wav_read_header(FILE *fp, int *channels, int *sample_rate, int *bits_per_sample) {
    uint8_t hdr[44];
    if (fread(hdr, 1, 44, fp) != 44) return false;

    /* Check RIFF header */
    if (memcmp(hdr, "RIFF", 4) != 0 || memcmp(hdr + 8, "WAVE", 4) != 0) return false;

    /* fmt chunk */
    *channels = hdr[22] | (hdr[23] << 8);
    *sample_rate = hdr[24] | (hdr[25] << 8) | (hdr[26] << 16) | (hdr[27] << 24);
    *bits_per_sample = hdr[34] | (hdr[35] << 8);

    return true;
}

/* Validate filepath for safe shell use (reject shell metacharacters) */
static bool voice_filepath_safe(const char *path) {
    /* Reject empty paths */
    if (!path || !*path) return false;
    /* Reject characters that could cause shell injection in popen */
    for (const char *p = path; *p; p++) {
        switch (*p) {
            case '`': case '$': case '\\': case '"': case '\'':
            case ';': case '|': case '&': case '<': case '>':
            case '(': case ')': case '{': case '}':
            case '\n': case '\r':
                return false;
        }
    }
    return true;
}

/* Check if source is a YouTube/supported streaming URL */
static bool is_youtube_url(const char *url) {
    return (strstr(url, "youtube.com/watch") != NULL ||
            strstr(url, "youtu.be/") != NULL ||
            strstr(url, "youtube.com/shorts/") != NULL ||
            strstr(url, "youtube.com/playlist") != NULL ||
            strstr(url, "music.youtube.com/") != NULL ||
            strstr(url, "soundcloud.com/") != NULL ||
            strstr(url, "nicovideo.jp/") != NULL ||
            strstr(url, "twitter.com/") != NULL ||
            strstr(url, "x.com/") != NULL);
}

/* Run yt-dlp and read output (helper) */
static char *ytdlp_exec(const char *args, const char *url) {
    if (!voice_filepath_safe(url)) return NULL;
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "yt-dlp %s %s \"%s\" 2>/dev/null",
             g_bot.ytdlp_cookie_opt[0] ? g_bot.ytdlp_cookie_opt : "",
             args, url);
    FILE *pp = popen(cmd, "r");
    if (!pp) return NULL;

    char *buf = (char *)calloc(1, 4096);
    if (!buf) { pclose(pp); return NULL; }
    size_t total = 0;
    char line[1024];
    while (fgets(line, sizeof(line), pp)) {
        size_t len = strlen(line);
        if (total + len >= 4095) break;
        memcpy(buf + total, line, len);
        total += len;
    }
    buf[total] = '\0';
    pclose(pp);
    /* Trim trailing newlines */
    while (total > 0 && (buf[total-1] == '\n' || buf[total-1] == '\r'))
        buf[--total] = '\0';
    return buf;
}

static void *voice_audio_thread_func(void *arg) {
    VoiceConn *vc = (VoiceConn *)arg;

    while (vc->active && !vc->stop_requested && !g_shutdown) {
        /* Get next item from queue */
        char filepath[256] = {0};

        pthread_mutex_lock(&vc->voice_mutex);
        if (vc->queue_count <= 0) {
            pthread_mutex_unlock(&vc->voice_mutex);
            /* Nothing to play, sleep and check again */
            usleep(100000); /* 100ms */
            continue;
        }
        snprintf(filepath, sizeof(filepath), "%s", vc->queue[vc->queue_head].path);
        vc->queue_head = (vc->queue_head + 1) % MAX_AUDIO_QUEUE;
        vc->queue_count--;
        pthread_mutex_unlock(&vc->voice_mutex);

        if (!filepath[0]) continue;

        LOG_I("音声再生開始: %s", filepath);
        vc->playing = true;
        vc->paused = false;

        /* Determine source: WAV file or pipe from ffmpeg */
        FILE *fp = NULL;
        bool use_ffmpeg = false;
        const char *ext = strrchr(filepath, '.');

        if (ext && (strcasecmp(ext, ".wav") == 0 || strcasecmp(ext, ".wave") == 0)) {
            fp = fopen(filepath, "rb");
            if (!fp) {
                LOG_E("音声ファイルを開けません: %s", filepath);
                vc->playing = false;
                continue;
            }
            int channels, sample_rate, bps;
            if (!wav_read_header(fp, &channels, &sample_rate, &bps)) {
                LOG_E("WAVヘッダーが不正です: %s", filepath);
                fclose(fp);
                vc->playing = false;
                continue;
            }
            LOG_D("WAV: ch=%d, sr=%d, bps=%d", channels, sample_rate, bps);
            /* We expect 48kHz, 16bit, stereo for direct Opus encoding.
             * If different, fall through to ffmpeg */
            if (sample_rate != VOICE_SAMPLE_RATE || channels != VOICE_CHANNELS || bps != 16) {
                fclose(fp);
                fp = NULL;
                use_ffmpeg = true;
            }
        } else {
            use_ffmpeg = true;
        }

        if (use_ffmpeg) {
            /* Validate filepath to prevent shell injection via popen */
            if (!voice_filepath_safe(filepath)) {
                LOG_E("音声ファイルパスに不正な文字が含まれています: %s", filepath);
                vc->playing = false;
                continue;
            }

            char cmd[2048];
            if (is_youtube_url(filepath)) {
                /* YouTube/streaming: yt-dlp → ffmpeg pipe */
                LOG_I("yt-dlp経由で再生: %s", filepath);
                snprintf(cmd, sizeof(cmd),
                    "yt-dlp -o - -f bestaudio --no-playlist --no-warnings %s \"%s\" 2>/dev/null | "
                    "ffmpeg -i pipe:0 -f s16le -ar %d -ac %d -loglevel error -",
                    g_bot.ytdlp_cookie_opt[0] ? g_bot.ytdlp_cookie_opt : "",
                    filepath, VOICE_SAMPLE_RATE, VOICE_CHANNELS);
            } else {
                /* Local file or direct URL: ffmpeg only */
                snprintf(cmd, sizeof(cmd),
                    "ffmpeg -i \"%s\" -f s16le -ar %d -ac %d -loglevel error -",
                    filepath, VOICE_SAMPLE_RATE, VOICE_CHANNELS);
            }
            fp = popen(cmd, "r");
            if (!fp) {
                LOG_E("ffmpeg起動失敗: %s", filepath);
                vc->playing = false;
                continue;
            }
        }

        /* Send SPEAKING */
        voice_send_speaking(vc, true);

        /* Initialize RTP counters */
        vc->rtp_seq = 0;
        vc->rtp_timestamp = 0;

        /* Audio loop: read PCM, Opus encode, encrypt, send RTP */
        int16_t pcm_buf[VOICE_FRAME_SIZE]; /* 960 * 2 = 1920 samples */
        uint8_t opus_buf[VOICE_MAX_PACKET];
        uint8_t packet[VOICE_MAX_PACKET + 12 + crypto_secretbox_MACBYTES];

        struct timespec frame_start, frame_end;

        while (vc->playing && !vc->stop_requested && !g_shutdown) {
            /* Handle pause */
            if (vc->paused) {
                usleep(50000); /* 50ms */
                continue;
            }

            clock_gettime(CLOCK_MONOTONIC, &frame_start);

            /* Read PCM data (VOICE_FRAME_SIZE samples * 2 bytes) */
            size_t read_bytes = fread(pcm_buf, sizeof(int16_t), VOICE_FRAME_SIZE, fp);
            if (read_bytes == 0) {
                /* EOF */
                break;
            }
            /* Pad with silence if partial frame */
            if ((int)read_bytes < VOICE_FRAME_SIZE) {
                memset(pcm_buf + read_bytes, 0,
                       (size_t)(VOICE_FRAME_SIZE - (int)read_bytes) * sizeof(int16_t));
            }

            /* Opus encode */
            int opus_len = opus_encode(vc->opus_enc, pcm_buf, VOICE_FRAME_SAMPLES,
                                       opus_buf, sizeof(opus_buf));
            if (opus_len < 0) {
                LOG_E("Opusエンコードエラー: %s", opus_strerror(opus_len));
                break;
            }

            /* Build RTP header (12 bytes) */
            uint8_t rtp_header[12];
            rtp_header[0] = 0x80; /* Version 2 */
            rtp_header[1] = 0x78; /* Payload type 120 */
            rtp_header[2] = (vc->rtp_seq >> 8) & 0xFF;
            rtp_header[3] = vc->rtp_seq & 0xFF;
            rtp_header[4] = (vc->rtp_timestamp >> 24) & 0xFF;
            rtp_header[5] = (vc->rtp_timestamp >> 16) & 0xFF;
            rtp_header[6] = (vc->rtp_timestamp >> 8) & 0xFF;
            rtp_header[7] = vc->rtp_timestamp & 0xFF;
            rtp_header[8] = (vc->ssrc >> 24) & 0xFF;
            rtp_header[9] = (vc->ssrc >> 16) & 0xFF;
            rtp_header[10] = (vc->ssrc >> 8) & 0xFF;
            rtp_header[11] = vc->ssrc & 0xFF;

            /* XSalsa20-Poly1305 encryption:
             * nonce = 24 bytes: RTP header (12) + 12 zero bytes */
            uint8_t nonce[24];
            memset(nonce, 0, sizeof(nonce));
            memcpy(nonce, rtp_header, 12);

            /* Encrypt opus data */
            uint8_t encrypted[VOICE_MAX_PACKET + crypto_secretbox_MACBYTES];
            if (crypto_secretbox_easy(encrypted, opus_buf, (unsigned long long)opus_len,
                                      nonce, vc->secret_key) != 0) {
                LOG_E("音声暗号化失敗");
                break;
            }

            int encrypted_len = opus_len + (int)crypto_secretbox_MACBYTES;

            /* Assemble final packet: RTP header + encrypted audio */
            memcpy(packet, rtp_header, 12);
            memcpy(packet + 12, encrypted, (size_t)encrypted_len);
            int total_len = 12 + encrypted_len;

            /* Send via UDP */
            ssize_t sent = sendto(vc->udp_fd, packet, (size_t)total_len, 0,
                                  (struct sockaddr *)&vc->udp_addr, sizeof(vc->udp_addr));
            if (sent < 0) {
                LOG_E("Voice UDP送信失敗: %s", strerror(errno));
                break;
            }

            vc->rtp_seq++;
            vc->rtp_timestamp += VOICE_FRAME_SAMPLES;

            /* Sleep for remainder of 20ms frame */
            clock_gettime(CLOCK_MONOTONIC, &frame_end);
            long elapsed_ns = (frame_end.tv_sec - frame_start.tv_sec) * 1000000000L +
                              (frame_end.tv_nsec - frame_start.tv_nsec);
            long target_ns = VOICE_FRAME_MS * 1000000L; /* 20ms */
            if (elapsed_ns < target_ns) {
                struct timespec sleep_ts;
                sleep_ts.tv_sec = 0;
                sleep_ts.tv_nsec = target_ns - elapsed_ns;
                nanosleep(&sleep_ts, NULL);
            }
        }

        /* Send SPEAKING off + 5 frames of silence */
        voice_send_speaking(vc, false);
        for (int i = 0; i < 5 && vc->active; i++) {
            /* Opus silence frame */
            static const uint8_t silence[] = {0xF8, 0xFF, 0xFE};
            uint8_t rtp_header[12];
            rtp_header[0] = 0x80;
            rtp_header[1] = 0x78;
            rtp_header[2] = (vc->rtp_seq >> 8) & 0xFF;
            rtp_header[3] = vc->rtp_seq & 0xFF;
            rtp_header[4] = (vc->rtp_timestamp >> 24) & 0xFF;
            rtp_header[5] = (vc->rtp_timestamp >> 16) & 0xFF;
            rtp_header[6] = (vc->rtp_timestamp >> 8) & 0xFF;
            rtp_header[7] = vc->rtp_timestamp & 0xFF;
            rtp_header[8] = (vc->ssrc >> 24) & 0xFF;
            rtp_header[9] = (vc->ssrc >> 16) & 0xFF;
            rtp_header[10] = (vc->ssrc >> 8) & 0xFF;
            rtp_header[11] = vc->ssrc & 0xFF;

            uint8_t nonce[24];
            memset(nonce, 0, sizeof(nonce));
            memcpy(nonce, rtp_header, 12);

            uint8_t enc_silence[3 + crypto_secretbox_MACBYTES];
            crypto_secretbox_easy(enc_silence, silence, 3, nonce, vc->secret_key);

            uint8_t pkt[12 + 3 + crypto_secretbox_MACBYTES];
            memcpy(pkt, rtp_header, 12);
            memcpy(pkt + 12, enc_silence, 3 + crypto_secretbox_MACBYTES);
            sendto(vc->udp_fd, pkt, sizeof(pkt), 0,
                   (struct sockaddr *)&vc->udp_addr, sizeof(vc->udp_addr));

            vc->rtp_seq++;
            vc->rtp_timestamp += VOICE_FRAME_SAMPLES;
            usleep(VOICE_FRAME_MS * 1000);
        }

        /* Close file/pipe */
        if (use_ffmpeg) {
            pclose(fp);
        } else {
            fclose(fp);
        }

        vc->playing = false;
        LOG_I("音声再生完了: %s", filepath);

        /* Fire event */
        Value done_val = hajimu_string(filepath);
        event_fire("音声再生完了", 1, &done_val);
        event_fire("VOICE_PLAY_END", 1, &done_val);

        /* Check loop mode (re-queue) */
        if (vc->loop_mode && !vc->stop_requested) {
            pthread_mutex_lock(&vc->voice_mutex);
            if (vc->queue_count < MAX_AUDIO_QUEUE) {
                int tail = vc->queue_tail;
                snprintf(vc->queue[tail].path, sizeof(vc->queue[tail].path), "%s", filepath);
                vc->queue_tail = (vc->queue_tail + 1) % MAX_AUDIO_QUEUE;
                vc->queue_count++;
            }
            pthread_mutex_unlock(&vc->voice_mutex);
        }
    }

    LOG_I("音声スレッド終了 (guild=%s)", vc->guild_id);
    return NULL;
}

/* --- Send Gateway op 4 (Voice State Update) --- */

static void gw_send_voice_state(const char *guild_id, const char *channel_id) {
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "op", GW_VOICE_STATE);
    jb_key(&sb, "d"); jb_obj_start(&sb);
    jb_str(&sb, "guild_id", guild_id);
    if (channel_id) {
        jb_str(&sb, "channel_id", channel_id);
    } else {
        jb_null(&sb, "channel_id");
    }
    jb_bool(&sb, "self_mute", false);
    jb_bool(&sb, "self_deaf", false);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);
    gw_send_json(sb.data);
    sb_free(&sb);
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
    pthread_mutex_init(&g_bot.collector_mutex, NULL);

    /* Init libcurl */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* CLIENT_ID が環境変数に設定されていれば application_id を先行設定 */
    const char *client_id_env = getenv("CLIENT_ID");
    if (!client_id_env) client_id_env = getenv("DISCORD_CLIENT_ID");
    if (client_id_env && client_id_env[0]) {
        snprintf(g_bot.application_id, sizeof(g_bot.application_id), "%s", client_id_env);
        LOG_I("CLIENT_ID を環境変数から設定: %s", g_bot.application_id);
    }

    /* YOUTUBE_COOKIES_BROWSER 環境変数からyt-dlpのcookieオプションを自動設定 */
    const char *cookies_browser = getenv("YOUTUBE_COOKIES_BROWSER");
    if (cookies_browser && cookies_browser[0]) {
        snprintf(g_bot.ytdlp_cookie_opt, sizeof(g_bot.ytdlp_cookie_opt),
                 "--cookies-from-browser %s", cookies_browser);
        LOG_I("yt-dlp Cookie設定 (環境変数): --cookies-from-browser %s", cookies_browser);
    } else {
        /* cookies.txt がカレントディレクトリに存在すれば自動使用 */
        FILE *cf = fopen("cookies.txt", "r");
        if (cf) {
            fclose(cf);
            snprintf(g_bot.ytdlp_cookie_opt, sizeof(g_bot.ytdlp_cookie_opt),
                     "--cookies cookies.txt");
            LOG_I("yt-dlp Cookie設定 (自動検出): --cookies cookies.txt");
        }
    }

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

    Value result = hajimu_bool(false);
    if (resp && code == 200) {
        result = json_to_value(resp);
    }
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
/* コマンド応答(インタラクション, 内容[, エフェメラル]) */
static Value fn_command_respond(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_DICT || argv[1].type != VALUE_STRING) {
        LOG_E("コマンド応答: (インタラクション, 内容[, エフェメラル]) が必要です");
        return hajimu_bool(false);
    }
    const char *interaction_id = value_get_str(&argv[0], "ID");
    const char *interaction_token = value_get_str(&argv[0], "トークン");
    if (!interaction_id || !interaction_token) {
        LOG_E("コマンド応答: インタラクションにIDまたはトークンがありません id=%s tok=%s",
              interaction_id ? interaction_id : "NULL",
              interaction_token ? "(present)" : "NULL");
        return hajimu_bool(false);
    }

    bool ephemeral = (argc >= 3 && argv[2].type == VALUE_BOOL && argv[2].boolean);

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 4); /* CHANNEL_MESSAGE_WITH_SOURCE */
    jb_key(&sb, "data"); jb_obj_start(&sb);
    jb_str(&sb, "content", argv[1].string.data);
    if (ephemeral) jb_int(&sb, "flags", 64); /* EPHEMERAL */
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);

    char ep[512];
    snprintf(ep, sizeof(ep), "/interactions/%s/%s/callback",
             interaction_id, interaction_token);

    LOG_I("コマンド応答: POST %s (ep_len=%zu, body_len=%zu)", ep, strlen(ep), strlen(sb.data));

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    LOG_I("コマンド応答: HTTP %ld", code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200 || code == 204);
}

/* コマンド遅延応答(インタラクション) */
static Value fn_command_defer(int argc, Value *argv) {
    LOG_I("DEFER: 呼び出し argc=%d type=%d", argc, argc > 0 ? argv[0].type : -1);
    if (argc < 1 || argv[0].type != VALUE_DICT) {
        LOG_E("DEFER: 引数エラー");
        return hajimu_bool(false);
    }
    const char *interaction_id = value_get_str(&argv[0], "ID");
    const char *interaction_token = value_get_str(&argv[0], "トークン");
    LOG_I("DEFER: id=%s tok=%s", interaction_id ? interaction_id : "NULL",
          interaction_token ? "(present)" : "NULL");
    if (!interaction_id || !interaction_token) {
        LOG_E("DEFER: IDまたはトークンがNULL");
        return hajimu_bool(false);
    }

    char ep[512];
    snprintf(ep, sizeof(ep), "/interactions/%s/%s/callback",
             interaction_id, interaction_token);
    LOG_I("DEFER: POST %s (len=%zu)", ep, strlen(ep));

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, "{\"type\":5}", &code);
    LOG_I("DEFER: HTTP %ld", code);
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

    char ep[512];
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

/* =========================================================================
 * v1.4.0: チャンネル・スレッド管理
 * ========================================================================= */

/* チャンネル作成(サーバーID, 名前, 種類)
 * 種類: "テキスト"=0, "ボイス"=2, "カテゴリ"=4, "ニュース"=5,
 *       "フォーラム"=15, "ステージ"=13, または数値 */
static Value fn_channel_create(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_null();

    int type = 0;  /* default: text */
    if (argv[2].type == VALUE_NUMBER) {
        type = (int)argv[2].number;
    } else if (argv[2].type == VALUE_STRING) {
        const char *s = argv[2].string.data;
        if (strcmp(s, "テキスト") == 0 || strcmp(s, "text") == 0) type = 0;
        else if (strcmp(s, "ボイス") == 0 || strcmp(s, "voice") == 0) type = 2;
        else if (strcmp(s, "カテゴリ") == 0 || strcmp(s, "category") == 0) type = 4;
        else if (strcmp(s, "ニュース") == 0 || strcmp(s, "news") == 0) type = 5;
        else if (strcmp(s, "ステージ") == 0 || strcmp(s, "stage") == 0) type = 13;
        else if (strcmp(s, "フォーラム") == 0 || strcmp(s, "forum") == 0) type = 15;
    }

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", argv[1].string.data);
    jb_int(&sb, "type", type);

    /* Optional 4th arg: parent (category) ID */
    if (argc >= 4 && argv[3].type == VALUE_STRING) {
        jb_str(&sb, "parent_id", argv[3].string.data);
    }
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/channels", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* チャンネル編集(チャンネルID, 設定辞書)
 * 設定: {"名前": "...", "トピック": "...", "NSFW": 真/偽, "位置": 数値, ...} */
static Value fn_channel_edit(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_DICT) return hajimu_null();

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);

    /* Iterate dict keys — use the hajimu runtime dict API */
    int count = argv[1].dict.length;
    for (int i = 0; i < count; i++) {
        const char *key = argv[1].dict.keys[i];
        Value val = argv[1].dict.values[i];
        const char *api_key = NULL;

        /* Map japanese keys to Discord API keys */
        if (strcmp(key, "名前") == 0 || strcmp(key, "name") == 0) api_key = "name";
        else if (strcmp(key, "トピック") == 0 || strcmp(key, "topic") == 0) api_key = "topic";
        else if (strcmp(key, "NSFW") == 0 || strcmp(key, "nsfw") == 0) api_key = "nsfw";
        else if (strcmp(key, "位置") == 0 || strcmp(key, "position") == 0) api_key = "position";
        else if (strcmp(key, "レート制限") == 0 || strcmp(key, "rate_limit_per_user") == 0)
            api_key = "rate_limit_per_user";
        else if (strcmp(key, "親カテゴリ") == 0 || strcmp(key, "parent_id") == 0)
            api_key = "parent_id";
        else if (strcmp(key, "ビットレート") == 0 || strcmp(key, "bitrate") == 0)
            api_key = "bitrate";
        else if (strcmp(key, "ユーザー上限") == 0 || strcmp(key, "user_limit") == 0)
            api_key = "user_limit";
        else api_key = key;  /* passthrough */

        if (val.type == VALUE_STRING) {
            jb_str(&sb, api_key, val.string.data);
        } else if (val.type == VALUE_NUMBER) {
            jb_int(&sb, api_key, (int64_t)val.number);
        } else if (val.type == VALUE_BOOL) {
            jb_bool(&sb, api_key, val.boolean);
        } else if (val.type == VALUE_NULL) {
            jb_null(&sb, api_key);
        }
    }
    jb_obj_end(&sb);

    char ep[64];
    snprintf(ep, sizeof(ep), "/channels/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* チャンネル削除(チャンネルID) */
static Value fn_channel_delete(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char ep[64];
    snprintf(ep, sizeof(ep), "/channels/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200);
}

/* スレッド作成(チャンネルID, 名前[, 自動アーカイブ分]) */
static Value fn_thread_create(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_null();

    int auto_archive = 1440;  /* default: 24h */
    if (argc >= 3 && argv[2].type == VALUE_NUMBER)
        auto_archive = (int)argv[2].number;

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", argv[1].string.data);
    jb_int(&sb, "auto_archive_duration", auto_archive);
    jb_int(&sb, "type", 11);
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/threads", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* スレッド参加(スレッドID) */
static Value fn_thread_join(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/thread-members/@me", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, "{}", &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* スレッド退出(スレッドID) */
static Value fn_thread_leave(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/thread-members/@me", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* スレッドメンバー追加(スレッドID, ユーザーID) */
static Value fn_thread_add_member(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/thread-members/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, "{}", &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* スレッドメンバー削除(スレッドID, ユーザーID) */
static Value fn_thread_remove_member(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/thread-members/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* 権限設定(チャンネルID, 対象ID, 許可, 拒否[, 種類])
 * 種類: "ロール"=0, "メンバー"=1 (default=1) 
 * 許可/拒否: 数値(Permission bitfield) または文字列 */
static Value fn_permission_overwrite(int argc, Value *argv) {
    if (argc < 4 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_bool(false);

    int64_t allow_bits = 0, deny_bits = 0;
    if (argv[2].type == VALUE_NUMBER) allow_bits = (int64_t)argv[2].number;
    if (argv[3].type == VALUE_NUMBER) deny_bits  = (int64_t)argv[3].number;

    int type = 1; /* member by default */
    if (argc >= 5) {
        if (argv[4].type == VALUE_NUMBER) type = (int)argv[4].number;
        else if (argv[4].type == VALUE_STRING) {
            if (strcmp(argv[4].string.data, "ロール") == 0 ||
                strcmp(argv[4].string.data, "role") == 0) type = 0;
        }
    }

    char body[256];
    snprintf(body, sizeof(body),
             "{\"id\":\"%s\",\"type\":%d,\"allow\":\"%lld\",\"deny\":\"%lld\"}",
             argv[1].string.data, type, (long long)allow_bits, (long long)deny_bits);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/permissions/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, body, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* 招待作成(チャンネルID[, 設定辞書])
 * 設定: {"有効期限": 秒数, "最大使用回数": 数値, "一時的": 真/偽} */
static Value fn_invite_create(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);

    if (argc >= 2 && argv[1].type == VALUE_DICT) {
        int count = argv[1].dict.length;
        for (int i = 0; i < count; i++) {
            const char *key = argv[1].dict.keys[i];
            Value val = argv[1].dict.values[i];

            if (strcmp(key, "有効期限") == 0 || strcmp(key, "max_age") == 0) {
                jb_int(&sb, "max_age", val.type == VALUE_NUMBER ? (int64_t)val.number : 86400);
            } else if (strcmp(key, "最大使用回数") == 0 || strcmp(key, "max_uses") == 0) {
                jb_int(&sb, "max_uses", val.type == VALUE_NUMBER ? (int64_t)val.number : 0);
            } else if (strcmp(key, "一時的") == 0 || strcmp(key, "temporary") == 0) {
                jb_bool(&sb, "temporary",
                        (val.type == VALUE_BOOL && val.boolean));
            } else {
                if (val.type == VALUE_NUMBER) jb_int(&sb, key, (int64_t)val.number);
                else if (val.type == VALUE_BOOL) jb_bool(&sb, key, val.boolean);
                else if (val.type == VALUE_STRING) jb_str(&sb, key, val.string.data);
            }
        }
    }
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/invites", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* 招待一覧(サーバーID) */
static Value fn_invite_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/invites", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* 招待削除(招待コード) */
static Value fn_invite_delete(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/invites/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* 招待情報(招待コード) */
static Value fn_invite_info(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/invites/%s?with_counts=true", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* =========================================================================
 * v1.5.0: Webhook & ファイル添付
 * ========================================================================= */

/* discord_rest_multipart: multipart/form-data で POST (ファイル添付用) */
static JsonNode *discord_rest_multipart(const char *endpoint,
                                        const char *json_payload,
                                        const char *filepath,
                                        long *http_code) {
    if (!g_bot.token_set) { LOG_E("トークンが設定されていません"); return NULL; }
    pthread_mutex_lock(&g_bot.rest_mutex);
    if (!g_bot.curl) g_bot.curl = curl_easy_init();
    CURL *curl = g_bot.curl;
    if (!curl) { pthread_mutex_unlock(&g_bot.rest_mutex); return NULL; }

    char url[MAX_URL_LEN];
    snprintf(url, sizeof(url), "%s%s", DISCORD_API_BASE, endpoint);

    CurlBuf resp = {NULL, 0};
    resp.data = (char *)calloc(1, REST_BUF_INIT);
    if (!resp.data) {
        pthread_mutex_unlock(&g_bot.rest_mutex);
        return NULL;
    }

    struct curl_slist *hdrs = NULL;
    char auth[MAX_TOKEN_LEN + 32];
    snprintf(auth, sizeof(auth), "Authorization: Bot %s", g_bot.token);
    hdrs = curl_slist_append(hdrs, auth);
    hdrs = curl_slist_append(hdrs, DISCORD_USER_AGENT);

    curl_mime *mime = curl_mime_init(curl);

    /* JSON payload part */
    if (json_payload) {
        curl_mimepart *part = curl_mime_addpart(mime);
        curl_mime_name(part, "payload_json");
        curl_mime_data(part, json_payload, CURL_ZERO_TERMINATED);
        curl_mime_type(part, "application/json");
    }

    /* File part */
    if (filepath) {
        curl_mimepart *fpart = curl_mime_addpart(mime);
        curl_mime_name(fpart, "files[0]");
        curl_mime_filedata(fpart, filepath);
    }

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_mime_free(mime);
    if (http_code) *http_code = code;

    JsonNode *result = NULL;
    if (res == CURLE_OK && resp.data && resp.len > 0) {
        result = json_parse(resp.data);
    } else if (res != CURLE_OK) {
        LOG_E("ファイル送信エラー: %s", curl_easy_strerror(res));
    }
    free(resp.data);
    pthread_mutex_unlock(&g_bot.rest_mutex);
    return result;
}

/* Webhook送信用 REST (トークン不要、Webhook URL を直接使う) */
static JsonNode *webhook_rest(const char *full_url, const char *body, long *http_code) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    CurlBuf resp = {NULL, 0};
    resp.data = (char *)calloc(1, REST_BUF_INIT);

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, DISCORD_USER_AGENT);

    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "{}");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (http_code) *http_code = code;

    JsonNode *result = NULL;
    if (res == CURLE_OK && resp.data && resp.len > 0) {
        result = json_parse(resp.data);
    }
    free(resp.data);
    return result;
}

/* Webhook作成(チャンネルID, 名前) */
static Value fn_webhook_create(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/webhooks", argv[0].string.data);
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", argv[1].string.data);
    jb_obj_end(&sb);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* Webhook一覧(チャンネルID) */
static Value fn_webhook_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/webhooks", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* Webhook削除(WebhookID) */
static Value fn_webhook_delete(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/webhooks/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* Webhook送信(URL, 内容[, ユーザー名, アバターURL])
 * URL は Discord Webhook の完全URL */
static Value fn_webhook_send(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_null();

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "content", argv[1].string.data);
    if (argc >= 3 && argv[2].type == VALUE_STRING) {
        jb_str(&sb, "username", argv[2].string.data);
    }
    if (argc >= 4 && argv[3].type == VALUE_STRING) {
        jb_str(&sb, "avatar_url", argv[3].string.data);
    }
    jb_obj_end(&sb);

    long code = 0;
    /* Webhook URLs are full URLs, use webhook_rest */
    char url[MAX_URL_LEN];
    snprintf(url, sizeof(url), "%s?wait=true", argv[0].string.data);
    JsonNode *resp = webhook_rest(url, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 204)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ファイル送信(チャンネルID, ファイルパス[, コメント]) */
static Value fn_send_file(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_null();

    /* Build JSON payload */
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    if (argc >= 3 && argv[2].type == VALUE_STRING) {
        jb_str(&sb, "content", argv[2].string.data);
    }
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/messages", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest_multipart(ep, sb.data, argv[1].string.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
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

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "delete_message_seconds", 0);
    jb_obj_end(&sb);

    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, sb.data, &code);
    if (resp) { json_free(resp); free(resp); }
    sb_free(&sb);
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

/* リアクション削除(チャンネルID, メッセージID, 絵文字[, ユーザーID]) */
static Value fn_remove_reaction(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);

    CURL *curl = curl_easy_init();
    char *encoded = curl_easy_escape(curl, argv[2].string.data, 0);
    curl_easy_cleanup(curl);

    char ep[256];
    if (argc >= 4 && argv[3].type == VALUE_STRING) {
        /* 特定ユーザーのリアクション削除 */
        snprintf(ep, sizeof(ep), "/channels/%s/messages/%s/reactions/%s/%s",
                 argv[0].string.data, argv[1].string.data, encoded, argv[3].string.data);
    } else {
        /* 自分のリアクション削除 */
        snprintf(ep, sizeof(ep), "/channels/%s/messages/%s/reactions/%s/@me",
                 argv[0].string.data, argv[1].string.data, encoded);
    }
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

/* ピン解除(チャンネルID, メッセージID) */
static Value fn_unpin_message(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/pins/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* ピン一覧(チャンネルID) */
static Value fn_pin_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/pins", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
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

/* --- v1.1.0: メッセージ操作拡張 --- */

/* メッセージ取得(チャンネルID, メッセージID) */
static Value fn_get_message(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("メッセージ取得: (チャンネルID, メッセージID) が必要です");
        return hajimu_null();
    }
    char ep[160];
    snprintf(ep, sizeof(ep), "/channels/%s/messages/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* メッセージ履歴(チャンネルID, 件数) */
static Value fn_message_history(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_NUMBER) {
        LOG_E("メッセージ履歴: (チャンネルID, 件数) が必要です");
        return hajimu_null();
    }
    int limit = (int)argv[1].number;
    if (limit < 1) limit = 1;
    if (limit > 100) limit = 100;

    char ep[160];
    snprintf(ep, sizeof(ep), "/channels/%s/messages?limit=%d",
             argv[0].string.data, limit);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* メッセージ一括削除(チャンネルID, 件数) — 最近N件を取得して一括削除 */
static Value fn_bulk_delete_count(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_NUMBER) {
        LOG_E("メッセージ一括削除: (チャンネルID, 件数) が必要です");
        return hajimu_bool(false);
    }
    int count = (int)argv[1].number;
    if (count < 2) count = 2;
    if (count > 100) count = 100;

    /* Step 1: Fetch recent message IDs */
    char fetch_ep[160];
    snprintf(fetch_ep, sizeof(fetch_ep), "/channels/%s/messages?limit=%d",
             argv[0].string.data, count);
    long fetch_code = 0;
    JsonNode *msgs = discord_rest("GET", fetch_ep, NULL, &fetch_code);
    if (!msgs || fetch_code != 200 || msgs->type != JSON_ARRAY || msgs->arr.count < 2) {
        LOG_E("メッセージ一括削除: メッセージの取得に失敗しました");
        if (msgs) { json_free(msgs); free(msgs); }
        return hajimu_bool(false);
    }

    /* Step 2: Build array of message IDs */
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_key(&sb, "messages"); jb_arr_start(&sb);
    for (int i = 0; i < msgs->arr.count; i++) {
        const char *mid = json_get_str(&msgs->arr.items[i], "id");
        if (mid) {
            json_escape_str(&sb, mid);
            sb_append_char(&sb, ',');
        }
    }
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);

    json_free(msgs); free(msgs);

    /* Step 3: Bulk delete */
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/messages/bulk-delete", argv[0].string.data);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* リアクション全削除(チャンネルID, メッセージID) */
static Value fn_remove_all_reactions(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("リアクション全削除: (チャンネルID, メッセージID) が必要です");
        return hajimu_bool(false);
    }
    char ep[160];
    snprintf(ep, sizeof(ep), "/channels/%s/messages/%s/reactions",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* タイムアウト(サーバーID, ユーザーID, 秒数) — 0で解除 */
static Value fn_timeout(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_NUMBER) {
        LOG_E("タイムアウト: (サーバーID, ユーザーID, 秒数) が必要です");
        return hajimu_bool(false);
    }
    int seconds = (int)argv[2].number;

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    if (seconds <= 0) {
        /* タイムアウト解除 */
        jb_null(&sb, "communication_disabled_until");
    } else {
        /* ISO 8601 timestamp: now + seconds */
        if (seconds > 2419200) seconds = 2419200; /* Max 28 days */
        time_t target = time(NULL) + seconds;
        struct tm *tm = gmtime(&target);
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm);
        jb_str(&sb, "communication_disabled_until", ts);
    }
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/members/%s",
             argv[0].string.data, argv[1].string.data);

    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, sb.data, &code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200 || code == 204);
}

/* --- v1.1.0: イベントハンドラ拡張 --- */

/* エラー時(コールバック) */
static Value fn_on_error(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION && argv[0].type != VALUE_BUILTIN)) {
        LOG_E("エラー時: コールバック関数が必要です");
        return hajimu_bool(false);
    }
    event_register("エラー", argv[0]);
    event_register("ERROR", argv[0]);
    return hajimu_bool(true);
}

/* 切断時(コールバック) */
static Value fn_on_disconnect(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION && argv[0].type != VALUE_BUILTIN)) {
        LOG_E("切断時: コールバック関数が必要です");
        return hajimu_bool(false);
    }
    event_register("切断", argv[0]);
    event_register("DISCONNECT", argv[0]);
    return hajimu_bool(true);
}

/* 再接続時(コールバック) */
static Value fn_on_reconnect(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION && argv[0].type != VALUE_BUILTIN)) {
        LOG_E("再接続時: コールバック関数が必要です");
        return hajimu_bool(false);
    }
    event_register("再接続", argv[0]);
    event_register("RECONNECT", argv[0]);
    return hajimu_bool(true);
}

/* =========================================================================
 * v1.2.0: Message Components — Button, Select Menu, Action Row
 * ========================================================================= */

/* --- ボタン --- */

static int button_alloc(void) {
    for (int i = 0; i < MAX_BUTTONS; i++) {
        if (!g_bot.buttons[i].active) {
            memset(&g_bot.buttons[i], 0, sizeof(Button));
            g_bot.buttons[i].active = true;
            g_bot.buttons[i].style = BTN_PRIMARY;
            return i;
        }
    }
    LOG_E("ボタンの上限に達しました");
    return -1;
}

static Button *button_get(int idx) {
    if (idx < 0 || idx >= MAX_BUTTONS || !g_bot.buttons[idx].active) return NULL;
    return &g_bot.buttons[idx];
}

/* ボタン作成(ラベル, スタイル, カスタムID) */
static Value fn_button_create(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING) {
        LOG_E("ボタン作成: (ラベル, スタイル, カスタムID) が必要です");
        return hajimu_null();
    }
    int idx = button_alloc();
    if (idx < 0) return hajimu_null();

    Button *b = &g_bot.buttons[idx];
    snprintf(b->label, sizeof(b->label), "%s", argv[0].string.data);
    snprintf(b->custom_id, sizeof(b->custom_id), "%s", argv[2].string.data);

    /* Parse style */
    const char *s = argv[1].string.data;
    if (strcmp(s, "プライマリ") == 0 || strcmp(s, "PRIMARY") == 0 || strcmp(s, "青") == 0) b->style = BTN_PRIMARY;
    else if (strcmp(s, "セカンダリ") == 0 || strcmp(s, "SECONDARY") == 0 || strcmp(s, "灰") == 0) b->style = BTN_SECONDARY;
    else if (strcmp(s, "成功") == 0 || strcmp(s, "SUCCESS") == 0 || strcmp(s, "緑") == 0) b->style = BTN_SUCCESS;
    else if (strcmp(s, "危険") == 0 || strcmp(s, "DANGER") == 0 || strcmp(s, "赤") == 0) b->style = BTN_DANGER;
    else if (strcmp(s, "リンク") == 0 || strcmp(s, "LINK") == 0) b->style = BTN_LINK;
    else b->style = BTN_PRIMARY;

    return hajimu_number(idx);
}

/* リンクボタン作成(ラベル, URL) */
static Value fn_link_button_create(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("リンクボタン作成: (ラベル, URL) が必要です");
        return hajimu_null();
    }
    int idx = button_alloc();
    if (idx < 0) return hajimu_null();

    Button *b = &g_bot.buttons[idx];
    snprintf(b->label, sizeof(b->label), "%s", argv[0].string.data);
    snprintf(b->url, sizeof(b->url), "%s", argv[1].string.data);
    b->style = BTN_LINK;
    b->custom_id[0] = '\0';

    return hajimu_number(idx);
}

/* ボタン無効化(ボタンID, 真偽) */
static Value fn_button_disable(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_BOOL)
        return hajimu_bool(false);
    Button *b = button_get((int)argv[0].number);
    if (!b) return hajimu_bool(false);
    b->disabled = argv[1].boolean;
    return hajimu_number(argv[0].number);
}

/* --- アクション行 --- */

static int row_alloc(void) {
    for (int i = 0; i < MAX_ACTION_ROWS; i++) {
        if (!g_bot.rows[i].active) {
            memset(&g_bot.rows[i], 0, sizeof(ActionRow));
            g_bot.rows[i].active = true;
            return i;
        }
    }
    LOG_E("アクション行の上限に達しました");
    return -1;
}

static ActionRow *row_get(int idx) {
    if (idx < 0 || idx >= MAX_ACTION_ROWS || !g_bot.rows[idx].active) return NULL;
    return &g_bot.rows[idx];
}

/* アクション行作成() */
static Value fn_action_row_create(int argc, Value *argv) {
    (void)argc; (void)argv;
    int idx = row_alloc();
    if (idx < 0) return hajimu_null();
    return hajimu_number(idx);
}

/* 行にボタン追加(行ID, ボタンID) */
static Value fn_row_add_button(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_NUMBER) {
        LOG_E("行にボタン追加: (行ID, ボタンID) が必要です");
        return hajimu_bool(false);
    }
    ActionRow *row = row_get((int)argv[0].number);
    if (!row) return hajimu_bool(false);
    if (row->comp_count >= MAX_ROW_COMPONENTS) {
        LOG_E("アクション行のコンポーネント上限（5）に達しました");
        return hajimu_bool(false);
    }
    Button *b = button_get((int)argv[1].number);
    if (!b) return hajimu_bool(false);

    int ci = row->comp_count++;
    row->comp_type[ci] = COMP_BUTTON;
    row->comp_idx[ci] = (int)argv[1].number;
    return hajimu_number(argv[0].number);
}

/* 行にメニュー追加(行ID, メニューID) */
static Value fn_row_add_menu(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_NUMBER) {
        LOG_E("行にメニュー追加: (行ID, メニューID) が必要です");
        return hajimu_bool(false);
    }
    ActionRow *row = row_get((int)argv[0].number);
    if (!row) return hajimu_bool(false);
    /* Select menus take up the whole row */
    if (row->comp_count >= 1) {
        LOG_E("セレクトメニューはアクション行に1つだけ配置できます");
        return hajimu_bool(false);
    }
    SelectMenu *m = &g_bot.menus[(int)argv[1].number];
    if (!m->active) return hajimu_bool(false);

    int ci = row->comp_count++;
    row->comp_type[ci] = COMP_STRING_SELECT;
    row->comp_idx[ci] = (int)argv[1].number;
    return hajimu_number(argv[0].number);
}

/* Serialize a button to JSON */
static void button_to_json(StrBuf *sb, Button *b) {
    jb_obj_start(sb);
    jb_int(sb, "type", COMP_BUTTON);
    jb_int(sb, "style", b->style);
    if (b->label[0]) jb_str(sb, "label", b->label);
    if (b->style == BTN_LINK) {
        if (b->url[0]) jb_str(sb, "url", b->url);
    } else {
        if (b->custom_id[0]) jb_str(sb, "custom_id", b->custom_id);
    }
    if (b->emoji_name[0]) {
        jb_key(sb, "emoji"); jb_obj_start(sb);
        jb_str(sb, "name", b->emoji_name);
        jb_obj_end(sb); sb_append_char(sb, ',');
    }
    if (b->disabled) jb_bool(sb, "disabled", true);
    jb_obj_end(sb);
}

/* Serialize a select menu to JSON */
static void menu_to_json(StrBuf *sb, SelectMenu *m) {
    jb_obj_start(sb);
    jb_int(sb, "type", COMP_STRING_SELECT);
    jb_str(sb, "custom_id", m->custom_id);
    if (m->placeholder[0]) jb_str(sb, "placeholder", m->placeholder);
    if (m->min_values > 0) jb_int(sb, "min_values", m->min_values);
    if (m->max_values > 0) jb_int(sb, "max_values", m->max_values);
    if (m->disabled) jb_bool(sb, "disabled", true);
    jb_key(sb, "options"); jb_arr_start(sb);
    for (int i = 0; i < m->option_count; i++) {
        jb_obj_start(sb);
        jb_str(sb, "label", m->options[i].label);
        jb_str(sb, "value", m->options[i].value);
        if (m->options[i].description[0]) jb_str(sb, "description", m->options[i].description);
        if (m->options[i].emoji_name[0]) {
            jb_key(sb, "emoji"); jb_obj_start(sb);
            jb_str(sb, "name", m->options[i].emoji_name);
            jb_obj_end(sb); sb_append_char(sb, ',');
        }
        if (m->options[i].default_selected) jb_bool(sb, "default", true);
        jb_obj_end(sb); sb_append_char(sb, ',');
    }
    jb_arr_end(sb); sb_append_char(sb, ',');
    jb_obj_end(sb);
}

/* Serialize an action row to JSON */
static void row_to_json(StrBuf *sb, ActionRow *r) {
    jb_obj_start(sb);
    jb_int(sb, "type", COMP_ACTION_ROW);
    jb_key(sb, "components"); jb_arr_start(sb);
    for (int i = 0; i < r->comp_count; i++) {
        if (r->comp_type[i] == COMP_BUTTON) {
            Button *b = button_get(r->comp_idx[i]);
            if (b) { button_to_json(sb, b); sb_append_char(sb, ','); }
        } else if (r->comp_type[i] == COMP_STRING_SELECT) {
            SelectMenu *m = &g_bot.menus[r->comp_idx[i]];
            if (m->active) { menu_to_json(sb, m); sb_append_char(sb, ','); }
        }
    }
    jb_arr_end(sb); sb_append_char(sb, ',');
    jb_obj_end(sb);
}

/* コンポーネント送信(チャンネルID, テキスト, 行配列) */
static Value fn_component_send(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_ARRAY) {
        LOG_E("コンポーネント送信: (チャンネルID, テキスト, 行配列) が必要です");
        return hajimu_bool(false);
    }

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "content", argv[1].string.data);
    jb_key(&sb, "components"); jb_arr_start(&sb);
    for (int i = 0; i < argv[2].array.length; i++) {
        Value *row_val = &argv[2].array.elements[i];
        if (row_val->type == VALUE_NUMBER) {
            ActionRow *r = row_get((int)row_val->number);
            if (r) { row_to_json(&sb, r); sb_append_char(&sb, ','); }
        }
    }
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/messages", argv[0].string.data);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);

    /* Free used components */
    for (int i = 0; i < argv[2].array.length; i++) {
        Value *row_val = &argv[2].array.elements[i];
        if (row_val->type == VALUE_NUMBER) {
            ActionRow *r = row_get((int)row_val->number);
            if (r) {
                for (int j = 0; j < r->comp_count; j++) {
                    if (r->comp_type[j] == COMP_BUTTON) {
                        Button *b = button_get(r->comp_idx[j]);
                        if (b) b->active = false;
                    } else if (r->comp_type[j] == COMP_STRING_SELECT) {
                        g_bot.menus[r->comp_idx[j]].active = false;
                    }
                }
                r->active = false;
            }
        }
    }

    Value result = hajimu_bool(false);
    if (resp && (code == 200 || code == 201)) {
        result = json_to_value(resp);
    }
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- セレクトメニュー --- */

static int menu_alloc(void) {
    for (int i = 0; i < MAX_SELECT_MENUS; i++) {
        if (!g_bot.menus[i].active) {
            memset(&g_bot.menus[i], 0, sizeof(SelectMenu));
            g_bot.menus[i].active = true;
            g_bot.menus[i].min_values = 1;
            g_bot.menus[i].max_values = 1;
            return i;
        }
    }
    LOG_E("セレクトメニューの上限に達しました");
    return -1;
}

/* セレクトメニュー作成(カスタムID, プレースホルダー) */
static Value fn_select_menu_create(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("セレクトメニュー作成: (カスタムID, プレースホルダー) が必要です");
        return hajimu_null();
    }
    int idx = menu_alloc();
    if (idx < 0) return hajimu_null();

    SelectMenu *m = &g_bot.menus[idx];
    snprintf(m->custom_id, sizeof(m->custom_id), "%s", argv[0].string.data);
    snprintf(m->placeholder, sizeof(m->placeholder), "%s", argv[1].string.data);
    return hajimu_number(idx);
}

/* メニュー選択肢(メニューID, ラベル, 値, 説明) */
static Value fn_menu_add_option(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_NUMBER ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING) {
        LOG_E("メニュー選択肢: (メニューID, ラベル, 値[, 説明]) が必要です");
        return hajimu_bool(false);
    }
    int idx = (int)argv[0].number;
    if (idx < 0 || idx >= MAX_SELECT_MENUS || !g_bot.menus[idx].active)
        return hajimu_bool(false);
    SelectMenu *m = &g_bot.menus[idx];
    if (m->option_count >= MAX_MENU_OPTIONS) {
        LOG_E("メニュー選択肢の上限に達しました");
        return hajimu_bool(false);
    }

    int oi = m->option_count++;
    snprintf(m->options[oi].label, sizeof(m->options[oi].label), "%s", argv[1].string.data);
    snprintf(m->options[oi].value, sizeof(m->options[oi].value), "%s", argv[2].string.data);
    if (argc >= 4 && argv[3].type == VALUE_STRING)
        snprintf(m->options[oi].description, sizeof(m->options[oi].description), "%s", argv[3].string.data);
    return hajimu_number(argv[0].number);
}

/* --- コンポーネントイベントハンドラ --- */

static int register_comp_handler(const char *custom_id, Value callback, int type) {
    /* Check for existing handler with same custom_id and update */
    for (int i = 0; i < g_bot.comp_handler_count; i++) {
        if (strcmp(g_bot.comp_handlers[i].custom_id, custom_id) == 0 &&
            g_bot.comp_handlers[i].type == type) {
            g_bot.comp_handlers[i].callback = callback;
            return 0;
        }
    }
    if (g_bot.comp_handler_count >= MAX_COMP_HANDLERS) {
        LOG_E("コンポーネントハンドラの上限に達しました");
        return -1;
    }
    ComponentHandler *h = &g_bot.comp_handlers[g_bot.comp_handler_count++];
    snprintf(h->custom_id, sizeof(h->custom_id), "%s", custom_id);
    h->callback = callback;
    h->type = type;
    return 0;
}

/* ボタン時(カスタムID, コールバック) */
static Value fn_on_button(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        (argv[1].type != VALUE_FUNCTION && argv[1].type != VALUE_BUILTIN)) {
        LOG_E("ボタン時: (カスタムID, コールバック) が必要です");
        return hajimu_bool(false);
    }
    register_comp_handler(argv[0].string.data, argv[1], COMP_BUTTON);
    LOG_D("ボタンハンドラ登録: %s", argv[0].string.data);
    return hajimu_bool(true);
}

/* セレクト時(カスタムID, コールバック) */
static Value fn_on_select(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        (argv[1].type != VALUE_FUNCTION && argv[1].type != VALUE_BUILTIN)) {
        LOG_E("セレクト時: (カスタムID, コールバック) が必要です");
        return hajimu_bool(false);
    }
    register_comp_handler(argv[0].string.data, argv[1], COMP_STRING_SELECT);
    LOG_D("セレクトハンドラ登録: %s", argv[0].string.data);
    return hajimu_bool(true);
}

/* --- インタラクション応答 --- */

/* インタラクション更新(インタラクション, 内容) — メッセージを更新（ボタンクリック後等） */
static Value fn_interaction_update(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_DICT || argv[1].type != VALUE_STRING) {
        LOG_E("インタラクション更新: (インタラクション, 内容) が必要です");
        return hajimu_bool(false);
    }
    const char *interaction_id = value_get_str(&argv[0], "ID");
    const char *interaction_token = value_get_str(&argv[0], "トークン");
    if (!interaction_id || !interaction_token) return hajimu_bool(false);

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 7); /* UPDATE_MESSAGE */
    jb_key(&sb, "data"); jb_obj_start(&sb);
    jb_str(&sb, "content", argv[1].string.data);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);

    char ep[512];
    snprintf(ep, sizeof(ep), "/interactions/%s/%s/callback",
             interaction_id, interaction_token);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200 || code == 204);
}

/* インタラクション遅延更新(インタラクション) — 遅延メッセージ更新（type 6） */
static Value fn_interaction_defer_update(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_DICT) return hajimu_bool(false);
    const char *interaction_id = value_get_str(&argv[0], "ID");
    const char *interaction_token = value_get_str(&argv[0], "トークン");
    if (!interaction_id || !interaction_token) return hajimu_bool(false);

    char ep[512];
    snprintf(ep, sizeof(ep), "/interactions/%s/%s/callback",
             interaction_id, interaction_token);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, "{\"type\":6}", &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200 || code == 204);
}

/* =========================================================================
 * v1.3.0: Modals, Subcommands, Context Menus, Autocomplete
 * ========================================================================= */

/* --- モーダル --- */

static int modal_alloc(void) {
    for (int i = 0; i < MAX_MODALS; i++) {
        if (!g_bot.modals[i].active) {
            memset(&g_bot.modals[i], 0, sizeof(Modal));
            g_bot.modals[i].active = true;
            return i;
        }
    }
    LOG_E("モーダルの上限に達しました");
    return -1;
}

static Modal *modal_get(int idx) {
    if (idx < 0 || idx >= MAX_MODALS || !g_bot.modals[idx].active) return NULL;
    return &g_bot.modals[idx];
}

/* モーダル作成(カスタムID, タイトル) */
static Value fn_modal_create(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("モーダル作成: (カスタムID, タイトル) が必要です");
        return hajimu_null();
    }
    int idx = modal_alloc();
    if (idx < 0) return hajimu_null();

    Modal *m = &g_bot.modals[idx];
    snprintf(m->custom_id, sizeof(m->custom_id), "%s", argv[0].string.data);
    snprintf(m->title, sizeof(m->title), "%s", argv[1].string.data);
    return hajimu_number(idx);
}

/* テキスト入力追加(モーダルID, ラベル, カスタムID, スタイル) */
static Value fn_modal_add_text_input(int argc, Value *argv) {
    if (argc < 4 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING || argv[3].type != VALUE_STRING) {
        LOG_E("テキスト入力追加: (モーダルID, ラベル, カスタムID, スタイル) が必要です");
        return hajimu_bool(false);
    }
    Modal *m = modal_get((int)argv[0].number);
    if (!m || m->input_count >= MAX_MODAL_INPUTS) return hajimu_bool(false);

    int ii = m->input_count++;
    snprintf(m->inputs[ii].label, sizeof(m->inputs[ii].label), "%s", argv[1].string.data);
    snprintf(m->inputs[ii].custom_id, sizeof(m->inputs[ii].custom_id), "%s", argv[2].string.data);
    m->inputs[ii].required = true;
    m->inputs[ii].max_length = 4000;

    const char *style = argv[3].string.data;
    if (strcmp(style, "短い") == 0 || strcmp(style, "SHORT") == 0 || strcmp(style, "一行") == 0)
        m->inputs[ii].style = 1;
    else if (strcmp(style, "長い") == 0 || strcmp(style, "PARAGRAPH") == 0 || strcmp(style, "複数行") == 0)
        m->inputs[ii].style = 2;
    else
        m->inputs[ii].style = 1;

    return hajimu_number(argv[0].number);
}

/* モーダル表示(インタラクション, モーダルID) */
static Value fn_modal_show(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_DICT || argv[1].type != VALUE_NUMBER) {
        LOG_E("モーダル表示: (インタラクション, モーダルID) が必要です");
        return hajimu_bool(false);
    }
    const char *interaction_id = value_get_str(&argv[0], "ID");
    const char *interaction_token = value_get_str(&argv[0], "トークン");
    if (!interaction_id || !interaction_token) return hajimu_bool(false);

    Modal *m = modal_get((int)argv[1].number);
    if (!m) return hajimu_bool(false);

    /* Build modal JSON */
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 9); /* MODAL */
    jb_key(&sb, "data"); jb_obj_start(&sb);
    jb_str(&sb, "custom_id", m->custom_id);
    jb_str(&sb, "title", m->title);
    jb_key(&sb, "components"); jb_arr_start(&sb);
    for (int i = 0; i < m->input_count; i++) {
        /* Each input in its own action row */
        jb_obj_start(&sb);
        jb_int(&sb, "type", COMP_ACTION_ROW);
        jb_key(&sb, "components"); jb_arr_start(&sb);
        jb_obj_start(&sb);
        jb_int(&sb, "type", 4); /* TEXT_INPUT */
        jb_str(&sb, "custom_id", m->inputs[i].custom_id);
        jb_str(&sb, "label", m->inputs[i].label);
        jb_int(&sb, "style", m->inputs[i].style);
        if (m->inputs[i].placeholder[0])
            jb_str(&sb, "placeholder", m->inputs[i].placeholder);
        if (m->inputs[i].default_value[0])
            jb_str(&sb, "value", m->inputs[i].default_value);
        if (m->inputs[i].min_length > 0)
            jb_int(&sb, "min_length", m->inputs[i].min_length);
        if (m->inputs[i].max_length > 0)
            jb_int(&sb, "max_length", m->inputs[i].max_length);
        jb_bool(&sb, "required", m->inputs[i].required);
        jb_obj_end(&sb);
        jb_arr_end(&sb); sb_append_char(&sb, ',');
        jb_obj_end(&sb); sb_append_char(&sb, ',');
    }
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);

    char ep[512];
    snprintf(ep, sizeof(ep), "/interactions/%s/%s/callback",
             interaction_id, interaction_token);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);

    /* Free modal slot */
    m->active = false;

    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200 || code == 204);
}

/* モーダル送信時(カスタムID, コールバック) */
static Value fn_on_modal_submit(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        (argv[1].type != VALUE_FUNCTION && argv[1].type != VALUE_BUILTIN)) {
        LOG_E("モーダル送信時: (カスタムID, コールバック) が必要です");
        return hajimu_bool(false);
    }
    register_comp_handler(argv[0].string.data, argv[1], -1); /* -1 = modal */
    LOG_D("モーダルハンドラ登録: %s", argv[0].string.data);
    return hajimu_bool(true);
}

/* --- サブコマンド --- */

/* サブコマンド追加(コマンドインデックス, サブ名, 説明, コールバック) */
static Value fn_subcommand_add(int argc, Value *argv) {
    if (argc < 4 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING ||
        (argv[3].type != VALUE_FUNCTION && argv[3].type != VALUE_BUILTIN)) {
        LOG_E("サブコマンド追加: (コマンドID, サブ名, 説明, コールバック) が必要です");
        return hajimu_bool(false);
    }
    int idx = (int)argv[0].number;
    if (idx < 0 || idx >= g_bot.command_count) return hajimu_bool(false);
    SlashCommand *parent = &g_bot.commands[idx];
    if (parent->option_count >= MAX_CMD_OPTIONS) return hajimu_bool(false);

    /* Add subcommand as option type 1 */
    int oi = parent->option_count++;
    parent->options[oi].type = 1; /* SUB_COMMAND */
    snprintf(parent->options[oi].name, sizeof(parent->options[oi].name), "%s", argv[1].string.data);
    snprintf(parent->options[oi].description, sizeof(parent->options[oi].description), "%s", argv[2].string.data);
    parent->options[oi].required = false;

    /* Register as a separate command handler for routing */
    if (g_bot.command_count < MAX_COMMANDS) {
        int sub_idx = g_bot.command_count++;
        SlashCommand *sub = &g_bot.commands[sub_idx];
        memset(sub, 0, sizeof(*sub));
        /* Name format: parent_name/sub_name for matching */
        snprintf(sub->name, sizeof(sub->name), "%s/%s", parent->name, argv[1].string.data);
        snprintf(sub->description, sizeof(sub->description), "%s", argv[2].string.data);
        sub->callback = argv[3];
        sub->registered = true; /* Don't register separately with Discord */
    }

    return hajimu_bool(true);
}

/* サブコマンドグループ追加(コマンドインデックス, グループ名, 説明) */
static Value fn_subcommand_group_add(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_NUMBER ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING) {
        LOG_E("サブコマンドグループ追加: (コマンドID, グループ名, 説明) が必要です");
        return hajimu_bool(false);
    }
    int idx = (int)argv[0].number;
    if (idx < 0 || idx >= g_bot.command_count) return hajimu_bool(false);
    SlashCommand *parent = &g_bot.commands[idx];
    if (parent->option_count >= MAX_CMD_OPTIONS) return hajimu_bool(false);

    /* Add subcommand group as option type 2 */
    int oi = parent->option_count++;
    parent->options[oi].type = 2; /* SUB_COMMAND_GROUP */
    snprintf(parent->options[oi].name, sizeof(parent->options[oi].name), "%s", argv[1].string.data);
    snprintf(parent->options[oi].description, sizeof(parent->options[oi].description), "%s", argv[2].string.data);

    return hajimu_bool(true);
}

/* --- オートコンプリート --- */

/* オートコンプリート時(コマンド名, コールバック) */
static Value fn_on_autocomplete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        (argv[1].type != VALUE_FUNCTION && argv[1].type != VALUE_BUILTIN)) {
        LOG_E("オートコンプリート時: (コマンド名, コールバック) が必要です");
        return hajimu_bool(false);
    }
    if (g_bot.autocomplete_count >= MAX_COMMANDS) return hajimu_bool(false);
    int ai = g_bot.autocomplete_count++;
    snprintf(g_bot.autocomplete_handlers[ai].command_name, 64, "%s", argv[0].string.data);
    g_bot.autocomplete_handlers[ai].callback = argv[1];
    LOG_D("オートコンプリート登録: %s", argv[0].string.data);
    return hajimu_bool(true);
}

/* オートコンプリート応答(インタラクション, 選択肢配列) */
static Value fn_autocomplete_respond(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_DICT || argv[1].type != VALUE_ARRAY) {
        LOG_E("オートコンプリート応答: (インタラクション, 選択肢配列) が必要です");
        return hajimu_bool(false);
    }
    const char *interaction_id = value_get_str(&argv[0], "ID");
    const char *interaction_token = value_get_str(&argv[0], "トークン");
    if (!interaction_id || !interaction_token) return hajimu_bool(false);

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 8); /* APPLICATION_COMMAND_AUTOCOMPLETE_RESULT */
    jb_key(&sb, "data"); jb_obj_start(&sb);
    jb_key(&sb, "choices"); jb_arr_start(&sb);
    for (int i = 0; i < argv[1].array.length && i < MAX_CMD_CHOICES; i++) {
        Value *item = &argv[1].array.elements[i];
        if (item->type == VALUE_DICT) {
            const char *name = value_get_str(item, "名前");
            const char *value = value_get_str(item, "値");
            if (name && value) {
                jb_obj_start(&sb);
                jb_str(&sb, "name", name);
                jb_str(&sb, "value", value);
                jb_obj_end(&sb); sb_append_char(&sb, ',');
            }
        } else if (item->type == VALUE_STRING) {
            jb_obj_start(&sb);
            jb_str(&sb, "name", item->string.data);
            jb_str(&sb, "value", item->string.data);
            jb_obj_end(&sb); sb_append_char(&sb, ',');
        }
    }
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);

    char ep[512];
    snprintf(ep, sizeof(ep), "/interactions/%s/%s/callback",
             interaction_id, interaction_token);

    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200 || code == 204);
}

/* --- コンテキストメニュー --- */

/* ユーザーメニュー登録(名前, コールバック) — context menu type 2 */
static Value fn_user_context_menu(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        (argv[1].type != VALUE_FUNCTION && argv[1].type != VALUE_BUILTIN)) {
        LOG_E("ユーザーメニュー登録: (名前, コールバック) が必要です");
        return hajimu_bool(false);
    }
    if (g_bot.command_count >= MAX_COMMANDS) return hajimu_bool(false);

    int idx = g_bot.command_count++;
    SlashCommand *cmd = &g_bot.commands[idx];
    memset(cmd, 0, sizeof(*cmd));
    snprintf(cmd->name, sizeof(cmd->name), "%s", argv[0].string.data);
    cmd->description[0] = '\0'; /* Context menus have no description */
    cmd->callback = argv[1];
    cmd->options[0].type = 2; /* marker: USER context menu */
    cmd->option_count = -2;   /* negative = context menu type for registration */
    LOG_D("ユーザーコンテキストメニュー登録: %s", cmd->name);
    return hajimu_number(idx);
}

/* メッセージメニュー登録(名前, コールバック) — context menu type 3 */
static Value fn_message_context_menu(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        (argv[1].type != VALUE_FUNCTION && argv[1].type != VALUE_BUILTIN)) {
        LOG_E("メッセージメニュー登録: (名前, コールバック) が必要です");
        return hajimu_bool(false);
    }
    if (g_bot.command_count >= MAX_COMMANDS) return hajimu_bool(false);

    int idx = g_bot.command_count++;
    SlashCommand *cmd = &g_bot.commands[idx];
    memset(cmd, 0, sizeof(*cmd));
    snprintf(cmd->name, sizeof(cmd->name), "%s", argv[0].string.data);
    cmd->description[0] = '\0';
    cmd->callback = argv[1];
    cmd->options[0].type = 3; /* marker: MESSAGE context menu */
    cmd->option_count = -3;
    LOG_D("メッセージコンテキストメニュー登録: %s", cmd->name);
    return hajimu_number(idx);
}

/* コマンド選択肢(コマンドインデックス, オプションインデックス, 名前, 値) */
static Value fn_command_choice(int argc, Value *argv) {
    if (argc < 4 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_NUMBER ||
        argv[2].type != VALUE_STRING || argv[3].type != VALUE_STRING) {
        LOG_E("コマンド選択肢: (コマンドID, オプションID, 名前, 値) が必要です");
        return hajimu_bool(false);
    }
    /* Note: choices are stored in registration JSON; for now this is a placeholder
       that marks the option as having choices. Full implementation would extend
       the option struct. */
    LOG_D("コマンド選択肢追加（オプション %d に選択肢 '%s'）",
          (int)argv[1].number, argv[2].string.data);
    return hajimu_bool(true);
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
 * v1.6.0: コレクター & キャッシュ
 * ========================================================================= */

/* Helper: allocate a collector slot */
static int collector_alloc(void) {
    for (int i = 0; i < MAX_COLLECTORS; i++) {
        if (!g_bot.collectors[i].active) return i;
    }
    return -1;
}

/* Helper: wait for collector to complete (blocking with timeout) */
static Value collector_await(Collector *c) {
    struct timespec ts;
    while (!c->done && g_bot.running) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        double elapsed = (ts.tv_sec - c->start_time.tv_sec) +
                         (ts.tv_nsec - c->start_time.tv_nsec) / 1e9;
        if (c->timeout_sec > 0 && elapsed >= c->timeout_sec) {
            c->done = true;
            break;
        }
        usleep(50000); /* 50ms poll */
    }

    /* Build result array */
    Value arr = hajimu_array();
    for (int i = 0; i < c->collected_count; i++) {
        hajimu_array_push(&arr, c->collected[i]);
    }
    c->active = false;
    return arr;
}

/* メッセージ収集(チャンネルID, フィルタ, タイムアウト秒[, 最大件数]) */
static Value fn_message_collector(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING) return hajimu_null();

    pthread_mutex_lock(&g_bot.collector_mutex);
    int idx = collector_alloc();
    if (idx < 0) {
        pthread_mutex_unlock(&g_bot.collector_mutex);
        LOG_E("コレクター上限です");
        return hajimu_null();
    }

    Collector *c = &g_bot.collectors[idx];
    memset(c, 0, sizeof(Collector));
    c->type = 0; /* message */
    snprintf(c->channel_id, sizeof(c->channel_id), "%s", argv[0].string.data);
    if (argv[1].type == VALUE_FUNCTION || argv[1].type == VALUE_BUILTIN) {
        c->filter = argv[1];
    }
    c->timeout_sec = (argv[2].type == VALUE_NUMBER) ? argv[2].number : 30.0;
    c->max_collect = (argc >= 4 && argv[3].type == VALUE_NUMBER) ? (int)argv[3].number : 0;
    clock_gettime(CLOCK_MONOTONIC, &c->start_time);
    c->active = true;
    c->done = false;
    pthread_mutex_unlock(&g_bot.collector_mutex);

    return collector_await(c);
}

/* リアクション収集(チャンネルID, メッセージID, タイムアウト秒[, 最大件数]) */
static Value fn_reaction_collector(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_null();

    pthread_mutex_lock(&g_bot.collector_mutex);
    int idx = collector_alloc();
    if (idx < 0) {
        pthread_mutex_unlock(&g_bot.collector_mutex);
        LOG_E("コレクター上限です");
        return hajimu_null();
    }

    Collector *c = &g_bot.collectors[idx];
    memset(c, 0, sizeof(Collector));
    c->type = 1; /* reaction */
    snprintf(c->channel_id, sizeof(c->channel_id), "%s", argv[0].string.data);
    snprintf(c->message_id, sizeof(c->message_id), "%s", argv[1].string.data);
    c->timeout_sec = (argv[2].type == VALUE_NUMBER) ? argv[2].number : 30.0;
    c->max_collect = (argc >= 4 && argv[3].type == VALUE_NUMBER) ? (int)argv[3].number : 0;
    clock_gettime(CLOCK_MONOTONIC, &c->start_time);
    c->active = true;
    c->done = false;
    pthread_mutex_unlock(&g_bot.collector_mutex);

    return collector_await(c);
}

/* インタラクション収集(チャンネルID, メッセージID, タイムアウト秒[, 最大件数]) */
static Value fn_interaction_collector(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_null();

    pthread_mutex_lock(&g_bot.collector_mutex);
    int idx = collector_alloc();
    if (idx < 0) {
        pthread_mutex_unlock(&g_bot.collector_mutex);
        LOG_E("コレクター上限です");
        return hajimu_null();
    }

    Collector *c = &g_bot.collectors[idx];
    memset(c, 0, sizeof(Collector));
    c->type = 2; /* interaction */
    snprintf(c->channel_id, sizeof(c->channel_id), "%s", argv[0].string.data);
    snprintf(c->message_id, sizeof(c->message_id), "%s", argv[1].string.data);
    c->timeout_sec = (argv[2].type == VALUE_NUMBER) ? argv[2].number : 30.0;
    c->max_collect = (argc >= 4 && argv[3].type == VALUE_NUMBER) ? (int)argv[3].number : 0;
    clock_gettime(CLOCK_MONOTONIC, &c->start_time);
    c->active = true;
    c->done = false;
    pthread_mutex_unlock(&g_bot.collector_mutex);

    return collector_await(c);
}

/* メンバー一覧(サーバーID[, 件数]) — GET /guilds/{id}/members?limit=N */
static Value fn_member_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    int limit = 100;
    if (argc >= 2 && argv[1].type == VALUE_NUMBER) limit = (int)argv[1].number;
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/members?limit=%d", argv[0].string.data, limit);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* メンバー検索(サーバーID, クエリ[, 件数]) — GET /guilds/{id}/members/search?query=... */
static Value fn_member_search(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_null();
    int limit = 10;
    if (argc >= 3 && argv[2].type == VALUE_NUMBER) limit = (int)argv[2].number;
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;

    /* URL-encode query */
    CURL *curl_h = curl_easy_init();
    char *encoded = curl_easy_escape(curl_h, argv[1].string.data, 0);
    curl_easy_cleanup(curl_h);

    char ep[256];
    snprintf(ep, sizeof(ep), "/guilds/%s/members/search?query=%s&limit=%d",
             argv[0].string.data, encoded, limit);
    curl_free(encoded);

    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* サーバー一覧() — GET /users/@me/guilds */
static Value fn_guild_list(int argc, Value *argv) {
    (void)argc; (void)argv;
    long code = 0;
    JsonNode *resp = discord_rest("GET", "/users/@me/guilds", NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* =========================================================================
 * v1.7.0: 監査ログ・AutoModeration・絵文字・スケジュールイベント・投票
 * ========================================================================= */

/* --- 監査ログ --- */

/* 監査ログ(サーバーID[, 種類, 件数])
 * GET /guilds/{id}/audit-logs?action_type=N&limit=N */
static Value fn_audit_log(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[256];
    int offset = 0;
    offset += snprintf(ep + offset, sizeof(ep) - offset,
                       "/guilds/%s/audit-logs", argv[0].string.data);
    bool has_param = false;
    if (argc >= 2 && argv[1].type == VALUE_NUMBER) {
        offset += snprintf(ep + offset, sizeof(ep) - offset,
                           "?action_type=%d", (int)argv[1].number);
        has_param = true;
    }
    if (argc >= 3 && argv[2].type == VALUE_NUMBER) {
        int limit = (int)argv[2].number;
        if (limit < 1) limit = 1;
        if (limit > 100) limit = 100;
        offset += snprintf(ep + offset, sizeof(ep) - offset,
                           "%slimit=%d", has_param ? "&" : "?", limit);
    }
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- AutoModeration --- */

/* Helper: serialize Value array of strings to JSON array string */
static void serialize_string_array(StrBuf *sb, Value *arr) {
    jb_arr_start(sb);
    if (arr->type == VALUE_ARRAY) {
        for (int i = 0; i < arr->array.length; i++) {
            if (arr->array.elements[i].type == VALUE_STRING) {
                json_escape_str(sb, arr->array.elements[i].string.data);
                sb_append_char(sb, ',');
            }
        }
    }
    jb_arr_end(sb);
}

/* AutoModルール一覧(サーバーID) */
static Value fn_automod_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/auto-moderation/rules",
             argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* AutoModルール取得(サーバーID, ルールID) */
static Value fn_automod_get(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_null();
    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/auto-moderation/rules/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* AutoModルール作成(サーバーID, 設定辞書)
 * 設定: {
 *   "名前": "ルール名",
 *   "トリガー種類": 1,  -- 1=キーワード, 3=スパム, 4=キーワードプリセット, 5=メンション
 *   "キーワード": ["bad", "evil"],
 *   "アクション種類": 1,  -- 1=ブロック, 2=アラート送信, 3=タイムアウト
 *   "アラートチャンネル": "channel_id",
 *   "タイムアウト秒数": 60,
 *   "有効": true
 * } */
static Value fn_automod_create(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_DICT) return hajimu_null();

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);

    int trigger_type = 1;
    int action_type = 1;
    const char *alert_channel = NULL;
    int timeout_secs = 0;
    Value *keywords = NULL;

    int count = argv[1].dict.length;
    for (int i = 0; i < count; i++) {
        const char *key = argv[1].dict.keys[i];
        Value val = argv[1].dict.values[i];

        if (strcmp(key, "名前") == 0 || strcmp(key, "name") == 0) {
            if (val.type == VALUE_STRING) jb_str(&sb, "name", val.string.data);
        } else if (strcmp(key, "トリガー種類") == 0 || strcmp(key, "trigger_type") == 0) {
            if (val.type == VALUE_NUMBER) trigger_type = (int)val.number;
        } else if (strcmp(key, "キーワード") == 0 || strcmp(key, "keywords") == 0) {
            keywords = &argv[1].dict.values[i];
        } else if (strcmp(key, "アクション種類") == 0 || strcmp(key, "action_type") == 0) {
            if (val.type == VALUE_NUMBER) action_type = (int)val.number;
        } else if (strcmp(key, "アラートチャンネル") == 0 || strcmp(key, "alert_channel") == 0) {
            if (val.type == VALUE_STRING) alert_channel = val.string.data;
        } else if (strcmp(key, "タイムアウト秒数") == 0 || strcmp(key, "timeout_seconds") == 0) {
            if (val.type == VALUE_NUMBER) timeout_secs = (int)val.number;
        } else if (strcmp(key, "有効") == 0 || strcmp(key, "enabled") == 0) {
            if (val.type == VALUE_BOOL) jb_bool(&sb, "enabled", val.boolean);
        }
    }

    jb_int(&sb, "trigger_type", trigger_type);
    jb_int(&sb, "event_type", 1); /* MESSAGE_SEND */

    /* trigger_metadata */
    if (keywords && keywords->type == VALUE_ARRAY) {
        jb_key(&sb, "trigger_metadata");
        jb_obj_start(&sb);
        jb_key(&sb, "keyword_filter");
        serialize_string_array(&sb, keywords);
        sb_append_char(&sb, ',');
        jb_obj_end(&sb);
        sb_append_char(&sb, ',');
    }

    /* actions array */
    jb_key(&sb, "actions");
    jb_arr_start(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", action_type);
    if (action_type == 2 && alert_channel) {
        jb_key(&sb, "metadata");
        jb_obj_start(&sb);
        jb_str(&sb, "channel_id", alert_channel);
        jb_obj_end(&sb);
        sb_append_char(&sb, ',');
    } else if (action_type == 3 && timeout_secs > 0) {
        jb_key(&sb, "metadata");
        jb_obj_start(&sb);
        jb_int(&sb, "duration_seconds", timeout_secs);
        jb_obj_end(&sb);
        sb_append_char(&sb, ',');
    }
    jb_obj_end(&sb);
    sb_append_char(&sb, ',');
    jb_arr_end(&sb);
    sb_append_char(&sb, ',');

    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/auto-moderation/rules",
             argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* AutoModルール編集(サーバーID, ルールID, 設定辞書) */
static Value fn_automod_edit(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_DICT) return hajimu_null();

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);

    int count = argv[2].dict.length;
    for (int i = 0; i < count; i++) {
        const char *key = argv[2].dict.keys[i];
        Value val = argv[2].dict.values[i];

        if (strcmp(key, "名前") == 0 || strcmp(key, "name") == 0) {
            if (val.type == VALUE_STRING) jb_str(&sb, "name", val.string.data);
        } else if (strcmp(key, "有効") == 0 || strcmp(key, "enabled") == 0) {
            if (val.type == VALUE_BOOL) jb_bool(&sb, "enabled", val.boolean);
        } else if (strcmp(key, "キーワード") == 0 || strcmp(key, "keywords") == 0) {
            if (val.type == VALUE_ARRAY) {
                jb_key(&sb, "trigger_metadata");
                jb_obj_start(&sb);
                jb_key(&sb, "keyword_filter");
                serialize_string_array(&sb, &argv[2].dict.values[i]);
                sb_append_char(&sb, ',');
                jb_obj_end(&sb);
                sb_append_char(&sb, ',');
            }
        } else if (strcmp(key, "アクション種類") == 0 || strcmp(key, "action_type") == 0) {
            if (val.type == VALUE_NUMBER) {
                jb_key(&sb, "actions");
                jb_arr_start(&sb);
                jb_obj_start(&sb);
                jb_int(&sb, "type", (int)val.number);
                jb_obj_end(&sb);
                sb_append_char(&sb, ',');
                jb_arr_end(&sb);
                sb_append_char(&sb, ',');
            }
        }
    }

    jb_obj_end(&sb);

    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/auto-moderation/rules/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* AutoModルール削除(サーバーID, ルールID) */
static Value fn_automod_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_bool(false);
    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/auto-moderation/rules/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* AutoMod実行時 — イベント登録ショートカット */
static Value fn_automod_on_action(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION && argv[0].type != VALUE_BUILTIN))
        return hajimu_bool(false);
    event_register("自動モデレーション実行", argv[0]);
    event_register("AUTO_MODERATION_ACTION_EXECUTION", argv[0]);
    return hajimu_bool(true);
}

/* --- 絵文字管理 --- */

/* 絵文字一覧(サーバーID) */
static Value fn_emoji_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/emojis", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* 絵文字作成(サーバーID, 名前, 画像パス)
 * 画像をBase64エンコードしてPOST /guilds/{id}/emojis */
static Value fn_emoji_create(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING) return hajimu_null();

    /* Read image file */
    FILE *fp = fopen(argv[2].string.data, "rb");
    if (!fp) {
        LOG_E("絵文字画像を開けません: %s", argv[2].string.data);
        return hajimu_null();
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0 || fsize > 256 * 1024) { /* Discord emoji max 256KB */
        fclose(fp);
        LOG_E("絵文字画像サイズ不正: %ld bytes", fsize);
        return hajimu_null();
    }
    uint8_t *img = (uint8_t *)malloc(fsize);
    if (!img) {
        fclose(fp);
        LOG_E("絵文字画像メモリ確保失敗");
        return hajimu_null();
    }
    size_t read_bytes = fread(img, 1, fsize, fp);
    fclose(fp);
    if ((long)read_bytes != fsize) {
        free(img);
        LOG_E("絵文字画像読み込み失敗");
        return hajimu_null();
    }

    /* Detect content type from extension */
    const char *path = argv[2].string.data;
    const char *ext = strrchr(path, '.');
    const char *mime = "image/png";
    if (ext) {
        if (strcasecmp(ext, ".gif") == 0) mime = "image/gif";
        else if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0)
            mime = "image/jpeg";
        else if (strcasecmp(ext, ".webp") == 0) mime = "image/webp";
    }

    char *b64 = base64_encode(img, (int)fsize);
    free(img);
    if (!b64) {
        LOG_E("絵文字Base64エンコード失敗");
        return hajimu_null();
    }

    /* Build data URI: "data:image/png;base64,XXXX" */
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", argv[1].string.data);
    jb_key(&sb, "image");
    sb_append(&sb, "\"data:");
    sb_append(&sb, mime);
    sb_append(&sb, ";base64,");
    sb_append(&sb, b64);
    sb_append(&sb, "\",");
    jb_obj_end(&sb);
    free(b64);

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/emojis", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 201) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* 絵文字削除(サーバーID, 絵文字ID) */
static Value fn_emoji_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_bool(false);
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/emojis/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* --- スケジュールイベント --- */

/* イベント作成(サーバーID, 名前, 開始時刻, 終了時刻[, 説明])
 * 開始/終了: ISO 8601 文字列 (例: "2026-03-01T18:00:00Z")
 * entity_type: 3 = EXTERNAL (場所指定あり) */
static Value fn_event_create(int argc, Value *argv) {
    if (argc < 4 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING ||
        argv[3].type != VALUE_STRING) return hajimu_null();

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", argv[1].string.data);
    jb_str(&sb, "scheduled_start_time", argv[2].string.data);
    jb_str(&sb, "scheduled_end_time", argv[3].string.data);
    jb_int(&sb, "privacy_level", 2); /* GUILD_ONLY */
    jb_int(&sb, "entity_type", 3);   /* EXTERNAL */

    /* entity_metadata with location */
    jb_key(&sb, "entity_metadata");
    jb_obj_start(&sb);
    jb_str(&sb, "location", "オンライン");
    jb_obj_end(&sb);
    sb_append_char(&sb, ',');

    if (argc >= 5 && argv[4].type == VALUE_STRING) {
        jb_str(&sb, "description", argv[4].string.data);
    }
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/scheduled-events",
             argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* イベント編集(サーバーID, イベントID, 設定辞書)
 * 設定: {"名前": "...", "説明": "...", "開始": "...", "終了": "...", "ステータス": 2} */
static Value fn_event_edit(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_DICT) return hajimu_null();

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);

    int count = argv[2].dict.length;
    for (int i = 0; i < count; i++) {
        const char *key = argv[2].dict.keys[i];
        Value val = argv[2].dict.values[i];
        if (strcmp(key, "名前") == 0 || strcmp(key, "name") == 0) {
            if (val.type == VALUE_STRING) jb_str(&sb, "name", val.string.data);
        } else if (strcmp(key, "説明") == 0 || strcmp(key, "description") == 0) {
            if (val.type == VALUE_STRING) jb_str(&sb, "description", val.string.data);
        } else if (strcmp(key, "開始") == 0 || strcmp(key, "scheduled_start_time") == 0) {
            if (val.type == VALUE_STRING) jb_str(&sb, "scheduled_start_time", val.string.data);
        } else if (strcmp(key, "終了") == 0 || strcmp(key, "scheduled_end_time") == 0) {
            if (val.type == VALUE_STRING) jb_str(&sb, "scheduled_end_time", val.string.data);
        } else if (strcmp(key, "ステータス") == 0 || strcmp(key, "status") == 0) {
            if (val.type == VALUE_NUMBER) jb_int(&sb, "status", (int)val.number);
        }
    }

    jb_obj_end(&sb);

    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/scheduled-events/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* イベント削除(サーバーID, イベントID) */
static Value fn_event_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_bool(false);
    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/scheduled-events/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* イベント一覧(サーバーID) */
static Value fn_event_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/scheduled-events",
             argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- 投票 (Poll) --- */

/* 投票作成(チャンネルID, 質問, 選択肢配列, 時間(h))
 * 選択肢配列: ["選択肢1", "選択肢2", ...]
 * 時間: 投票期間（時間単位、1-168） */
static Value fn_poll_create(int argc, Value *argv) {
    if (argc < 4 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_ARRAY ||
        argv[3].type != VALUE_NUMBER) return hajimu_null();

    int duration = (int)argv[3].number;
    if (duration < 1) duration = 1;
    if (duration > 168) duration = 168; /* max 7 days */

    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);

    /* poll object */
    jb_key(&sb, "poll");
    jb_obj_start(&sb);

    /* question */
    jb_key(&sb, "question");
    jb_obj_start(&sb);
    jb_str(&sb, "text", argv[1].string.data);
    jb_obj_end(&sb);
    sb_append_char(&sb, ',');

    /* answers array */
    jb_key(&sb, "answers");
    jb_arr_start(&sb);
    for (int i = 0; i < argv[2].array.length && i < 10; i++) {
        Value *item = &argv[2].array.elements[i];
        if (item->type == VALUE_STRING) {
            jb_obj_start(&sb);
            jb_key(&sb, "poll_media");
            jb_obj_start(&sb);
            jb_str(&sb, "text", item->string.data);
            jb_obj_end(&sb);
            sb_append_char(&sb, ',');
            jb_obj_end(&sb);
            sb_append_char(&sb, ',');
        }
    }
    jb_arr_end(&sb);
    sb_append_char(&sb, ',');

    jb_int(&sb, "duration", duration);
    jb_bool(&sb, "allow_multiselect",
            (argc >= 5 && argv[4].type == VALUE_BOOL) ? argv[4].boolean : false);
    jb_int(&sb, "layout_type", 1); /* DEFAULT */

    jb_obj_end(&sb);
    sb_append_char(&sb, ',');

    jb_obj_end(&sb);

    char ep[64];
    snprintf(ep, sizeof(ep), "/channels/%s/messages", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* 投票終了(チャンネルID, メッセージID) — POST /channels/{id}/polls/{msg}/expire */
static Value fn_poll_end(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/polls/%s/expire",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* =========================================================================
 * v2.0.0: ボイスチャンネル対応
 * ========================================================================= */

/* ユーザーボイスチャンネル(サーバーID, ユーザーID) — Get user's current voice channel */
static Value fn_get_user_voice_channel(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        return hajimu_null();
    }
    const char *vc = voice_state_cache_get(argv[0].string.data, argv[1].string.data);
    if (vc) return hajimu_string(vc);
    return hajimu_null();
}

/* VC接続(サーバーID, チャンネルID) — Join a voice channel */
static Value fn_vc_join(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("VC接続: サーバーID(文字列), チャンネルID(文字列)が必要です");
        return hajimu_bool(false);
    }
    const char *guild_id = argv[0].string.data;
    const char *channel_id = argv[1].string.data;

    /* Check for existing connection */
    VoiceConn *vc = voice_find(guild_id);
    if (vc) {
        LOG_W("VC接続: サーバー %s は既に接続中です", guild_id);
        return hajimu_bool(false);
    }

    /* Allocate voice connection */
    vc = voice_alloc(guild_id);
    if (!vc) return hajimu_bool(false);

    snprintf(vc->channel_id, sizeof(vc->channel_id), "%s", channel_id);
    vc->waiting_for_state = true;
    vc->waiting_for_server = true;
    vc->state_received = false;
    vc->server_received = false;

    /* Start audio thread */
    pthread_create(&vc->audio_thread, NULL, voice_audio_thread_func, vc);

    /* Send Gateway op 4 to join voice channel */
    gw_send_voice_state(guild_id, channel_id);
    LOG_I("VC接続リクエスト送信: guild=%s, channel=%s", guild_id, channel_id);

    return hajimu_bool(true);
}

/* VC切断(サーバーID) — Leave a voice channel */
static Value fn_vc_leave(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("VC切断: サーバーID(文字列)が必要です");
        return hajimu_bool(false);
    }
    const char *guild_id = argv[0].string.data;

    VoiceConn *vc = voice_find(guild_id);
    if (!vc) {
        LOG_W("VC切断: サーバー %s は接続されていません", guild_id);
        return hajimu_bool(false);
    }

    /* Send Gateway op 4 with null channel to leave */
    gw_send_voice_state(guild_id, NULL);

    /* Clean up voice connection */
    voice_free(vc);

    LOG_I("VC切断完了: guild=%s", guild_id);

    Value guild_val = hajimu_string(guild_id);
    event_fire("ボイス切断", 1, &guild_val);
    event_fire("VOICE_DISCONNECTED", 1, &guild_val);

    return hajimu_bool(true);
}

/* 音声再生(サーバーID, ソース) — Play audio file */
static Value fn_voice_play(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("音声再生: サーバーID(文字列), ソース(文字列)が必要です");
        return hajimu_bool(false);
    }
    const char *guild_id = argv[0].string.data;
    const char *source = argv[1].string.data;

    VoiceConn *vc = voice_find(guild_id);
    if (!vc || !vc->ready) {
        LOG_E("音声再生: ボイス接続が準備できていません (guild=%s)", guild_id);
        return hajimu_bool(false);
    }

    /* Add to queue */
    pthread_mutex_lock(&vc->voice_mutex);
    if (vc->queue_count >= MAX_AUDIO_QUEUE) {
        pthread_mutex_unlock(&vc->voice_mutex);
        LOG_E("音声再生: キューが満杯です");
        return hajimu_bool(false);
    }
    int tail = vc->queue_tail;
    snprintf(vc->queue[tail].path, sizeof(vc->queue[tail].path), "%s", source);
    vc->queue_tail = (vc->queue_tail + 1) % MAX_AUDIO_QUEUE;
    vc->queue_count++;
    pthread_mutex_unlock(&vc->voice_mutex);

    LOG_I("音声キューに追加: %s", source);
    return hajimu_bool(true);
}

/* 音声停止(サーバーID) — Stop playback and clear queue */
static Value fn_voice_stop(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("音声停止: サーバーID(文字列)が必要です");
        return hajimu_bool(false);
    }
    VoiceConn *vc = voice_find(argv[0].string.data);
    if (!vc) return hajimu_bool(false);

    pthread_mutex_lock(&vc->voice_mutex);
    vc->playing = false;
    vc->paused = false;
    /* Don't set stop_requested=true: that kills the audio thread entirely.
       Just stop current playback and clear queue so nothing else plays. */
    /* Clear queue */
    vc->queue_head = 0;
    vc->queue_tail = 0;
    vc->queue_count = 0;
    pthread_mutex_unlock(&vc->voice_mutex);

    LOG_I("音声停止: guild=%s", vc->guild_id);
    return hajimu_bool(true);
}

/* 音声一時停止(サーバーID) — Pause playback */
static Value fn_voice_pause(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("音声一時停止: サーバーID(文字列)が必要です");
        return hajimu_bool(false);
    }
    VoiceConn *vc = voice_find(argv[0].string.data);
    if (!vc || !vc->playing) return hajimu_bool(false);

    vc->paused = true;
    voice_send_speaking(vc, false);
    LOG_I("音声一時停止: guild=%s", vc->guild_id);
    return hajimu_bool(true);
}

/* 音声再開(サーバーID) — Resume playback */
static Value fn_voice_resume(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("音声再開: サーバーID(文字列)が必要です");
        return hajimu_bool(false);
    }
    VoiceConn *vc = voice_find(argv[0].string.data);
    if (!vc || !vc->paused) return hajimu_bool(false);

    vc->paused = false;
    voice_send_speaking(vc, true);
    LOG_I("音声再開: guild=%s", vc->guild_id);
    return hajimu_bool(true);
}

/* 音声スキップ(サーバーID) — Skip current track */
static Value fn_voice_skip(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("音声スキップ: サーバーID(文字列)が必要です");
        return hajimu_bool(false);
    }
    VoiceConn *vc = voice_find(argv[0].string.data);
    if (!vc) return hajimu_bool(false);

    /* Stop current track (audio thread will pick next from queue) */
    vc->playing = false;
    vc->paused = false;
    vc->stop_requested = false; /* Don't stop the thread, just skip */
    LOG_I("音声スキップ: guild=%s", vc->guild_id);
    return hajimu_bool(true);
}

/* 音声キュー(サーバーID) — Get current queue as array */
static Value fn_voice_queue(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("音声キュー: サーバーID(文字列)が必要です");
        return hajimu_array();
    }
    VoiceConn *vc = voice_find(argv[0].string.data);
    if (!vc) return hajimu_array();

    Value arr = hajimu_array();
    pthread_mutex_lock(&vc->voice_mutex);
    for (int i = 0; i < vc->queue_count; i++) {
        int idx = (vc->queue_head + i) % MAX_AUDIO_QUEUE;
        Value item = hajimu_string(vc->queue[idx].path);
        hajimu_array_push(&arr, item);
    }
    pthread_mutex_unlock(&vc->voice_mutex);
    return arr;
}

/* 音声ループ(サーバーID, 有効) — Toggle loop mode */
static Value fn_voice_loop(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_BOOL) {
        LOG_E("音声ループ: サーバーID(文字列), 有効(真偽)が必要です");
        return hajimu_bool(false);
    }
    VoiceConn *vc = voice_find(argv[0].string.data);
    if (!vc) return hajimu_bool(false);

    vc->loop_mode = argv[1].boolean;
    LOG_I("音声ループ %s: guild=%s", vc->loop_mode ? "有効" : "無効", vc->guild_id);
    return hajimu_bool(true);
}

/* VC状態(サーバーID) — Get voice connection status */
static Value fn_vc_status(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("VC状態: サーバーID(文字列)が必要です");
        return hajimu_null();
    }
    VoiceConn *vc = voice_find(argv[0].string.data);
    if (!vc) return hajimu_null();

    /* Return a map-like string with status info */
    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"接続中\":true,\"チャンネル\":\"%s\",\"再生中\":%s,"
        "\"一時停止\":%s,\"キュー数\":%d,\"ループ\":%s}",
        vc->channel_id,
        vc->playing ? "true" : "false",
        vc->paused ? "true" : "false",
        vc->queue_count,
        vc->loop_mode ? "true" : "false");

    /* Parse as value */
    JsonNode *node = json_parse(buf);
    if (node) {
        Value val = json_to_value(node);
        json_free(node);
        return val;
    }
    return hajimu_string(buf);
}

/* 音声音量(サーバーID, 音量) — Set Opus encoder bitrate (proxy for volume) */
static Value fn_voice_volume(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_NUMBER) {
        LOG_E("音声音量: サーバーID(文字列), 音量(数値 1-200)が必要です");
        return hajimu_bool(false);
    }
    VoiceConn *vc = voice_find(argv[0].string.data);
    if (!vc || !vc->opus_enc) return hajimu_bool(false);

    int vol = (int)argv[1].number;
    if (vol < 1) vol = 1;
    if (vol > 200) vol = 200;

    /* Map volume percentage to bitrate: 100% = 64kbps, 200% = 128kbps */
    int bitrate = 640 * vol;
    opus_encoder_ctl(vc->opus_enc, OPUS_SET_BITRATE(bitrate));
    LOG_I("音声ビットレート設定: %d bps (volume=%d%%)", bitrate, vol);
    return hajimu_bool(true);
}

/* =========================================================================
 * YouTube / yt-dlp 連携
 * ========================================================================= */

/* YouTube情報(URL) — yt-dlp で動画情報を取得 (タイトル, 再生時間, サムネイル等) */
static Value fn_ytdlp_info(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("YouTube情報: URL(文字列)が必要です");
        return hajimu_null();
    }
    const char *url = argv[0].string.data;
    if (!voice_filepath_safe(url)) {
        LOG_E("YouTube情報: URLに不正な文字が含まれています");
        return hajimu_null();
    }

    /* Get JSON info from yt-dlp */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "yt-dlp --no-playlist --no-warnings %s -j \"%s\" 2>/dev/null",
        g_bot.ytdlp_cookie_opt[0] ? g_bot.ytdlp_cookie_opt : "", url);
    FILE *pp = popen(cmd, "r");
    if (!pp) {
        LOG_E("YouTube情報: yt-dlp起動失敗");
        return hajimu_null();
    }

    /* Read JSON output (can be large, limit to 32KB) */
    size_t buf_size = 32768;
    char *buf = (char *)calloc(1, buf_size);
    if (!buf) { pclose(pp); return hajimu_null(); }
    size_t total = 0;
    char chunk[4096];
    while (fgets(chunk, sizeof(chunk), pp)) {
        size_t len = strlen(chunk);
        if (total + len >= buf_size - 1) break;
        memcpy(buf + total, chunk, len);
        total += len;
    }
    buf[total] = '\0';
    pclose(pp);

    if (total == 0) {
        free(buf);
        LOG_E("YouTube情報: yt-dlpから出力がありません");
        return hajimu_null();
    }

    /* Parse the full JSON */
    JsonNode *root = json_parse(buf);
    free(buf);
    if (!root) {
        LOG_E("YouTube情報: JSON解析失敗");
        return hajimu_null();
    }

    /* Extract key fields into a compact dict */
    const char *title    = json_get_str(root, "title");
    const char *uploader = json_get_str(root, "uploader");
    const char *thumb    = json_get_str(root, "thumbnail");
    const char *webpage  = json_get_str(root, "webpage_url");
    const char *vid_id   = json_get_str(root, "id");
    double duration      = json_get_num(root, "duration");
    double view_count    = json_get_num(root, "view_count");
    double like_count    = json_get_num(root, "like_count");
    bool is_live         = false;
    JsonNode *live_node  = json_get(root, "is_live");
    if (live_node && live_node->type == JSON_BOOL) is_live = live_node->boolean;

    /* Build result dict */
    Value dict;
    memset(&dict, 0, sizeof(dict));
    dict.type = VALUE_DICT;
    int n = 10;
    dict.dict.keys     = (char **)calloc((size_t)n, sizeof(char *));
    dict.dict.values   = (Value *)calloc((size_t)n, sizeof(Value));
    dict.dict.length   = 0;
    dict.dict.capacity = n;

    #define YT_SET_STR(k, v) do { \
        dict.dict.keys[dict.dict.length] = strdup(k); \
        dict.dict.values[dict.dict.length] = hajimu_string((v) ? (v) : ""); \
        dict.dict.length++; \
    } while(0)
    #define YT_SET_NUM(k, v) do { \
        dict.dict.keys[dict.dict.length] = strdup(k); \
        dict.dict.values[dict.dict.length] = hajimu_number(v); \
        dict.dict.length++; \
    } while(0)
    #define YT_SET_BOOL(k, v) do { \
        dict.dict.keys[dict.dict.length] = strdup(k); \
        dict.dict.values[dict.dict.length] = hajimu_bool(v); \
        dict.dict.length++; \
    } while(0)

    YT_SET_STR("タイトル", title);
    YT_SET_STR("投稿者", uploader);
    YT_SET_NUM("再生時間", duration);
    YT_SET_STR("サムネイル", thumb);
    YT_SET_STR("URL", webpage);
    YT_SET_STR("ID", vid_id);
    YT_SET_NUM("再生回数", view_count);
    YT_SET_NUM("高評価数", like_count);
    YT_SET_BOOL("ライブ", is_live);

    /* Duration formatted string */
    int dur_min = (int)duration / 60;
    int dur_sec = (int)duration % 60;
    char dur_str[32];
    snprintf(dur_str, sizeof(dur_str), "%d:%02d", dur_min, dur_sec);
    YT_SET_STR("再生時間表示", dur_str);

    #undef YT_SET_STR
    #undef YT_SET_NUM
    #undef YT_SET_BOOL

    json_free(root);
    free(root);
    return dict;
}

/* YouTube検索(クエリ[, 件数]) — yt-dlp で検索して結果を返す */
static Value fn_ytdlp_search(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("YouTube検索: クエリ(文字列)が必要です");
        return hajimu_null();
    }
    const char *query = argv[0].string.data;
    int count = 1;
    if (argc >= 2 && argv[1].type == VALUE_NUMBER)
        count = (int)argv[1].number;
    if (count < 1) count = 1;
    if (count > 10) count = 10;

    if (!voice_filepath_safe(query)) {
        LOG_E("YouTube検索: クエリに不正な文字が含まれています");
        return hajimu_null();
    }

    /* yt-dlp ytsearch: returns JSON for each result */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "yt-dlp --no-playlist --no-warnings --flat-playlist %s "
        "--print \"{\\\"タイトル\\\": \\\"%%(title)s\\\", \\\"URL\\\": \\\"https://www.youtube.com/watch?v=%%(id)s\\\", \\\"ID\\\": \\\"%%(id)s\\\", \\\"投稿者\\\": \\\"%%(uploader)s\\\", \\\"再生時間\\\": %%(duration)s}\" "
        "\"ytsearch%d:%s\" 2>/dev/null",
        g_bot.ytdlp_cookie_opt[0] ? g_bot.ytdlp_cookie_opt : "",
        count, query);
    FILE *pp = popen(cmd, "r");
    if (!pp) {
        LOG_E("YouTube検索: yt-dlp起動失敗");
        return hajimu_null();
    }

    Value arr = hajimu_array();
    char line[2048];
    while (fgets(line, sizeof(line), pp)) {
        /* Trim newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        JsonNode *node = json_parse(line);
        if (node) {
            Value val = json_to_value(node);
            hajimu_array_push(&arr, val);
            json_free(node);
            free(node);
        }
    }
    pclose(pp);

    /* If only 1 result requested, return the single item directly */
    if (count == 1 && arr.type == VALUE_ARRAY && arr.array.length > 0) {
        return arr.array.elements[0];
    }
    return arr;
}

/* YouTubeクッキー設定(ブラウザ名またはファイルパス) */
static Value fn_ytdlp_set_cookies(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("YouTubeクッキー設定: 文字列が必要です (ブラウザ名 or ファイルパス)");
        return hajimu_bool(false);
    }
    const char *val = argv[0].string.data;

    /* ブラウザ名判定 */
    if (strcmp(val, "chrome") == 0 || strcmp(val, "firefox") == 0 ||
        strcmp(val, "safari") == 0 || strcmp(val, "edge") == 0 ||
        strcmp(val, "brave") == 0 || strcmp(val, "opera") == 0 ||
        strcmp(val, "chromium") == 0 || strcmp(val, "vivaldi") == 0) {
        snprintf(g_bot.ytdlp_cookie_opt, sizeof(g_bot.ytdlp_cookie_opt),
                 "--cookies-from-browser %s", val);
        LOG_I("yt-dlp Cookie設定: --cookies-from-browser %s", val);
    } else if (strcmp(val, "none") == 0 || strcmp(val, "なし") == 0) {
        g_bot.ytdlp_cookie_opt[0] = '\0';
        LOG_I("yt-dlp Cookie設定: 無効化");
    } else {
        /* ファイルパスとして扱う */
        snprintf(g_bot.ytdlp_cookie_opt, sizeof(g_bot.ytdlp_cookie_opt),
                 "--cookies \"%s\"", val);
        LOG_I("yt-dlp Cookie設定: --cookies %s", val);
    }
    return hajimu_bool(true);
}

/* YouTubeタイトル(URL) — URLからタイトルだけ取得 (軽量) */
static Value fn_ytdlp_title(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("YouTubeタイトル: URL(文字列)が必要です");
        return hajimu_null();
    }
    char *result = ytdlp_exec("--no-playlist --no-warnings --print title", argv[0].string.data);
    if (!result || !result[0]) {
        free(result);
        return hajimu_null();
    }
    Value val = hajimu_string(result);
    free(result);
    return val;
}

/* =========================================================================
 * v2.1.0: ステージチャンネル・スタンプ・サーバー編集・フォーラム・Markdown
 * ========================================================================= */

/* --- ステージチャンネル管理 --- */

/* ステージ開始(チャンネルID, トピック[, 公開]) — Create Stage Instance */
static Value fn_stage_start(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("ステージ開始: チャンネルID(文字列), トピック(文字列)が必要です");
        return hajimu_null();
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "channel_id", argv[0].string.data);
    jb_str(&sb, "topic", argv[1].string.data);
    /* privacy_level: 1=PUBLIC, 2=GUILD_ONLY (default) */
    int privacy = 2;
    if (argc >= 3 && argv[2].type == VALUE_BOOL && argv[2].boolean) privacy = 1;
    jb_int(&sb, "privacy_level", privacy);
    jb_obj_end(&sb);

    long code = 0;
    JsonNode *resp = discord_rest("POST", "/stage-instances", sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    LOG_I("ステージ開始: channel=%s", argv[0].string.data);
    return result;
}

/* ステージ編集(チャンネルID, トピック) — Modify Stage Instance */
static Value fn_stage_edit(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("ステージ編集: チャンネルID(文字列), トピック(文字列)が必要です");
        return hajimu_bool(false);
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "topic", argv[1].string.data);
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/stage-instances/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, sb.data, &code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200);
}

/* ステージ終了(チャンネルID) — Delete Stage Instance */
static Value fn_stage_end(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) {
        LOG_E("ステージ終了: チャンネルID(文字列)が必要です");
        return hajimu_bool(false);
    }
    char ep[128];
    snprintf(ep, sizeof(ep), "/stage-instances/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    LOG_I("ステージ終了: channel=%s", argv[0].string.data);
    return hajimu_bool(code == 204);
}

/* ステージ情報(チャンネルID) — Get Stage Instance */
static Value fn_stage_info(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/stage-instances/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- スタンプ管理 --- */

/* スタンプ一覧(サーバーID) — List Guild Stickers */
static Value fn_sticker_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_array();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/stickers", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_array();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* スタンプ取得(サーバーID, スタンプID) — Get Guild Sticker */
static Value fn_sticker_get(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/stickers/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* スタンプ作成(サーバーID, 名前, ファイルパス[, 説明, タグ]) — Create Guild Sticker */
static Value fn_sticker_create(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING) {
        LOG_E("スタンプ作成: サーバーID, 名前, ファイルパスが必要です");
        return hajimu_null();
    }
    const char *guild_id = argv[0].string.data;
    const char *name = argv[1].string.data;
    const char *filepath = argv[2].string.data;
    const char *description = (argc >= 4 && argv[3].type == VALUE_STRING) ?
                               argv[3].string.data : "";
    const char *tags = (argc >= 5 && argv[4].type == VALUE_STRING) ?
                        argv[4].string.data : name;

    /* Build JSON payload for multipart */
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", name);
    jb_str(&sb, "description", description);
    jb_str(&sb, "tags", tags);
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/stickers", guild_id);
    long code = 0;
    JsonNode *resp = discord_rest_multipart(ep, sb.data, filepath, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* スタンプ編集(サーバーID, スタンプID, 設定) — Modify Guild Sticker */
static Value fn_sticker_edit(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING) {
        LOG_E("スタンプ編集: サーバーID, スタンプID, 設定(JSON文字列)が必要です");
        return hajimu_bool(false);
    }
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/stickers/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, argv[2].string.data, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200);
}

/* スタンプ削除(サーバーID, スタンプID) — Delete Guild Sticker */
static Value fn_sticker_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("スタンプ削除: サーバーID, スタンプIDが必要です");
        return hajimu_bool(false);
    }
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/stickers/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* --- ウェルカム画面管理 --- */

/* ウェルカム画面取得(サーバーID) — Get Guild Welcome Screen */
static Value fn_welcome_screen_get(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/welcome-screen", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ウェルカム画面編集(サーバーID, 設定) — Modify Guild Welcome Screen */
static Value fn_welcome_screen_edit(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("ウェルカム画面編集: サーバーID, 設定(JSON文字列)が必要です");
        return hajimu_null();
    }
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/welcome-screen", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, argv[1].string.data, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- サーバー編集 --- */

/* サーバー編集(サーバーID, 設定) — Modify Guild */
static Value fn_guild_edit(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("サーバー編集: サーバーID, 設定(JSON文字列)が必要です");
        return hajimu_null();
    }
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, argv[1].string.data, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ロール作成(サーバーID, 名前[, 色, 権限]) — Create Guild Role */
static Value fn_role_create(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("ロール作成: サーバーID, 名前が必要です");
        return hajimu_null();
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", argv[1].string.data);
    if (argc >= 3 && argv[2].type == VALUE_NUMBER)
        jb_int(&sb, "color", (int64_t)argv[2].number);
    if (argc >= 4 && argv[3].type == VALUE_STRING)
        jb_raw(&sb, "permissions", argv[3].string.data);
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/roles", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ロール編集(サーバーID, ロールID, 設定) — Modify Guild Role */
static Value fn_role_edit(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING) {
        LOG_E("ロール編集: サーバーID, ロールID, 設定(JSON)が必要です");
        return hajimu_null();
    }
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/roles/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, argv[2].string.data, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ロール削除(サーバーID, ロールID) — Delete Guild Role */
static Value fn_role_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("ロール削除: サーバーID, ロールIDが必要です");
        return hajimu_bool(false);
    }
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/roles/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* --- フォーラムチャンネル --- */

/* フォーラム投稿(チャンネルID, タイトル, 内容[, タグ配列]) — Create Forum Thread */
static Value fn_forum_post(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING) {
        LOG_E("フォーラム投稿: チャンネルID, タイトル, 内容が必要です");
        return hajimu_null();
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", argv[1].string.data);
    jb_key(&sb, "message"); jb_obj_start(&sb);
    jb_str(&sb, "content", argv[2].string.data);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    /* applied_tags */
    if (argc >= 4 && argv[3].type == VALUE_ARRAY) {
        jb_key(&sb, "applied_tags"); jb_arr_start(&sb);
        for (int i = 0; i < argv[3].array.length; i++) {
            if (argv[3].array.elements[i].type == VALUE_STRING) {
                json_escape_str(&sb, argv[3].array.elements[i].string.data);
                sb_append_char(&sb, ',');
            }
        }
        jb_arr_end(&sb); sb_append_char(&sb, ',');
    }
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/threads", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* フォーラムタグ一覧(チャンネルID) — Get Forum Tags (from channel info) */
static Value fn_forum_tags(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_array();
    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_array();
    if (resp && code == 200) {
        JsonNode *tags = json_get(resp, "available_tags");
        if (tags) result = json_to_value(tags);
    }
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- Markdown ユーティリティ --- */

/* 太字(テキスト) */
static Value fn_md_bold(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    char buf[8192];
    snprintf(buf, sizeof(buf), "**%s**", argv[0].string.data);
    return hajimu_string(buf);
}

/* 斜体(テキスト) */
static Value fn_md_italic(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    char buf[8192];
    snprintf(buf, sizeof(buf), "*%s*", argv[0].string.data);
    return hajimu_string(buf);
}

/* 下線(テキスト) */
static Value fn_md_underline(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    char buf[8192];
    snprintf(buf, sizeof(buf), "__%s__", argv[0].string.data);
    return hajimu_string(buf);
}

/* 取り消し線(テキスト) */
static Value fn_md_strikethrough(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    char buf[8192];
    snprintf(buf, sizeof(buf), "~~%s~~", argv[0].string.data);
    return hajimu_string(buf);
}

/* コード(テキスト) */
static Value fn_md_code(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    char buf[8192];
    snprintf(buf, sizeof(buf), "`%s`", argv[0].string.data);
    return hajimu_string(buf);
}

/* コードブロック(テキスト[, 言語]) */
static Value fn_md_codeblock(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    const char *lang = (argc >= 2 && argv[1].type == VALUE_STRING) ?
                        argv[1].string.data : "";
    char buf[16384];
    snprintf(buf, sizeof(buf), "```%s\n%s\n```", lang, argv[0].string.data);
    return hajimu_string(buf);
}

/* 引用(テキスト) */
static Value fn_md_quote(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    char buf[8192];
    snprintf(buf, sizeof(buf), "> %s", argv[0].string.data);
    return hajimu_string(buf);
}

/* スポイラー(テキスト) */
static Value fn_md_spoiler(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    char buf[8192];
    snprintf(buf, sizeof(buf), "||%s||", argv[0].string.data);
    return hajimu_string(buf);
}

/* ユーザーメンション(ユーザーID) */
static Value fn_md_mention_user(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    char buf[128];
    snprintf(buf, sizeof(buf), "<@%s>", argv[0].string.data);
    return hajimu_string(buf);
}

/* チャンネルメンション(チャンネルID) */
static Value fn_md_mention_channel(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    char buf[128];
    snprintf(buf, sizeof(buf), "<#%s>", argv[0].string.data);
    return hajimu_string(buf);
}

/* ロールメンション(ロールID) */
static Value fn_md_mention_role(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    char buf[128];
    snprintf(buf, sizeof(buf), "<@&%s>", argv[0].string.data);
    return hajimu_string(buf);
}

/* タイムスタンプ(UNIX秒[, スタイル]) — Discord timestamp format
 * スタイル: "t"=短時間, "T"=長時間, "d"=短日付, "D"=長日付,
 *           "f"=短日時(デフォルト), "F"=長日時, "R"=相対 */
static Value fn_md_timestamp(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_NUMBER) return hajimu_string("");
    int64_t ts = (int64_t)argv[0].number;
    char buf[128];
    if (argc >= 2 && argv[1].type == VALUE_STRING && argv[1].string.data[0]) {
        snprintf(buf, sizeof(buf), "<t:%lld:%s>", (long long)ts, argv[1].string.data);
    } else {
        snprintf(buf, sizeof(buf), "<t:%lld>", (long long)ts);
    }
    return hajimu_string(buf);
}

/* カスタム絵文字(名前, ID[, アニメーション]) — <:name:id> or <a:name:id> */
static Value fn_md_emoji(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_string("");
    bool animated = (argc >= 3 && argv[2].type == VALUE_BOOL && argv[2].boolean);
    char buf[256];
    snprintf(buf, sizeof(buf), "<%s:%s:%s>",
             animated ? "a" : "",
             argv[0].string.data, argv[1].string.data);
    return hajimu_string(buf);
}

/* ハイパーリンク(テキスト, URL) — [text](url) — Embed内で使用可能 */
static Value fn_md_link(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_string("");
    char buf[4096];
    snprintf(buf, sizeof(buf), "[%s](%s)",
             argv[0].string.data, argv[1].string.data);
    return hajimu_string(buf);
}

/* 見出し(テキスト, レベル) — # テキスト (レベル1-3) */
static Value fn_md_heading(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_NUMBER)
        return hajimu_string("");
    int level = (int)argv[1].number;
    if (level < 1) level = 1;
    if (level > 3) level = 3;
    char prefix[4] = {0};
    for (int i = 0; i < level; i++) prefix[i] = '#';
    char buf[8192];
    snprintf(buf, sizeof(buf), "%s %s", prefix, argv[0].string.data);
    return hajimu_string(buf);
}

/* リスト(配列[, 番号付き]) — builds a markdown list from array */
static Value fn_md_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_ARRAY) return hajimu_string("");
    bool numbered = (argc >= 2 && argv[1].type == VALUE_BOOL && argv[1].boolean);

    StrBuf sb; sb_init(&sb);
    for (int i = 0; i < argv[0].array.length; i++) {
        if (argv[0].array.elements[i].type == VALUE_STRING) {
            if (numbered) {
                sb_appendf(&sb, "%d. %s\n", i + 1, argv[0].array.elements[i].string.data);
            } else {
                sb_appendf(&sb, "- %s\n", argv[0].array.elements[i].string.data);
            }
        }
    }
    Value result = hajimu_string(sb.data ? sb.data : "");
    sb_free(&sb);
    return result;
}

/* =========================================================================
 * v2.2.0: Components V2・テンプレート・オンボーディング・サウンドボード・
 *         ロール接続・エンタイトルメント・OAuth2・シャーディング
 * ========================================================================= */

/* ===========================================
 * Components V2  (flags: 1<<15 = 32768)
 * =========================================== */

/* テキスト表示(ID, テキスト) — type:10 TextDisplay */
static Value fn_comp_text_display(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING)
        return hajimu_string("");
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 10);
    jb_int(&sb, "id", (int64_t)argv[0].number);
    jb_str(&sb, "content", argv[1].string.data);
    jb_obj_end(&sb);
    Value r = hajimu_string(sb.data);
    sb_free(&sb);
    return r;
}

/* セパレーター(ID[, 余白, 区切り線]) — type:14 Separator */
static Value fn_comp_separator(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_NUMBER) return hajimu_string("");
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 14);
    jb_int(&sb, "id", (int64_t)argv[0].number);
    if (argc >= 2 && argv[1].type == VALUE_BOOL)
        jb_bool(&sb, "spacing", argv[1].boolean);
    if (argc >= 3 && argv[2].type == VALUE_BOOL)
        jb_bool(&sb, "divider", argv[2].boolean);
    jb_obj_end(&sb);
    Value r = hajimu_string(sb.data);
    sb_free(&sb);
    return r;
}

/* メディアギャラリー(ID, アイテム配列) — type:12 MediaGallery */
static Value fn_comp_media_gallery(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_ARRAY)
        return hajimu_string("");
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 12);
    jb_int(&sb, "id", (int64_t)argv[0].number);
    jb_key(&sb, "items"); jb_arr_start(&sb);
    for (int i = 0; i < argv[1].array.length; i++) {
        if (argv[1].array.elements[i].type == VALUE_STRING) {
            sb_append(&sb, argv[1].array.elements[i].string.data);
            sb_append_char(&sb, ',');
        }
    }
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);
    Value r = hajimu_string(sb.data);
    sb_free(&sb);
    return r;
}

/* メディアアイテム(URL[, 説明]) — MediaGalleryItem JSON snippet */
static Value fn_comp_media_item(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_string("");
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_key(&sb, "media"); jb_obj_start(&sb);
    jb_str(&sb, "url", argv[0].string.data);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    if (argc >= 2 && argv[1].type == VALUE_STRING)
        jb_str(&sb, "description", argv[1].string.data);
    jb_obj_end(&sb);
    Value r = hajimu_string(sb.data);
    sb_free(&sb);
    return r;
}

/* サムネイル(ID, URL[, 説明]) — type:11 Thumbnail */
static Value fn_comp_thumbnail(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING)
        return hajimu_string("");
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 11);
    jb_int(&sb, "id", (int64_t)argv[0].number);
    jb_key(&sb, "media"); jb_obj_start(&sb);
    jb_str(&sb, "url", argv[1].string.data);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    if (argc >= 3 && argv[2].type == VALUE_STRING)
        jb_str(&sb, "description", argv[2].string.data);
    jb_obj_end(&sb);
    Value r = hajimu_string(sb.data);
    sb_free(&sb);
    return r;
}

/* セクション(ID, コンポーネント配列[, サムネイル]) — type:9 Section */
static Value fn_comp_section(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_ARRAY)
        return hajimu_string("");
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 9);
    jb_int(&sb, "id", (int64_t)argv[0].number);
    jb_key(&sb, "components"); jb_arr_start(&sb);
    for (int i = 0; i < argv[1].array.length; i++) {
        if (argv[1].array.elements[i].type == VALUE_STRING) {
            sb_append(&sb, argv[1].array.elements[i].string.data);
            sb_append_char(&sb, ',');
        }
    }
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    if (argc >= 3 && argv[2].type == VALUE_STRING) {
        jb_key(&sb, "accessory");
        sb_append(&sb, argv[2].string.data);
        sb_append_char(&sb, ',');
    }
    jb_obj_end(&sb);
    Value r = hajimu_string(sb.data);
    sb_free(&sb);
    return r;
}

/* コンテナ(ID, コンポーネント配列[, 色, スポイラー]) — type:17 Container */
static Value fn_comp_container(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_ARRAY)
        return hajimu_string("");
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 17);
    jb_int(&sb, "id", (int64_t)argv[0].number);
    jb_key(&sb, "components"); jb_arr_start(&sb);
    for (int i = 0; i < argv[1].array.length; i++) {
        if (argv[1].array.elements[i].type == VALUE_STRING) {
            sb_append(&sb, argv[1].array.elements[i].string.data);
            sb_append_char(&sb, ',');
        }
    }
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    if (argc >= 3 && argv[2].type == VALUE_NUMBER)
        jb_int(&sb, "accent_color", (int64_t)argv[2].number);
    if (argc >= 4 && argv[3].type == VALUE_BOOL)
        jb_bool(&sb, "spoiler", argv[3].boolean);
    jb_obj_end(&sb);
    Value r = hajimu_string(sb.data);
    sb_free(&sb);
    return r;
}

/* ファイル表示(ID, URL) — type:13 File */
static Value fn_comp_file(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_STRING)
        return hajimu_string("");
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "type", 13);
    jb_int(&sb, "id", (int64_t)argv[0].number);
    jb_key(&sb, "file"); jb_obj_start(&sb);
    jb_str(&sb, "url", argv[1].string.data);
    jb_obj_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);
    Value r = hajimu_string(sb.data);
    sb_free(&sb);
    return r;
}

/* V2メッセージ送信(チャンネルID, コンポーネント配列) — Send with IS_COMPONENTS_V2 flag */
static Value fn_send_components_v2(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_ARRAY) {
        LOG_E("V2メッセージ送信: チャンネルID, コンポーネント配列が必要です");
        return hajimu_null();
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_int(&sb, "flags", 32768); /* IS_COMPONENTS_V2 = 1<<15 */
    jb_key(&sb, "components"); jb_arr_start(&sb);
    for (int i = 0; i < argv[1].array.length; i++) {
        if (argv[1].array.elements[i].type == VALUE_STRING) {
            sb_append(&sb, argv[1].array.elements[i].string.data);
            sb_append_char(&sb, ',');
        }
    }
    jb_arr_end(&sb); sb_append_char(&sb, ',');
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/messages", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ===========================================
 * サーバーテンプレート
 * =========================================== */

/* テンプレート一覧(サーバーID) — Get Guild Templates */
static Value fn_template_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_array();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/templates", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_array();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* テンプレート取得(テンプレートコード) — Get Guild Template */
static Value fn_template_get(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/templates/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* テンプレート作成(サーバーID, 名前[, 説明]) — Create Guild Template */
static Value fn_template_create(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("テンプレート作成: サーバーID, 名前が必要です");
        return hajimu_null();
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", argv[1].string.data);
    if (argc >= 3 && argv[2].type == VALUE_STRING)
        jb_str(&sb, "description", argv[2].string.data);
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/templates", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* テンプレート同期(サーバーID, テンプレートコード) — Sync Guild Template */
static Value fn_template_sync(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/templates/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200);
}

/* テンプレート編集(サーバーID, テンプレートコード, 設定) — Modify Guild Template */
static Value fn_template_edit(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_null();
    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/templates/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, argv[2].string.data, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* テンプレート削除(サーバーID, テンプレートコード) — Delete Guild Template */
static Value fn_template_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/templates/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* テンプレートからサーバー作成(テンプレートコード, サーバー名) — Create Guild from Template */
static Value fn_template_use(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("テンプレートからサーバー作成: テンプレートコード, サーバー名が必要です");
        return hajimu_null();
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", argv[1].string.data);
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/templates/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ===========================================
 * オンボーディング設定
 * =========================================== */

/* オンボーディング取得(サーバーID) — Get Guild Onboarding */
static Value fn_onboarding_get(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/onboarding", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* オンボーディング設定(サーバーID, 設定) — Modify Guild Onboarding */
static Value fn_onboarding_edit(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("オンボーディング設定: サーバーID, 設定(JSON)が必要です");
        return hajimu_null();
    }
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/onboarding", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, argv[1].string.data, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ===========================================
 * サウンドボード
 * =========================================== */

/* サウンドボード一覧(サーバーID) — List Guild Soundboard Sounds */
static Value fn_soundboard_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_array();
    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/soundboard-sounds", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_array();
    if (resp && code == 200) {
        JsonNode *items = json_get(resp, "items");
        result = json_to_value(items ? items : resp);
    }
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* サウンドボード取得(サーバーID, サウンドID) — Get Guild Soundboard Sound */
static Value fn_soundboard_get(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_null();
    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/soundboard-sounds/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* サウンドボード作成(サーバーID, 名前, サウンドデータ[, 音量, 絵文字ID]) */
static Value fn_soundboard_create(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING) {
        LOG_E("サウンドボード作成: サーバーID, 名前, base64データが必要です");
        return hajimu_null();
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "name", argv[1].string.data);
    jb_str(&sb, "sound", argv[2].string.data); /* base64 encoded */
    if (argc >= 4 && argv[3].type == VALUE_NUMBER)
        jb_num(&sb, "volume", argv[3].number);
    if (argc >= 5 && argv[4].type == VALUE_STRING)
        jb_str(&sb, "emoji_id", argv[4].string.data);
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/guilds/%s/soundboard-sounds", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* サウンドボード編集(サーバーID, サウンドID, 設定) */
static Value fn_soundboard_edit(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_null();
    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/soundboard-sounds/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", ep, argv[2].string.data, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* サウンドボード削除(サーバーID, サウンドID) */
static Value fn_soundboard_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[160];
    snprintf(ep, sizeof(ep), "/guilds/%s/soundboard-sounds/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* サウンドボード再生(チャンネルID, サウンドID[, ソースサーバーID]) — Send Soundboard Sound */
static Value fn_soundboard_play(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "sound_id", argv[1].string.data);
    if (argc >= 3 && argv[2].type == VALUE_STRING)
        jb_str(&sb, "source_guild_id", argv[2].string.data);
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/channels/%s/send-soundboard-sound",
             argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200 || code == 204);
}

/* デフォルトサウンドボード一覧() — List Default Soundboard Sounds */
static Value fn_soundboard_defaults(int argc, Value *argv) {
    (void)argc; (void)argv;
    long code = 0;
    JsonNode *resp = discord_rest("GET", "/soundboard-default-sounds", NULL, &code);
    Value result = hajimu_array();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ===========================================
 * ロール接続メタデータ (Linked Roles)
 * =========================================== */

/* ロール接続メタデータ取得(アプリケーションID) */
static Value fn_role_connection_meta_get(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_array();
    char ep[128];
    snprintf(ep, sizeof(ep), "/applications/%s/role-connections/metadata",
             argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_array();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ロール接続メタデータ設定(アプリケーションID, メタデータ配列JSON) */
static Value fn_role_connection_meta_set(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        LOG_E("ロール接続メタデータ設定: アプリケーションID, JSON配列が必要です");
        return hajimu_null();
    }
    char ep[128];
    snprintf(ep, sizeof(ep), "/applications/%s/role-connections/metadata",
             argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, argv[1].string.data, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ユーザーロール接続取得(アプリケーションID) — Get User Role Connection */
static Value fn_user_role_connection_get(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/users/@me/applications/%s/role-connection",
             argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ユーザーロール接続更新(アプリケーションID, 設定) — Update User Role Connection */
static Value fn_user_role_connection_set(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_null();
    char ep[128];
    snprintf(ep, sizeof(ep), "/users/@me/applications/%s/role-connection",
             argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PUT", ep, argv[1].string.data, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ===========================================
 * エンタイトルメント / SKU
 * =========================================== */

/* SKU一覧(アプリケーションID) — List SKUs */
static Value fn_sku_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_array();
    char ep[128];
    snprintf(ep, sizeof(ep), "/applications/%s/skus", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_array();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* エンタイトルメント一覧(アプリケーションID) — List Entitlements */
static Value fn_entitlement_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_array();
    char ep[128];
    snprintf(ep, sizeof(ep), "/applications/%s/entitlements", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", ep, NULL, &code);
    Value result = hajimu_array();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* エンタイトルメント消費(アプリケーションID, エンタイトルメントID) — Consume */
static Value fn_entitlement_consume(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[160];
    snprintf(ep, sizeof(ep), "/applications/%s/entitlements/%s/consume",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* テストエンタイトルメント作成(アプリケーションID, SKU_ID, OwnerID, OwnerType) */
static Value fn_entitlement_test_create(int argc, Value *argv) {
    if (argc < 4 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING ||
        argv[3].type != VALUE_NUMBER) {
        LOG_E("テストエンタイトルメント作成: アプリID, SKU_ID, OwnerID, OwnerType(1=guild,2=user)が必要です");
        return hajimu_null();
    }
    StrBuf sb; sb_init(&sb);
    jb_obj_start(&sb);
    jb_str(&sb, "sku_id", argv[1].string.data);
    jb_str(&sb, "owner_id", argv[2].string.data);
    jb_int(&sb, "owner_type", (int64_t)argv[3].number);
    jb_obj_end(&sb);

    char ep[128];
    snprintf(ep, sizeof(ep), "/applications/%s/entitlements", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", ep, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && (code == 200 || code == 201)) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* テストエンタイトルメント削除(アプリケーションID, エンタイトルメントID) */
static Value fn_entitlement_test_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char ep[160];
    snprintf(ep, sizeof(ep), "/applications/%s/entitlements/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", ep, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* ===========================================
 * OAuth2
 * =========================================== */

/* OAuth2トークン交換(クライアントID, クライアントシークレット, コード, リダイレクトURI) */
static Value fn_oauth2_token_exchange(int argc, Value *argv) {
    if (argc < 4 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING || argv[3].type != VALUE_STRING) {
        LOG_E("OAuth2トークン交換: クライアントID, シークレット, コード, リダイレクトURIが必要です");
        return hajimu_null();
    }
    /* OAuth2 token exchange uses application/x-www-form-urlencoded */
    CURL *curl = curl_easy_init();
    if (!curl) return hajimu_null();

    char post_data[2048];
    char *encoded_uri = curl_easy_escape(curl, argv[3].string.data, 0);
    snprintf(post_data, sizeof(post_data),
             "grant_type=authorization_code&code=%s&redirect_uri=%s",
             argv[2].string.data, encoded_uri ? encoded_uri : argv[3].string.data);
    if (encoded_uri) curl_free(encoded_uri);

    char url[] = "https://discord.com/api/v10/oauth2/token";
    CurlBuf resp_buf = {(char *)calloc(1, 4096), 0};

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_USERNAME, argv[0].string.data);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, argv[1].string.data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    Value result = hajimu_null();
    if (res == CURLE_OK && resp_buf.data && resp_buf.len > 0) {
        JsonNode *json = json_parse(resp_buf.data);
        if (json && code == 200) result = json_to_value(json);
        if (json) { json_free(json); free(json); }
    }
    free(resp_buf.data);
    return result;
}

/* OAuth2トークンリフレッシュ(クライアントID, シークレット, リフレッシュトークン) */
static Value fn_oauth2_token_refresh(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING) {
        LOG_E("OAuth2トークンリフレッシュ: クライアントID, シークレット, リフレッシュトークンが必要です");
        return hajimu_null();
    }
    CURL *curl = curl_easy_init();
    if (!curl) return hajimu_null();

    char post_data[1024];
    snprintf(post_data, sizeof(post_data),
             "grant_type=refresh_token&refresh_token=%s", argv[2].string.data);

    char url[] = "https://discord.com/api/v10/oauth2/token";
    CurlBuf resp_buf = {(char *)calloc(1, REST_BUF_INIT), 0};
    if (!resp_buf.data) { curl_easy_cleanup(curl); return hajimu_null(); }

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_USERNAME, argv[0].string.data);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, argv[1].string.data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    Value result = hajimu_null();
    if (res == CURLE_OK && resp_buf.data) {
        JsonNode *json = json_parse(resp_buf.data);
        if (json && code == 200) result = json_to_value(json);
        if (json) { json_free(json); free(json); }
    }
    free(resp_buf.data);
    return result;
}

/* OAuth2トークン無効化(クライアントID, シークレット, トークン) */
static Value fn_oauth2_token_revoke(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);
    CURL *curl = curl_easy_init();
    if (!curl) return hajimu_bool(false);

    char post_data[1024];
    snprintf(post_data, sizeof(post_data), "token=%s", argv[2].string.data);

    char url[] = "https://discord.com/api/v10/oauth2/token/revoke";
    CurlBuf resp_buf = {(char *)calloc(1, REST_BUF_INIT), 0};
    if (!resp_buf.data) { curl_easy_cleanup(curl); return hajimu_bool(false); }

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_USERNAME, argv[0].string.data);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, argv[1].string.data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    free(resp_buf.data);
    return hajimu_bool(res == CURLE_OK && code == 200);
}

/* OAuth2自分情報() — GET /oauth2/@me */
static Value fn_oauth2_me(int argc, Value *argv) {
    (void)argc; (void)argv;
    long code = 0;
    JsonNode *resp = discord_rest("GET", "/oauth2/@me", NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* OAuth2認可URL生成(クライアントID, リダイレクトURI, スコープ配列) */
static Value fn_oauth2_auth_url(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_ARRAY) {
        LOG_E("OAuth2認可URL生成: クライアントID, リダイレクトURI, スコープ配列が必要です");
        return hajimu_string("");
    }
    StrBuf sb; sb_init(&sb);
    sb_append(&sb, "https://discord.com/oauth2/authorize?client_id=");
    sb_append(&sb, argv[0].string.data);
    sb_append(&sb, "&redirect_uri=");

    CURL *curl = curl_easy_init();
    if (curl) {
        char *encoded = curl_easy_escape(curl, argv[1].string.data, 0);
        if (encoded) { sb_append(&sb, encoded); curl_free(encoded); }
        else sb_append(&sb, argv[1].string.data);
        curl_easy_cleanup(curl);
    }

    sb_append(&sb, "&response_type=code&scope=");
    for (int i = 0; i < argv[2].array.length; i++) {
        if (argv[2].array.elements[i].type == VALUE_STRING) {
            if (i > 0) sb_append(&sb, "%20");
            sb_append(&sb, argv[2].array.elements[i].string.data);
        }
    }
    Value r = hajimu_string(sb.data);
    sb_free(&sb);
    return r;
}

/* ===========================================
 * シャーディング
 * =========================================== */

/* シャード設定(シャードID, シャード数) — Configure sharding for IDENTIFY */
static Value fn_shard_set(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_NUMBER) {
        LOG_E("シャード設定: シャードID(数値), シャード数(数値)が必要です");
        return hajimu_bool(false);
    }
    g_bot.shard_id = (int)argv[0].number;
    g_bot.shard_count = (int)argv[1].number;
    if (g_bot.shard_id < 0 || g_bot.shard_count <= 0 || g_bot.shard_id >= g_bot.shard_count) {
        LOG_E("シャード設定: 無効な値です (shard_id=%d, shard_count=%d). "
              "shard_id >= 0 かつ shard_id < shard_count が必要です",
              g_bot.shard_id, g_bot.shard_count);
        g_bot.shard_id = 0;
        g_bot.shard_count = 1;
        return hajimu_bool(false);
    }
    g_bot.sharding_enabled = true;
    LOG_I("シャード設定: shard_id=%d, shard_count=%d",
          g_bot.shard_id, g_bot.shard_count);
    return hajimu_bool(true);
}

/* シャード情報() — Get Gateway Bot (recommended shards) */
static Value fn_shard_info(int argc, Value *argv) {
    (void)argc; (void)argv;
    long code = 0;
    JsonNode *resp = discord_rest("GET", "/gateway/bot", NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* シャードID計算(サーバーID, シャード数) — (guild_id >> 22) % num_shards */
static Value fn_shard_id_for(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_NUMBER)
        return hajimu_number(0);
    uint64_t guild_id = (uint64_t)strtoull(argv[0].string.data, NULL, 10);
    int num_shards = (int)argv[1].number;
    if (num_shards <= 0) num_shards = 1;
    int shard = (int)((guild_id >> 22) % (uint64_t)num_shards);
    return hajimu_number(shard);
}

/* =========================================================================
 * Section 14.5: v2.3.0 — 互換性強化 (discord.js/discord.py 機能対応)
 * ========================================================================= */

/* --- Auto-populated Select Menus (User/Role/Channel/Mentionable) --- */

/* ユーザーセレクト作成(カスタムID [, プレースホルダー]) */
static Value fn_user_select_create(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    StrBuf sb; sb_init(&sb);
    sb_append(&sb, "{\"type\":5,\"custom_id\":\"");
    sb_append(&sb, argv[0].string.data);
    sb_append(&sb, "\"");
    if (argc >= 2 && argv[1].type == VALUE_STRING) {
        sb_append(&sb, ",\"placeholder\":\"");
        sb_append(&sb, argv[1].string.data);
        sb_append(&sb, "\"");
    }
    sb_append(&sb, "}");
    Value result = hajimu_string(sb.data);
    sb_free(&sb);
    return result;
}

/* ロールセレクト作成(カスタムID [, プレースホルダー]) */
static Value fn_role_select_create(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    StrBuf sb; sb_init(&sb);
    sb_append(&sb, "{\"type\":6,\"custom_id\":\"");
    sb_append(&sb, argv[0].string.data);
    sb_append(&sb, "\"");
    if (argc >= 2 && argv[1].type == VALUE_STRING) {
        sb_append(&sb, ",\"placeholder\":\"");
        sb_append(&sb, argv[1].string.data);
        sb_append(&sb, "\"");
    }
    sb_append(&sb, "}");
    Value result = hajimu_string(sb.data);
    sb_free(&sb);
    return result;
}

/* チャンネルセレクト作成(カスタムID [, プレースホルダー]) */
static Value fn_channel_select_create(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    StrBuf sb; sb_init(&sb);
    sb_append(&sb, "{\"type\":8,\"custom_id\":\"");
    sb_append(&sb, argv[0].string.data);
    sb_append(&sb, "\"");
    if (argc >= 2 && argv[1].type == VALUE_STRING) {
        sb_append(&sb, ",\"placeholder\":\"");
        sb_append(&sb, argv[1].string.data);
        sb_append(&sb, "\"");
    }
    sb_append(&sb, "}");
    Value result = hajimu_string(sb.data);
    sb_free(&sb);
    return result;
}

/* メンション可能セレクト作成(カスタムID [, プレースホルダー]) */
static Value fn_mentionable_select_create(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    StrBuf sb; sb_init(&sb);
    sb_append(&sb, "{\"type\":7,\"custom_id\":\"");
    sb_append(&sb, argv[0].string.data);
    sb_append(&sb, "\"");
    if (argc >= 2 && argv[1].type == VALUE_STRING) {
        sb_append(&sb, ",\"placeholder\":\"");
        sb_append(&sb, argv[1].string.data);
        sb_append(&sb, "\"");
    }
    sb_append(&sb, "}");
    Value result = hajimu_string(sb.data);
    sb_free(&sb);
    return result;
}

/* --- BAN管理拡張 --- */

/* BAN一覧(サーバーID [, 上限]) */
static Value fn_ban_list(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char endpoint[256];
    if (argc >= 2 && argv[1].type == VALUE_NUMBER) {
        snprintf(endpoint, sizeof(endpoint), "/guilds/%s/bans?limit=%d",
                 argv[0].string.data, (int)argv[1].number);
    } else {
        snprintf(endpoint, sizeof(endpoint), "/guilds/%s/bans", argv[0].string.data);
    }
    long code = 0;
    JsonNode *resp = discord_rest("GET", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* BAN一括(サーバーID, ユーザーID配列 [, 削除秒数]) */
static Value fn_bulk_ban(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_ARRAY)
        return hajimu_null();
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/bulk-ban", argv[0].string.data);
    StrBuf sb; sb_init(&sb);
    sb_append(&sb, "{\"user_ids\":[");
    for (int i = 0; i < argv[1].array.length; i++) {
        if (i > 0) sb_append_char(&sb, ',');
        if (argv[1].array.elements[i].type == VALUE_STRING) {
            sb_append_char(&sb, '"');
            sb_append(&sb, argv[1].array.elements[i].string.data);
            sb_append_char(&sb, '"');
        }
    }
    sb_append(&sb, "]");
    if (argc >= 3 && argv[2].type == VALUE_NUMBER) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), ",\"delete_message_seconds\":%d", (int)argv[2].number);
        sb_append(&sb, tmp);
    }
    sb_append(&sb, "}");
    long code = 0;
    JsonNode *resp = discord_rest("POST", endpoint, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- メンバー管理拡張 --- */

/* メンバー編集(サーバーID, ユーザーID, 変更内容) */
static Value fn_member_edit(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING) return hajimu_bool(false);
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", endpoint, argv[2].string.data, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code >= 200 && code < 300);
}

/* ニックネーム変更(サーバーID, ニックネーム) */
static Value fn_nick_change(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/@me", argv[0].string.data);
    StrBuf sb; sb_init(&sb);
    sb_append(&sb, "{\"nick\":\"");
    StrBuf esc; sb_init(&esc);
    json_escape_str(&esc, argv[1].string.data);
    sb_append(&sb, esc.data);
    sb_free(&esc);
    sb_append(&sb, "\"}");
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", endpoint, sb.data, &code);
    sb_free(&sb);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code >= 200 && code < 300);
}

/* --- Webhook拡張 --- */

/* Webhook編集(WebhookID, 変更内容JSON) */
static Value fn_webhook_edit(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_null();
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "/webhooks/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", endpoint, argv[1].string.data, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* Webhook情報(WebhookID) */
static Value fn_webhook_info(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "/webhooks/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- スレッド拡張 --- */

/* アクティブスレッド一覧(サーバーID) */
static Value fn_active_threads(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/threads/active", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* アーカイブスレッド一覧(チャンネルID [, "public"/"private"]) */
static Value fn_archived_threads(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    const char *kind = "public";
    if (argc >= 2 && argv[1].type == VALUE_STRING) kind = argv[1].string.data;
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/threads/archived/%s",
             argv[0].string.data, kind);
    long code = 0;
    JsonNode *resp = discord_rest("GET", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- アナウンスチャンネル対応 --- */

/* クロスポスト(チャンネルID, メッセージID) */
static Value fn_crosspost(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_null();
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages/%s/crosspost",
             argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("POST", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* チャンネルフォロー(ソースチャンネルID, ターゲットチャンネルID) */
static Value fn_channel_follow(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_null();
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/followers", argv[0].string.data);
    StrBuf sb; sb_init(&sb);
    sb_append(&sb, "{\"webhook_channel_id\":\"");
    sb_append(&sb, argv[1].string.data);
    sb_append(&sb, "\"}");
    long code = 0;
    JsonNode *resp = discord_rest("POST", endpoint, sb.data, &code);
    sb_free(&sb);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- サーバー管理拡張 --- */

/* プルーン確認(サーバーID [, 日数]) */
static Value fn_prune_count(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    int days = 7;
    if (argc >= 2 && argv[1].type == VALUE_NUMBER) days = (int)argv[1].number;
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/prune?days=%d",
             argv[0].string.data, days);
    long code = 0;
    JsonNode *resp = discord_rest("GET", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* プルーン実行(サーバーID [, 日数]) */
static Value fn_prune(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    int days = 7;
    if (argc >= 2 && argv[1].type == VALUE_NUMBER) days = (int)argv[1].number;
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/prune", argv[0].string.data);
    char body[64];
    snprintf(body, sizeof(body), "{\"days\":%d}", days);
    long code = 0;
    JsonNode *resp = discord_rest("POST", endpoint, body, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* サーバー削除(サーバーID) — ボットがオーナーの場合のみ */
static Value fn_guild_delete(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", endpoint, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* サーバープレビュー(サーバーID) */
static Value fn_guild_preview(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/preview", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ウィジェット設定取得(サーバーID) */
static Value fn_widget_settings_get(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/widget", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ウィジェット設定更新(サーバーID, 設定JSON) */
static Value fn_widget_settings_edit(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/widget", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", endpoint, argv[1].string.data, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200);
}

/* バニティURL取得(サーバーID) */
static Value fn_vanity_url(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/vanity-url", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("GET", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* Voice地域一覧() */
static Value fn_voice_regions(int argc, Value *argv) {
    (void)argc; (void)argv;
    long code = 0;
    JsonNode *resp = discord_rest("GET", "/voice/regions", NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* --- ユーティリティ拡張 --- */

/* Snowflakeタイムスタンプ(ID) — Discord ID → Unix timestamp (ms) */
static Value fn_snowflake_timestamp(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_number(0);
    uint64_t id = (uint64_t)strtoull(argv[0].string.data, NULL, 10);
    /* Discord epoch: 2015-01-01T00:00:00Z = 1420070400000 ms */
    uint64_t timestamp_ms = (id >> 22) + 1420070400000ULL;
    return hajimu_number((double)timestamp_ms);
}

/* 権限値(権限名) — Discord permission name → bit value */
static Value fn_permission_value(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_number(0);
    const char *name = argv[0].string.data;
    /* Discord Permissions - comprehensive list */
    static const struct { const char *name; uint64_t value; } perms[] = {
        {"CREATE_INSTANT_INVITE", 1ULL << 0},
        {"KICK_MEMBERS",          1ULL << 1},
        {"BAN_MEMBERS",           1ULL << 2},
        {"ADMINISTRATOR",         1ULL << 3},
        {"MANAGE_CHANNELS",       1ULL << 4},
        {"MANAGE_GUILD",          1ULL << 5},
        {"ADD_REACTIONS",         1ULL << 6},
        {"VIEW_AUDIT_LOG",        1ULL << 7},
        {"PRIORITY_SPEAKER",      1ULL << 8},
        {"STREAM",                1ULL << 9},
        {"VIEW_CHANNEL",          1ULL << 10},
        {"SEND_MESSAGES",         1ULL << 11},
        {"SEND_TTS_MESSAGES",     1ULL << 12},
        {"MANAGE_MESSAGES",       1ULL << 13},
        {"EMBED_LINKS",           1ULL << 14},
        {"ATTACH_FILES",          1ULL << 15},
        {"READ_MESSAGE_HISTORY",  1ULL << 16},
        {"MENTION_EVERYONE",      1ULL << 17},
        {"USE_EXTERNAL_EMOJIS",   1ULL << 18},
        {"VIEW_GUILD_INSIGHTS",   1ULL << 19},
        {"CONNECT",               1ULL << 20},
        {"SPEAK",                 1ULL << 21},
        {"MUTE_MEMBERS",          1ULL << 22},
        {"DEAFEN_MEMBERS",        1ULL << 23},
        {"MOVE_MEMBERS",          1ULL << 24},
        {"USE_VAD",               1ULL << 25},
        {"CHANGE_NICKNAME",       1ULL << 26},
        {"MANAGE_NICKNAMES",      1ULL << 27},
        {"MANAGE_ROLES",          1ULL << 28},
        {"MANAGE_WEBHOOKS",       1ULL << 29},
        {"MANAGE_EMOJIS_AND_STICKERS", 1ULL << 30},
        {"USE_APPLICATION_COMMANDS", 1ULL << 31},
        {"REQUEST_TO_SPEAK",      1ULL << 32},
        {"MANAGE_EVENTS",         1ULL << 33},
        {"MANAGE_THREADS",        1ULL << 34},
        {"CREATE_PUBLIC_THREADS",  1ULL << 35},
        {"CREATE_PRIVATE_THREADS", 1ULL << 36},
        {"USE_EXTERNAL_STICKERS", 1ULL << 37},
        {"SEND_MESSAGES_IN_THREADS", 1ULL << 38},
        {"USE_EMBEDDED_ACTIVITIES", 1ULL << 39},
        {"MODERATE_MEMBERS",      1ULL << 40},
        {"VIEW_CREATOR_MONETIZATION_ANALYTICS", 1ULL << 41},
        {"USE_SOUNDBOARD",        1ULL << 42},
        {"USE_EXTERNAL_SOUNDS",   1ULL << 45},
        {"SEND_VOICE_MESSAGES",   1ULL << 46},
        {"SEND_POLLS",            1ULL << 49},
        /* 日本語エイリアス */
        {"招待作成",              1ULL << 0},
        {"メンバーキック",        1ULL << 1},
        {"メンバーBAN",           1ULL << 2},
        {"管理者",                1ULL << 3},
        {"チャンネル管理",        1ULL << 4},
        {"サーバー管理",          1ULL << 5},
        {"リアクション追加",      1ULL << 6},
        {"監査ログ表示",          1ULL << 7},
        {"チャンネル表示",        1ULL << 10},
        {"メッセージ送信",        1ULL << 11},
        {"メッセージ管理",        1ULL << 13},
        {"メッセージ履歴読取",    1ULL << 16},
        {"全員メンション",        1ULL << 17},
        {"接続",                  1ULL << 20},
        {"発言",                  1ULL << 21},
        {"ミュート",              1ULL << 22},
        {"スピーカーミュート",    1ULL << 23},
        {"メンバー移動",          1ULL << 24},
        {"ニックネーム変更",      1ULL << 26},
        {"ロール管理",            1ULL << 28},
        {"Webhook管理",           1ULL << 29},
        {"スレッド管理",          1ULL << 34},
        {"モデレート",            1ULL << 40},
        {NULL, 0}
    };
    for (int i = 0; perms[i].name; i++) {
        if (strcmp(name, perms[i].name) == 0)
            return hajimu_number((double)perms[i].value);
    }
    return hajimu_number(0);
}

/* 権限チェック(権限値, チェック対象) — ビット演算 */
static Value fn_permission_check(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER || argv[1].type != VALUE_NUMBER)
        return hajimu_bool(false);
    uint64_t perms = (uint64_t)argv[0].number;
    uint64_t check = (uint64_t)argv[1].number;
    /* ADMINISTRATOR = 0x8 has all permissions */
    if (perms & (1ULL << 3)) return hajimu_bool(true);
    return hajimu_bool((perms & check) == check);
}

/* アプリ情報() — Current application info */
static Value fn_app_info(int argc, Value *argv) {
    (void)argc; (void)argv;
    long code = 0;
    JsonNode *resp = discord_rest("GET", "/applications/@me", NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ステッカーパック一覧() — List Sticker Packs (Nitro) */
static Value fn_sticker_packs(int argc, Value *argv) {
    (void)argc; (void)argv;
    long code = 0;
    JsonNode *resp = discord_rest("GET", "/sticker-packs", NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* ────────────────────────────────────────────────────
 * .env ファイル読み込み
 * ──────────────────────────────────────────────────── */

/* env値の内部ストレージ (最大256エントリ) */
#define ENV_MAX 256
static struct {
    char key[128];
    char value[1024];
} g_env_entries[ENV_MAX];
static int g_env_count = 0;

/* 内部: .env の1行をパースして setenv + 内部テーブルに格納 */
static void env_parse_line(const char *line) {
    /* 空行・コメント行をスキップ */
    while (*line == ' ' || *line == '\t') line++;
    if (*line == '\0' || *line == '#' || *line == '\n') return;

    /* KEY=VALUE を分離 */
    const char *eq = strchr(line, '=');
    if (!eq) return;

    /* KEY を取得 (前後の空白を除去) */
    size_t klen = (size_t)(eq - line);
    while (klen > 0 && (line[klen-1] == ' ' || line[klen-1] == '\t')) klen--;
    if (klen == 0 || klen >= 128) return;

    char key[128];
    memcpy(key, line, klen);
    key[klen] = '\0';

    /* VALUE を取得 (先頭の空白とクォートを除去) */
    const char *vstart = eq + 1;
    while (*vstart == ' ' || *vstart == '\t') vstart++;

    char value[1024];
    size_t vlen = strlen(vstart);

    /* 末尾の改行・空白を除去 */
    while (vlen > 0 && (vstart[vlen-1] == '\n' || vstart[vlen-1] == '\r'
                        || vstart[vlen-1] == ' ' || vstart[vlen-1] == '\t'))
        vlen--;

    /* クォート (' or ") の除去 */
    if (vlen >= 2 &&
        ((vstart[0] == '"' && vstart[vlen-1] == '"') ||
         (vstart[0] == '\'' && vstart[vlen-1] == '\''))) {
        vstart++;
        vlen -= 2;
    }
    if (vlen >= sizeof(value)) vlen = sizeof(value) - 1;
    memcpy(value, vstart, vlen);
    value[vlen] = '\0';

    /* 環境変数にセット (既存なら上書きしない: overwrite=0) */
    setenv(key, value, 0);

    /* 内部テーブルに保存 */
    if (g_env_count < ENV_MAX) {
        strncpy(g_env_entries[g_env_count].key, key, 127);
        g_env_entries[g_env_count].key[127] = '\0';
        strncpy(g_env_entries[g_env_count].value, value, 1023);
        g_env_entries[g_env_count].value[1023] = '\0';
        g_env_count++;
    }
}

/* env読み込み([ファイルパス]) — .env を読み込んで環境変数に設定 */
static Value fn_env_load(int argc, Value *argv) {
    const char *path = ".env";
    if (argc >= 1 && argv[0].type == VALUE_STRING)
        path = argv[0].string.data;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[hajimu_discord] .env ファイルが見つかりません: %s\n", path);
        return hajimu_bool(false);
    }

    char line[2048];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        int before = g_env_count;
        env_parse_line(line);
        if (g_env_count > before) count++;
    }
    fclose(fp);

    if (g_bot.log_level >= 1)
        fprintf(stderr, "[hajimu_discord] .env 読み込み完了: %s (%d 件)\n", path, count);

    return hajimu_bool(true);
}

/* env取得(キー[, デフォルト値]) — 環境変数を取得 */
static Value fn_env_get(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_null();

    const char *val = getenv(argv[0].string.data);
    if (val) return hajimu_string(val);

    /* デフォルト値 */
    if (argc >= 2 && argv[1].type == VALUE_STRING)
        return hajimu_string(argv[1].string.data);

    return hajimu_null();
}

/* チャンネル位置変更(サーバーID, 変更内容JSON配列) */
static Value fn_channel_position(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/channels", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", endpoint, argv[1].string.data, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* ロール位置変更(サーバーID, 変更内容JSON配列) */
static Value fn_role_position(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING)
        return hajimu_null();
    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/roles", argv[0].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", endpoint, argv[1].string.data, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* リアクションユーザー一覧(チャンネルID, メッセージID, 絵文字 [, 上限]) */
static Value fn_reaction_users(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING) return hajimu_null();
    char endpoint[512];
    int limit = 25;
    if (argc >= 4 && argv[3].type == VALUE_NUMBER) limit = (int)argv[3].number;
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages/%s/reactions/%s?limit=%d",
             argv[0].string.data, argv[1].string.data, argv[2].string.data, limit);
    long code = 0;
    JsonNode *resp = discord_rest("GET", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* メッセージリアクション全種削除(チャンネルID, メッセージID, 絵文字) — 特定絵文字のリアクションを全削除 */
static Value fn_remove_emoji_reactions(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING) return hajimu_bool(false);
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages/%s/reactions/%s",
             argv[0].string.data, argv[1].string.data, argv[2].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", endpoint, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* スレッドアーカイブ(チャンネルID, アーカイブするか) */
static Value fn_thread_archive(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s", argv[0].string.data);
    bool archive = true;
    if (argv[1].type == VALUE_BOOL) archive = argv[1].boolean;
    else if (argv[1].type == VALUE_NUMBER) archive = (int)argv[1].number != 0;
    char body[64];
    snprintf(body, sizeof(body), "{\"archived\":%s}", archive ? "true" : "false");
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", endpoint, body, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200);
}

/* スレッドロック(チャンネルID, ロックするか) */
static Value fn_thread_lock(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s", argv[0].string.data);
    bool lock = true;
    if (argv[1].type == VALUE_BOOL) lock = argv[1].boolean;
    else if (argv[1].type == VALUE_NUMBER) lock = (int)argv[1].number != 0;
    char body[64];
    snprintf(body, sizeof(body), "{\"locked\":%s}", lock ? "true" : "false");
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", endpoint, body, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200);
}

/* スレッドピン(チャンネルID, ピンするか) */
static Value fn_thread_pin(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s", argv[0].string.data);
    bool pin = true;
    if (argv[1].type == VALUE_BOOL) pin = argv[1].boolean;
    else if (argv[1].type == VALUE_NUMBER) pin = (int)argv[1].number != 0;
    char body[64];
    /* flags bit 1 = PINNED */
    snprintf(body, sizeof(body), "{\"flags\":%d}", pin ? 2 : 0);
    long code = 0;
    JsonNode *resp = discord_rest("PATCH", endpoint, body, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200);
}

/* コマンド削除(コマンドID [, サーバーID]) — Delete application command */
static Value fn_command_delete(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    char endpoint[256];
    if (argc >= 2 && argv[1].type == VALUE_STRING) {
        snprintf(endpoint, sizeof(endpoint), "/applications/%s/guilds/%s/commands/%s",
                 g_bot.application_id, argv[1].string.data, argv[0].string.data);
    } else {
        snprintf(endpoint, sizeof(endpoint), "/applications/%s/commands/%s",
                 g_bot.application_id, argv[0].string.data);
    }
    long code = 0;
    JsonNode *resp = discord_rest("DELETE", endpoint, NULL, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 204);
}

/* コマンド一覧([サーバーID]) — List application commands */
static Value fn_command_list(int argc, Value *argv) {
    char endpoint[256];
    if (argc >= 1 && argv[0].type == VALUE_STRING) {
        snprintf(endpoint, sizeof(endpoint), "/applications/%s/guilds/%s/commands",
                 g_bot.application_id, argv[0].string.data);
    } else {
        snprintf(endpoint, sizeof(endpoint), "/applications/%s/commands", g_bot.application_id);
    }
    long code = 0;
    JsonNode *resp = discord_rest("GET", endpoint, NULL, &code);
    Value result = hajimu_null();
    if (resp && code == 200) result = json_to_value(resp);
    if (resp) { json_free(resp); free(resp); }
    return result;
}

/* コマンド権限設定(サーバーID, コマンドID, 権限配列JSON) */
static Value fn_command_permissions(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING) return hajimu_bool(false);
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint),
             "/applications/%s/guilds/%s/commands/%s/permissions",
             g_bot.application_id, argv[0].string.data, argv[1].string.data);
    long code = 0;
    JsonNode *resp = discord_rest("PUT", endpoint, argv[2].string.data, &code);
    if (resp) { json_free(resp); free(resp); }
    return hajimu_bool(code == 200);
}

/* Webhook編集メッセージ(WebhookID, トークン, MessageID, 内容) */
static Value fn_webhook_edit_message(int argc, Value *argv) {
    if (argc < 4 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING || argv[3].type != VALUE_STRING)
        return hajimu_null();
    char url[512];
    snprintf(url, sizeof(url), "%s/webhooks/%s/%s/messages/%s",
             DISCORD_API_BASE, argv[0].string.data, argv[1].string.data, argv[2].string.data);
    /* Use direct curl since this doesn't use bot auth */
    CURL *curl = curl_easy_init();
    if (!curl) return hajimu_null();
    CurlBuf resp = {(char *)calloc(1, REST_BUF_INIT), 0};
    if (!resp.data) { curl_easy_cleanup(curl); return hajimu_null(); }
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, argv[3].string.data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    Value result = hajimu_null();
    if (code == 200 && resp.data) {
        JsonNode *j = json_parse(resp.data);
        if (j) { result = json_to_value(j); json_free(j); free(j); }
    }
    free(resp.data);
    return result;
}

/* Webhook削除メッセージ(WebhookID, トークン, MessageID) */
static Value fn_webhook_delete_message(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_STRING) return hajimu_bool(false);
    char url[512];
    snprintf(url, sizeof(url), "%s/webhooks/%s/%s/messages/%s",
             DISCORD_API_BASE, argv[0].string.data, argv[1].string.data, argv[2].string.data);
    CURL *curl = curl_easy_init();
    if (!curl) return hajimu_bool(false);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    return hajimu_bool(code == 204);
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
    {"エラー時",             fn_on_error,          1,  1},
    {"切断時",               fn_on_disconnect,     1,  1},
    {"再接続時",             fn_on_reconnect,      1,  1},

    /* メッセージ */
    {"メッセージ送信",       fn_send_message,      2,  2},
    {"返信",                 fn_reply,             2,  2},
    {"メッセージ編集",       fn_edit_message,      3,  3},
    {"メッセージ削除",       fn_delete_message,    2,  2},
    {"一括削除",             fn_bulk_delete,       2,  2},
    {"メッセージ取得",       fn_get_message,       2,  2},
    {"メッセージ履歴",       fn_message_history,   2,  2},
    {"メッセージ一括削除",   fn_bulk_delete_count, 2,  2},

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
    {"コマンド応答",         fn_command_respond,   2,  3},
    {"コマンド遅延応答",     fn_command_defer,     1,  1},
    {"コマンドフォローアップ", fn_command_followup, 2,  2},

    /* コンポーネント (v1.2.0) */
    {"ボタン作成",           fn_button_create,     3,  3},
    {"リンクボタン作成",     fn_link_button_create, 2, 2},
    {"ボタン無効化",         fn_button_disable,    2,  2},
    {"アクション行作成",     fn_action_row_create, 0,  0},
    {"行にボタン追加",       fn_row_add_button,    2,  2},
    {"行にメニュー追加",     fn_row_add_menu,      2,  2},
    {"コンポーネント送信",   fn_component_send,    3,  3},
    {"セレクトメニュー作成", fn_select_menu_create, 2, 2},
    {"メニュー選択肢",       fn_menu_add_option,   3,  4},
    {"ボタン時",             fn_on_button,         2,  2},
    {"セレクト時",           fn_on_select,         2,  2},
    {"インタラクション更新", fn_interaction_update, 2, 2},
    {"インタラクション遅延更新", fn_interaction_defer_update, 1, 1},

    /* モーダル (v1.3.0) */
    {"モーダル作成",         fn_modal_create,      2,  2},
    {"テキスト入力追加",     fn_modal_add_text_input, 4, 4},
    {"モーダル表示",         fn_modal_show,        2,  2},
    {"モーダル送信時",       fn_on_modal_submit,   2,  2},

    /* サブコマンド (v1.3.0) */
    {"サブコマンド追加",     fn_subcommand_add,    4,  4},
    {"サブコマンドグループ追加", fn_subcommand_group_add, 3, 3},

    /* オートコンプリート (v1.3.0) */
    {"オートコンプリート時", fn_on_autocomplete,   2,  2},
    {"オートコンプリート応答", fn_autocomplete_respond, 2, 2},

    /* コンテキストメニュー (v1.3.0) */
    {"ユーザーメニュー登録", fn_user_context_menu, 2,  2},
    {"メッセージメニュー登録", fn_message_context_menu, 2, 2},
    {"コマンド選択肢",       fn_command_choice,    4,  4},

    /* チャンネル */
    {"チャンネル情報",       fn_channel_info,      1,  1},
    {"チャンネル一覧",       fn_channel_list,      1,  1},
    {"タイピング表示",       fn_typing,            1,  1},
    {"チャンネル作成",       fn_channel_create,    3,  4},
    {"チャンネル編集",       fn_channel_edit,      2,  2},
    {"チャンネル削除",       fn_channel_delete,    1,  1},

    /* スレッド (v1.4.0) */
    {"スレッド作成",           fn_thread_create,     2,  3},
    {"スレッド参加",           fn_thread_join,       1,  1},
    {"スレッド退出",           fn_thread_leave,      1,  1},
    {"スレッドメンバー追加", fn_thread_add_member, 2, 2},
    {"スレッドメンバー削除", fn_thread_remove_member, 2, 2},

    /* 権限 (v1.4.0) */
    {"権限設定",           fn_permission_overwrite, 4, 5},

    /* 招待 (v1.4.0) */
    {"招待作成",           fn_invite_create,     1,  2},
    {"招待一覧",           fn_invite_list,       1,  1},
    {"招待削除",           fn_invite_delete,     1,  1},
    {"招待情報",           fn_invite_info,       1,  1},

    /* Webhook (v1.5.0) */
    {"Webhook作成",         fn_webhook_create,    2,  2},
    {"Webhook一覧",         fn_webhook_list,      1,  1},
    {"Webhook削除",         fn_webhook_delete,    1,  1},
    {"Webhook送信",         fn_webhook_send,      2,  4},

    /* ファイル (v1.5.0) */
    {"ファイル送信",           fn_send_file,         2,  3},

    /* コレクター (v1.6.0) */
    {"メッセージ収集",       fn_message_collector,  3,  4},
    {"リアクション収集",   fn_reaction_collector, 3,  4},
    {"インタラクション収集", fn_interaction_collector, 3, 4},

    /* メンバー (v1.6.0) */
    {"メンバー一覧",         fn_member_list,       1,  2},
    {"メンバー検索",         fn_member_search,     2,  3},

    /* サーバー一覧 (v1.6.0) */
    {"サーバー一覧",         fn_guild_list,        0,  0},

    /* v1.7.0: 監査ログ・AutoMod・絵文字・イベント・投票 */
    {"監査ログ",             fn_audit_log,         1,  3},
    {"AutoModルール一覧",    fn_automod_list,      1,  1},
    {"AutoModルール取得",    fn_automod_get,       2,  2},
    {"AutoModルール作成",    fn_automod_create,    2,  2},
    {"AutoModルール編集",    fn_automod_edit,      3,  3},
    {"AutoModルール削除",    fn_automod_delete,    2,  2},
    {"AutoMod実行時",        fn_automod_on_action, 1,  1},
    {"絵文字一覧",           fn_emoji_list,        1,  1},
    {"絵文字作成",           fn_emoji_create,      3,  3},
    {"絵文字削除",           fn_emoji_delete,      2,  2},
    {"イベント作成",         fn_event_create,      4,  5},
    {"イベント編集",         fn_event_edit,        3,  3},
    {"イベント削除",         fn_event_delete,      2,  2},
    {"イベント一覧",         fn_event_list,        1,  1},
    {"投票作成",             fn_poll_create,       4,  5},
    {"投票終了",             fn_poll_end,          2,  2},

    /* ボイスチャンネル (v2.0.0) */
    {"ユーザーボイスチャンネル", fn_get_user_voice_channel, 2, 2},
    {"VC接続",               fn_vc_join,           2,  2},
    {"VC切断",               fn_vc_leave,          1,  1},
    {"音声再生",             fn_voice_play,        2,  2},
    {"音声停止",             fn_voice_stop,        1,  1},
    {"音声一時停止",         fn_voice_pause,       1,  1},
    {"音声再開",             fn_voice_resume,      1,  1},
    {"音声スキップ",         fn_voice_skip,        1,  1},
    {"音声キュー",           fn_voice_queue,       1,  1},
    {"音声ループ",           fn_voice_loop,        2,  2},
    {"VC状態",               fn_vc_status,         1,  1},
    {"音声音量",             fn_voice_volume,      2,  2},

    /* YouTube / yt-dlp (v2.4.0+) */
    {"YouTube情報",          fn_ytdlp_info,        1,  1},
    {"YouTube検索",          fn_ytdlp_search,      1,  2},
    {"YouTubeタイトル",      fn_ytdlp_title,       1,  1},
    {"YouTubeクッキー設定",  fn_ytdlp_set_cookies, 1,  1},

    /* ステージチャンネル (v2.1.0) */
    {"ステージ開始",         fn_stage_start,       2,  3},
    {"ステージ編集",         fn_stage_edit,        2,  2},
    {"ステージ終了",         fn_stage_end,         1,  1},
    {"ステージ情報",         fn_stage_info,        1,  1},

    /* スタンプ管理 (v2.1.0) */
    {"スタンプ一覧",         fn_sticker_list,      1,  1},
    {"スタンプ取得",         fn_sticker_get,       2,  2},
    {"スタンプ作成",         fn_sticker_create,    3,  5},
    {"スタンプ編集",         fn_sticker_edit,      3,  3},
    {"スタンプ削除",         fn_sticker_delete,    2,  2},

    /* ウェルカム画面 (v2.1.0) */
    {"ウェルカム画面取得",   fn_welcome_screen_get,  1,  1},
    {"ウェルカム画面編集",   fn_welcome_screen_edit, 2,  2},

    /* サーバー・ロール管理 (v2.1.0) */
    {"サーバー編集",         fn_guild_edit,        2,  2},
    {"ロール作成",           fn_role_create,       2,  4},
    {"ロール編集",           fn_role_edit,         3,  3},
    {"ロール削除",           fn_role_delete,       2,  2},

    /* フォーラムチャンネル (v2.1.0) */
    {"フォーラム投稿",       fn_forum_post,        3,  4},
    {"フォーラムタグ一覧",   fn_forum_tags,        1,  1},

    /* Markdownユーティリティ (v2.1.0) */
    {"太字",                 fn_md_bold,           1,  1},
    {"斜体",                 fn_md_italic,         1,  1},
    {"下線",                 fn_md_underline,      1,  1},
    {"取り消し線",           fn_md_strikethrough,  1,  1},
    {"コード",               fn_md_code,           1,  1},
    {"コードブロック",       fn_md_codeblock,      1,  2},
    {"引用",                 fn_md_quote,          1,  1},
    {"スポイラー",           fn_md_spoiler,        1,  1},
    {"ユーザーメンション",   fn_md_mention_user,   1,  1},
    {"チャンネルメンション", fn_md_mention_channel, 1, 1},
    {"ロールメンション",     fn_md_mention_role,   1,  1},
    {"タイムスタンプ",       fn_md_timestamp,      1,  2},
    {"カスタム絵文字",       fn_md_emoji,          2,  3},
    {"リンク",               fn_md_link,           2,  2},
    {"見出し",               fn_md_heading,        2,  2},
    {"リスト",               fn_md_list,           1,  2},

    /* Components V2 (v2.2.0) */
    {"テキスト表示",         fn_comp_text_display, 2,  2},
    {"セパレーター",         fn_comp_separator,    1,  3},
    {"メディアギャラリー",   fn_comp_media_gallery, 2, 2},
    {"メディアアイテム",     fn_comp_media_item,   1,  2},
    {"サムネイル",           fn_comp_thumbnail,    2,  3},
    {"セクション",           fn_comp_section,      2,  3},
    {"コンテナ",             fn_comp_container,    2,  4},
    {"ファイル表示",         fn_comp_file,         2,  2},
    {"V2メッセージ送信",     fn_send_components_v2, 2, 2},

    /* サーバーテンプレート (v2.2.0) */
    {"テンプレート一覧",     fn_template_list,     1,  1},
    {"テンプレート取得",     fn_template_get,      1,  1},
    {"テンプレート作成",     fn_template_create,   2,  3},
    {"テンプレート同期",     fn_template_sync,     2,  2},
    {"テンプレート編集",     fn_template_edit,     3,  3},
    {"テンプレート削除",     fn_template_delete,   2,  2},
    {"テンプレートからサーバー作成", fn_template_use, 2, 2},

    /* オンボーディング (v2.2.0) */
    {"オンボーディング取得", fn_onboarding_get,    1,  1},
    {"オンボーディング設定", fn_onboarding_edit,   2,  2},

    /* サウンドボード (v2.2.0) */
    {"サウンドボード一覧",   fn_soundboard_list,   1,  1},
    {"サウンドボード取得",   fn_soundboard_get,    2,  2},
    {"サウンドボード作成",   fn_soundboard_create, 3,  5},
    {"サウンドボード編集",   fn_soundboard_edit,   3,  3},
    {"サウンドボード削除",   fn_soundboard_delete, 2,  2},
    {"サウンドボード再生",   fn_soundboard_play,   2,  3},
    {"デフォルトサウンドボード一覧", fn_soundboard_defaults, 0, 0},

    /* ロール接続メタデータ (v2.2.0) */
    {"ロール接続メタデータ取得",   fn_role_connection_meta_get, 1, 1},
    {"ロール接続メタデータ設定",   fn_role_connection_meta_set, 2, 2},
    {"ユーザーロール接続取得",     fn_user_role_connection_get, 1, 1},
    {"ユーザーロール接続更新",     fn_user_role_connection_set, 2, 2},

    /* エンタイトルメント / SKU (v2.2.0) */
    {"SKU一覧",              fn_sku_list,                 1,  1},
    {"エンタイトルメント一覧", fn_entitlement_list,       1,  1},
    {"エンタイトルメント消費", fn_entitlement_consume,    2,  2},
    {"テストエンタイトルメント作成", fn_entitlement_test_create, 4, 4},
    {"テストエンタイトルメント削除", fn_entitlement_test_delete, 2, 2},

    /* OAuth2 (v2.2.0) */
    {"OAuth2トークン交換",   fn_oauth2_token_exchange,    4,  4},
    {"OAuth2トークンリフレッシュ", fn_oauth2_token_refresh, 3, 3},
    {"OAuth2トークン無効化", fn_oauth2_token_revoke,      3,  3},
    {"OAuth2自分情報",       fn_oauth2_me,                0,  0},
    {"OAuth2認可URL生成",    fn_oauth2_auth_url,          3,  3},

    /* シャーディング (v2.2.0) */
    {"シャード設定",         fn_shard_set,                2,  2},
    {"シャード情報",         fn_shard_info,               0,  0},
    {"シャードID計算",       fn_shard_id_for,             2,  2},

    /* サーバー */
    {"サーバー情報",         fn_guild_info,        1,  1},
    {"メンバー情報",         fn_member_info,       2,  2},
    {"キック",               fn_kick,              2,  3},
    {"BAN",                  fn_ban,               2,  3},
    {"BAN解除",              fn_unban,             2,  2},
    {"タイムアウト",         fn_timeout,           3,  3},

    /* ロール */
    {"ロール付与",           fn_add_role,          3,  3},
    {"ロール剥奪",           fn_remove_role,       3,  3},
    {"ロール一覧",           fn_role_list,         1,  1},

    /* リアクション */
    {"リアクション追加",     fn_add_reaction,      3,  3},
    {"リアクション削除",     fn_remove_reaction,   3,  4},
    {"リアクション全削除",   fn_remove_all_reactions, 2, 2},

    /* ステータス */
    {"ステータス設定",       fn_set_status,        1,  3},

    /* ユーザー */
    {"自分情報",             fn_me,                0,  0},
    {"ユーザー情報",         fn_user_info,         1,  1},

    /* ピン */
    {"ピン留め",             fn_pin_message,       2,  2},
    {"ピン解除",             fn_unpin_message,     2,  2},
    {"ピン一覧",             fn_pin_list,          1,  1},

    /* その他 */
    {"DM作成",               fn_create_dm,         1,  1},
    {"ログレベル設定",       fn_set_log_level,     1,  1},
    {"インテント値",         fn_intent_value,      1,  1},
    {"バージョン",           fn_version,           0,  0},

    /* ===== v2.3.0: 互換性強化 ===== */

    /* 自動選択メニュー (Auto-populated Select Menus) */
    {"ユーザーセレクト作成",     fn_user_select_create,        1,  2},
    {"ロールセレクト作成",       fn_role_select_create,        1,  2},
    {"チャンネルセレクト作成",   fn_channel_select_create,     1,  2},
    {"メンション可能セレクト作成", fn_mentionable_select_create, 1, 2},

    /* BAN管理拡張 */
    {"BAN一覧",                 fn_ban_list,                  1,  2},
    {"BAN一括",                 fn_bulk_ban,                  2,  3},

    /* メンバー管理拡張 */
    {"メンバー編集",             fn_member_edit,               3,  3},
    {"ニックネーム変更",         fn_nick_change,               2,  2},

    /* Webhook拡張 */
    {"Webhook編集",             fn_webhook_edit,              2,  2},
    {"Webhook情報",             fn_webhook_info,              1,  1},
    {"Webhookメッセージ編集",   fn_webhook_edit_message,      4,  4},
    {"Webhookメッセージ削除",   fn_webhook_delete_message,    3,  3},

    /* スレッド管理拡張 */
    {"アクティブスレッド一覧",   fn_active_threads,            1,  1},
    {"アーカイブスレッド一覧",   fn_archived_threads,          1,  2},
    {"スレッドアーカイブ",       fn_thread_archive,            2,  2},
    {"スレッドロック",           fn_thread_lock,               2,  2},
    {"スレッドピン",             fn_thread_pin,                2,  2},

    /* アナウンスチャンネル */
    {"クロスポスト",             fn_crosspost,                 2,  2},
    {"チャンネルフォロー",       fn_channel_follow,            2,  2},

    /* サーバー管理拡張 */
    {"プルーン確認",             fn_prune_count,               1,  2},
    {"プルーン実行",             fn_prune,                     1,  2},
    {"サーバー削除",             fn_guild_delete,              1,  1},
    {"サーバープレビュー",       fn_guild_preview,             1,  1},
    {"ウィジェット設定取得",     fn_widget_settings_get,       1,  1},
    {"ウィジェット設定更新",     fn_widget_settings_edit,      2,  2},
    {"バニティURL取得",         fn_vanity_url,                1,  1},

    /* チャンネル・ロール並べ替え */
    {"チャンネル位置変更",       fn_channel_position,          2,  2},
    {"ロール位置変更",           fn_role_position,             2,  2},

    /* リアクション拡張 */
    {"リアクションユーザー一覧", fn_reaction_users,            3,  4},
    {"絵文字リアクション削除",   fn_remove_emoji_reactions,    3,  3},

    /* コマンド管理 */
    {"コマンド削除",             fn_command_delete,            1,  2},
    {"コマンド一覧",             fn_command_list,              0,  1},
    {"コマンド権限設定",         fn_command_permissions,       3,  3},

    /* ユーティリティ */
    {"Snowflakeタイムスタンプ",  fn_snowflake_timestamp,       1,  1},
    {"権限値",                   fn_permission_value,          1,  1},
    {"権限チェック",             fn_permission_check,          2,  2},
    {"アプリ情報",               fn_app_info,                  0,  0},
    {"Voice地域一覧",            fn_voice_regions,             0,  0},
    {"ステッカーパック一覧",     fn_sticker_packs,             0,  0},

    /* .env */
    {"env読み込み",               fn_env_load,                  0,  1},
    {"env取得",                   fn_env_get,                   1,  2},
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
