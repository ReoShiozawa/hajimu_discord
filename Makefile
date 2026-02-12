# =============================================================================
# hajimu_discord — はじむ言語用 Discord Bot 開発プラグイン
# =============================================================================

PLUGIN_NAME = hajimu_discord
OUT         = $(PLUGIN_NAME).hjp

# ソース
SRC = src/hajimu_discord.c

# コンパイラ
CC ?= gcc

# はじむヘッダーパス自動検出
HAJIMU_INCLUDE ?= $(shell \
	if [ -d "../../jp/include" ]; then echo "../../jp/include"; \
	elif [ -d "../jp/include" ]; then echo "../jp/include"; \
	elif [ -d "/opt/homebrew/include/hajimu" ]; then echo "/opt/homebrew/include/hajimu"; \
	elif [ -d "/usr/local/include/hajimu" ]; then echo "/usr/local/include/hajimu"; \
	else echo "./include"; fi)

# OpenSSL パス (macOS Homebrew)
OPENSSL_PREFIX ?= $(shell \
	if [ -d "/opt/homebrew/opt/openssl" ]; then echo "/opt/homebrew/opt/openssl"; \
	elif [ -d "/usr/local/opt/openssl" ]; then echo "/usr/local/opt/openssl"; \
	else echo "/usr"; fi)

# コンパイルフラグ
CFLAGS  = -Wall -Wextra -O2 -std=c11 -fPIC
CFLAGS += -I$(HAJIMU_INCLUDE)
CFLAGS += -I$(OPENSSL_PREFIX)/include

# リンクフラグ
LDFLAGS  = -L$(OPENSSL_PREFIX)/lib
LDFLAGS += -lcurl -lssl -lcrypto -lz -lpthread

# OS 判定
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	CFLAGS  += -shared -dynamiclib
else ifeq ($(UNAME_S),Linux)
	CFLAGS  += -shared
else
	CFLAGS  += -shared
endif

# インストール先
INSTALL_DIR = $(HOME)/.hajimu/plugins

# =============================================================================
# ターゲット
# =============================================================================

.PHONY: all clean install uninstall test help

all: $(OUT)
	@echo ""
	@echo "  ✅ ビルド完了: $(OUT)"
	@echo "     関数数: $$(grep -c '\"[^\"]*\",' src/hajimu_discord.c | tail -1) (概算)"
	@echo ""

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(OUT)
	@echo "  🧹 クリーン完了"

install: $(OUT)
	@mkdir -p $(INSTALL_DIR)/$(PLUGIN_NAME)
	cp $(OUT) $(INSTALL_DIR)/$(PLUGIN_NAME)/
	cp hajimu.json $(INSTALL_DIR)/$(PLUGIN_NAME)/
	@echo ""
	@echo "  📦 インストール完了: $(INSTALL_DIR)/$(PLUGIN_NAME)/"
	@echo ""

uninstall:
	rm -rf $(INSTALL_DIR)/$(PLUGIN_NAME)
	@echo "  🗑  アンインストール完了"

# テスト: echo bot を起動
NIHONGO ?= $(shell \
	if [ -x "../../jp/nihongo" ]; then echo "../../jp/nihongo"; \
	elif [ -x "../jp/nihongo" ]; then echo "../jp/nihongo"; \
	elif command -v hajimu >/dev/null 2>&1; then echo "hajimu"; \
	elif command -v nihongo >/dev/null 2>&1; then echo "nihongo"; \
	else echo "./nihongo"; fi)

test: $(OUT)
	@echo "  🤖 テストBot起動 (examples/hello_bot.jp)"
	@echo "  ※ DISCORD_TOKEN 環境変数にBotトークンを設定してください"
	$(NIHONGO) examples/hello_bot.jp

help:
	@echo ""
	@echo "  hajimu_discord — はじむ用 Discord Bot 開発プラグイン"
	@echo ""
	@echo "  ターゲット:"
	@echo "    make             ビルド ($(OUT))"
	@echo "    make clean       クリーン"
	@echo "    make install     ~/.hajimu/plugins/ にインストール"
	@echo "    make uninstall   アンインストール"
	@echo "    make test        テストBot起動"
	@echo "    make help        このヘルプ"
	@echo ""
	@echo "  環境変数:"
	@echo "    HAJIMU_INCLUDE   はじむヘッダーパス (デフォルト: 自動検出)"
	@echo "    OPENSSL_PREFIX   OpenSSLパス (デフォルト: 自動検出)"
	@echo "    CC               コンパイラ (デフォルト: gcc)"
	@echo "    NIHONGO          はじむ実行パス (デフォルト: 自動検出)"
	@echo ""
	@echo "  依存ライブラリ:"
	@echo "    libcurl, OpenSSL (libssl + libcrypto), zlib, pthread"
	@echo ""
	@echo "  macOS: brew install openssl curl"
	@echo "  Ubuntu: sudo apt install libcurl4-openssl-dev libssl-dev zlib1g-dev"
	@echo ""
