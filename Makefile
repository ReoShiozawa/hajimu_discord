# =============================================================================
# hajimu_discord — はじむ言語用 Discord Bot 開発プラグイン
# クロスプラットフォーム Makefile (macOS / Linux / Windows MinGW)
# =============================================================================

PLUGIN_NAME = hajimu_discord
OUT         = $(PLUGIN_NAME).hjp

# ソース
SRC = src/hajimu_discord.c

# コンパイラ
# CC ?= gcc だと GNU make 組み込みデフォルト(cc)が優先されるため = で上書き
# コマンドラインから make CC=clang のように引き続きオーバーライド可能
CC = gcc

# =============================================================================
# OS 判定
# $(OS) は Windows CMD/PowerShell で自動的に "Windows_NT" になる。
# uname -s は Windows で動かないため $(OS) を先にチェックする。
# =============================================================================
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
else
    DETECTED_OS := $(shell uname -s 2>/dev/null || echo Unknown)
endif

# =============================================================================
# はじむヘッダーパス自動検出
# =============================================================================
ifeq ($(OS),Windows_NT)
    ifndef HAJIMU_INCLUDE
        HAJIMU_INCLUDE := $(or \
            $(if $(wildcard ../../jp/include/hajimu.h),../../jp/include),\
            $(if $(wildcard ../jp/include/hajimu.h),../jp/include),\
            ./include)
    endif
else
    ifndef HAJIMU_INCLUDE
        HAJIMU_INCLUDE := $(shell \
            if [ -d "../../jp/include" ]; then echo "../../jp/include"; \
            elif [ -d "../jp/include" ]; then echo "../jp/include"; \
            elif [ -d "/opt/homebrew/include/hajimu" ]; then echo "/opt/homebrew/include/hajimu"; \
            elif [ -d "/usr/local/include/hajimu" ]; then echo "/usr/local/include/hajimu"; \
            else echo "./include"; fi)
    endif
endif

# =============================================================================
# OpenSSL パス
# Windows: MSYS2 で  pacman -S mingw-w64-x86_64-openssl  でインストール可能
# =============================================================================
ifeq ($(OS),Windows_NT)
    ifndef OPENSSL_PREFIX
        OPENSSL_PREFIX := $(or \
            $(if $(wildcard /mingw64/include/openssl/ssl.h),/mingw64),\
            $(if $(wildcard C:/msys64/mingw64/include/openssl/ssl.h),C:/msys64/mingw64),\
            /mingw64)
    endif
    OPENSSL_CFLAGS  = -I$(OPENSSL_PREFIX)/include
    OPENSSL_LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
else ifeq ($(DETECTED_OS),Darwin)
    # macOS Homebrew
    ifndef OPENSSL_PREFIX
        OPENSSL_PREFIX := $(shell \
            if [ -d "/opt/homebrew/opt/openssl" ]; then echo "/opt/homebrew/opt/openssl"; \
            elif [ -d "/usr/local/opt/openssl" ]; then echo "/usr/local/opt/openssl"; \
            else echo "/usr"; fi)
    endif
    OPENSSL_CFLAGS  = -I$(OPENSSL_PREFIX)/include
    OPENSSL_LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
else
    # Linux: pkg-config で検出
    OPENSSL_CFLAGS  := $(shell pkg-config --cflags openssl 2>/dev/null || echo "")
    OPENSSL_LDFLAGS := $(shell pkg-config --libs   openssl 2>/dev/null || echo "-lssl -lcrypto")
endif

# =============================================================================
# Opus (ボイスチャンネル v2.0.0+) — 任意依存
# =============================================================================
ifeq ($(OS),Windows_NT)
    OPUS_CFLAGS  := $(if $(wildcard /mingw64/include/opus/opus.h),-I/mingw64/include/opus,)
    OPUS_LDFLAGS := $(if $(wildcard /mingw64/lib/libopus.a),-L/mingw64/lib -lopus,)
else
    OPUS_CFLAGS  := $(shell pkg-config --cflags opus 2>/dev/null || echo "")
    OPUS_LDFLAGS := $(shell pkg-config --libs   opus 2>/dev/null || echo "")
endif
ifeq ($(OPUS_CFLAGS),)
    OPUS_DEFINE := -DHJP_NO_VOICE
else
    OPUS_DEFINE :=
endif

# =============================================================================
# libsodium (音声暗号化 v2.0.0+) — 任意依存
# =============================================================================
ifeq ($(OS),Windows_NT)
    SODIUM_CFLAGS  := $(if $(wildcard /mingw64/include/sodium.h),-I/mingw64/include,)
    SODIUM_LDFLAGS := $(if $(wildcard /mingw64/lib/libsodium.a),-L/mingw64/lib -lsodium,)
else
    SODIUM_CFLAGS  := $(shell pkg-config --cflags libsodium 2>/dev/null || echo "")
    SODIUM_LDFLAGS := $(shell pkg-config --libs   libsodium 2>/dev/null || echo "")
endif
ifeq ($(SODIUM_CFLAGS),)
    SODIUM_DEFINE := -DHJP_NO_SODIUM
else
    SODIUM_DEFINE :=
endif

# =============================================================================
# コンパイル / リンクフラグ (OS 別)
# =============================================================================
ifeq ($(OS),Windows_NT)
    # Windows (MinGW/MSYS2): -fPIC 不要、Windows 固有ライブラリを追加
    CFLAGS  = -Wall -Wextra -O2 -std=c11
    CFLAGS += -D_WIN32_WINNT=0x0601 -DWIN32_LEAN_AND_MEAN
    CFLAGS += $(OPUS_DEFINE) $(SODIUM_DEFINE)
    CFLAGS += -I$(HAJIMU_INCLUDE) $(OPENSSL_CFLAGS) $(OPUS_CFLAGS) $(SODIUM_CFLAGS)
    CFLAGS += -shared

    LDFLAGS  = $(OPENSSL_LDFLAGS) -lcurl -lz -lpthread
    LDFLAGS += -lws2_32 -lwinmm -lbcrypt -lcrypt32
    LDFLAGS += $(OPUS_LDFLAGS) $(SODIUM_LDFLAGS)
    LDFLAGS += -static-libgcc

    INSTALL_DIR = $(USERPROFILE)/.hajimu/plugins
else ifeq ($(DETECTED_OS),Darwin)
    CFLAGS  = -Wall -Wextra -O2 -std=c11 -fPIC
    CFLAGS += $(OPUS_DEFINE) $(SODIUM_DEFINE)
    CFLAGS += -I$(HAJIMU_INCLUDE) $(OPENSSL_CFLAGS) $(OPUS_CFLAGS) $(SODIUM_CFLAGS)
    CFLAGS += -shared -dynamiclib

    LDFLAGS  = $(OPENSSL_LDFLAGS) -lz -lpthread -lcurl
    LDFLAGS += $(OPUS_LDFLAGS) $(SODIUM_LDFLAGS)

    INSTALL_DIR = $(HOME)/.hajimu/plugins
else
    CFLAGS  = -Wall -Wextra -O2 -std=c11 -fPIC
    CFLAGS += $(OPUS_DEFINE) $(SODIUM_DEFINE)
    CFLAGS += -I$(HAJIMU_INCLUDE) $(OPENSSL_CFLAGS) $(OPUS_CFLAGS) $(SODIUM_CFLAGS)
    CFLAGS += -shared

    LDFLAGS  = $(OPENSSL_LDFLAGS) -lz -lpthread -lcurl
    LDFLAGS += $(OPUS_LDFLAGS) $(SODIUM_LDFLAGS)

    INSTALL_DIR = $(HOME)/.hajimu/plugins
endif

# =============================================================================
# ターゲット
# =============================================================================

.PHONY: all deps-check clean install uninstall test help

# deps-check: 必要な依存ライブラリを自動インストール
# Windows (MSYS2): pacman -S --noconfirm --needed でスキップしつつ自動インストール
# macOS: brew install (存在しない場合のみ)
deps-check:
ifeq ($(OS),Windows_NT)
	@command -v pacman >/dev/null 2>&1 && \
		echo "  依存ライブラリを確認中 (MSYS2 pacman)..." && \
		pacman -S --noconfirm --needed \
			mingw-w64-x86_64-openssl \
			mingw-w64-x86_64-curl \
			mingw-w64-x86_64-gcc \
	|| echo "  ヒント: MSYS2 MinGW64 コンソールから実行してください (https://www.msys2.org/)"
else ifeq ($(DETECTED_OS),Darwin)
	@command -v openssl >/dev/null 2>&1 || brew install openssl curl
endif

all: deps-check $(OUT)
	@echo ""
	@echo "  ビルド完了: $(OUT)"
ifeq ($(OS),Windows_NT)
	@echo "  Opus ボイス: $(if $(OPUS_LDFLAGS),有効,無効)"
	@echo "  音声暗号化: $(if $(SODIUM_LDFLAGS),有効,無効)"
endif
	@echo ""

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
ifeq ($(OS),Windows_NT)
	-del /F /Q $(OUT) 2>NUL
else
	rm -f $(OUT)
endif
	@echo "  クリーン完了"

install: $(OUT)
ifeq ($(OS),Windows_NT)
	if not exist "$(INSTALL_DIR)\$(PLUGIN_NAME)" mkdir "$(INSTALL_DIR)\$(PLUGIN_NAME)"
	copy /Y $(OUT) "$(INSTALL_DIR)\$(PLUGIN_NAME)"
	copy /Y hajimu.json "$(INSTALL_DIR)\$(PLUGIN_NAME)"
else
	@mkdir -p $(INSTALL_DIR)/$(PLUGIN_NAME)
	cp $(OUT) $(INSTALL_DIR)/$(PLUGIN_NAME)/
	cp hajimu.json $(INSTALL_DIR)/$(PLUGIN_NAME)/
endif
	@echo "  インストール完了: $(INSTALL_DIR)/$(PLUGIN_NAME)/"

uninstall:
ifeq ($(OS),Windows_NT)
	-rmdir /S /Q "$(INSTALL_DIR)\$(PLUGIN_NAME)" 2>NUL
else
	rm -rf $(INSTALL_DIR)/$(PLUGIN_NAME)
endif
	@echo "  アンインストール完了"

test: $(OUT)
	@echo "  テストBot起動 (examples/hello_bot.jp)"
	@echo "  ※ DISCORD_TOKEN 環境変数にBotトークンを設定してください"

help:
	@echo ""
	@echo "  hajimu_discord — はじむ用 Discord Bot 開発プラグイン"
	@echo ""
	@echo "  ターゲット:"
	@echo "    make             ビルド ($(OUT))"
	@echo "    make clean       クリーン"
	@echo "    make install     ~/.hajimu/plugins/ にインストール"
	@echo "    make uninstall   アンインストール"
	@echo "    make help        このヘルプ"
	@echo ""
	@echo "  macOS:   brew install openssl curl opus libsodium"
	@echo "  Linux:   sudo apt install libcurl4-openssl-dev libssl-dev zlib1g-dev libopus-dev libsodium-dev"
	@echo "  Windows: MSYS2 MinGW64 ターミナルで実行:"
	@echo "    pacman -S mingw-w64-x86_64-openssl mingw-w64-x86_64-curl"
	@echo "    pacman -S mingw-w64-x86_64-libopus   (任意: ボイス)"
	@echo "    pacman -S mingw-w64-x86_64-libsodium  (任意: 音声暗号化)"
	@echo "  (MSYS2: https://www.msys2.org/ からインストール)"
	@echo ""
