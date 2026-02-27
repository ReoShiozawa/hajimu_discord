#!/bin/bash
# jp-discord クロスプラットフォームビルド & コミット
set -e
cd "$(dirname "$0")"

echo "=== jp-discord: ビルド開始 ==="
make build-all

echo "=== jp-discord: git add ==="
git add dist/

if git diff --cached --quiet; then
    echo "  変更なし、スキップ"
else
    git commit -m "build: cross-platform $(date +%Y%m%d)"
    git push
    echo "  プッシュ完了"
fi
