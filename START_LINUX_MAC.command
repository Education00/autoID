#!/usr/bin/env bash
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

if [ ! -x ".venv/bin/python" ] || [ ! -f ".venv/.setup_complete" ]; then
  echo "[1/3] Đang tạo môi trường..."
  python3 -m venv .venv
  echo "[2/3] Đang cài Playwright..."
  .venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
  echo "[3/3] Đang tải Chromium..."
  .venv/bin/python -m playwright install chromium
  : > .venv/.setup_complete
fi

echo "Đang mở giao diện..."
exec .venv/bin/python server.py
