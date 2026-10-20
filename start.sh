#!/usr/bin/env bash
# 一键启动: 第一次会自动装依赖, 之后直接起服务并打开浏览器。
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  echo "第一次运行, 先安装依赖…"
  ./install.sh
fi

export JSLW_HOST="${JSLW_HOST:-127.0.0.1}"
export JSLW_PORT="${JSLW_PORT:-8787}"
URL="http://${JSLW_HOST}:${JSLW_PORT}"

if [ "${JSLW_NO_BROWSER:-0}" != "1" ]; then
  (
    sleep 2
    if command -v open >/dev/null 2>&1; then open "$URL"
    elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
    fi
  ) >/dev/null 2>&1 &
fi

echo "JSLeakWatch -> ${URL}   (Ctrl+C 停止)"
exec .venv/bin/python -m app.main
