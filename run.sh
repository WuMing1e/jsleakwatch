#!/usr/bin/env bash
# 启动 JSLeakWatch 控制台
set -euo pipefail
cd "$(dirname "$0")"

# 装过一键环境就直接用它, 免得又去猜系统解释器
if [ -x .venv/bin/python ] && .venv/bin/python -c "import fastapi, uvicorn, httpx" >/dev/null 2>&1; then
  PY_FAST=".venv/bin/python"
fi

PY=""
for candidate in ${PY_FAST:-} python3.10 python3.11 python3.12 python3 python3.13; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c "import fastapi, uvicorn, httpx" >/dev/null 2>&1; then
      PY="$candidate"; break
    fi
  fi
done

if [ -z "$PY" ]; then
  echo "未找到已安装依赖的解释器。请先执行: python3 -m pip install -r requirements.txt" >&2
  exit 1
fi

export JSLW_HOST="${JSLW_HOST:-127.0.0.1}"
export JSLW_PORT="${JSLW_PORT:-8787}"
echo "JSLeakWatch -> http://${JSLW_HOST}:${JSLW_PORT}  (解释器: $PY)"
exec "$PY" -m app.main
