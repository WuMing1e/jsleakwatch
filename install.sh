#!/usr/bin/env bash
# 一键安装: 建虚拟环境(.venv) + 装依赖。可重复执行, 已装好会直接复用。
set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"

find_python() {
  local candidate
  # 优先用经过验证的 3.10, 再往新版本找; 系统自带的 3.9 会被跳过
  for candidate in python3.10 python3.11 python3.12 python3.13 python3; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

if [ -x "$VENV/bin/python" ]; then
  PY="$VENV/bin/python"
  echo "复用已有虚拟环境: $("$PY" -V 2>&1)"
else
  if ! BASE="$(find_python)"; then
    cat >&2 <<'EOF'
未找到 Python 3.10 或更高版本。
  macOS:  brew install python@3.12
  其它:    https://www.python.org/downloads/
装好后重新运行本脚本。
EOF
    exit 1
  fi
  echo "使用解释器: $BASE ($("$BASE" -V 2>&1))"
  "$BASE" -m venv "$VENV"
  PY="$VENV/bin/python"
fi

PIP="$VENV/bin/pip"
"$PIP" install --upgrade pip >/dev/null 2>&1 || true

# 依次尝试: 环境变量指定的源 → 官方源 → 清华镜像 → 阿里云镜像
indexes=("${PIP_INDEX_URL:-}" "" "https://pypi.tuna.tsinghua.edu.cn/simple" "https://mirrors.aliyun.com/pypi/simple")
ok=0
for idx in "${indexes[@]}"; do
  if [ -z "$idx" ]; then
    echo "安装依赖(官方源)…"
    if "$PIP" install -q -r requirements.txt; then ok=1; break; fi
  else
    echo "安装依赖(镜像: $idx)…"
    host="$(printf '%s' "$idx" | awk -F/ '{print $3}')"
    if "$PIP" install -q -r requirements.txt -i "$idx" --trusted-host "$host"; then ok=1; break; fi
  fi
  echo "  这个源没成功, 换下一个"
done

if [ "$ok" != "1" ]; then
  echo "依赖安装失败。可以手动执行: $PIP install -r requirements.txt" >&2
  exit 1
fi

"$PY" - <<'EOF'
import fastapi, httpx, pydantic, uvicorn
print(f"依赖就绪: fastapi {fastapi.__version__} | uvicorn {uvicorn.__version__} | httpx {httpx.__version__}")
EOF
echo
echo "安装完成。启动: ./start.sh  (或双击 一键启动.command)"
