#!/bin/bash
# macOS: 在访达里双击本文件即可安装依赖并启动。
cd "$(dirname "$0")" || exit 1
./start.sh
status=$?
if [ "$status" -ne 0 ]; then
  echo
  read -n 1 -s -r -p "启动失败（退出码 $status），按任意键关闭窗口…"
fi
