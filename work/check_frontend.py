"""前端与后端的一致性自检:
1. 页面上出现的每个 data-act 都必须有处理分支;
2. 前端调用的每个 /api 路径都必须真实注册在 FastAPI 上。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(ROOT))
from app.api import app  # noqa: E402

JS = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")

acts_used = set(re.findall(r'data-act="([a-z\-]+)"', JS))
handled = set(re.findall(r"act === '([a-z\-]+)'", JS))
handled |= set(re.findall(r"act === \"([a-z\-]+)\"", JS))

# 纯表单态动作: 只在点"保存"时落库, 不需要即时处理分支
FORM_ONLY = {"analyzer-toggle", "scanner-toggle", "target-select"}
acts_used -= FORM_ONLY

# setValue/click 之外的隐式处理: change 监听里的分支
change_branch = set(re.findall(r"act === '([a-z\-]+)'", JS[JS.find("addEventListener('change'"):]))

failures: list[str] = []
missing = sorted(acts_used - handled)
if missing:
    failures.append(f"缺少处理分支的 data-act: {missing}")

# ---- API 路径核对
paths = set(re.findall(r"""api\(\s*[`'"](/api[^`'"]*)""", JS))
paths |= set(re.findall(r"""['"]&?(/api/[a-zA-Z0-9/_.\-]+)""", JS))
registry = set()
for route in app.routes:
    path = getattr(route, "path", "")
    if path.startswith("/api"):
        registry.add(path)

def normalize(value: str) -> str:
    value = value.split("?")[0].rstrip("/")
    value = re.sub(r"\$\{[^}]*\}", "#", value)   # 前端模板变量
    value = re.sub(r"\{[^}]+\}", "#", value)     # 后端路径参数
    return value


registered = {normalize(reg) for reg in registry}
bad = []
for raw in sorted(paths):
    normalized = normalize(raw)
    if normalized not in registered:
        bad.append(raw)
if bad:
    failures.append(f"前端调用了未注册的接口: {bad}")

print(f"data-act 使用: {len(acts_used)} 个")
print(f"handleAction 分支: {len(handled)} 个")
print("change 事件分支:", sorted(change_branch))
print(f"前端调用的接口: {len(paths)} 个 | 后端注册接口: {len(registry)} 个")
unused = sorted(handled - acts_used)
if unused:
    print("仅由 change 事件或其他路径触发的分支:", unused)

if failures:
    print("\n发现问题:")
    for item in failures:
        print("  -", item)
    sys.exit(1)
print("\n一致性检查通过")
