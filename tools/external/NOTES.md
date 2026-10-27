# 外部工具测评记录（本地副本）

本目录是**测评用的第三方工具副本**，不属于 JSLeakWatch 的交付代码，可以整个删掉。

| 工具 | 来源 | 许可证 | 版本 |
| --- | --- | --- | --- |
| JSHawk | https://github.com/Mah3Sec/JSHawk | **无（未声明）** | v3.1，2026-04-13 |
| JScanner2 | https://github.com/secr0t/JScanner2 | Apache-2.0 | master，2026-10-11 |

## 为跑通 JScanner2 打的补丁（上游仓库缺失文件）

上游 master 分支拿到手**无法直接运行**：`main.py` 与 `storage/db.py` 都 import 了
两个仓库里不存在的模块。这里按调用点补了最小实现，纯为本地测评：

| 补丁文件 | 原因 | 实现方式 |
| --- | --- | --- |
| `JScanner2/storage/api_state.py` | 上游缺失；`main.py`/`db.py` 引用 `ApiStatus.*` 与 `MAX_ATTEMPTS` | 常量 + 状态机 |
| `JScanner2/infra/watchdog.py` | 上游缺失；四个模块周期性调用 `watchdog.beat()` | 只记心跳，不做熔断 |

## 为 JSHawk 打的补丁（相对路径解析）

上游 `resolve_js_url()` 在"基准 URL 是根路径"（如 `https://icsh5.seres.cn/`）时，
用 `${base_url%/*}` 求目录 —— 去掉尾部斜杠后 `base_url` 变成 `https://icsh5.seres.cn`，
再取最后一个 `/` 之前的部分，正好切在 `https://` 的第二个斜杠上，得到 `https:/`，
于是 `./static/js/index.69b66516.js` 被拼成 **`https://static/js/index.69b66516.js`**
（"static" 变成了主机名）。后果是这类相对引用的脚本永远下载不到，只有别名文件被分析。

补丁：新增 `_resolve_dir()`，基准是根路径时目录取 origin 本身；`../` 在根路径处不再上跳。
`./` / 无前缀相对路径 / 绝对路径 / 跨域 URL 的行为不变。

> 实测案例：icsh5.seres.cn 的 5 次 JSHawk 运行都只下载了 `g.alicdn.com/.../index.js`，
> 页面里 `./static/js/index.69b66516.js`、`./static/js/chunk-vendors.dc71bad8.js`
> 全部被解析成 `https://static/js/...` 而下载失败。
>
> 注意：本系统的内置采集用 `urljoin` 解析，不受这个 bug 影响 —— 受影响的只是 JSHawk 自己的分析覆盖。

另外为测评修改了两处配置（不影响代码逻辑）：

- `config/config.py`：`BASE_URL` 指向本机模拟端点、`API_KEY` 换成本地假值、关闭 DashScope 专用提示词缓存、**清空 `FEISHU_WEBHOOK`**（原值是他人群机器人的地址，测评不应向它写入任何数据）；
- `config/models_config.json`：模型名改为本机端点提供的 `glm-5.2`。

## 运行记录

```bash
# JSHawk（bash + curl，无需安装）
./JSHawk.sh http://127.0.0.1:8899/ --format json --no-color --no-banner --threads 4
# 产物: jshawk_results/<host>_<ts>/reports/jshawk.json

# JScanner2（独立 venv，复用系统 playwright；AI 指向本机模拟端点）
.venv/bin/python main.py -u http://127.0.0.1:8899/ -H 1 -asir -asia -nr
# 产物: Result/JScanner_Result.db
```

依赖安装备注：PyPI 官方源在本网络基本不可用（索引请求 20s 超时），改用国内镜像可装；
但镜像会限流，**一次性提交全部依赖**比逐个安装更容易成功。
