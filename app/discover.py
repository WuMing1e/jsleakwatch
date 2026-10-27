"""资产发现: 从 HTML / JS 中提取脚本、chunk、sourcemap 等可扫描目标。

现代前端站点真正的密钥常常藏在按需加载的 chunk 里, 只抓入口文件会漏报,
因此这里实现了压缩产物的引用提取 (含 webpack/Next.js 的 chunk 映射)。
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

# HTML 中的脚本引用
HTML_SCRIPT_RE = re.compile(
    r"""<script[^>]*\ssrc\s*=\s*["']([^"'>]+)["']""", re.I)
HTML_MODULEPRELOAD_RE = re.compile(
    r"""<link[^>]*\srel\s*=\s*["'](?:modulepreload|preload)["'][^>]*>""", re.I)
HTML_HREF_RE = re.compile(r"""href\s*=\s*["']([^"'>]+)["']""", re.I)
HTML_INLINE_SCRIPT_RE = re.compile(
    r"""<script(?![^>]*\ssrc=)[^>]*>(.*?)</script>""", re.I | re.S)
HTML_LINK_PAGE_RE = re.compile(r"""<a[^>]*\shref\s*=\s*["']([^"'#]+)["']""", re.I)

# JS 中的引用
JS_QUOTED_PATH_RE = re.compile(
    r"""["'`]([^"'`\s]{1,300}?\.(?:js|mjs|cjs))(?:\?[^"'`]*)?["'`]""", re.I)
JS_DYNAMIC_IMPORT_RE = re.compile(r"""import\s*\(\s*["'`]([^"'`]+)["'`]""", re.I)
JS_SOURCEMAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s'"]+)""", re.I)
JS_STATIC_PREFIX_RE = re.compile(
    r"""["'`]([^"'`\s]{0,200}?(?:static|assets|_next|chunks|dist|build|js|scripts?)/)["'`]""")
JS_CHUNK_MAP_RE = re.compile(r"""["'](\d{1,5})["']\s*:\s*["']([A-Za-z0-9_\-]{4,40})["']""")
CHUNK_HASH_RE = re.compile(r"^[0-9a-f]{6,20}$", re.I)
# 对象字面量形式的字符串映射表, 以及其中的键值对
# 映射表的 key 有些是带引号的, 有些是裸标识符 ({about:"about"} / {"1":"4f2a1b"})
JS_STRING_MAP_RE = re.compile(
    r"""\{((?:\s*["']?[A-Za-z0-9_$.\-]{1,60}["']?\s*:\s*["'][^"'{}]{1,60}["']\s*,?)+)\}""")
# key 里不能出现逗号/空白/冒号/花括号, 否则会把分隔符吃进 key（早期踩过: ",y"）
JS_MAP_PAIR_RE = re.compile(
    r"""["']?\s*([^"'{}:,\s]{1,60})\s*["']?\s*:\s*["']([^"'{}]{1,60})["']""")
# 形如 `"." + {MAP}[e] + ".js"` 的拼接表达式: 其中的 MAP 才是拼 .js 的哈希表。
# 同一份产物里往往还有一张拼 .css 的同名表, 用它合成 .js 必然 404（实测踩过）。
JS_JS_HASH_MAP_RE = re.compile(
    r"""['"]\.['"]\s*\+\s*(\{[^{}]{4,20000}\})\s*\[[^\]]{1,30}\]\s*\+\s*["']\.js["']""")
MODULE_SPECIFIER_RE = re.compile(r"^(?:\./|\.\./)")
JS_IMPORT_SCRIPTS_RE = re.compile(r"""importScripts\s*\(\s*["'`]([^"'`]+)["'`]""", re.I)

# 接口地址: fetch("...") / axios.get("...") / $.post("...") / XHR.open("GET", "...")
# 现代前端把配置和密钥放在接口响应里, 只看 JS 文件会漏掉这一层。
API_FETCH_RE = re.compile(r"""\bfetch\s*\(\s*["'`]([^"'`\s]{2,300})["'`]""", re.I)
API_AXIOS_RE = re.compile(
    r"""\b(?:axios|http|request|api|client|httpClient)\s*\.\s*(?:get|head)\s*\(\s*["'`]([^"'`\s]{2,300})["'`]""",
    re.I)
API_JQUERY_RE = re.compile(
    r"""\$\.(?:get|getJSON|ajax)\s*\(\s*["'`]([^"'`\s]{2,300})["'`]""", re.I)
API_XHR_RE = re.compile(
    r"""\.open\s*\(\s*["'`]GET["'`]\s*,\s*["'`]([^"'`\s]{2,300})["'`]""",
    re.I)
API_METHOD_RE = re.compile(r"""\bmethod\s*:\s*["'`](POST|PUT|PATCH|DELETE)["'`]""", re.I)
API_URL_FIELD_RE = re.compile(
    r"""\burl\s*:\s*["'`]([^"'`\s]{2,300})["'`]""", re.I)

SCRIPT_EXT = (".js", ".mjs", ".cjs")
STATIC_HINT = re.compile(r"(static|assets|_next|chunks|dist|build|js|bundle)", re.I)
NON_PAGE_EXT = re.compile(
    r"\.(js|mjs|cjs|css|json|xml|txt|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|mp4|webm|pdf|zip|gz)$", re.I)

COMMON_CONFIG_PATHS = (
    "/config.js", "/env.js", "/runtime-config.js", "/app-config.js",
    "/config.json", "/settings.js", "/static/config.js", "/assets/config.js",
    "/js/config.js", "/global.js", "/env-config.js", "/appsettings.json",
)

# 接口响应的常见形态: 去重后按上限抓取
API_EXT_OK = (".json", ".xml", ".txt", ".yaml", ".yml", ".csv")
API_EXT_SKIP = re.compile(
    r"\.(js|mjs|cjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|mp4|webm|pdf|zip|gz)$", re.I)


@dataclass
class Candidate:
    url: str
    kind: str          # html | script | inline | map | config
    depth: int = 0
    inline: str = ""   # 内联脚本内容
    label: str = ""


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc.lower()) == (pb.scheme, pb.netloc.lower())


def _norm(url: str) -> str:
    parts = urlparse(url)
    path = parts.path or "/"
    return f"{parts.scheme}://{parts.netloc.lower()}{path}"


@dataclass
class Extractor:
    base_url: str
    scope: str = "same-origin"
    follow_sourcemaps: bool = True
    max_synth_chunks: int = 200
    scan_api: bool = False          # 是否顺带采集接口响应（默认关，属于额外请求）
    max_api: int = 30               # 单个站点最多抓几个接口
    stats: dict[str, int] = field(default_factory=dict)

    def _keep(self, url: str) -> bool:
        if not url.startswith(("http://", "https://")):
            return False
        if self.scope == "same-origin":
            return same_origin(url, self.base_url)
        if self.scope == "same-host":
            return urlparse(url).netloc.lower() == urlparse(self.base_url).netloc.lower()
        return True  # any

    def _add(self, out: dict[str, Candidate], url: str, kind: str, depth: int, label: str = "") -> None:
        url = url.split("#")[0]
        if not self._keep(url):
            return
        if kind == "html" and NON_PAGE_EXT.search(urlparse(url).path):
            return
        key = _norm(url)
        if key in out:
            return
        out[key] = Candidate(url=url, kind=kind, depth=depth, label=label)

    @staticmethod
    def _resolve_code_reference(asset_url: str, ref: str) -> str:
        """解析 JS 引用，去掉当前目录与引用路径的重复前缀。"""
        ref = ref.strip()
        parsed_ref = urlsplit(ref)
        if (not ref or ref.startswith(("/", "./", "../"))
                or parsed_ref.scheme or parsed_ref.netloc):
            return urljoin(asset_url, ref)

        base = urlsplit(asset_url)
        base_dir = posixpath.dirname(base.path)
        base_parts = [part for part in base_dir.split("/") if part]
        ref_parts = [part for part in parsed_ref.path.split("/") if part]
        if not base_parts or not ref_parts:
            return urljoin(asset_url, ref)

        overlap = 0
        for size in range(min(len(base_parts), len(ref_parts)), 0, -1):
            if base_parts[-size:] == ref_parts[:size]:
                overlap = size
                break
        if not overlap:
            return urljoin(asset_url, ref)

        merged = "/" + "/".join(base_parts[:-overlap] + ref_parts)
        return urlunsplit((base.scheme, base.netloc, merged,
                           parsed_ref.query, parsed_ref.fragment))

    # ---------------------------------------------------------- HTML
    def from_html(self, page_url: str, html: str, depth: int) -> list[Candidate]:
        out: dict[str, Candidate] = {}
        for src in HTML_SCRIPT_RE.findall(html):
            self._add(out, self._resolve_code_reference(page_url, src),
                      "script", depth)
        for block in HTML_MODULEPRELOAD_RE.findall(html):
            for href in HTML_HREF_RE.findall(block):
                if href.lower().endswith(SCRIPT_EXT):
                    self._add(out, self._resolve_code_reference(page_url, href),
                              "script", depth)
        for idx, body in enumerate(HTML_INLINE_SCRIPT_RE.findall(html)):
            if len(body.strip()) < 40:
                continue
            out[f"{_norm(page_url)}#inline-{idx}"] = Candidate(
                url=f"{page_url}#inline-{idx}", kind="inline", depth=depth,
                inline=body, label=f"inline script #{idx + 1}")
            # 内联脚本里也可能声明外部 chunk
            for ref in JS_QUOTED_PATH_RE.findall(body):
                self._add(out, self._resolve_code_reference(page_url, ref),
                          "script", depth)
        # 内联 JSON 配置 (window.__CONFIG__ = {...}) 通常就在 script 标签里, 上面已覆盖
        self.stats["html_scripts"] = self.stats.get("html_scripts", 0) + len(out)
        return list(out.values())

    def pages_from_html(self, page_url: str, html: str, depth: int) -> list[Candidate]:
        out: dict[str, Candidate] = {}
        for href in HTML_LINK_PAGE_RE.findall(html):
            target = urljoin(page_url, href.strip())
            if not target.startswith(("http://", "https://")):
                continue
            if not self._keep(target):
                continue
            if NON_PAGE_EXT.search(urlparse(target).path):
                continue
            out[_norm(target)] = Candidate(url=target, kind="html", depth=depth)
        return list(out.values())

    # ---------------------------------------------------------- JS
    def from_js(self, asset_url: str, text: str, depth: int) -> list[Candidate]:
        out: dict[str, Candidate] = {}
        for ref in JS_QUOTED_PATH_RE.findall(text):
            # 语言包/模块名（如 moment 的 "./af.js"）不是构建产物, 抓它只会得到 404
            if MODULE_SPECIFIER_RE.match(ref) and not re.search(r"[0-9a-f]{6,}", ref, re.I):
                continue
            self._add(out, self._resolve_code_reference(asset_url, ref), "script", depth)
        for ref in JS_DYNAMIC_IMPORT_RE.findall(text):
            if ref.lower().endswith(SCRIPT_EXT) or not posixpath.splitext(ref)[1]:
                self._add(out, self._resolve_code_reference(asset_url, ref),
                          "script", depth)
        for ref in JS_IMPORT_SCRIPTS_RE.findall(text):
            self._add(out, self._resolve_code_reference(asset_url, ref), "script", depth)

        # webpack / Vue CLI 的 chunk 映射: 用前缀 + 映射表拼出实际文件
        prefixes = JS_STATIC_PREFIX_RE.findall(text)
        if prefixes:
            best = max(set(prefixes), key=prefixes.count)
            if not best.startswith(("http://", "https://", "/")):
                best = "/" + best

            # 形态 A: 两张表按同名 key 拼接 —— Vue CLI / CRA 的运行时写法:
            #   "js/" + ({about:"about",...}[e]||e) + "." + {about:"ba4219c8",...}[e] + ".js"
            #
            # 产物里往往同时存在多张表(名字表、内容哈希表、分片哈希表、尺寸表),
            # 任意两两组合会产出大量错误文件名。因此只做"名字表 × 纯哈希表"配对:
            # 名字表的值不是哈希, 哈希表的值必须全是哈希。
            maps = self._string_maps(text)
            hex_maps = [m for m in maps if all(CHUNK_HASH_RE.fullmatch(v) for v in m.values())]
            name_maps = [m for m in maps if m not in hex_maps]
            # 真实源码是 名字表 + "." + 哈希表 + ".js"，因此"紧跟 '.' + 之后"的那张表
            # 才是 JS 用的哈希表。产物里往往还有一张（如 CSS 的）哈希表，
            # 不加区分地两两组合会凭空多出一倍的 404 请求。
            preferred = self._js_hash_maps(text)
            if preferred:
                # 按内容比较（两次解析出的 dict 不是同一对象, 不能用 id）
                wanted = {frozenset(m.items()) for m in preferred}
                narrowed = [m for m in hex_maps if frozenset(m.items()) in wanted]
                hex_maps = narrowed or preferred
            synth_budget = self.max_synth_chunks
            for names in name_maps:
                for hashes in hex_maps:
                    shared = set(names) & set(hashes)
                    if len(shared) < 2:
                        continue
                    for key in list(shared)[: max(0, synth_budget)]:
                        name, hashed = names[key], hashes[key]
                        if not self._plausible_chunk_part(name):
                            continue
                        self._add(out, self._resolve_code_reference(
                                      asset_url, f"{best}{name}.{hashed}.js"),
                                  "script", depth, "chunk-map")
                        synth_budget -= 1
                    self.stats["synth_chunks"] = self.stats.get("synth_chunks", 0) + 1
                if synth_budget <= 0:
                    break

            # 形态 B: 数字键映射表（老式 webpack）
            pairs = JS_CHUNK_MAP_RE.findall(text)
            names = [name for _, name in pairs if not name.isdigit()]
            hashed = [n for n in names if CHUNK_HASH_RE.fullmatch(n)]
            # 至少出现一个哈希式文件名, 才认为这是 webpack 的 chunk 映射表
            if names and hashed:
                for name in dict.fromkeys(names[: self.max_synth_chunks]):
                    self._add(out, self._resolve_code_reference(
                                  asset_url, best + name + ".js"),
                              "script", depth, "chunk-map")
                self.stats["synth_chunks"] = self.stats.get("synth_chunks", 0) + min(
                    len(names), self.max_synth_chunks)

        if self.follow_sourcemaps:
            for ref in JS_SOURCEMAP_RE.findall(text):
                if ref.startswith("data:"):
                    continue
                self._add(out, self._resolve_code_reference(asset_url, ref),
                          "map", depth)
        if self.scan_api:
            self._add_api(out, asset_url, text, depth)
        return list(out.values())

    def _add_api(self, out: dict[str, Candidate], asset_url: str, text: str, depth: int) -> None:
        """从 JS 里挑出接口地址。

        三条自我约束: 只收静态字面量（带 ${} / {{}} 的模板串跳过, 不猜参数）; 只收
        "应用自己就是 GET 读"的地址（POST/PUT/DELETE 一律不要, 免得 GET 到写接口）;
        只 GET 同源地址。所以这里不会构造出站点没打算暴露的请求。
        """
        if not self.scan_api or self.max_api <= 0:
            return
        found: list[str] = []
        for match in API_FETCH_RE.finditer(text):
            # fetch(url, {method: "POST"}) 这类虽然字面量是地址, 但语义是写操作, 跳过。
            # 只看这次调用自己的参数（截到第一个右括号）, 否则会把下一个 fetch 的 method 算进来
            tail = text[match.end():match.end() + 200].split(")", 1)[0]
            if API_METHOD_RE.search(tail):
                continue
            found.append(match.group(1))
        for pattern in (API_AXIOS_RE, API_JQUERY_RE, API_XHR_RE, API_URL_FIELD_RE):
            found.extend(pattern.findall(text))
        picked = 0
        for raw in found:
            ref = raw.strip()
            if not ref or any(token in ref for token in ("${", "{{", "}}", "://{", "?" + "{")):
                continue
            if ref.startswith(("data:", "blob:", "javascript:", "#")):
                continue
            if any(ch in ref for ch in (" ", "\n", "\t", "\\")):
                continue
            full = urljoin(asset_url, ref)
            path = urlparse(full).path
            if not path or path == "/":
                continue
            if API_EXT_SKIP.search(path) and not path.lower().endswith(API_EXT_OK):
                continue
            if "?" in full and "=" in full.split("?", 1)[1] and not API_EXT_OK and \
                    path.count(".") == 0 and not path.startswith("/api"):
                continue        # 带查询串的动态地址容易构造出无用请求, 只放行明显像接口的
            before = len(out)
            self._add(out, full, "api", depth, "接口响应")
            if len(out) > before:
                picked += 1
            if picked >= self.max_api:
                break
        if picked:
            self.stats["api_endpoints"] = self.stats.get("api_endpoints", 0) + picked

    @staticmethod
    def _string_maps(text: str, limit: int = 12) -> list[dict[str, str]]:
        """抽出源码里"{字符串: 字符串}"形态的对象字面量（webpack 映射表）。"""
        maps: list[dict[str, str]] = []
        for block in JS_STRING_MAP_RE.finditer(text):
            pairs = JS_MAP_PAIR_RE.findall(block.group(1))
            if len(pairs) >= 2:
                maps.append(dict(pairs))
            if len(maps) >= limit:
                break
        return maps

    @staticmethod
    def _js_hash_maps(text: str, limit: int = 4) -> list[dict[str, str]]:
        """抽出 `"." + {MAP}[e] + ".js"` 里的 MAP（真正用于 .js 哈希的那张表）。"""
        out: list[dict[str, str]] = []
        for match in JS_JS_HASH_MAP_RE.finditer(text):
            pairs = JS_MAP_PAIR_RE.findall(match.group(1))
            if len(pairs) >= 2:
                out.append(dict(pairs))
            if len(out) >= limit:
                break
        return out

    @staticmethod
    def _plausible_chunk_part(value: str) -> bool:
        """拼进文件名的那一段必须像文件名, 排除 "./af" 这类模块路径。"""
        return bool(value) and "/" not in value and "\\" not in value and len(value) <= 64


def config_probe_candidates(base_url: str) -> list[Candidate]:
    root = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    return [Candidate(url=root + path, kind="config", depth=0, label="常见配置入口")
            for path in COMMON_CONFIG_PATHS]


def looks_like_script_path(path: str) -> bool:
    return path.lower().split("?")[0].endswith(SCRIPT_EXT) or bool(STATIC_HINT.search(path))
