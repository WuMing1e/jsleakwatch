"""资产发现单元测试。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.discover import Extractor, config_probe_candidates  # noqa: E402

BASE = "https://shop.example.com/"


def extractor(scope: str = "same-origin") -> Extractor:
    return Extractor(base_url=BASE, scope=scope)


def test_html_scripts_and_inline() -> None:
    html = """
    <html><head>
      <script src="/js/app.js"></script>
      <script src="https://cdn.other.com/lib.js"></script>
      <script>window.__C = {apiKey: "aB3kQ9mZx2VnPr7YqW3FbC8dE1fG4hI6j"};</script>
    </head></html>"""
    found = extractor().from_html(BASE, html, 0)
    scripts = {c.url for c in found if c.kind == "script"}
    inline = [c for c in found if c.kind == "inline"]
    assert "https://shop.example.com/js/app.js" in scripts
    assert all("other.com" not in url for url in scripts)  # 默认不跨域
    assert len(inline) == 1 and "apiKey" in inline[0].inline


def test_prefetched_scripts_are_discovered() -> None:
    html = """
    <link rel="modulepreload" href="/assets/app-AbCd1234.js">
    <link rel="prefetch" href="/assets/lazy-EfGh5678.js">
    <link rel="prefetch" href="/assets/style.css">
    """
    scripts = {c.url for c in extractor().from_html(BASE, html, 0) if c.kind == "script"}
    assert "https://shop.example.com/assets/app-AbCd1234.js" in scripts
    assert "https://shop.example.com/assets/lazy-EfGh5678.js" in scripts
    assert not any(url.endswith(".css") for url in scripts)


def test_cross_origin_script_switch_only_allows_scripts() -> None:
    html = """
    <script src="https://cdn.other.com/lib.js"></script>
    <a href="https://cdn.other.com/page">跨域页面</a>
    """
    assert extractor().from_html(BASE, html, 0) == []

    cross = Extractor(base_url=BASE, scope="same-origin",
                      allow_cross_origin_scripts=True)
    candidates = cross.from_html(BASE, html, 0)
    assert {c.url for c in candidates} == {"https://cdn.other.com/lib.js"}


def test_js_dynamic_import_and_sourcemap() -> None:
    js = 'import("/js/lazy.js");\n//# sourceMappingURL=app.js.map'
    found = extractor().from_js("https://shop.example.com/js/app.js", js, 0)
    kinds = {(c.kind, c.url) for c in found}
    assert ("script", "https://shop.example.com/js/lazy.js") in kinds
    assert ("map", "https://shop.example.com/js/app.js.map") in kinds


def test_webpack_chunk_map_is_expanded() -> None:
    js = 'var p="/js/";var m={"0":"vendor","1":"4f2a1b","2":"9c3d7e"};'
    urls = {c.url for c in extractor().from_js("https://shop.example.com/js/app.js", js, 0)}
    assert "https://shop.example.com/js/4f2a1b.js" in urls
    assert "https://shop.example.com/js/9c3d7e.js" in urls


def test_chunk_map_without_hash_is_ignored() -> None:
    js = 'var p="/js/";var m={"a":"home","b":"about","c":"contact"};'
    urls = {c.url for c in extractor().from_js("https://shop.example.com/js/app.js", js, 0)}
    assert not any("home.js" in u for u in urls)


def test_vue_cli_name_plus_hash_maps_are_joined() -> None:
    """回归（真实站点测试发现）: Vue CLI 的输出是"名字表 + 哈希表"两表拼接,
    且表里的 key 不带引号。早期只认数字键映射表, 这类 chunk 全部漏采。"""
    js = ('var app=function(e){return"js/"+({AccountListList:"AccountListList",'
          'RoleManageADD:"RoleManageADD",about:"about"}[e]||e)+"."+'
          '{AccountListList:"3601b1da",RoleManageADD:"51406e15",about:"ba4219c8"}[e]+".js"}')
    urls = {c.url for c in Extractor(base_url="https://s.test/").from_js(
        "https://s.test/js/app.abc123.js", js, 0)}
    assert "https://s.test/js/AccountListList.3601b1da.js" in urls
    assert "https://s.test/js/RoleManageADD.51406e15.js" in urls
    assert "https://s.test/js/about.ba4219c8.js" in urls


def test_two_hash_maps_are_not_cross_joined() -> None:
    """产物里常同时有几张哈希表; 哈希表互配会产出 "hash.hash.js" 这类不存在的名字。

    注: "名字表 × 第二张哈希表" 是允许的取舍 —— 从静态代码无法判断哪张才是
    JS 的 contenthash 表, 多试几个的成本是一次 404。
    """
    import re

    js = ('var a="js/"+({x:"x",y:"y"}[e])+"."+{x:"aaaaaaaa",y:"bbbbbbbb"}[e]+".js";'
          'var b={x:"11111111",y:"22222222"};')
    urls = {c.url for c in Extractor(base_url="https://s.test/").from_js(
        "https://s.test/js/a.js", js, 0)}
    assert "https://s.test/js/x.aaaaaaaa.js" in urls
    assert not any(re.search(r"\.[0-9a-f]{8}\.[0-9a-f]{8}\.js$", u) for u in urls)


def test_library_module_specifiers_are_not_treated_as_chunks() -> None:
    """回归（真实站点测试发现）: moment 语言包里的 "./af.js" 是模块 id,
    抓它只会得到 404。带哈希的产物路径仍应保留。"""
    js = ('var m={"./af.js":"2bfb","./ar-dz.js":"a356"};'
          'var real="./chunk.9f8e7d6c.js";')
    urls = {c.url for c in Extractor(base_url="https://s.test/").from_js(
        "https://s.test/js/app.js", js, 0)}
    assert not any(u.endswith("/af.js") or u.endswith("/ar-dz.js") for u in urls)
    assert any("chunk.9f8e7d6c.js" in u for u in urls)


def test_bundler_source_paths_are_not_treated_as_assets() -> None:
    """回归（真实站点）: node_modules 与 webpack loader 模板不能变成线上 URL。"""
    js = """
      require("node_modules/core-js/internals/ieee754.js");
      require("node-forge/lib/ed25519.js");
      const bad = "}!./node_modules/vue-loader/lib/loaders/templateLoader.js";
      const real = "static/js/chunk-AbCd1234.js";
      const locale = "locale.js";
    """
    urls = {c.url for c in extractor().from_js(
        "https://shop.example.com/static/js/index-Main1234.js", js, 1)}
    assert "https://shop.example.com/static/js/chunk-AbCd1234.js" in urls
    assert "https://shop.example.com/static/js/locale.js" in urls
    assert not any("node_modules" in url or "vue-loader" in url for url in urls)


def test_js_template_paths_are_not_treated_as_assets() -> None:
    """带运行时变量的 import 路径不能猜成具体 URL。"""
    js = """
      import(`./assets/${name}.js`);
      import(`./panels/${panel}/index.js`);
      importScripts("/workers/${version}/worker.js");
      const real = "assets/index-AbCd1234.js";
    """
    urls = {c.url for c in extractor().from_js(
        "https://shop.example.com/assets/main-Main1234.js", js, 1)}
    assert urls == {"https://shop.example.com/assets/index-AbCd1234.js"}


def test_css_hash_map_is_not_used_for_js_chunks() -> None:
    """回归（真实站点发现）: 同一份产物里有一张拼 .js 的表，还有一张拼 .css 的同名表。
    用后者合成 .js 必然 404 —— 实测在一个站点上白发了 13 个请求。"""
    js = ('var a="js/"+({x:"x",y:"y"}[e]||e)+"."+{x:"aaaaaaaa",y:"bbbbbbbb"}[e]+".js";'
          'var c="css/"+({x:"x",y:"y"}[e]||e)+"."+{x:"11111111",y:"22222222"}[e]+".css";')
    urls = {c.url for c in Extractor(base_url="https://s.test/").from_js(
        "https://s.test/js/a.js", js, 0)}
    assert "https://s.test/js/x.aaaaaaaa.js" in urls
    assert not any("11111111" in u for u in urls), "不应把 CSS 哈希表拼成 .js"


def test_relative_chunk_path_does_not_duplicate_static_prefix() -> None:
    """Vite 依赖表里的 static/js 路径不能与当前 /static/js 目录重复拼接。"""
    js = """
      const deps = ["static/js/index-AbCd1234.js", "static/js/vendor-EfGh5678.js"];
      import("./locale.js");
      const nested = "chunks/panel-IjKl9012.js";
    """
    urls = {c.url for c in extractor().from_js(
        "https://shop.example.com/static/js/index-Main1234.js", js, 1)}
    assert "https://shop.example.com/static/js/index-AbCd1234.js" in urls
    assert "https://shop.example.com/static/js/vendor-EfGh5678.js" in urls
    assert "https://shop.example.com/static/js/locale.js" in urls
    assert "https://shop.example.com/static/js/chunks/panel-IjKl9012.js" in urls
    assert not any("/static/js/static/js/" in url for url in urls)


def test_relative_chunk_path_preserves_app_mount_prefix() -> None:
    urls = {c.url for c in extractor().from_js(
        "https://shop.example.com/app/static/js/index-Main1234.js",
        'const deps = ["static/js/lazy-AbCd1234.js"];', 1)}
    assert urls == {"https://shop.example.com/app/static/js/lazy-AbCd1234.js"}


def test_pages_from_html_same_origin_only() -> None:
    html = '<a href="/about">a</a><a href="https://other.com/x">b</a><a href="/logo.png">c</a>'
    pages = {c.url for c in extractor().pages_from_html(BASE, html, 1)}
    assert "https://shop.example.com/about" in pages
    assert not any("other.com" in p for p in pages)
    assert not any(p.endswith("logo.png") for p in pages)


def test_scope_any_allows_cross_origin() -> None:
    html = '<script src="https://cdn.other.com/lib.js"></script>'
    found = extractor("any").from_html(BASE, html, 0)
    assert any("other.com" in c.url for c in found)


def test_config_probe_candidates() -> None:
    urls = {c.url for c in config_probe_candidates(BASE)}
    assert "https://shop.example.com/config.js" in urls
    assert "https://shop.example.com/env.js" in urls


def api_urls(js: str, **kwargs) -> set[str]:
    ex = Extractor(base_url=BASE, scope="same-origin", scan_api=True, **kwargs)
    out: dict = {}
    ex._add_api(out, f"{BASE}js/app.js", js, 1)
    return {cand.url for cand in out.values()}


def test_api_endpoints_only_read_calls() -> None:
    js = """
    fetch("/api/v1/config");
    fetch("/api/v1/write", { method: "POST", body: payload });
    axios.get("/api/user/profile");
    axios.post("/api/v1/notify", payload);
    $.getJSON("/api/v1/list");
    $.post("/api/v1/create");
    xhr.open("GET", "/api/v1/orders?page=1");
    xhr.open("POST", "/api/v1/remove");
    """
    urls = api_urls(js)
    assert urls == {
        "https://shop.example.com/api/v1/config",
        "https://shop.example.com/api/user/profile",
        "https://shop.example.com/api/v1/list",
        "https://shop.example.com/api/v1/orders?page=1",
    }, "只收应用自己就是 GET 读的地址, 写接口一律不要"


def test_api_endpoints_skip_templates_and_static() -> None:
    js = """
    fetch(`/api/tpl/${id}/detail`);
    fetch("/static/logo.png");
    fetch("/js/main.js");
    fetch("https://cdn.other.com/api/x");
    const cfg = { url: "/internal/settings.json" };
    """
    urls = api_urls(js)
    assert urls == {"https://shop.example.com/internal/settings.json"}, \
        "模板地址、静态资源、跨域地址都要跳过"


def test_api_endpoints_respect_cap_and_toggle() -> None:
    js = "\n".join(f'fetch("/api/v1/item{i}");' for i in range(10))
    assert len(api_urls(js, max_api=3)) == 3, "单站接口上限要生效"
    off = Extractor(base_url=BASE, scope="same-origin")
    out: dict = {}
    off._add_api(out, f"{BASE}js/app.js", js, 1)
    assert out == {}, "开关关闭时不采集任何接口"
