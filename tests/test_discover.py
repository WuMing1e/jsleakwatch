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


def test_css_hash_map_is_not_used_for_js_chunks() -> None:
    """回归（真实站点发现）: 同一份产物里有一张拼 .js 的表，还有一张拼 .css 的同名表。
    用后者合成 .js 必然 404 —— 实测在一个站点上白发了 13 个请求。"""
    js = ('var a="js/"+({x:"x",y:"y"}[e]||e)+"."+{x:"aaaaaaaa",y:"bbbbbbbb"}[e]+".js";'
          'var c="css/"+({x:"x",y:"y"}[e]||e)+"."+{x:"11111111",y:"22222222"}[e]+".css";')
    urls = {c.url for c in Extractor(base_url="https://s.test/").from_js(
        "https://s.test/js/a.js", js, 0)}
    assert "https://s.test/js/x.aaaaaaaa.js" in urls
    assert not any("11111111" in u for u in urls), "不应把 CSS 哈希表拼成 .js"


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
