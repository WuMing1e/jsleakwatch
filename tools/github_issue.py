#!/usr/bin/env python3
"""通过 GitHub REST API 查询或创建去重后的 Issue。

认证令牌从 GITHUB_TOKEN 读取；未设置时调用 git credential fill，兼容本机
osxkeychain。脚本只输出 Issue 编号、URL 和是否新建，不会打印令牌。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


API = "https://api.github.com"
MARKER = "<!-- jslw-automation-issue -->"


def repo_from_remote(raw: str) -> str:
    value = (raw or "").strip()
    match = re.search(r"github\.com[/:]([^/\s]+)/([^/\s]+?)(?:\.git)?$", value)
    if not match:
        raise ValueError(f"无法从 origin 识别 GitHub 仓库: {value}")
    return f"{match.group(1)}/{match.group(2)}"


def current_repo(root: Path) -> str:
    try:
        raw = subprocess.check_output(
            ["git", "remote", "get-url", "origin"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("当前目录不是带 origin 的 Git 仓库") from exc
    return repo_from_remote(raw)


def git_token() -> str:
    token = (os.getenv("GITHUB_TOKEN") or "").strip()
    if token:
        return token
    try:
        result = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            text=True,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("没有 GITHUB_TOKEN，且 git credential 无法提供令牌") from exc
    for line in result.stdout.splitlines():
        if line.startswith("password="):
            value = line.split("=", 1)[1].strip()
            if value:
                return value
    raise RuntimeError("git credential 中没有 GitHub 令牌")


def api_request(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {git_token()}",
            "Content-Type": "application/json",
            "User-Agent": "JSLeakWatch-issue-automation",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("message", "")
        except (ValueError, AttributeError):
            detail = ""
        raise RuntimeError(f"GitHub API {method} {path} 失败: HTTP {exc.code} {detail[:200]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GitHub API 连接失败: {exc.reason}") from exc


def normalize_title(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip()).casefold()


def open_issues(repo: str) -> list[dict[str, Any]]:
    rows = api_request("GET", f"/repos/{repo}/issues?state=open&per_page=100")
    return [item for item in rows if not item.get("pull_request")]


def find_issue(repo: str, title: str) -> dict[str, Any] | None:
    wanted = normalize_title(title)
    for item in open_issues(repo):
        body = str(item.get("body") or "")
        if normalize_title(str(item.get("title") or "")) == wanted or MARKER in body:
            return item
    return None


def issue_payload(title: str, body: str, labels: list[str]) -> dict[str, Any]:
    clean_title = re.sub(r"\s+", " ", title or "").strip()
    if len(clean_title) < 8:
        raise ValueError("Issue 标题至少需要 8 个字符")
    if MARKER not in body:
        body = body.rstrip() + f"\n\n{MARKER}\n"
    return {
        "title": clean_title[:240],
        "body": body[:65000],
        "labels": [item for item in dict.fromkeys(labels) if item],
    }


def summary(item: dict[str, Any], created: bool) -> dict[str, Any]:
    return {
        "created": created,
        "number": item.get("number"),
        "title": item.get("title"),
        "url": item.get("html_url"),
        "state": item.get("state"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="查询或创建去重后的 GitHub Issue")
    parser.add_argument("--repo", default="", help="owner/repo；默认读取 origin")
    sub = parser.add_subparsers(dest="command", required=True)

    find = sub.add_parser("find", help="查找同名 open Issue")
    find.add_argument("--title", required=True)

    ensure = sub.add_parser("ensure", help="不存在时创建 Issue，存在则复用")
    ensure.add_argument("--title", required=True)
    body = ensure.add_mutually_exclusive_group(required=True)
    body.add_argument("--body")
    body.add_argument("--body-file")
    ensure.add_argument("--label", action="append", default=["bug"])

    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    repo = args.repo or current_repo(root)

    try:
        existing = find_issue(repo, args.title)
        if args.command == "find":
            print(json.dumps({
                "found": existing is not None,
                "issue": summary(existing, False) if existing else None,
            }, ensure_ascii=False))
            return 0
        if existing:
            print(json.dumps(summary(existing, False), ensure_ascii=False))
            return 0
        body_text = Path(args.body_file).read_text(encoding="utf-8") if args.body_file else args.body
        payload = issue_payload(args.title, body_text or "", args.label)
        created = api_request("POST", f"/repos/{repo}/issues", payload)
        print(json.dumps(summary(created, True), ensure_ascii=False))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
