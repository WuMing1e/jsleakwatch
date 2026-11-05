"""GitHub Issue 自动化工具的离线单元测试。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import github_issue  # noqa: E402


@pytest.mark.parametrize("remote, expected", [
    ("https://github.com/WuMing1e/jsleakwatch.git", "WuMing1e/jsleakwatch"),
    ("git@github.com:WuMing1e/jsleakwatch.git", "WuMing1e/jsleakwatch"),
    ("https://github.com/WuMing1e/jsleakwatch", "WuMing1e/jsleakwatch"),
])
def test_repo_from_remote(remote: str, expected: str) -> None:
    assert github_issue.repo_from_remote(remote) == expected


def test_issue_payload_adds_marker_and_deduplicates_labels() -> None:
    payload = github_issue.issue_payload(
        "  自动巡检   发现扫描状态过滤失效  ",
        "复现步骤",
        ["bug", "automation", "bug"],
    )
    assert payload["title"] == "自动巡检 发现扫描状态过滤失效"
    assert payload["labels"] == ["bug", "automation"]
    assert github_issue.MARKER in payload["body"]


def test_find_issue_matches_normalized_title_without_search_api(monkeypatch) -> None:
    monkeypatch.setattr(github_issue, "open_issues", lambda repo: [
        {"number": 7, "title": "自动巡检  发现扫描状态过滤失效", "state": "open"},
        {"number": 8, "title": "另一个问题", "state": "open"},
    ])
    found = github_issue.find_issue("owner/repo", "自动巡检 发现扫描状态过滤失效")
    assert found is not None and found["number"] == 7


def test_issue_payload_rejects_short_title() -> None:
    with pytest.raises(ValueError, match="至少需要"):
        github_issue.issue_payload("bug", "body", ["bug"])
