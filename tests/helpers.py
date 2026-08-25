import base64
import json

from commitgate_core import (
    github_commit_url,
    github_compare_url,
    github_content_url,
)


OWNER = "GIFTEDLOV"
REPO = "commitgate-fixture"
BASE = "1" * 40
TARGET = "2" * 40
RESPONSE = "3" * 40
CHALLENGE = "4" * 40
PATH = "src/guard.py"
CHALLENGE_PATH = ".commitgate/challenges/authorization.md"


class MockFetch:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        value = self.routes[url]
        if isinstance(value, Exception):
            raise value
        return value


def response(value, status=200):
    body = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
    return status, {}, body


def commit(owner, repo, sha):
    url = github_commit_url(owner, repo, sha)
    return {
        "sha": sha,
        "url": url,
        "html_url": f"https://github.com/{owner}/{repo}/commit/{sha}",
    }


def compare(owner, repo, base, target):
    return {
        "status": "ahead",
        "ahead_by": 1,
        "behind_by": 0,
        "base_commit": {"sha": base},
        "merge_base_commit": {"sha": base},
        "commits": [{"sha": target}],
    }


def content(owner, repo, sha, path, raw):
    url = github_content_url(owner, repo, path, sha)
    return {
        "type": "file",
        "path": path,
        "url": url,
        "download_url": f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}",
        "encoding": "base64",
        "size": len(raw),
        "content": base64.b64encode(raw).decode(),
    }


def evidence_routes(
    owner=OWNER,
    repo=REPO,
    base=BASE,
    target=TARGET,
    path=PATH,
    base_content=b"def allowed(user):\n    return True\n",
    target_content=b"def allowed(user):\n    return user.is_admin\n",
):
    return {
        github_commit_url(owner, repo, base): response(commit(owner, repo, base)),
        github_commit_url(owner, repo, target): response(commit(owner, repo, target)),
        github_compare_url(owner, repo, base, target): response(compare(owner, repo, base, target)),
        github_content_url(owner, repo, path, base): response(content(owner, repo, base, path, base_content)),
        github_content_url(owner, repo, path, target): response(content(owner, repo, target, path, target_content)),
    }

