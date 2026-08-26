import json

from commitgate_core import (
    github_git_commit_url,
    github_raw_url,
    github_repository_url,
)


OWNER = "GIFTEDLOV"
REPO = "commitgate-fixture"
BASE = "1" * 40
TARGET = "2" * 40
RESPONSE = "3" * 40
CHALLENGE = "4" * 40
PATH = "src/guard.py"
CHALLENGE_PATH = ".commitgate/challenges/authorization.md"
REPO_ID = 987654321


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


def repository(owner, repo, repository_id=REPO_ID):
    return {
        "id": repository_id,
        "full_name": f"{owner}/{repo}",
    }


def commit(owner, repo, sha, parents=()):
    url = github_git_commit_url(owner, repo, sha)
    return {
        "sha": sha,
        "url": url,
        "html_url": f"https://github.com/{owner}/{repo}/commit/{sha}",
        "parents": [{"sha": parent} for parent in parents],
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
        github_git_commit_url(owner, repo, base): response(commit(owner, repo, base)),
        github_git_commit_url(owner, repo, target): response(commit(owner, repo, target, [base])),
        github_raw_url(owner, repo, path, base): response(base_content),
        github_raw_url(owner, repo, path, target): response(target_content),
        # Keep the repository route last for the released GLSim mock matcher,
        # which treats patterns as prefixes rather than exact URLs.
        github_repository_url(owner, repo): response(repository(owner, repo)),
    }
