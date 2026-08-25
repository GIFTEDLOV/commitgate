import pytest

from commitgate_core import (
    GateError,
    MAX_CRITERIA_BYTES,
    MAX_PATH_LENGTH,
    MAX_POLICY_BYTES,
    checked_deadline,
    github_commit_url,
    github_content_url,
    validate_gate_terms,
    validate_repo_component,
    validate_review_path,
    validate_review_paths,
    validate_sha,
)


@pytest.mark.parametrize(
    "value",
    ["owner/repo", " owner", "owner ", "https://evil.test", "owner\\repo", "a:b", "..", "", "\x00x"],
)
def test_repository_injection_rejected(value):
    with pytest.raises(GateError):
        validate_repo_component(value, "repo_owner")


def test_repository_bounds():
    assert validate_repo_component("a" * 39, "repo_owner") == "a" * 39
    with pytest.raises(GateError):
        validate_repo_component("a" * 40, "repo_owner")
    assert validate_repo_component("r" * 100, "repo_name") == "r" * 100
    with pytest.raises(GateError):
        validate_repo_component("r" * 101, "repo_name")


@pytest.mark.parametrize("sha", ["a" * 39, "a" * 41, "A" * 40, "g" * 40, "main", "", None])
def test_sha_must_be_exact_lowercase_40_hex(sha):
    with pytest.raises(GateError):
        validate_sha(sha)


@pytest.mark.parametrize(
    "path",
    ["", "..", "../x", "a/../x", "/etc/passwd", r"C:\\x", r"a\\..\\x", "https://evil/x", "a//b", "a/./b", "a\x00b", " a"],
)
def test_path_attacks_rejected(path):
    with pytest.raises(GateError):
        validate_review_path(path)


def test_path_bounds_duplicates_and_ordering():
    with pytest.raises(GateError):
        validate_review_path("a" * (MAX_PATH_LENGTH + 1))
    with pytest.raises(GateError):
        validate_review_paths(["src/a.py", "src/a.py"])
    with pytest.raises(GateError):
        validate_review_paths([])
    with pytest.raises(GateError):
        validate_review_paths([f"src/{x}.py" for x in range(5)])
    assert validate_review_paths(["z.py", "a.py"]) == ["a.py", "z.py"]


def test_challenge_path_prefix_is_mandatory():
    assert validate_review_path(".commitgate/challenges/x.md", challenge=True)
    for value in ("challenges/x.md", ".commitgate/challenges", ".commitgate/challenges/../x"):
        with pytest.raises(GateError):
            validate_review_path(value, challenge=True)


def test_policy_criteria_and_window_bounds():
    args = ("owner", "repo", "a" * 40, "policy", "criteria", ["src/a.py"], 60, 60)
    terms = validate_gate_terms(*args)
    assert terms["review_paths"] == ["src/a.py"]
    for policy, criteria, cw, rw in [
        ("", "criteria", 60, 60),
        ("x" * (MAX_POLICY_BYTES + 1), "criteria", 60, 60),
        ("policy", "x" * (MAX_CRITERIA_BYTES + 1), 60, 60),
        ("policy", "criteria", 59, 60),
        ("policy", "criteria", 60, 604801),
        ("policy", "criteria", True, 60),
    ]:
        with pytest.raises(GateError):
            validate_gate_terms("owner", "repo", "a" * 40, policy, criteria, ["a"], cw, rw)


def test_urls_are_constructed_commit_pinned_and_fixed_host():
    sha = "a" * 40
    assert github_commit_url("owner", "repo", sha) == f"https://api.github.com/repos/owner/repo/commits/{sha}"
    url = github_content_url("owner", "repo", "src/a.py", sha)
    assert url == f"https://api.github.com/repos/owner/repo/contents/src/a.py?ref={sha}"
    assert "main" not in url and "latest" not in url and "raw_url" not in url


def test_checked_deadline_and_overflow():
    assert checked_deadline(100, 60) == 160
    with pytest.raises(GateError):
        checked_deadline(9_223_372_036_854_775_807, 1)

