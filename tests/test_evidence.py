import pytest

from commitgate_core import (
    GateError,
    MAX_ANCESTRY_COMMITS,
    MAX_REVIEW_FILE_BYTES,
    collect_challenge_evidence,
    collect_review_evidence,
    digest_json,
    github_git_commit_url,
    github_raw_url,
    github_repository_url,
)
from tests.helpers import (
    BASE,
    CHALLENGE,
    CHALLENGE_PATH,
    OWNER,
    PATH,
    REPO,
    TARGET,
    MockFetch,
    commit,
    evidence_routes,
    repository,
    response,
)


def collect(fetch):
    return collect_review_evidence(fetch, OWNER, REPO, BASE, TARGET, [PATH])


def test_authenticated_manifest_and_exact_content_digests():
    fetch = MockFetch(evidence_routes())
    manifest, semantic = collect(fetch)
    assert manifest["repo_owner"] == OWNER
    assert manifest["repo_name"] == REPO
    assert manifest["github_repository_id"] == 987654321
    assert manifest["base_commit_sha"] == BASE
    assert manifest["target_commit_sha"] == TARGET
    assert manifest["lineage_verified"] is True
    assert manifest["ci"] == "NOT_USED_V1"
    assert manifest["files"][0]["base_presence"] == "PRESENT"
    assert manifest["files"][0]["target_presence"] == "PRESENT"
    assert semantic[0]["base"].startswith("def allowed")
    assert github_repository_url(OWNER, REPO) in fetch.calls
    assert github_git_commit_url(OWNER, REPO, TARGET) in fetch.calls
    assert github_raw_url(OWNER, REPO, PATH, BASE) in fetch.calls
    assert not any("/commits/" in url and "/git/commits/" not in url for url in fetch.calls)
    assert all("/compare/" not in url for url in fetch.calls)
    assert all("/contents/" not in url for url in fetch.calls)


def test_large_legacy_commit_metadata_is_not_requested():
    routes = evidence_routes()
    legacy_url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits/{BASE}"
    routes[legacy_url] = response(b"x" * 300_000)
    fetch = MockFetch(routes)
    collect(fetch)
    assert legacy_url not in fetch.calls
    assert all("/compare/" not in url and "/contents/" not in url for url in fetch.calls)


def test_compact_git_data_commit_endpoint_is_used():
    fetch = MockFetch(evidence_routes())
    collect(fetch)
    assert any("/git/commits/" in url for url in fetch.calls)
    assert not any("/commits/" in url and "/git/commits/" not in url for url in fetch.calls)


def test_raw_commit_pinned_paths_are_used_without_contents_json():
    fetch = MockFetch(evidence_routes())
    collect(fetch)
    raw_urls = [url for url in fetch.calls if url.startswith("https://raw.githubusercontent.com/")]
    assert raw_urls == [
        github_raw_url(OWNER, REPO, PATH, BASE),
        github_raw_url(OWNER, REPO, PATH, TARGET),
    ]


def test_content_mutation_changes_manifest_digest():
    first, _ = collect(MockFetch(evidence_routes(target_content=b"safe\n")))
    second, _ = collect(MockFetch(evidence_routes(target_content=b"unsafe\n")))
    assert digest_json(first) != digest_json(second)
    assert first["files"][0]["target_content_sha256"] != second["files"][0]["target_content_sha256"]


def test_direct_child_lineage_passes():
    collect(MockFetch(evidence_routes()))


def test_bounded_multi_parent_lineage_passes():
    unrelated = "4" * 40
    routes = evidence_routes()
    routes[github_git_commit_url(OWNER, REPO, TARGET)] = response(
        commit(OWNER, REPO, TARGET, [unrelated, BASE])
    )
    routes[github_git_commit_url(OWNER, REPO, unrelated)] = response(
        commit(OWNER, REPO, unrelated)
    )
    fetch = MockFetch(routes)
    collect(fetch)
    assert github_git_commit_url(OWNER, REPO, unrelated) in fetch.calls


def test_non_descendant_fails_closed():
    unrelated = "4" * 40
    routes = evidence_routes()
    routes[github_git_commit_url(OWNER, REPO, TARGET)] = response(
        commit(OWNER, REPO, TARGET, [unrelated])
    )
    routes[github_git_commit_url(OWNER, REPO, unrelated)] = response(
        commit(OWNER, REPO, unrelated)
    )
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))


def test_lineage_beyond_traversal_bound_is_evidence_error():
    chain = [f"{index:040x}" for index in range(MAX_ANCESTRY_COMMITS + 1)]
    routes = {github_repository_url(OWNER, REPO): response(repository(OWNER, REPO))}
    for index, sha in enumerate(chain):
        parents = [chain[index + 1]] if index + 1 < len(chain) else []
        routes[github_git_commit_url(OWNER, REPO, sha)] = response(
            commit(OWNER, REPO, sha, parents)
        )
    with pytest.raises(GateError, match="EVIDENCE_ERROR.*traversal bound"):
        collect_review_evidence(MockFetch(routes), OWNER, REPO, chain[-1], chain[0], [PATH])


def test_wrong_repository_identity_fails():
    routes = evidence_routes()
    routes[github_repository_url(OWNER, REPO)] = response(
        repository("other-owner", REPO)
    )
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))


@pytest.mark.parametrize("which", ["base", "target"])
def test_missing_review_content_is_evidence_failure(which):
    routes = evidence_routes()
    sha = BASE if which == "base" else TARGET
    routes[github_raw_url(OWNER, REPO, PATH, sha)] = response(b"", 404)
    with pytest.raises(GateError, match="EVIDENCE_ERROR"):
        collect(MockFetch(routes))


def test_oversized_raw_file_is_evidence_failure():
    routes = evidence_routes()
    routes[github_raw_url(OWNER, REPO, PATH, TARGET)] = response(
        b"x" * (MAX_REVIEW_FILE_BYTES + 1)
    )
    with pytest.raises(GateError, match="EVIDENCE_ERROR"):
        collect(MockFetch(routes))


def test_redirect_is_rejected_without_following_location():
    routes = evidence_routes()
    url = github_raw_url(OWNER, REPO, PATH, TARGET)
    routes[url] = (302, {"location": "https://evil.test/x"}, b"")
    fetch = MockFetch(routes)
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(fetch)
    assert "https://evil.test/x" not in fetch.calls


def test_malformed_git_commit_shapes_and_duplicate_keys_fail():
    routes = evidence_routes()
    url = github_git_commit_url(OWNER, REPO, BASE)
    routes[url] = response({"sha": BASE})
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))
    routes[url] = (200, {}, b'{"sha":"x","sha":"y"}')
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))


def test_commit_repository_binding_is_authenticated():
    routes = evidence_routes()
    url = github_git_commit_url(OWNER, REPO, TARGET)
    bad = commit(OWNER, REPO, TARGET, [BASE])
    bad["html_url"] = f"https://github.com/evil/repo/commit/{TARGET}"
    routes[url] = response(bad)
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))


def test_raw_non_utf8_content_is_evidence_failure():
    routes = evidence_routes(target_content=b"\xff\xfe")
    with pytest.raises(GateError, match="EVIDENCE_ERROR"):
        collect(MockFetch(routes))


def test_github_unavailable_http_error_and_malformed_json_are_not_verdicts():
    url = github_git_commit_url(OWNER, REPO, BASE)
    for route in (RuntimeError("offline"), response({}, 503), (200, {}, b"{")):
        routes = evidence_routes()
        routes[url] = route
        with pytest.raises(GateError, match="EVIDENCE_ERROR"):
            collect(MockFetch(routes))


def test_branch_head_substitution_cannot_enter_evidence_urls():
    fetch = MockFetch(evidence_routes())
    collect(fetch)
    assert all("?ref=main" not in url and "/heads/" not in url and "/latest" not in url for url in fetch.calls)


def test_challenge_uses_compact_identity_lineage_and_raw_path():
    routes = evidence_routes()
    challenge_bytes = b"Participant allegation; authentication does not make this true."
    routes[github_git_commit_url(OWNER, REPO, CHALLENGE)] = response(
        commit(OWNER, REPO, CHALLENGE, [TARGET])
    )
    routes[github_raw_url(OWNER, REPO, CHALLENGE_PATH, CHALLENGE)] = response(challenge_bytes)
    fetch = MockFetch(routes)
    evidence, text = collect_challenge_evidence(
        fetch, OWNER, REPO, TARGET, CHALLENGE, CHALLENGE_PATH
    )
    assert evidence["github_repository_id"] == 987654321
    assert evidence["challenge_commit_sha"] == CHALLENGE
    assert evidence["challenge_path"].startswith(".commitgate/challenges/")
    assert text == challenge_bytes.decode()
    assert github_raw_url(OWNER, REPO, CHALLENGE_PATH, CHALLENGE) in fetch.calls
    assert not any("/compare/" in url or "/contents/" in url for url in fetch.calls)


def test_ci_is_explicitly_excluded_not_faked():
    manifest, _ = collect(MockFetch(evidence_routes()))
    assert manifest["ci"] == "NOT_USED_V1"
    assert "ci_sha" not in manifest
