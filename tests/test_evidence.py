import json
import pytest

from commitgate_core import (
    GateError,
    collect_challenge_evidence,
    collect_review_evidence,
    digest_json,
    github_commit_url,
    github_compare_url,
    github_content_url,
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
    compare,
    content,
    evidence_routes,
    response,
)


def collect(fetch):
    return collect_review_evidence(fetch, OWNER, REPO, BASE, TARGET, [PATH])


def test_authenticated_manifest_and_exact_content_digests():
    fetch = MockFetch(evidence_routes())
    manifest, semantic = collect(fetch)
    assert manifest["repo_owner"] == OWNER
    assert manifest["repo_name"] == REPO
    assert manifest["base_commit_sha"] == BASE
    assert manifest["target_commit_sha"] == TARGET
    assert manifest["lineage_verified"] is True
    assert manifest["ci"] == "NOT_USED_V1"
    assert manifest["files"][0]["base_presence"] == "PRESENT"
    assert manifest["files"][0]["target_presence"] == "PRESENT"
    assert semantic[0]["base"].startswith("def allowed")
    assert all(url.startswith("https://api.github.com/repos/GIFTEDLOV/commitgate-fixture/") for url in fetch.calls)


def test_content_mutation_changes_manifest_digest():
    first, _ = collect(MockFetch(evidence_routes(target_content=b"safe\n")))
    second, _ = collect(MockFetch(evidence_routes(target_content=b"unsafe\n")))
    assert digest_json(first) != digest_json(second)
    assert first["files"][0]["target_content_sha256"] != second["files"][0]["target_content_sha256"]


def test_wrong_repository_commit_binding_is_integrity_error():
    routes = evidence_routes()
    url = github_commit_url(OWNER, REPO, TARGET)
    bad = commit(OWNER, REPO, TARGET)
    bad["html_url"] = f"https://github.com/evil/repo/commit/{TARGET}"
    routes[url] = response(bad)
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))


@pytest.mark.parametrize("status", ["behind", "diverged", "identical"])
def test_invalid_or_unrelated_lineage_rejected(status):
    routes = evidence_routes()
    url = github_compare_url(OWNER, REPO, BASE, TARGET)
    bad = compare(OWNER, REPO, BASE, TARGET)
    bad["status"] = status
    routes[url] = response(bad)
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))


def test_malformed_lineage_response_rejected():
    routes = evidence_routes()
    routes[github_compare_url(OWNER, REPO, BASE, TARGET)] = response({"status": "ahead"})
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))


@pytest.mark.parametrize("which", ["base", "target"])
def test_missing_review_content_is_evidence_failure(which):
    routes = evidence_routes()
    sha = BASE if which == "base" else TARGET
    routes[github_content_url(OWNER, REPO, PATH, sha)] = response({"message": "Not Found"}, 404)
    with pytest.raises(GateError, match="EVIDENCE_ERROR"):
        collect(MockFetch(routes))


def test_hash_size_mismatch_is_integrity_failure():
    routes = evidence_routes()
    url = github_content_url(OWNER, REPO, PATH, TARGET)
    bad = content(OWNER, REPO, TARGET, PATH, b"safe")
    bad["size"] = 6
    routes[url] = response(bad)
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))


def test_malformed_base64_is_integrity_failure():
    routes = evidence_routes()
    url = github_content_url(OWNER, REPO, PATH, TARGET)
    bad = content(OWNER, REPO, TARGET, PATH, b"safe")
    bad["content"] = "%%%"
    routes[url] = response(bad)
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))


def test_github_unavailable_http_error_and_malformed_json_are_not_verdicts():
    url = github_commit_url(OWNER, REPO, BASE)
    for route in (RuntimeError("offline"), response({}, 503), (200, {}, b"{")):
        routes = evidence_routes()
        routes[url] = route
        with pytest.raises(GateError, match="EVIDENCE_ERROR"):
            collect(MockFetch(routes))


def test_redirect_is_rejected_without_following_location():
    routes = evidence_routes()
    url = github_content_url(OWNER, REPO, PATH, TARGET)
    routes[url] = (302, {"location": "https://evil.test/x"}, b"")
    fetch = MockFetch(routes)
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(fetch)
    assert "https://evil.test/x" not in fetch.calls


def test_malformed_github_shapes_and_duplicate_keys_fail():
    routes = evidence_routes()
    url = github_commit_url(OWNER, REPO, BASE)
    routes[url] = (200, {}, b'[{"sha":"x"}]')
    with pytest.raises(GateError, match="EVIDENCE_ERROR"):
        collect(MockFetch(routes))
    routes[url] = (200, {}, b'{"sha":"x","sha":"y"}')
    with pytest.raises(GateError, match="INTEGRITY_ERROR"):
        collect(MockFetch(routes))


def test_branch_head_substitution_cannot_enter_evidence_urls():
    fetch = MockFetch(evidence_routes())
    collect(fetch)
    assert all("?ref=main" not in url and "/heads/" not in url and "/latest" not in url for url in fetch.calls)


def test_challenge_is_commit_pinned_bounded_and_participant_authored():
    routes = evidence_routes()
    routes[github_commit_url(OWNER, REPO, CHALLENGE)] = response(commit(OWNER, REPO, CHALLENGE))
    routes[github_compare_url(OWNER, REPO, TARGET, CHALLENGE)] = response(compare(OWNER, REPO, TARGET, CHALLENGE))
    raw = b"Participant allegation; authentication does not make this true."
    routes[github_content_url(OWNER, REPO, CHALLENGE_PATH, CHALLENGE)] = response(
        content(OWNER, REPO, CHALLENGE, CHALLENGE_PATH, raw)
    )
    evidence, text = collect_challenge_evidence(
        MockFetch(routes), OWNER, REPO, TARGET, CHALLENGE, CHALLENGE_PATH
    )
    assert evidence["challenge_commit_sha"] == CHALLENGE
    assert evidence["challenge_path"].startswith(".commitgate/challenges/")
    assert text == raw.decode()


def test_ci_is_explicitly_excluded_not_faked():
    manifest, _ = collect(MockFetch(evidence_routes()))
    assert manifest["ci"] == "NOT_USED_V1"
    assert "ci_sha" not in manifest

