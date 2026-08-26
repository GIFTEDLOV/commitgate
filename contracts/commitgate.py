# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""CommitGate: challenge-aware software release authorization.

This source targets the exact runner published in current official GenLayer
documentation and available on Bradbury GenVM v0.2.11.  The
release script in ``tools/make_deployable.py`` inlines ``commitgate_core.py`` so
the deployed artifact is a single independently reproducible file.
"""

from genlayer import *
from datetime import datetime
import json

from commitgate_core import (
    GateError,
    MAX_RESPONSE_ATTEMPTS,
    assessment_digest,
    build_semantic_prompt,
    canonical_json,
    checked_deadline,
    collect_challenge_evidence,
    collect_review_evidence,
    digest_json,
    final_authorization_record,
    require_transition,
    strict_parse_verdict,
    validate_address,
    validate_gate_terms,
    validate_review_path,
    validate_sha,
    verify_lineage,
)

class CommitGate(gl.Contract):
    gates: TreeMap[str, str]
    submissions: TreeMap[str, str]
    assessments: TreeMap[str, str]
    challenges: TreeMap[str, str]
    authorizations: TreeMap[str, str]
    submitted_targets: TreeMap[str, str]
    gate_ids: TreeMap[str, str]
    gate_count: u256
    submission_count: u256
    assessment_count: u256
    challenge_count: u256

    def __init__(self):
        self.gate_count = 0
        self.submission_count = 0
        self.assessment_count = 0
        self.challenge_count = 0

    def _now(self) -> int:
        raw = gl.message_raw["datetime"]
        return int(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())

    def _sender(self) -> str:
        return validate_address(gl.message.sender_address, "caller")

    def _load_json(self, mapping, key: str, kind: str) -> dict:
        if key not in mapping:
            raise gl.vm.UserError(f"INTEGRITY_ERROR:unknown {kind}")
        # TreeMap[str, str] yields a primitive memory string, not a storage
        # proxy (copy_to_memory asserts for primitives in the Bradbury SDK).
        # JSON decoding then creates the isolated mutable memory object used by
        # nondeterministic closures.
        raw = mapping[key]
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise gl.vm.UserError(f"INTEGRITY_ERROR:corrupt {kind}")
        return value

    def _store_gate(self, gate: dict) -> None:
        self.gates[gate["gate_id"]] = canonical_json(gate)

    def _require_caller(self, expected: str, role: str) -> None:
        if self._sender() != expected:
            raise gl.vm.UserError(f"INTEGRITY_ERROR:caller is not {role}")

    def _derive_assessment(
        self,
        gate: dict,
        submission_id: str,
        target_sha: str,
        fetch,
        challenge_context: dict | None = None,
    ) -> dict:
        manifest, semantic_inputs = collect_review_evidence(
            fetch,
            gate["repo_owner"],
            gate["repo_name"],
            gate["base_commit_sha"],
            target_sha,
            gate["review_paths"],
        )
        challenge_digest = ""
        challenge_text = ""
        prompt_challenge = None
        if challenge_context is not None:
            challenge_evidence, challenge_text = collect_challenge_evidence(
                fetch,
                gate["repo_owner"],
                gate["repo_name"],
                gate["current_target_sha"],
                challenge_context["challenge_commit_sha"],
                challenge_context["challenge_path"],
            )
            challenge_digest = digest_json(challenge_evidence)
            if challenge_digest != challenge_context["challenge_evidence_digest"]:
                raise GateError("INTEGRITY_ERROR", "challenge evidence digest changed")
            challenged_manifest, challenged_inputs = collect_review_evidence(
                fetch,
                gate["repo_owner"],
                gate["repo_name"],
                gate["base_commit_sha"],
                gate["current_target_sha"],
                gate["review_paths"],
            )
            verify_lineage(
                fetch,
                gate["repo_owner"],
                gate["repo_name"],
                gate["current_target_sha"],
                target_sha,
                allow_equal=True,
            )
            prompt_challenge = {
                "challenge_evidence": challenge_evidence,
                "challenged_evidence_manifest": challenged_manifest,
                "challenged_review_content": challenged_inputs,
                "response_target_sha": target_sha,
            }
        prompt = build_semantic_prompt(
            gate["software_policy"],
            gate["acceptance_criteria"],
            manifest,
            semantic_inputs,
            prompt_challenge,
            challenge_text,
        )
        raw = gl.nondet.exec_prompt(prompt)
        verdict = strict_parse_verdict(raw)
        manifest_digest = digest_json(manifest)
        result = {
            "verdict": verdict,
            "target_sha": target_sha,
            "evidence_manifest": manifest,
            "evidence_manifest_digest": manifest_digest,
            "assessment_digest": assessment_digest(
                gate["gate_id"],
                submission_id,
                verdict,
                manifest_digest,
                gate["policy_digest"],
                challenge_digest,
            ),
            "challenge_evidence_digest": challenge_digest,
        }
        return result

    def _consensus_assessment(
        self,
        gate: dict,
        submission_id: str,
        target_sha: str,
        challenge_context: dict | None = None,
    ) -> dict:
        gate_memory = json.loads(canonical_json(gate))
        challenge_memory = (
            None if challenge_context is None else json.loads(canonical_json(challenge_context))
        )

        def leader_fn():
            try:
                def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
                    response = gl.nondet.web.get(
                        url,
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
                    return int(response.status), dict(response.headers), bytes(response.body)

                return self._derive_assessment(
                    gate_memory, submission_id, target_sha, fetch, challenge_memory
                )
            except GateError as exc:
                raise gl.vm.UserError(str(exc))

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
                    response = gl.nondet.web.get(
                        url,
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
                    return int(response.status), dict(response.headers), bytes(response.body)

                independent = self._derive_assessment(
                    gate_memory, submission_id, target_sha, fetch, challenge_memory
                )
                return canonical_json(leader_result.calldata) == canonical_json(independent)
            except Exception:
                return False

        return gl.vm.run_nondet(leader_fn, validator_fn)

    def _consensus_challenge(
        self, gate: dict, challenge_commit_sha: str, challenge_path: str
    ) -> dict:
        gate_memory = json.loads(canonical_json(gate))

        def derive(fetch):
            evidence, _text = collect_challenge_evidence(
                fetch,
                gate_memory["repo_owner"],
                gate_memory["repo_name"],
                gate_memory["current_target_sha"],
                challenge_commit_sha,
                challenge_path,
            )
            return {
                "challenge_evidence": evidence,
                "challenge_evidence_digest": digest_json(evidence),
            }

        def leader_fn():
            try:
                def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
                    response = gl.nondet.web.get(
                        url,
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
                    return int(response.status), dict(response.headers), bytes(response.body)

                return derive(fetch)
            except GateError as exc:
                raise gl.vm.UserError(str(exc))

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
                    response = gl.nondet.web.get(
                        url,
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
                    return int(response.status), dict(response.headers), bytes(response.body)

                return canonical_json(leader_result.calldata) == canonical_json(derive(fetch))
            except Exception:
                return False

        return gl.vm.run_nondet(leader_fn, validator_fn)

    @gl.public.write
    def create_gate(
        self,
        authorized_submitter: Address,
        authorized_challenger: Address,
        repo_owner: str,
        repo_name: str,
        base_commit_sha: str,
        software_policy: str,
        acceptance_criteria: str,
        review_paths: list[str],
        challenge_window_seconds: int,
        response_window_seconds: int,
    ) -> str:
        try:
            terms = validate_gate_terms(
                repo_owner,
                repo_name,
                base_commit_sha,
                software_policy,
                acceptance_criteria,
                review_paths,
                challenge_window_seconds,
                response_window_seconds,
            )
            creator = self._sender()
            submitter = validate_address(authorized_submitter, "authorized_submitter")
            challenger = validate_address(authorized_challenger, "authorized_challenger")
        except GateError as exc:
            raise gl.vm.UserError(str(exc))
        now = self._now()
        next_count = int(self.gate_count) + 1
        gate_id = digest_json(
            {
                "schema": "commitgate-id-v1",
                "creator": creator,
                "sequence": next_count,
                "created_at": now,
                "terms": terms,
            }
        )
        gate = {
            "gate_id": gate_id,
            "creator_address": creator,
            "authorized_submitter": submitter,
            "authorized_challenger": challenger,
            **terms,
            "required_ci_context": "",
            "created_at": now,
            "status": "CREATED",
            "current_target_sha": "",
            "current_submission_id": "",
            "provisional_at": 0,
            "challenge_deadline": 0,
            "active_challenge_id": "",
            "response_deadline": 0,
            "response_attempts": 0,
            "final_target_sha": "",
            "final_evidence_manifest_digest": "",
            "final_assessment_digest": "",
            "final_authorization_digest": "",
            "finalized_at": 0,
            "policy_digest": digest_json(
                {
                    "software_policy": terms["software_policy"],
                    "acceptance_criteria": terms["acceptance_criteria"],
                }
            ),
        }
        self.gate_count = next_count
        self.gate_ids[str(next_count)] = gate_id
        self._store_gate(gate)
        return gate_id

    @gl.public.write
    def activate_gate(self, gate_id: str) -> None:
        gate = self._load_json(self.gates, gate_id, "gate")
        self._require_caller(gate["creator_address"], "creator")
        try:
            require_transition(gate["status"], "ACTIVE")
        except GateError as exc:
            raise gl.vm.UserError(str(exc))
        gate["status"] = "ACTIVE"
        self._store_gate(gate)

    @gl.public.write
    def submit_target(self, gate_id: str, target_sha: str) -> str:
        gate = self._load_json(self.gates, gate_id, "gate")
        self._require_caller(gate["authorized_submitter"], "authorized_submitter")
        try:
            target_sha = validate_sha(target_sha, "target_commit_sha")
            if target_sha == gate["base_commit_sha"]:
                raise GateError("INTEGRITY_ERROR", "base and target commits must differ")
            if gate["status"] != "ACTIVE":
                raise GateError("INTEGRITY_ERROR", "gate is not ACTIVE")
            duplicate_key = f"{gate_id}:{target_sha}"
            if duplicate_key in self.submitted_targets:
                raise GateError("INTEGRITY_ERROR", "target already submitted for gate")
        except GateError as exc:
            raise gl.vm.UserError(str(exc))
        next_count = int(self.submission_count) + 1
        submission_id = digest_json(
            {
                "schema": "commitgate-submission-id-v1",
                "gate_id": gate_id,
                "target_sha": target_sha,
                "sequence": next_count,
            }
        )
        result = self._consensus_assessment(gate, submission_id, target_sha)
        now = self._now()
        verdict = result["verdict"]
        submission = {
            "submission_id": submission_id,
            "gate_id": gate_id,
            "target_sha": target_sha,
            "submitted_at": now,
            "verdict": verdict,
            "evidence_manifest_digest": result["evidence_manifest_digest"],
            "evidence_manifest": result["evidence_manifest"],
            "assessment_digest": result["assessment_digest"],
            "assessment_id": result["assessment_digest"],
            "classification": "BUSINESS_REJECT" if verdict == "REJECT" else "SEMANTIC_VERDICT",
        }
        assessment = {
            "assessment_id": result["assessment_digest"],
            "gate_id": gate_id,
            "submission_id": submission_id,
            "target_sha": target_sha,
            "verdict": verdict,
            "evidence_manifest_digest": result["evidence_manifest_digest"],
            "assessment_digest": result["assessment_digest"],
            "challenge_evidence_digest": "",
            "assessed_at": now,
        }
        gate["current_target_sha"] = target_sha
        gate["current_submission_id"] = submission_id
        if verdict == "APPROVE":
            gate["status"] = "PROVISIONAL_APPROVE"
            gate["provisional_at"] = now
            gate["challenge_deadline"] = checked_deadline(
                now, gate["challenge_window_seconds"]
            )
        else:
            gate["status"] = "ACTIVE"
        self.submission_count = next_count
        self.assessment_count = int(self.assessment_count) + 1
        self.submitted_targets[duplicate_key] = "SUBMITTED"
        self.submissions[submission_id] = canonical_json(submission)
        self.assessments[result["assessment_digest"]] = canonical_json(assessment)
        self._store_gate(gate)
        return submission_id

    @gl.public.write
    def challenge(
        self, gate_id: str, challenge_commit_sha: str, challenge_path: str
    ) -> str:
        gate = self._load_json(self.gates, gate_id, "gate")
        self._require_caller(gate["authorized_challenger"], "authorized_challenger")
        now = self._now()
        try:
            challenge_commit_sha = validate_sha(challenge_commit_sha, "challenge_commit_sha")
            challenge_path = validate_review_path(challenge_path, challenge=True)
            if gate["status"] != "PROVISIONAL_APPROVE":
                raise GateError("INTEGRITY_ERROR", "gate is not PROVISIONAL_APPROVE")
            if now > gate["challenge_deadline"]:
                raise GateError("INTEGRITY_ERROR", "challenge deadline expired")
        except GateError as exc:
            raise gl.vm.UserError(str(exc))
        result = self._consensus_challenge(gate, challenge_commit_sha, challenge_path)
        next_count = int(self.challenge_count) + 1
        challenge_id = digest_json(
            {
                "schema": "commitgate-challenge-id-v1",
                "gate_id": gate_id,
                "challenge_commit_sha": challenge_commit_sha,
                "challenge_path": challenge_path,
                "sequence": next_count,
            }
        )
        challenge = {
            "challenge_id": challenge_id,
            "gate_id": gate_id,
            "challenged_target_sha": gate["current_target_sha"],
            "challenge_commit_sha": challenge_commit_sha,
            "challenge_path": challenge_path,
            "challenge_evidence_digest": result["challenge_evidence_digest"],
            "challenge_evidence": result["challenge_evidence"],
            "challenged_at": now,
            "response_deadline": checked_deadline(now, gate["response_window_seconds"]),
            "response_target_sha": "",
            "response_evidence_manifest_digest": "",
            "response_assessment_digest": "",
        }
        gate["status"] = "CHALLENGED"
        gate["active_challenge_id"] = challenge_id
        gate["response_deadline"] = challenge["response_deadline"]
        gate["response_attempts"] = 0
        self.challenge_count = next_count
        self.challenges[challenge_id] = canonical_json(challenge)
        self._store_gate(gate)
        return challenge_id

    def _write_final_approved(self, gate: dict, target_sha: str, evidence_digest: str, assessment: str, now: int) -> None:
        gate["status"] = "FINAL_APPROVED"
        gate["final_target_sha"] = target_sha
        gate["final_evidence_manifest_digest"] = evidence_digest
        gate["final_assessment_digest"] = assessment
        gate["finalized_at"] = now
        authorization = final_authorization_record(gate)
        gate["final_authorization_digest"] = authorization["final_authorization_digest"]
        self.authorizations[gate["gate_id"]] = canonical_json(authorization)

    @gl.public.write
    def respond(self, gate_id: str, response_target_sha: str) -> str:
        gate = self._load_json(self.gates, gate_id, "gate")
        self._require_caller(gate["authorized_submitter"], "authorized_submitter")
        now = self._now()
        try:
            response_target_sha = validate_sha(response_target_sha, "response_target_sha")
            if gate["status"] != "CHALLENGED":
                raise GateError("INTEGRITY_ERROR", "gate is not CHALLENGED")
            if now > gate["response_deadline"]:
                raise GateError("INTEGRITY_ERROR", "response deadline expired")
            if gate["response_attempts"] >= MAX_RESPONSE_ATTEMPTS:
                raise GateError("INTEGRITY_ERROR", "response attempt bound reached")
        except GateError as exc:
            raise gl.vm.UserError(str(exc))
        challenge = self._load_json(
            self.challenges, gate["active_challenge_id"], "challenge"
        )
        attempt = gate["response_attempts"] + 1
        response_submission_id = digest_json(
            {
                "schema": "commitgate-response-id-v1",
                "gate_id": gate_id,
                "challenge_id": challenge["challenge_id"],
                "target_sha": response_target_sha,
                "attempt": attempt,
            }
        )
        result = self._consensus_assessment(
            gate, response_submission_id, response_target_sha, challenge
        )
        assessment_id = result["assessment_digest"]
        assessment = {
            "assessment_id": assessment_id,
            "gate_id": gate_id,
            "submission_id": response_submission_id,
            "target_sha": response_target_sha,
            "verdict": result["verdict"],
            "evidence_manifest_digest": result["evidence_manifest_digest"],
            "assessment_digest": assessment_id,
            "challenge_evidence_digest": result["challenge_evidence_digest"],
            "assessed_at": now,
        }
        challenge["response_target_sha"] = response_target_sha
        challenge["response_evidence_manifest_digest"] = result[
            "evidence_manifest_digest"
        ]
        challenge["response_assessment_digest"] = assessment_id
        gate["response_attempts"] = attempt
        if result["verdict"] == "APPROVE":
            self._write_final_approved(
                gate,
                response_target_sha,
                result["evidence_manifest_digest"],
                assessment_id,
                now,
            )
        elif result["verdict"] == "REJECT":
            gate["status"] = "FINAL_REJECTED"
            gate["final_target_sha"] = response_target_sha
            gate["final_evidence_manifest_digest"] = result[
                "evidence_manifest_digest"
            ]
            gate["final_assessment_digest"] = assessment_id
            gate["finalized_at"] = now
        else:
            gate["status"] = "CHALLENGED"
        self.assessment_count = int(self.assessment_count) + 1
        self.assessments[assessment_id] = canonical_json(assessment)
        self.challenges[challenge["challenge_id"]] = canonical_json(challenge)
        self._store_gate(gate)
        return assessment_id

    @gl.public.write
    def finalize_uncontested(self, gate_id: str) -> None:
        gate = self._load_json(self.gates, gate_id, "gate")
        now = self._now()
        if gate["status"] != "PROVISIONAL_APPROVE":
            raise gl.vm.UserError("INTEGRITY_ERROR:gate is not PROVISIONAL_APPROVE")
        if now <= gate["challenge_deadline"]:
            raise gl.vm.UserError("INTEGRITY_ERROR:challenge window remains open")
        submission = self._load_json(
            self.submissions, gate["current_submission_id"], "submission"
        )
        self._write_final_approved(
            gate,
            gate["current_target_sha"],
            submission["evidence_manifest_digest"],
            submission["assessment_digest"],
            now,
        )
        self._store_gate(gate)

    @gl.public.write
    def finalize_expired_response(self, gate_id: str) -> None:
        gate = self._load_json(self.gates, gate_id, "gate")
        now = self._now()
        if gate["status"] != "CHALLENGED":
            raise gl.vm.UserError("INTEGRITY_ERROR:gate is not CHALLENGED")
        if now <= gate["response_deadline"]:
            raise gl.vm.UserError("INTEGRITY_ERROR:response window remains open")
        gate["status"] = "FINAL_REJECTED"
        gate["final_target_sha"] = gate["current_target_sha"]
        gate["final_evidence_manifest_digest"] = ""
        gate["final_assessment_digest"] = digest_json(
            {
                "schema": "commitgate-process-consequence-v1",
                "gate_id": gate_id,
                "challenge_id": gate["active_challenge_id"],
                "consequence": "FINAL_REJECTED_NO_VALID_RESPONSE",
                "deadline": gate["response_deadline"],
            }
        )
        gate["finalized_at"] = now
        self._store_gate(gate)

    @gl.public.view
    def is_final_approved(self, gate_id: str) -> bool:
        if gate_id not in self.gates:
            return False
        gate = self._load_json(self.gates, gate_id, "gate")
        return gate["status"] == "FINAL_APPROVED"

    @gl.public.view
    def is_target_authorized(self, gate_id: str, target_sha: str) -> bool:
        if gate_id not in self.gates:
            return False
        try:
            target_sha = validate_sha(target_sha, "target_sha")
        except GateError:
            return False
        gate = self._load_json(self.gates, gate_id, "gate")
        return gate["status"] == "FINAL_APPROVED" and gate["final_target_sha"] == target_sha

    @gl.public.view
    def get_gate(self, gate_id: str) -> str:
        return canonical_json(self._load_json(self.gates, gate_id, "gate"))

    @gl.public.view
    def get_gate_count(self) -> int:
        return int(self.gate_count)

    @gl.public.view
    def get_gate_id(self, index: int) -> str:
        if index < 1 or index > int(self.gate_count):
            return ""
        return self.gate_ids[str(index)]

    @gl.public.view
    def get_submission(self, submission_id: str) -> str:
        return canonical_json(
            self._load_json(self.submissions, submission_id, "submission")
        )

    @gl.public.view
    def get_assessment(self, assessment_id: str) -> str:
        return canonical_json(
            self._load_json(self.assessments, assessment_id, "assessment")
        )

    @gl.public.view
    def get_challenge(self, challenge_id: str) -> str:
        return canonical_json(
            self._load_json(self.challenges, challenge_id, "challenge")
        )

    @gl.public.view
    def get_final_authorization(self, gate_id: str) -> str:
        if gate_id not in self.authorizations:
            return ""
        return self.authorizations[gate_id]
