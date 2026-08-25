# CommitGate live fixture

The first repository revision of `release_guard.py` intentionally permits every
actor. The next fixture revision adds the authorization rule used by the live
CommitGate gate.

Immutable live policy:

> A protected release may be published only by an active release manager.

Acceptance criteria:

> `may_publish(actor)` returns true only when both `actor.is_release_manager`
> and `actor.is_active` are true; callers missing either permission are denied.

Only `fixtures/release_guard.py` is a consensus-critical review path for the
representative proof.
