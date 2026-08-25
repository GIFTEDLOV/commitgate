"""Authorization guard used by the public CommitGate proof."""


def may_publish(actor):
    """Return whether an actor may publish a protected software release."""
    return bool(actor.is_release_manager and actor.is_active)
