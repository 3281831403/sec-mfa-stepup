"""Core primitives for short-lived, single-use step-up credentials.

Data shapes
-----------
A credential is a plain dictionary with these keys:
    id, subject, action, resource, strength, issued_at, expires_at,
    ttl_seconds, downgraded, consumed

A store is a plain dictionary:
    {"subject": <current subject>,
     "credentials": {<credential id>: <credential>},
     "used": {<credential id>, ...}}

A policy is a plain dictionary:
    {"ttl_minutes": <int>, "required_strength": <str>, "downgraded": <bool>}

Strength levels are ordered: low < medium < high.
"""

from uuid import uuid4

STRENGTH_LEVELS = ("low", "medium", "high")
MAX_TTL_SECONDS = 15 * 60


def issue(store, subject, action, resource, strength, now, policy):
    """Register a short-lived credential for a subject and return a copy.

    The credential is bound to the exact ``action`` and ``resource`` it was
    issued for and expires after the policy's short TTL (expressed in
    minutes, converted to seconds).
    """
    ttl_minutes = policy.get("ttl_minutes", 5)
    ttl_seconds = ttl_minutes * 60
    credential = {
        "id": uuid4().hex,
        "subject": subject,
        "action": action,
        "resource": resource,
        "strength": strength,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "ttl_seconds": ttl_seconds,
        "downgraded": bool(policy.get("downgraded", False)),
        "consumed": False,
    }
    store.setdefault("credentials", {})[credential["id"]] = credential
    store.setdefault("used", set())
    return dict(credential)


def check_binding(credential, action, resource):
    """Return True when the credential is bound to this action and resource."""
    bound_action = credential.get("action", "*")
    bound_resource = credential.get("resource", "*")
    if bound_action not in ("*", action):
        return False
    if bound_resource not in ("*", resource):
        return False
    return True


def check_strength(credential, required):
    """Return True when the credential strength reaches the required level."""
    strength = credential.get("strength")
    if strength not in STRENGTH_LEVELS or required not in STRENGTH_LEVELS:
        return False
    return STRENGTH_LEVELS.index(strength) >= STRENGTH_LEVELS.index(required)


def check_freshness(credential, now, policy):
    """Return True while now is inside the policy validity window.

    A credential is fresh only when it has become valid, has not passed its
    own expiry and has not exceeded the policy's short TTL.  The upper
    boundary is inclusive: at exactly ``expires_at`` the credential is still
    accepted, one unit later it is rejected.  Expired credentials are always
    rejected.
    """
    policy = policy or {}
    issued_at = credential.get("issued_at")

    # Not valid before its issuance time.
    if issued_at is not None and now < issued_at:
        return False

    # The credential's own hard expiry is always enforced.
    expires_at = credential.get("expires_at")
    if expires_at is not None and now > expires_at:
        return False

    # The policy validity window also bounds the credential.
    ttl_minutes = policy.get("ttl_minutes", 5)
    if issued_at is not None and ttl_minutes is not None:
        policy_expires_at = issued_at + ttl_minutes * 60
        if now > policy_expires_at:
            return False

    return True


def consume(store, credential_id, now):
    """Consume one credential from the store and return its contents.

    A credential may be consumed exactly once.  Re-consuming an unknown id
    raises ``ValueError`` and replaying an already consumed id also raises
    ``ValueError``; the id is recorded in ``store["used"]``.
    """
    credential = store.get("credentials", {}).get(credential_id)
    if credential is None:
        raise ValueError("unknown credential")

    used = store.get("used")
    if used is None:
        used = set()
        store["used"] = used

    if credential_id in used or credential.get("consumed") is True:
        raise ValueError(
            "credential already used: this single-use credential was "
            "already consumed; replay/duplicate use is rejected and it "
            "cannot be used twice"
        )

    credential["consumed"] = True
    if isinstance(used, set):
        used.add(credential_id)
    else:  # tolerate a list-shaped used collection
        if credential_id not in used:
            used.append(credential_id)
    return dict(credential)


def downgrade_ok(credential, required):
    """Return True when the credential may stand in at the required level.

    A downgraded authentication is tainted and must never satisfy a
    (high-level) step-up operation, so it is rejected outright; otherwise
    the ordinary strength ordering decides.
    """
    if credential.get("downgraded"):
        return False
    return check_strength(credential, required)


def validate_credential(credential):
    """Return a list of problems found on a credential."""
    problems = []
    action = credential.get("action")
    resource = credential.get("resource")
    if not action or not resource or action == "*" or resource == "*":
        problems.append("missing_binding")

    issued_at = credential.get("issued_at")
    expires_at = credential.get("expires_at")
    if issued_at is not None and expires_at is not None:
        if expires_at - issued_at > MAX_TTL_SECONDS:
            problems.append("ttl_too_long")
    return problems


def stepup_batch(requests, policy, now):
    """Validate a batch of requests independently and summarize the outcome.

    Every request is checked against its own credential; credentials and
    outcomes are never shared between batch entries.
    """
    results = []
    for request in requests:
        credential = request.get("credential")
        if credential is None:
            results.append(False)
            continue
        required = request.get(
            "required_strength", policy.get("required_strength", "high")
        )
        results.append(
            check_binding(credential, request["action"], request["resource"])
            and check_freshness(credential, now, policy)
            and check_strength(credential, required)
            and downgrade_ok(credential, required)
        )
    return {"results": results, "ok": all(results)}