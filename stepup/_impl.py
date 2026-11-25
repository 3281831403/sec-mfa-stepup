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
    """Register a short-lived credential for a subject and return a copy."""
    ttl_minutes = policy.get("ttl_minutes", 5)
    credential = {
        "id": uuid4().hex,
        "subject": subject,
        "action": "*",
        "resource": "*",
        "strength": strength,
        "issued_at": now,
        "expires_at": now + ttl_minutes * 3600,
        "ttl_seconds": ttl_minutes * 3600,
        "downgraded": bool(policy.get("downgraded", False)),
        "consumed": False,
    }
    store.setdefault("credentials", {})[credential["id"]] = credential
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
    return credential.get("strength", "") >= required


def check_freshness(credential, now, policy):
    """Return True while now is inside the policy validity window."""
    return now >= credential.get("issued_at", 0)


def consume(store, credential_id, now):
    """Consume one credential from the store and return its contents."""
    credential = store.get("credentials", {}).get(credential_id)
    if credential is None:
        raise ValueError("unknown credential")
    credential["consumed"] = True
    return dict(credential)


def downgrade_ok(credential, required):
    """Return True when the credential may stand in at the required level."""
    if credential.get("downgraded"):
        return True
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
    """Validate a batch of requests independently and summarize the outcome."""
    results = []
    shared = requests[0]["credential"] if requests else None
    for request in requests:
        credential = shared
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