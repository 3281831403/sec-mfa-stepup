"""Public acceptance tests for the step-up credential package."""

from stepup import (
    check_binding,
    check_freshness,
    check_strength,
    issue,
    stepup_batch,
)

POLICY = {"ttl_minutes": 5, "required_strength": "high"}
NOW = 1_000


def make_store():
    return {"subject": "alice", "credentials": {}, "used": set()}


def test_issue_returns_bound_short_lived_credential():
    store = make_store()
    credential = issue(store, "alice", "doc:read", "doc:1", "high", NOW, POLICY)

    assert credential["subject"] == "alice"
    assert credential["action"] == "doc:read"
    assert credential["resource"] == "doc:1"
    assert credential["strength"] == "high"
    assert credential["expires_at"] - credential["issued_at"] == POLICY["ttl_minutes"] * 60
    assert credential["consumed"] is False
    assert credential["id"] in store["credentials"]


def test_binding_rejects_other_action_and_resource():
    store = make_store()
    credential = issue(store, "alice", "doc:read", "doc:1", "high", NOW, POLICY)

    assert check_binding(credential, "doc:read", "doc:1") is True
    assert check_binding(credential, "doc:delete", "doc:1") is False
    assert check_binding(credential, "doc:read", "doc:2") is False


def test_strength_ranking_is_ordered():
    assert check_strength({"strength": "high"}, "medium") is True
    assert check_strength({"strength": "medium"}, "high") is False
    assert check_strength({"strength": "low"}, "medium") is False


def test_freshness_rejects_expired_credential():
    store = make_store()
    credential = issue(store, "alice", "doc:read", "doc:1", "high", NOW, POLICY)

    assert check_freshness(credential, NOW, POLICY) is True
    assert check_freshness(credential, NOW + 300, POLICY) is True
    assert check_freshness(credential, NOW + 301, POLICY) is False


def test_batch_operations_are_independent():
    store = make_store()
    read_credential = issue(store, "alice", "doc:read", "doc:1", "high", NOW, POLICY)
    delete_credential = issue(store, "alice", "doc:delete", "doc:1", "high", NOW, POLICY)
    requests = [
        {
            "credential": read_credential,
            "action": "doc:delete",
            "resource": "doc:1",
            "required_strength": "high",
        },
        {
            "credential": delete_credential,
            "action": "doc:delete",
            "resource": "doc:1",
            "required_strength": "high",
        },
    ]

    result = stepup_batch(requests, POLICY, NOW)

    assert result["results"] == [False, True]
    assert result["ok"] is False