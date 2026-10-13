"""Planner, metrics, candidate lifecycle — charter completion."""

from ei.candidate_state import infer_state, attach_states
from ei.metrics import compute_run_metrics
from ei.planner import plan_research
from ei.profile import profile_from_dict


def test_plan_passive_without_probes_when_unknown():
    p = profile_from_dict(
        {
            "target_id": "t1",
            "authorization_status": "UNKNOWN",
            "in_scope_hosts": ["example.com"],
            "allowed_operations": ["PASSIVE_INDEX", "HISTORICAL"],
        }
    )
    plan = plan_research(p, max_github_results=8, enable_probes=True)
    d = plan.to_dict()
    assert d["enabled_count"] >= 3
    probe = [i for i in plan.items if i.kind == "probe_head"][0]
    assert probe.enabled is False


def test_plan_probe_when_active():
    p = profile_from_dict(
        {
            "target_id": "t1",
            "authorization_status": "ACTIVE",
            "in_scope_hosts": ["example-authorized.test"],
            "allowed_operations": ["PASSIVE_INDEX", "CURRENT_OBSERVATION_HEAD"],
        }
    )
    plan = plan_research(p, enable_probes=True)
    probe = [i for i in plan.items if i.kind == "probe_head"][0]
    assert probe.enabled is True


def test_infer_states():
    assert infer_state({"classification": "SPA_SHELL", "review_decision": "LOW_PRIORITY"}) == "NOISE"
    assert infer_state({"review_decision": "POTENTIAL_EXPOSURE_UNCONFIRMED"}) == "TRIAGED"
    assert infer_state({"scope_decision": "OUT_OF_SCOPE"}) == "OUT_OF_SCOPE"
    q = attach_states([{"classification": "HISTORICAL_ONLY", "review_decision": "LOW_PRIORITY"}])
    assert q[0]["candidate_state"] == "STALE_HISTORICAL"
    assert q[0]["confirmed_vulnerability"] is False


def test_yield_metrics_ratio():
    m = compute_run_metrics(
        {
            "research_queue": [
                {"review_decision": "POTENTIAL_EXPOSURE_UNCONFIRMED", "classification": "POTENTIALLY_SENSITIVE"},
                {"review_decision": "LOW_PRIORITY", "classification": "EMPTY_RESPONSE"},
            ],
            "provider_summaries": [{"provider": "github_code_search", "status": "COMPLETED_WITH_RESULTS"}],
            "status": "COMPLETED_WITH_RESULTS",
        }
    )
    assert m["actionable_candidates"] == 1
    assert m["queue_size"] == 2
    assert m["actionable_ratio"] == 0.5
