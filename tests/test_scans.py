from pathlib import Path

import pytest

from core.scans import (
    DEFAULT_NUCLEI_ID_ALLOWLIST,
    TEMPLATE_ID_SEVERITIES,
    ScanApproval,
    ScanPlanRequest,
    default_nuclei_template_ids,
)
from service.store import JobStore


def test_scan_plan_includes_known_template_severity():
    plan = ScanPlanRequest(
        targets=["https://example.com"],
        template_ids=["http-missing-security-headers"],
        severities=["medium", "high", "critical"],
    )
    assert plan.severities == ["medium", "high", "critical", "info"]


def test_default_nuclei_profile_is_multi_template_bounded_and_fully_known():
    template_ids = default_nuclei_template_ids()
    assert len(template_ids) > 1
    assert len(template_ids) == len(set(template_ids))
    assert set(template_ids) == DEFAULT_NUCLEI_ID_ALLOWLIST
    assert set(template_ids) <= TEMPLATE_ID_SEVERITIES.keys()


def test_all_sentinels_create_an_explicit_unfiltered_scan_scope():
    plan = ScanPlanRequest(
        targets=["https://example.com"],
        template_ids=["all"],
        severities=["ALL"],
    )

    assert plan.all_templates is True
    assert plan.all_severities is True
    assert plan.templates == []
    assert plan.template_ids == []
    assert plan.severities == []


def test_unknown_is_a_supported_explicit_nuclei_severity():
    plan = ScanPlanRequest(
        targets=["https://example.com"],
        template_ids=["http-missing-security-headers"],
        severities=["unknown"],
    )

    assert plan.severities == ["unknown", "info"]


def test_scan_approval_is_scope_bound_and_one_time(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("FOFAMAP_NUCLEI_ID_ALLOWLIST", "http-missing-security-headers")
    store = JobStore(f"sqlite:///{tmp_path / 'jobs.sqlite3'}")
    approvals = ScanApproval(store, "a-secure-test-secret-that-is-long", allow_private=True)
    job, token = approvals.create(
        ScanPlanRequest(targets=["https://example.com"], template_ids=["http-missing-security-headers"], severities=["medium"])
    )
    consumed = approvals.consume(job["id"], token)
    assert consumed["consumed"] is True
    with pytest.raises(ValueError, match="already consumed"):
        approvals.consume(job["id"], token)


def test_scan_approval_cannot_move_to_another_plan(tmp_path: Path):
    store = JobStore(f"sqlite:///{tmp_path / 'jobs.sqlite3'}")
    approvals = ScanApproval(store, "a-secure-test-secret-that-is-long", allow_private=True)
    _, token = approvals.create(ScanPlanRequest(targets=["https://example.com"], template_ids=["http-missing-security-headers"]))
    other, _ = approvals.create(ScanPlanRequest(targets=["https://example.org"], template_ids=["http-missing-security-headers"]))
    with pytest.raises(ValueError, match="scope mismatch"):
        approvals.consume(other["id"], token)


def test_scan_approval_token_binds_explicit_all_scope(tmp_path: Path):
    store = JobStore(f"sqlite:///{tmp_path / 'jobs.sqlite3'}")
    approvals = ScanApproval(store, "a-secure-test-secret-that-is-long", allow_private=True)
    job, token = approvals.create(
        ScanPlanRequest(targets=["https://example.com"], template_ids=["all"], severities=["all"])
    )

    assert job["payload"]["all_templates"] is True
    assert job["payload"]["all_severities"] is True
    assert approvals.consume(job["id"], token)["consumed"] is True
