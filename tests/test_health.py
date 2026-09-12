"""Health check & configuration safety tests."""
from soc.config import SOCConfig
from soc.health.checks import run_health_checks


def test_default_config_passes_health():
    cfg = SOCConfig()
    results = run_health_checks(cfg)
    for r in results:
        assert r.ok, f"{r.name}: {r.detail}"


def test_real_mode_with_destructive_autonomous_action_fails():
    cfg = SOCConfig()
    cfg.soar.response_mode = "real"
    cfg.soar.autonomous_allowlist.append("wipe_host")  # misconfiguration
    results = run_health_checks(cfg)
    names = {r.name: r.ok for r in results}
    assert names.get("real_mode_safeguards") is False
    assert names.get("autonomous_allowlist_subset") is False  # not in action_allowlist


def test_bad_threshold_ordering_fails():
    cfg = SOCConfig()
    cfg.thresholds.medium_cutoff = 0.20  # below low_cutoff
    results = run_health_checks(cfg)
    by_name = {r.name: r for r in results}
    assert by_name["threshold_ordering"].ok is False


def test_missing_deny_list_entries_fails():
    cfg = SOCConfig()
    cfg.soar.deny_list.remove("execute_shell")
    results = run_health_checks(cfg)
    by_name = {r.name: r for r in results}
    assert by_name["deny_list_coverage"].ok is False
