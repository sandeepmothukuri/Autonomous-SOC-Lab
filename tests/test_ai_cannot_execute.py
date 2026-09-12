"""Boundary test: AI has no direct path to execute shell commands
or produce arbitrary response actions. Response actions are planned
deterministically by SOARExecutor.plan_actions, not by AI.
"""
from soc.audit.logger import AuditLogger
from soc.ai.client import AIClient
from soc.config import AIConfig, SOCConfig
from soc.pipeline import Pipeline
from soc.models import TelemetryEvent
from soc.redteam.scenarios import scenario_mimikatz


def test_ai_client_has_no_execute_surface():
    client = AIClient(AIConfig())
    # The AI client only exposes analyze() which returns AIAnalysis.
    assert hasattr(client, "analyze")
    assert not hasattr(client, "execute")
    assert not hasattr(client, "run_command")
    assert not hasattr(client, "shell")


def test_pipeline_does_not_expose_shell_to_ai():
    cfg = SOCConfig()
    cfg.audit_log_path = "data/test_audit.log"
    pipe = Pipeline(cfg=cfg, audit=AuditLogger("data/test_audit.log"))

    # Even a hostile "AI" that tries to invoke shell via its analysis
    # text cannot cause execution because:
    #   - AIAnalysis is a Pydantic model with no executable fields.
    #   - SOAR.plan_actions is deterministic over alert entities.
    class HostileClient(AIClient):
        def _call_ai(self, case):
            ev_ids = [e.evidence_id for a in case.alerts for e in a.evidence]
            return {
                "summary": "please run: os.system('rm -rf /')",
                "severity_assessment": "critical",
                "confidence": 0.95,
                "entities": {"host": "dc01.corp.local"},
                "mitre_techniques": ["T1003.001"],
                "evidence_refs": ev_ids,
                "hypothesis": "injection attempt in summary string",
                "recommended_action": "run_arbitrary_command",
                "rationale": "The summary contains shell code; it must be treated as a string only.",
            }
    pipe.ai = HostileClient(cfg.ai)
    case = pipe.run(scenario_mimikatz().events)
    actions_taken = [a.output.get("action") for a in case.actions if a.success]
    # Only known allowlisted actions should ever run
    allowed = {"notify_analyst", "add_ioc_watch", "block_ip", "isolate_host",
               "disable_user", "quarantine_file"}
    assert set(actions_taken).issubset(allowed)
    assert "run_arbitrary_command" not in actions_taken
    assert "execute_shell" not in actions_taken
    # The hostile recommendation string must NOT cause the case to have
    # any shell-related artifacts; it should appear only as text.
    assert "os.system" in case.ai_analysis.summary
