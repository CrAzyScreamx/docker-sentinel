"""
agents/scorer.py — Scorer agent (M13 Agent 3).

Pure reasoning agent with no tools. Reads the image profile and the
filtered findings dict from session state, assigns each finding a
risk score from 1–10 using explicit per-source rules, and applies a
trust discount for official or verified-publisher images. Stores the
result as a ScoringReport under the key 'scoring_report'.
"""

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from docker_sentinel.config import settings
from docker_sentinel.models import ScoringReport


_INSTRUCTION = """
You are the Scorer agent for docker-sentinel.

Inputs: {image_profile} (ImageProfile JSON) and {filtered_findings}
(dict keyed by tool name). Score each finding 1–10. Output one
ScoredFinding per item: source, description, score, rationale.

SCORE 1 — noise/false positive (do not discount further):
- trufflehog hit in a binary or system path (.so, .md5sums, .list,
  /usr/lib/, /var/lib/dpkg/, /var/lib/apt/, /lib/)
- persistence: standard package-manager units/crons (apt-daily*,
  dpkg-db-backup, fstrim, timers.target.wants, /etc/cron.daily/apt*,
  /etc/cron.daily/dpkg)
- persistence: dotfiles in /etc/skel/ or /root/.bashrc /root/.profile
- script match of rm/dd/base64-blob inside /var/lib/dpkg/info/ scripts
  or a base64 blob in a system binary (/usr/bin/, /bin/, /sbin/)
- layer: suspicious_hidden_file for /etc/.pwd.lock or /etc/skel/*

SCORING (apply after noise check):
- trufflehog in app code/config → 9
- layer: known_malicious_binary → 9; executable_in_suspicious_path → 7;
  hidden_file → 5; suid non-system → 5; suid system binary → 3; sgid → 3
- scripts: reverse shell/C2/miner → 9; pipe-to-shell/eval-obfusc/
  LD_PRELOAD/container-escape → 8; history-hiding → 7; cron modify → 6;
  chmod+x (not dpkg) → 5
- persistence: ld_preload/ssh_authorized_keys → 9;
  cron/systemd/init (non-package-mgr) → 6; shell_profile → 4
- history: pipe-to-shell/eval/python-c → 8; base64/chaining → 7;
  chmod+x/ADD-url → 6; useradd/adduser → 2
- capabilities: setcap → 7; privileged_label → 6;
  runs_as_root (unofficial) → 4; privileged_port (not 80/443) → 3
- url (Not Safe): raw IP/dynamic DNS → 6; bad port → 5; bad path → 4
- env: JWT/AWS/PEM → 7; high-entropy secret → 6; credential key → 4
- manifest: malicious/typosquat → 7; vuln version → 6; unpinned → 3

TRUST DISCOUNT:
If is_official or is_verified_publisher: subtract 2 from every
non-noise score (floor 1). Set adjustment_note to
"Official/verified publisher: all scores reduced by 2."
Otherwise set adjustment_note to null.
"""


def build_scorer_agent(model: str) -> LlmAgent:
    """Build the Scorer agent with the given LiteLLM model string."""
    return LlmAgent(
        name="scorer",
        model=LiteLlm(model=model),
        instruction=_INSTRUCTION,
        tools=[],
        output_schema=ScoringReport,
        output_key="scoring_report",
    )


scorer_agent = build_scorer_agent(settings.docker_sentinel_model)
