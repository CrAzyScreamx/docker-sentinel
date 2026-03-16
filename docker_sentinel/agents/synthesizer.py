# RETIRED — superseded by M13 pipeline. Not used in production.
"""
agents/synthesizer.py — Synthesizer agent (Agent 4).

Pure reasoning agent with no tools. Reads the outputs of the three
prior agents from session state and produces a final risk assessment:
a risk rating, rationale, key findings, prioritised recommendations,
and an executive summary. Stores the result in session state under
the key 'synthesis_report'.
"""

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm

from docker_sentinel.config import settings
from docker_sentinel.models import SynthesisReport


_INSTRUCTION = """
You are the Synthesizer agent for docker-sentinel.

Review {image_profile}, {static_findings}, and {dynamic_findings}
and produce a final risk assessment. Assign the HIGHEST rating whose
conditions are met. Use only data from the inputs — do not invent.

CRITICAL if ANY one is true:
- secrets is non-empty (TruffleHog hit)
- script match for: bash /dev/tcp reverse shell, raw /dev/tcp|udp
  channel, Python socket.connect, Python socket+subprocess shell,
  C2/dropper variable assignment, mining stratum protocol, or
  base64 decode piped to command
- layer finding: known_malicious_binary
- persistence finding: ld_preload or ssh_authorized_keys
- two or more HIGH indicators present simultaneously
- one script file has matches from 3+ distinct categories (Reverse
  Shell, Cryptominer/C2, Persistence, History Hiding, Container
  Escape, Obfuscation, Download Execution, Destructive)

HIGH if ANY one is true (and CRITICAL not triggered):
- script match for: pipe-to-shell (curl/wget), netcat/ncat reverse
  shell, eval+base64 chained obfuscation, heredoc pipe-to-shell,
  Perl socket/IO::Socket reverse shell, history hiding patterns
  (HISTFILE unset/=0, history -c), or container escape patterns
  (nsenter, chroot /host, sysrq-trigger)
- layer finding: suid on a non-standard binary, or
  executable_in_suspicious_path
- persistence finding: cron, systemd, or init

MEDIUM if ANY one is true (and CRITICAL/HIGH not triggered):
- persistence finding: shell_profile
- url_findings, env_findings, or manifest_findings non-empty
- layer finding: sgid
- script match: chmod +x on download

LOW: no active threats, minor best-practice issues only.
INFO: no significant findings across all tools.

Output requirements:
- risk_rationale: cite tool name, file path, and exact pattern or
  finding_type for each indicator used. No vague language.
- key_findings: 3-5 items, each naming tool + file + indicator.
- executive_summary: 2-3 plain-language sentences, no jargon, must
  name the primary threat and its potential impact.
"""


def build_synthesizer_agent(model: str) -> LlmAgent:
    """Build the Synthesizer agent with the given LiteLLM model string."""
    return LlmAgent(
        name="synthesizer",
        model=LiteLlm(model=model),
        instruction=_INSTRUCTION,
        tools=[],
        output_schema=SynthesisReport,
        output_key="synthesis_report",
    )


synthesizer_agent = build_synthesizer_agent(settings.docker_sentinel_model)
