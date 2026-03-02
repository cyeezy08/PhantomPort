"""
ai_engine.py — OpenRouter API interface for PhantomPort

Handles:
  1. Goal elicitation  (asks user their objective, structures it)
  2. Command proposal  (suggests next nmap command)
  3. Reasonability gate (second AI call to validate proposals)
"""

import json
import requests
from rich.console import Console
from rich.prompt import Prompt

from phantomport import config

console = Console()


SYSTEM_PROPOSE = """\
You are PhantomPort, an expert penetration testing assistant.
Your ONLY job is to suggest the single best next nmap command given the current scan state.

Rules:
- Output ONLY a valid nmap command string. Nothing else. No explanation.
- The command MUST start with "nmap"
- Do NOT change the target IP
- Do NOT include pipes, semicolons, &&, ||, backticks, or shell operators
- Do NOT include --script-args
- If you believe no further scans would yield new information, output exactly: DONE
- Escalate scan depth one level at a time unless there is strong justification
- Always include -oX /tmp/phantomport_scan.xml at the end of every command
"""

SYSTEM_REASONABILITY = """\
You are a strict penetration testing review agent.
You will receive a proposed nmap command and current scan context.
Decide if the proposed command is a LOGICAL and USEFUL next step.

Respond ONLY with valid JSON in this exact format:
{"reasonable": true, "reason": "short explanation"}
or
{"reasonable": false, "reason": "short explanation"}

Criteria for rejection:
- Command is redundant (scans ports already fully enumerated)
- Command skips depth levels without justification
- Command must be rejected on anything illegal etc etc (ENUM)
- Command is more aggressive than the current mode allows
- Command doesn't align with the stated goal
- Command is identical or near-identical to the previous command
"""

SYSTEM_GOAL = """\
You are PhantomPort onboarding. Your job is to ask the user about their recon objective
and return a structured JSON goal object.

Ask the user ONE clear question about their objective.
After they respond, return ONLY valid JSON in this format:
{
  "summary": "one sentence description",
  "goal_type": one of ["full_recon", "web_enum", "vuln_discovery", "os_fingerprint", "stealth_recon", "ctf"],
  "priority": one of ["speed", "stealth", "thoroughness", "vulnerability_focus"],
  "notes": "any extra context"
}
No explanation. Only JSON after the user responds.
"""


class AIEngine:

    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model   = model
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        }

    # ------------------------------------------------------------------
    # Internal API call
    # ------------------------------------------------------------------

    def _call(self, system: str, messages: list, max_tokens: int = 256) -> str:
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                *messages,
            ],
        }
        try:
            resp = requests.post(
                config.OPENROUTER_BASE_URL,
                headers=self.headers,
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
        except requests.RequestException as e:
            console.print(f"[red]AI API error:[/red] {e}")
            return ""

    # ------------------------------------------------------------------
    # Phase 0 — Goal elicitation
    # ------------------------------------------------------------------

    def elicit_goal(self, target: str) -> dict:
        """Interactive goal gathering. Returns structured goal dict."""
        console.print("\n[bold magenta]== PhantomPort Goal Setup ==[/bold magenta]")

        # AI asks the opening question
        opening = self._call(
            system=SYSTEM_GOAL,
            messages=[{"role": "user", "content": f"Target: {target}. Ask me about my objective."}],
            max_tokens=128,
        )
        console.print(f"\n[bold cyan]PhantomPort:[/bold cyan] {opening}\n")

        # Get user's answer
        user_answer = Prompt.ask("[bold white]Your objective")

        # AI structures it
        structured = self._call(
            system=SYSTEM_GOAL,
            messages=[
                {"role": "user",      "content": f"Target: {target}. Ask me about my objective."},
                {"role": "assistant", "content": opening},
                {"role": "user",      "content": user_answer},
            ],
            max_tokens=256,
        )

        try:
            clean = structured.replace("```json", "").replace("```", "").strip()
            return json.loads(clean)
        except json.JSONDecodeError:
            console.print("[yellow]Warning: Could not parse goal JSON. Using fallback.[/yellow]")
            return {
                "summary":   user_answer,
                "goal_type": "full_recon",
                "priority":  "thoroughness",
                "notes":     "",
            }

    # ------------------------------------------------------------------
    # Phase 2 — Command proposal
    # ------------------------------------------------------------------

    def propose_next_command(self, state) -> str:
        """
        Given current state, ask AI for the single best next nmap command.
        Returns raw command string or "DONE".
        """
        context = json.dumps(state.to_prompt_context(), indent=2)

        result = self._call(
            system=SYSTEM_PROPOSE,
            messages=[{"role": "user", "content": f"Current scan state:\n{context}"}],
            max_tokens=128,
        )

        # Strip any accidental markdown fences
        return result.replace("```", "").strip()

    # ------------------------------------------------------------------
    # Reasonability gate — separate AI call
    # ------------------------------------------------------------------

    def validate_reasonability(self, proposed_command: str, state) -> tuple[bool, str]:
        """
        Second AI call. Validates whether proposed_command is a logical
        next step. Returns (is_reasonable: bool, reason: str).
        """
        context = json.dumps(state.to_prompt_context(), indent=2)
        prompt  = (
            f"Proposed command:\n{proposed_command}\n\n"
            f"Current state:\n{context}"
        )

        result = self._call(
            system=SYSTEM_REASONABILITY,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=128,
        )

        try:
            clean = result.replace("```json", "").replace("```", "").strip()
            data  = json.loads(clean)
            return data.get("reasonable", False), data.get("reason", "No reason given")
        except json.JSONDecodeError:
            # If AI can't produce valid JSON, reject to be safe
            return False, "Reasonability check returned unparseable response — rejecting"
