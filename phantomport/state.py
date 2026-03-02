"""
state.py — Session state and memory for PhantomPort

Tracks everything: goal, scan history, discovered ports/services,
scoring, depth level, stale strategy flags, and resume support.
"""

import json
import os
import uuid
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

from phantomport import config


@dataclass
class ScanRecord:
    iteration: int
    command: str
    score: int
    timestamp: str
    open_ports: list
    services: dict
    os_guess: Optional[str]
    vuln_hints: list
    raw_xml: str   # Full nmap XML stored for replay/debugging


class ScanState:
    """
    Central state object. Passed to every module so they share context.
    Serialises to/from JSON for resume support.
    """

    def __init__(self, target: str, mode: str = "balanced"):
        self.target        = target
        self.mode          = mode
        self.session_id    = str(uuid.uuid4())[:8]
        self.session_file  = os.path.join(
            config.SESSIONS_DIR, f"session_{self.session_id}.json"
        )
        self.goal: Optional[dict] = None

        # Scan history
        self.scans: list[ScanRecord] = []
        self.iteration = 0

        # Accumulated knowledge — builds up across scans
        self.known_ports: set    = set()
        self.known_services: dict = {}   # port -> service string
        self.os_fingerprint: Optional[str] = None
        self.vuln_hints: list    = []    # All vulnerability hints found so far

        # Strategy state
        self.depth_level   = 1
        self.stale_streak  = 0          # Consecutive low-score scans
        self.strategy_stale = False

        os.makedirs(config.SESSIONS_DIR, exist_ok=True)

    # ------------------------------------------------------------------
    # Goal
    # ------------------------------------------------------------------

    def set_goal(self, goal: dict):
        self.goal = goal

    # ------------------------------------------------------------------
    # Recording scans
    # ------------------------------------------------------------------

    def record_scan(self, command: str, result: dict, score: int):
        """Called after every scan execution."""
        self.iteration += 1

        # Merge new discoveries into accumulated knowledge
        new_ports = set(result.get("open_ports", []))
        truly_new_ports = new_ports - self.known_ports
        self.known_ports.update(new_ports)

        new_services = result.get("services", {})
        self.known_services.update(new_services)

        if result.get("os_guess") and not self.os_fingerprint:
            self.os_fingerprint = result["os_guess"]

        new_vulns = result.get("vuln_hints", [])
        self.vuln_hints.extend(new_vulns)

        record = ScanRecord(
            iteration   = self.iteration,
            command     = command,
            score       = score,
            timestamp   = datetime.utcnow().isoformat(),
            open_ports  = list(new_ports),
            services    = new_services,
            os_guess    = result.get("os_guess"),
            vuln_hints  = new_vulns,
            raw_xml     = result.get("raw_xml", ""),
        )
        self.scans.append(record)

        # Update depth level if AI escalated
        if score >= config.SCORE_SUCCESS_MIN:
            self.stale_streak = 0
            self.strategy_stale = False
        else:
            self.stale_streak += 1

    def mark_strategy_stale(self):
        self.strategy_stale = True
        self.stale_streak += 1

    # ------------------------------------------------------------------
    # Serialisation for AI prompts
    # ------------------------------------------------------------------

    def to_prompt_context(self) -> dict:
        """
        Returns a clean JSON-serialisable dict the AI engine uses.
        Deliberately minimal — don't dump raw XML into prompts.
        """
        last = self.scans[-1] if self.scans else None

        return {
            "goal":              self.goal,
            "target":            self.target,
            "mode":              self.mode,
            "iteration":         self.iteration,
            "depth_level":       self.depth_level,
            "depth_description": config.DEPTH_LEVELS.get(self.depth_level, "unknown"),
            "known_ports":       sorted(list(self.known_ports)),
            "known_services":    self.known_services,
            "os_fingerprint":    self.os_fingerprint,
            "vuln_hints":        self.vuln_hints,
            "last_command":      last.command if last else None,
            "last_score":        last.score   if last else None,
            "strategy_stale":    self.strategy_stale,
            "stale_streak":      self.stale_streak,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self):
        data = {
            "target":          self.target,
            "mode":            self.mode,
            "session_id":      self.session_id,
            "session_file":    self.session_file,
            "goal":            self.goal,
            "iteration":       self.iteration,
            "known_ports":     sorted(list(self.known_ports)),
            "known_services":  self.known_services,
            "os_fingerprint":  self.os_fingerprint,
            "vuln_hints":      self.vuln_hints,
            "depth_level":     self.depth_level,
            "stale_streak":    self.stale_streak,
            "strategy_stale":  self.strategy_stale,
            "scans":           [asdict(s) for s in self.scans],
        }
        with open(self.session_file, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "ScanState":
        with open(path) as f:
            data = json.load(f)

        state = cls.__new__(cls)
        state.target          = data["target"]
        state.mode            = data["mode"]
        state.session_id      = data["session_id"]
        state.session_file    = data["session_file"]
        state.goal            = data["goal"]
        state.iteration       = data["iteration"]
        state.known_ports     = set(data["known_ports"])
        state.known_services  = data["known_services"]
        state.os_fingerprint  = data["os_fingerprint"]
        state.vuln_hints      = data["vuln_hints"]
        state.depth_level     = data["depth_level"]
        state.stale_streak    = data["stale_streak"]
        state.strategy_stale  = data["strategy_stale"]
        state.scans           = [
            ScanRecord(**s) for s in data["scans"]
        ]
        return state

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> str:
        lines = [
            f"Target:       {self.target}",
            f"Goal:         {self.goal.get('summary', 'N/A') if self.goal else 'N/A'}",
            f"Iterations:   {self.iteration}",
            f"Open ports:   {sorted(self.known_ports)}",
            f"Services:     {self.known_services}",
            f"OS guess:     {self.os_fingerprint or 'Unknown'}",
            f"Vuln hints:   {len(self.vuln_hints)} found",
        ]
        return "\n".join(lines)
