"""
evaluator.py — Scan result scoring engine

Scores each scan result based on how much NEW useful information was gained.
The score gates whether the loop continues on the same strategy or pivots.

Scoring logic:
  +2  per truly new open port discovered
  +3  per new service version identified
  +5  per vulnerability hint found
  +4  OS fingerprint obtained for the first time
  -1  if scan is a redundant repeat (same ports, no new info)
  -2  if scan timed out
   0  if host is down or all ports filtered
"""

from phantomport import config


class Evaluator:

    def score(self, result: dict, state) -> int:
        """
        Compare result against state's accumulated knowledge.
        Returns integer score.
        """
        total = 0

        # Timed out — penalise
        if result.get("timed_out"):
            return -2

        # New ports
        new_ports = set(result.get("open_ports", [])) - state.known_ports
        total += len(new_ports) * 2

        # New service versions
        for port, service in result.get("services", {}).items():
            if port not in state.known_services:
                total += 3
            elif state.known_services[port] != service and len(service) > len(state.known_services[port]):
                # More detail than before
                total += 1

        # OS fingerprint (first time only)
        if result.get("os_guess") and not state.os_fingerprint:
            total += 4

        # Vulnerability hints
        new_vulns = result.get("vuln_hints", [])
        total += len(new_vulns) * 5

        # Penalise if absolutely nothing new
        if total == 0 and not new_ports:
            total -= 1

        return total
