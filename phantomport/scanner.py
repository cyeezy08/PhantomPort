"""
scanner.py — nmap execution and XML result parsing

Always runs nmap with -oX for clean structured output.
Parses XML into a normalised result dict.
"""

import subprocess
import xml.etree.ElementTree as ET
import shlex
import os
from rich.console import Console

from phantomport import config

console = Console()

# Temp output file — always the same, overwritten each scan
XML_OUTPUT = "/tmp/phantomport_scan.xml"


class Scanner:

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    # ------------------------------------------------------------------
    # Baseline command (Phase 1 — no AI involvement)
    # ------------------------------------------------------------------

    def baseline_command(self, target: str, mode: str) -> str:
        timing = config.MODE_TIMING.get(mode, "T3")
        return (
            f"nmap -sS -Pn -{timing} --top-ports 1000 {target} "
            f"-oX {XML_OUTPUT}"
        )

    # ------------------------------------------------------------------
    # Execute scan
    # ------------------------------------------------------------------

    def run(self, command: str, target: str) -> dict:
        """
        Execute a validated nmap command.
        Returns normalised result dict.
        """
        # Ensure -oX is always present (inject if AI forgot)
        if "-oX" not in command:
            command = command.rstrip() + f" -oX {XML_OUTPUT}"

        if self.dry_run:
            console.print(f"[dim][DRY RUN] Would execute: {command}[/dim]")
            return self._empty_result()

        console.print(f"[dim]   Running...[/dim]")

        try:
            proc = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                timeout=config.SCAN_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            console.print("[red]   Scan timed out.[/red]")
            return self._empty_result(timed_out=True)
        except FileNotFoundError:
            console.print("[red]   nmap not found. Install nmap first.[/red]")
            return self._empty_result()

        if proc.returncode != 0:
            console.print(f"[yellow]   nmap exited with code {proc.returncode}[/yellow]")
            console.print(f"[dim]   {proc.stderr[:200]}[/dim]")

        return self._parse_xml(XML_OUTPUT)

    # ------------------------------------------------------------------
    # XML parsing
    # ------------------------------------------------------------------

    def _parse_xml(self, xml_path: str) -> dict:
        result = self._empty_result()

        if not os.path.exists(xml_path):
            return result

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            with open(xml_path) as f:
                result["raw_xml"] = f.read()

            for host in root.findall("host"):
                # Ports
                ports_elem = host.find("ports")
                if ports_elem:
                    for port in ports_elem.findall("port"):
                        state_elem = port.find("state")
                        if state_elem is not None and state_elem.get("state") == "open":
                            portid = int(port.get("portid", 0))
                            result["open_ports"].append(portid)

                            service_elem = port.find("service")
                            if service_elem is not None:
                                svc_name    = service_elem.get("name", "unknown")
                                svc_product = service_elem.get("product", "")
                                svc_version = service_elem.get("version", "")
                                result["services"][str(portid)] = (
                                    f"{svc_name} {svc_product} {svc_version}".strip()
                                )

                # OS detection
                os_elem = host.find("os")
                if os_elem is not None:
                    for osmatch in os_elem.findall("osmatch"):
                        result["os_guess"] = osmatch.get("name", "")
                        break  # Take highest confidence match

                # Script output (vuln hints)
                for script in host.iter("script"):
                    output = script.get("output", "")
                    sid    = script.get("id", "")
                    if output and any(k in output.lower() for k in
                                      ["vuln", "exploit", "cve", "vulnerable", "critical"]):
                        result["vuln_hints"].append(f"[{sid}] {output[:200]}")

        except ET.ParseError as e:
            console.print(f"[yellow]   XML parse error: {e}[/yellow]")

        return result

    # ------------------------------------------------------------------

    @staticmethod
    def _empty_result(timed_out: bool = False) -> dict:
        return {
            "open_ports": [],
            "services":   {},
            "os_guess":   None,
            "vuln_hints": [],
            "raw_xml":    "",
            "timed_out":  timed_out,
        }
