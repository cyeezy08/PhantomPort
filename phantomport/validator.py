"""
validator.py — Hard rule-based safety layer

This runs BEFORE execution. If it fails, the command is binned.
No exceptions. No AI override.

Belt AND suspenders approach:
  1. Check for banned patterns first (fast rejection)
  2. Tokenise and validate each flag against whitelist
  3. Verify target matches session target (no mid-session target swaps)
"""

import re
import shlex
from phantomport import config


class Validator:

    def check(self, command: str, session_target: str) -> tuple[bool, str]:
        """
        Returns (is_safe: bool, violation_reason: str).
        Empty reason string if safe.
        """

        # 1. Must start with nmap
        if not command.strip().lower().startswith("nmap"):
            return False, "Command does not start with 'nmap'"

        # 2. Banned pattern scan (covers injection, shell ops, dangerous commands)
        for pattern in config.BANNED_PATTERNS:
            if pattern in command:
                return False, f"Banned pattern detected: '{pattern}'"

        # 3. No backticks or $() even without the banned list catching them
        if re.search(r'`|\$\(|\${', command):
            return False, "Shell substitution detected"

        # 4. Tokenise and check flags
        try:
            tokens = shlex.split(command)
        except ValueError as e:
            return False, f"Failed to tokenise command: {e}"

        # First token is "nmap" — skip it
        i = 1
        while i < len(tokens):
            token = tokens[i]

            if token.startswith("-"):
                # Normalise: --flag=value → --flag
                flag = token.split("=")[0]

                if flag not in config.ALLOWED_FLAGS:
                    return False, f"Flag not in whitelist: '{flag}'"

                # -D (decoy) only allowed in stealth mode — enforced at call site
                # Here just validate syntax
                i += 1

            else:
                # Non-flag token — should be target IP/hostname or port spec or script name
                # Make sure it's not something dangerous
                if re.search(r'[;&|`$]', token):
                    return False, f"Dangerous characters in argument: '{token}'"
                i += 1

        # 5. Target lock — ensure session target appears in command
        #    (prevents AI from pivoting to a different host mid-session)
        if session_target not in command:
            return False, f"Target '{session_target}' not found in command — possible target swap"

        return True, ""
