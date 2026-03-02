"""
config.py — Central configuration for PhantomPort
Edit this file or use environment variables.
"""

import os

# --- OpenRouter API ---
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "put_ur_own_shit")
# set YOU OWN DESIRED MODELS PAID OR FREE RECOMMEND HERMES but adjust railguards urself
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"


# Use a capable model — free or paid
MODEL = os.getenv("PHANTOMPORT_MODEL", "nousresearch/hermes-3-llama-3.1-405b:free")

# --- Scan limits ---
MAX_ITERATIONS = 15          # Hard ceiling on loop iterations
SCAN_TIMEOUT   = 120         # Seconds before a scan is killed

# --- Scoring thresholds ---
SCORE_STALE_THRESHOLD = 0    # Score <= this triggers strategy_stale
SCORE_SUCCESS_MIN     = 2    # Score >= this counts as a good result

# --- Scan depth levels ---
# AI can only move one level at a time
DEPTH_LEVELS = {
    1: "Top 1000 ports, SYN scan",
    2: "Full port range",
    3: "Service version detection",
    4: "Default script scan",
    5: "Targeted vulnerability scripts",
}

# --- Mode timing maps ---
MODE_TIMING = {
    "stealth":    "T2",
    "balanced":   "T3",
    "aggressive": "T4",
}

# --- Allowed nmap flags whitelist ---
ALLOWED_FLAGS = {
    "-sS", "-sT", "-sU", "-sV", "-sC", "-sn",
    "-O", "-A",
    "-p", "--top-ports", "-p-",
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "-Pn", "-n",
    "--script", "--open",
    "-oX",       # Always added automatically — do not remove
    "--version-intensity",
    "--min-rate", "--max-rate",
    "-f",        # Fragmentation (stealth mode only)
    "-D",        # Decoy (stealth mode only)
}

# --- Explicitly banned substrings (safety layer) ---
BANNED_PATTERNS = [
    ";", "&&", "||", "|",
    "`", "$(", "${",
    "rm", "wget", "curl", "nc", "bash", "sh",
    "/etc", "/bin", "/usr",
    "--script-args",    # Prevent script argument injection
]

# --- Session storage ---
SESSIONS_DIR = os.getenv("PHANTOMPORT_SESSIONS", "./sessions")
