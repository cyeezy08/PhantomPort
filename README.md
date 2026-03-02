<div align="center">

```
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██████╗  ██████╗ ██████╗ ████████╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║██████╔╝██║   ██║██████╔╝   ██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔═══╝ ██║   ██║██╔══██╗   ██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║     ╚██████╔╝██║  ██║   ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

**AI-guided reconnaissance engine. Not a toy.**

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)

</div>

---

## What is PhantomPort?

PhantomPort uses an AI model as a **strategy engine** — not a shell.

Most "AI + security" tools just wrap a CLI in ChatGPT. PhantomPort is different. It runs a goal-driven decision loop where the AI evaluates what was found, scores whether the scan was actually useful, and only then decides what to do next. Every proposed command passes through a hard rule-based safety validator before anything executes.

The AI suggests. You control execution. Nothing runs blind.

---

## How it works

```
┌─────────────────────────────────────────────────────────┐
│                   PhantomPort Loop                      │
│                                                         │
│   Phase 0 — AI asks user for their recon objective      │
│                        │                                │
│   Phase 1 — Baseline scan (no AI, always runs first)    │
│                        │                                │
│   Phase 2 — AI decision loop:                           │
│                                                         │
│        AI proposes next nmap command                    │
│                        │                                │
│             Reasonability gate                          │
│        (is this a logical next step?)                   │
│                        │                                │
│              Safety validator                           │
│         (hard rules, no exceptions)                     │
│                        │                                │
│                    Execute                              │
│                        │                                │
│               Score the result                          │
│                        │                                │
│         score > 0 ──► keep going                        │
│         score ≤ 0 ──► pivot strategy                    │
│                        │                                │
│              Save state to JSON                         │
│         (resume if interrupted)                         │
└─────────────────────────────────────────────────────────┘
```

---

## Features

- **Goal-driven scanning** — AI asks what you're trying to achieve before touching a single port
- **Adaptive decision loop** — each scan informs the next; no mindless repetition
- **Scoring system** — new ports, service versions, OS fingerprints, and vuln hints all scored; redundant scans penalised
- **Dual validation gate** — AI reasonability check + hard rule-based safety validator before every execution
- **XML-first parsing** — nmap always outputs `-oX`; structured data not regex'd terminal spam
- **Session persistence** — full state saved to JSON after every scan; resume anytime with `--resume`
- **Dry run mode** — see exactly what the AI would do without executing a single scan
- **Three scan modes** — stealth, balanced, aggressive

---

## Architecture

| File | Responsibility |
|---|---|
| `main.py` | Entry point, CLI args, orchestration loop |
| `phantomport/ai_engine.py` | OpenRouter API, goal elicitation, command proposal, reasonability gate |
| `phantomport/scanner.py` | nmap execution, XML parsing, result normalisation |
| `phantomport/validator.py` | Hard rule-based safety — flag whitelist, injection blocking, target lock |
| `phantomport/evaluator.py` | Scores scan results, determines if strategy should pivot |
| `phantomport/state.py` | Session state, accumulated knowledge, JSON persistence |
| `phantomport/config.py` | All constants, API config, mode maps, safety lists |

---

## Scoring System

PhantomPort scores every scan result before deciding whether to continue on the same strategy:

| Event | Score |
|---|---|
| New open port discovered | +2 |
| New service version identified | +3 |
| OS fingerprint obtained (first time) | +4 |
| Vulnerability hint found | +5 |
| Redundant scan (nothing new) | -1 |
| Scan timed out | -2 |

If the score is `<= 0`, the AI is told the strategy is stale and must pivot approach.

---

## Safety

PhantomPort is built with the assumption that the AI **cannot be fully trusted**.

Every proposed command goes through two gates before execution:

**Gate 1 — Reasonability (AI)**
A separate AI call reviews the proposal and the current state. It rejects commands that are redundant, skip depth levels, don't align with the goal, or are too aggressive for the current mode.

**Gate 2 — Safety Validator (hard rules, no AI)**
- Command must start with `nmap`
- All flags checked against an explicit whitelist
- Banned patterns: `;` `&&` `||` `|` backticks `$()` `${}`
- Banned commands: `rm` `wget` `curl` `nc` `bash` `sh`
- Target lock — the session target must appear in the command (prevents mid-session host pivots)

The safety validator cannot be overridden by the AI. Ever.

---

## Install

```bash
git clone https://github.com/yourusername/phantomport
cd phantomport
pip install -r requirements.txt
pip install -e .
```

**Requirements:** Python 3.11+, nmap installed on your system, an OpenRouter API key.

Set your API key:
```bash
# Option 1 — environment variable
export OPENROUTER_API_KEY="sk-or-v1-..."

# Option 2 — edit phantomport/config.py directly
OPENROUTER_API_KEY = "sk-or-v1-..."
```

Set your model in `phantomport/config.py`:
```python
MODEL = "nousresearch/hermes-3-llama-3.1-405b:free"
```

---

## Usage

```bash
# Standard scan
python main.py 10.10.10.10

# Stealth mode (slower timing, lower footprint)
python main.py 10.10.10.10 --mode stealth

# Aggressive mode (faster, noisier)
python main.py 10.10.10.10 --mode aggressive

# Dry run — AI proposes commands, nothing executes
python main.py 10.10.10.10 --dry-run

# Resume an interrupted session
python main.py --resume sessions/session_abc123.json

# Cap the number of scan iterations
python main.py 10.10.10.10 --max-iter 10
```

---

## Recommended Free Models (OpenRouter)

The `:free` suffix is required for free tier models on OpenRouter.

| Model | Notes |
|---|---|
| `nousresearch/hermes-3-llama-3.1-405b:free` | Best reasoning, recommended |
| `meta-llama/llama-3.1-8b-instruct:free` | Fast, lighter |
| `google/gemma-3-4b-it:free` | Fallback |

Free tier models can go down. If you get a 503, swap the model string and retry.

---

## Session Files

Every session saves to `sessions/session_<id>.json` after each scan. The file contains the full scan history, all discovered ports and services, OS fingerprint, vulnerability hints, current depth level, strategy state, and your original goal. If PhantomPort is interrupted mid-session you lose nothing — pass the file to `--resume` and it picks up exactly where it stopped.

---

## Scan Depth Levels

The AI escalates through depth levels one at a time:

| Level | Description |
|---|---|
| 1 | Top 1000 ports, SYN scan |
| 2 | Full port range |
| 3 | Service version detection |
| 4 | Default script scan |
| 5 | Targeted vulnerability scripts |

Skipping levels requires justification. The reasonability gate enforces this.

---

## Legal

**For authorized targets only.**

Use PhantomPort on your own machines, lab environments, HackTheBox, TryHackMe, VulnHub, or any target you have explicit written permission to scan. Unauthorized scanning is illegal. The authors accept no liability for misuse.

---

## Roadmap

- [ ] Merge propose + reasonability into single API call (reduce rate limit pressure)
- [ ] CVE lookup integration per discovered service
- [ ] Web service fingerprinting hints (gobuster/ffuf suggestions)
- [ ] Service-specific script auto-selection (WinRM, SMB, FTP logic)
- [ ] HTML session report export
- [ ] Docker container for portable deployment

---

## Contributing

Pull requests welcome. If you find a bypass for the safety validator, open an issue — don't exploit it.

---

*Built for OSCP prep. Understand every line before you trust it.*
