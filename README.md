<div align="center">



**Smart recon engine powered by OpenRouter. Built for labs and CTFs by CYezzy**

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)

</div>

## What is PhantomPort?

PhantomPort is a recon engine that uses a language model via OpenRouter to decide what nmap scan to run next based on what it already found. Instead of running the same commands every time, it builds up a picture of the target and escalates intelligently.

You set the goal. It figures out the path.

```
Phase 0 - asks what you're trying to find
Phase 1 - runs a baseline scan with no model involvement
Phase 2 - loop starts:
          model proposes next command
          reasonability check runs
          safety validator runs
          command executes
          result gets scored
          if score is good, keep going
          if score is bad, change strategy
          state saves to disk
          repeat
```

## Features

- Set a goal at the start and every decision gets made around it
- Each scan builds on the last, no repeated commands
- Every result gets a score based on what new info was found
- Two validation steps before anything runs
- nmap output saved as XML and parsed properly, not scraped from terminal text
- Full session state saved after every scan so you can resume if it gets interrupted
- Dry run mode to preview what would run without touching anything
- Stealth, balanced, and aggressive modes

## Architecture

| File | What it does |
|---|---|
| `main.py` | entry point, CLI, main loop |
| `phantomport/ai_engine.py` | OpenRouter calls, goal setup, command proposals |
| `phantomport/scanner.py` | runs nmap, parses XML output |
| `phantomport/validator.py` | blocks unsafe commands, checks flags against whitelist |
| `phantomport/evaluator.py` | scores results, flags stale strategies |
| `phantomport/state.py` | tracks everything found, saves to JSON |
| `phantomport/config.py` | settings, model config, safety lists |

## Scoring

Results get scored after every scan. If the score hits zero or below, the engine changes approach.

| What happened | Score |
|---|---|
| New open port | +2 |
| New service version | +3 |
| OS fingerprint (first time) | +4 |
| Vulnerability hint | +5 |
| Nothing new found | -1 |
| Timed out | -2 |

## Safety

Two checks run before every command executes.

**Check 1 - logic review**
Looks at the proposal and the current state. Rejects anything redundant, anything that jumps scan depth too fast, or anything that does not match the goal.

**Check 2 - hard validator**
- Command must start with `nmap`
- Every flag is checked against a whitelist
- Blocks `;` `&&` `||` `|` backticks `$()` `${}`
- Blocks `rm` `wget` `curl` `nc` `bash` `sh`
- Target lock prevents the model from scanning a different host mid-session

Nothing bypasses the validator.

## Install

```bash
git clone https://github.com/cyeezy08/phantomport
cd phantomport
pip install -r requirements.txt
pip install -e .
```

Python 3.11+, nmap on your system, and an OpenRouter API key required.

```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
```

Or paste it directly into `phantomport/config.py`.

Set your model in `phantomport/config.py`:
```python
MODEL = "nousresearch/hermes-3-llama-3.1-405b:free"
```

## Usage

```bash
# basic scan
python main.py 10.10.10.10

# stealth mode
python main.py 10.10.10.10 --mode stealth

# aggressive mode
python main.py 10.10.10.10 --mode aggressive

# preview without running anything
python main.py 10.10.10.10 --dry-run

# resume a previous session
python main.py --resume sessions/session_abc123.json

# limit iterations
python main.py 10.10.10.10 --max-iter 10
```

## Models

Free tier on OpenRouter requires the `:free` suffix.

| Model | Notes |
|---|---|
| `nousresearch/hermes-3-llama-3.1-405b:free` | best results so far |
| `meta-llama/llama-3.1-8b-instruct:free` | faster |
| `google/gemma-3-4b-it:free` | backup |

503 errors mean the model is overloaded. Swap the string and try again.

## Sessions

Sessions save to `sessions/session_<id>.json` after every scan. Includes the full scan history, every port and service found, OS info, vuln hints, current depth, and the original goal. Pick up where you left off with `--resume`.

## Scan Depth

The engine moves through depth levels one step at a time.

| Level | What runs |
|---|---|
| 1 | top 1000 ports, SYN scan |
| 2 | full port range |
| 3 | service version detection |
| 4 | default script scan |
| 5 | targeted vuln scripts |

## Legal

For authorized targets only. Your own machines, home labs, HackTheBox, TryHackMe, VulnHub. Do not scan anything you do not have permission to scan. The authors take no responsibility for misuse.

## What'd I like to do next 

- [ ] single API call for propose and validate combined (cuts rate limit issues)
- [ ] CVE lookup per service found
- [ ] gobuster/ffuf hints for web ports
- [ ] auto script selection based on service (WinRM, SMB, FTP etc)
- [ ] HTML report export
- [ ] Docker support

## Contributing

PRs are open. If you find a way around the validator, open an issue.
