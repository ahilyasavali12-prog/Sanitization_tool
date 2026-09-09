# Agentic Firewall — Claude Code Plugin

Local prompt-injection/jailbreak firewall. Scans every prompt and Bash
tool call in Claude Code before the model sees it. 100% free, localhost only.

## Setup
1. pip install -r requirements.txt
2. ./start_sidecar.sh
3. In Claude Code:
   /plugin marketplace add youruser/agentic-firewall-plugin
   /plugin install agentic-firewall@agentic-firewall-plugin
4. Restart Claude Code. Approve the hooks when prompted.

## Commands
- /fw-learn <text>  — add an attack sample
- /fw-stats         — view stats & recent audit log

## Fail-open policy
If the sidecar is down, prompts are allowed (session never breaks).
Run ./start_sidecar.sh after reboot.