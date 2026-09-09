#!/usr/bin/env python3
"""Claude Code hook — reads hook JSON on stdin, checks the sidecar.

Exit 0  → allow
Exit 2  → BLOCK (stderr shown as the reason)
Fails open if sidecar is down, so the session never breaks.
"""
import json
import sys
import urllib.request

SIDECAR = "http://127.0.0.1:8100/scan"
TIMEOUT = 5  # seconds


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # malformed payload → fail open

    # UserPromptSubmit puts the prompt in "prompt";
    # PreToolUse puts the tool call in "tool_input"
    text = payload.get("prompt") or ""
    if not text:
        tool_input = payload.get("tool_input", {})
        text = str(tool_input.get("command", ""))
    if not text.strip():
        sys.exit(0)

    req = urllib.request.Request(
        SIDECAR,
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            result = json.loads(r.read().decode())
    except Exception:
        sys.exit(0)  # sidecar down → fail open (or fail closed: exit 2)

    if not result.get("allowed", True):
        print(f"🛑 AGENTIC FIREWALL: {result.get('reason', 'blocked')}", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()