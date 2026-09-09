"""
Tool Sanitization Sandbox — core logic.

Extends the existing prompt-injection detection (regex + gibberish +
ML classifier + vector similarity) to a different attack surface:
MCP tool lists / OpenAPI specs, instead of chat prompts.

Three kinds of checks:
  1. Per-tool text scan       — hidden instructions inside a tool's own
                                 name/description/parameter docs.
  2. Cross-tool correlation   — a set of tools that, combined, imply a
                                 dangerous capability (e.g. one tool reads
                                 secrets, another sends data out) even
                                 though no single tool looks dangerous
                                 alone. This is "multi-tool threshold
                                 poisoning."
  3. Image asset scan         — OCR any icon/screenshot bundled with a
                                 tool, then run the same text checks on
                                 whatever text comes out.
"""

import re
import sys
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CORE_DIR))

from agentic_firewall import INJECTION_PATTERNS  # noqa: E402
from agentic_firewall import looks_like_gibberish as _chat_gibberish_check  # noqa: E402


def looks_like_tool_gibberish(text: str) -> bool:
    """
    A length-aware variant of the chat gibberish heuristic.

    The original check's character-diversity ratio
    (unique chars / total length < 0.15) is tuned for short chat
    messages. Longer, naturally-written text — like a tool description —
    naturally has a lower ratio just because English text reuses common
    letters, which causes false positives on perfectly normal
    descriptions. We only apply that specific sub-check to short text,
    and keep the no-vowel-word and repeated-character checks (which
    don't have this length bias) for all lengths.
    """
    text = text.strip()
    if len(text) < 8:
        return False

    words = re.findall(r"[a-zA-Z]+", text)
    if not words:
        return True

    no_vowel = sum(1 for w in words if len(w) > 3 and not (set(w) & set("aeiouAEIOU")))
    if no_vowel / len(words) > 0.4:
        return True

    if re.search(r"(.)\1{5,}", text):
        return True

    # Character-diversity check only makes sense on short text — skip it
    # for anything long enough to be a real sentence or two.
    if len(text) <= 60 and len(set(text.lower())) / len(text) < 0.15:
        return True

    return False

# ── Patterns specific to poisoned tool metadata ────────────────────────
# These target phrasing an attacker would hide in a tool's *description*
# field, which an agent reads and trusts when deciding how/when to call
# the tool — different from a user typing a jailbreak in chat.
TOOL_METADATA_PATTERNS = [
    r"before (responding|replying) to the user,? first",
    r"without (telling|informing|notifying) the user",
    r"do this (silently|quietly|secretly)",
    r"always call this (tool|function) (first|before any other)",
    r"append (this|the following) to (every|each|all) (response|message|output)",
    r"send (a copy|the (result|output|response)) to https?://",
    r"also (send|forward|post|upload) .* to https?://",
    r"ignore (any|all) (safety|security) (warnings?|checks?)",
    r"this tool (must|should) be (called|used) (on every|before every)",
    r"hidden instruction",
    r"do not (mention|disclose|reveal) this to the user",
]

# ── Capability keywords for cross-tool correlation ─────────────────────
# Each tool's description/params gets tagged with zero or more of these
# capability categories based on keyword matches. Certain *combinations*
# across tools are the actual risk signal — not any one tool alone.
#
# IMPORTANT DISTINCTION: "credential_access" is split into two tiers.
# A login/authenticate endpoint that ACCEPTS a username/password as input
# is completely normal API design — it is not "credential access" in the
# exfiltration sense. What's actually suspicious is a tool that READS or
# EXPOSES secrets that don't belong to the immediate user action — stored
# API keys, .env files, SSH keys, arbitrary "credentials". Only the
# latter counts toward cross-tool risk scoring.
AUTH_FLOW_TOOL_NAME_PATTERN = re.compile(
    r"\b(login|logout|log[_ ]?in|log[_ ]?out|signin|sign[_ ]?in|signup|sign[_ ]?up|"
    r"signout|sign[_ ]?out|authenticate|auth)\b", re.IGNORECASE
)

CAPABILITY_KEYWORDS = {
    "data_read": [
        r"\breads?(ing)?\b", r"\bfetch(es|ing)?\b", r"\bgets?\b", r"\bretriev(e|es|ing)\b",
        r"\blists?\b", r"\bviews?(ing)?\b", r"\bfile contents?\b", r"\bdatabase\b", r"\bquer(y|ies|ying)\b",
    ],
    "data_exfil": [
        r"\bsends?(ing)?\b", r"\buploads?(ing)?\b", r"\bposts?(ing)?\b", r"\btransmits?(ting)?\b",
        r"\bemails?(ing)?\b", r"\bwebhooks?\b", r"http[s]?://", r"\bexternal (url|endpoint|server)s?\b",
    ],
    # Weak signal: appears in normal login/auth flows too — excluded from
    # cross-tool scoring when the tool name looks like an auth endpoint.
    "credential_access": [
        r"\bpasswords?\b", r"\btokens?\b",
    ],
    # Strong signal: reading/exposing STORED secrets, not accepting login
    # input. This is the tier that actually drives cross-tool findings.
    "secret_exposure": [
        r"\bapi[_ ]?keys?\b", r"\bsecrets?\b", r"\bcredentials?\b", r"\bssh[_ ]?keys?\b",
        r"\benv(iron(ment)?)? var(iable)?s?", r"\.env\b",
    ],
    "code_exec": [
        r"\bexecut(e|es|ing)\b", r"\bruns?(ning)?\b", r"\bevals?(uating)?\b", r"\bshells?\b",
        r"\bcommands?\b", r"\bscripts?\b", r"\bsubprocess(es)?\b",
    ],
    "destructive": [
        r"\bdeletes?(ing)?\b", r"\bremoves?(ing)?\b", r"\boverwrit(e|es|ing)\b",
        r"\breformat(s|ting)?\b", r"\bformat(s|ting)? (the )?(disk|drive|database|table)\b",
        r"\bdrop tables?\b", r"\btruncates?\b",
    ],
}

# Combinations of capabilities across DIFFERENT tools that together
# represent a real risk pattern, even if no single tool trips anything.
# "secret_exposure" (not the weaker "credential_access") is what's used
# for the genuinely suspicious combinations — accepting a login password
# is not treated as risky on its own.
RISKY_COMBINATIONS = [
    ({"secret_exposure", "data_exfil"},
     "One tool exposes stored secrets/credentials and another can send "
     "data out — combined, this is a plausible credential-exfiltration path.",
     "high"),
    ({"data_read", "data_exfil"},
     "One tool can read data (files/DB) and another can transmit data "
     "out — combined, this is a plausible data-exfiltration path.",
     "low"),
    ({"code_exec", "data_exfil"},
     "One tool can execute code/commands and another can send data out — "
     "combined, arbitrary code could be used to stage an exfiltration.",
     "medium"),
    ({"secret_exposure", "destructive"},
     "One tool exposes stored secrets and another can perform destructive "
     "actions — combined, an exposed credential could be used "
     "destructively without a human noticing either step.",
     "medium"),
]


def _combined_text(tool: dict) -> str:
    """Pull all the text an agent would actually read for this tool."""
    parts = [
        str(tool.get("name", "")),
        str(tool.get("description", "")),
    ]
    params = tool.get("parameters") or tool.get("inputSchema") or {}
    if isinstance(params, dict):
        # descriptions can be nested inside JSON-schema "properties"
        props = params.get("properties", {})
        for p in props.values():
            if isinstance(p, dict) and "description" in p:
                parts.append(str(p["description"]))
    return "\n".join(parts)


def scan_tool_text(tool: dict) -> dict:
    """Layer 1: scan a single tool's own metadata for hidden instructions."""
    text = _combined_text(tool)
    lowered = text.lower()

    for pattern in INJECTION_PATTERNS + TOOL_METADATA_PATTERNS:
        if re.search(pattern, lowered):
            return {
                "allowed": False,
                "reason": f"Hidden instruction pattern matched: {pattern}",
            }

    if looks_like_tool_gibberish(text):
        return {"allowed": False, "reason": "Tool metadata looks like gibberish/obfuscated text"}

    return {"allowed": True, "reason": "passed"}


def classify_capabilities(tool: dict) -> set:
    """
    Tag a tool with capability categories based on keyword matches.

    Excludes "credential_access" for tools whose NAME looks like a normal
    login/auth endpoint — accepting a username/password to authenticate
    is not the same signal as a tool that reads/exposes stored secrets
    (that's "secret_exposure", which is never excluded this way).
    """
    name = str(tool.get("name", ""))
    text = _combined_text(tool).lower()
    found = set()

    is_auth_flow_tool = bool(AUTH_FLOW_TOOL_NAME_PATTERN.search(name))

    for category, patterns in CAPABILITY_KEYWORDS.items():
        if category == "credential_access" and is_auth_flow_tool:
            continue  # normal login/logout accepting a password: not a signal
        for pattern in patterns:
            if re.search(pattern, text):
                found.add(category)
                break
    return found


def _tool_narrowness(caps: set) -> str:
    """
    A tool tagged with only 1 capability is "narrow" (single-purpose) —
    which matches how a deliberately-poisoned toolset tends to look
    (minimal tools with no other function). A tool tagged with 3+
    capabilities is "broad" — typical of a full-featured, legitimate
    REST resource (a pet endpoint that reads, updates, AND deletes is
    normal API design, not evidence of anything).
    """
    if len(caps) <= 1:
        return "narrow"
    if len(caps) >= 3:
        return "broad"
    return "medium"


def detect_multi_tool_threshold(tools: list) -> list:
    """
    Layer 2: cross-tool correlation, with severity scoring.

    Looks across the WHOLE toolset for risky capability combinations
    spread across two or more different tools. Each finding gets a
    severity based on:
      - the combination's inherent risk tier (set in RISKY_COMBINATIONS)
      - whether the contributing tools are "narrow" (single-purpose —
        more suspicious, matches how poisoned toolsets tend to look) or
        "broad" (full-featured — normal for large, legitimate APIs)
      - the overall size of the toolset (a risky combo inside a tiny,
        minimal toolset is more suspicious than the same combo buried
        inside a large, diverse, everyday API)
    """
    per_tool_caps = {tool.get("name", f"tool_{i}"): classify_capabilities(tool)
                     for i, tool in enumerate(tools)}
    total_tools = len(tools)

    findings = []
    for combo, explanation, base_severity in RISKY_COMBINATIONS:
        contributors = {cap: [] for cap in combo}
        for name, caps in per_tool_caps.items():
            for cap in combo:
                if cap in caps:
                    contributors[cap].append(name)

        if not all(contributors[cap] for cap in combo):
            continue

        distinct_tools = set()
        for tool_list in contributors.values():
            distinct_tools.update(tool_list)
        if len(distinct_tools) < 2:
            continue

        # narrowness check: are the contributing tools single-purpose?
        narrow_count = sum(
            1 for t in distinct_tools if _tool_narrowness(per_tool_caps[t]) == "narrow"
        )
        all_narrow = narrow_count == len(distinct_tools)

        # small toolset = more suspicious (poisoned sets tend to be
        # minimal); large diverse toolset = normal overlap is expected
        small_toolset = total_tools <= 8

        # escalate severity if the signal is strong (narrow tools) or
        # de-escalate if it's likely just normal API breadth
        severity = base_severity
        if base_severity == "high" and not (all_narrow or small_toolset):
            severity = "medium"  # still worth a look, but less alarming
        elif base_severity == "medium" and (all_narrow and small_toolset):
            severity = "high"
        elif base_severity in ("medium", "low") and not all_narrow and not small_toolset:
            severity = "low"

        findings.append({
            "combination": sorted(combo),
            "contributing_tools": {cap: names for cap, names in contributors.items()},
            "explanation": explanation,
            "severity": severity,
            "note": ("Contributing tools are broad/multi-purpose and the toolset is "
                     "large — likely normal API breadth rather than poisoning."
                     if severity == "low" else
                     "Contributing tools are narrow/single-purpose in a small "
                     "toolset — matches how a poisoned tool set tends to look."
                     if severity == "high" else
                     "Worth a manual look, but not a strong standalone signal."),
        })
    return findings


def scan_image_text(extracted_text: str) -> dict:
    """
    Layer 3: run the same text checks against OCR output from an image
    asset (icon, screenshot) bundled with a tool. Caller is responsible
    for actually running OCR — this function only does the text analysis,
    so it stays testable without a real OCR engine installed.
    """
    if not extracted_text or not extracted_text.strip():
        return {"allowed": True, "reason": "no text found in image"}

    lowered = extracted_text.lower()
    for pattern in INJECTION_PATTERNS + TOOL_METADATA_PATTERNS:
        if re.search(pattern, lowered):
            return {
                "allowed": False,
                "reason": f"Hidden instruction found in image text: {pattern}",
            }
    return {"allowed": True, "reason": "passed"}


def sanitize_toolset(tools: list, image_texts: dict = None) -> dict:
    """
    Run all layers against a full list of tools (as you'd get from an
    MCP tools/list response or a parsed OpenAPI spec).

    tools: list of dicts, each with at least "name" and "description",
           optionally "parameters"/"inputSchema".
    image_texts: optional dict of {tool_name: ocr_extracted_text}
    """
    image_texts = image_texts or {}
    per_tool_results = []

    for tool in tools:
        name = tool.get("name", "<unnamed>")
        text_result = scan_tool_text(tool)
        image_result = None
        if name in image_texts:
            image_result = scan_image_text(image_texts[name])

        overall_allowed = text_result["allowed"] and (image_result is None or image_result["allowed"])
        per_tool_results.append({
            "name": name,
            "allowed": overall_allowed,
            "text_scan": text_result,
            "image_scan": image_result,
        })

    cross_tool_findings = detect_multi_tool_threshold(tools)
    high_severity_findings = [f for f in cross_tool_findings if f["severity"] == "high"]

    return {
        "per_tool_results": per_tool_results,
        "cross_tool_findings": cross_tool_findings,
        "any_tool_blocked": any(not r["allowed"] for r in per_tool_results),
        "cross_tool_risk_detected": len(high_severity_findings) > 0,
    }