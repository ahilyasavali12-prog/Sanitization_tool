"""
Tool Sanitization Sandbox — CLI.

Loads a JSON file of tools (matching MCP tools/list shape, or a simple
extraction from an OpenAPI spec) and runs it through the sanitizer,
printing a readable report.

Usage:
    python sanitize_tools.py sample_poisoned_tools.json
"""

import sys
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parent / "core"
sys.path.insert(0, str(CORE_DIR))

from tool_sanitizer import sanitize_toolset  # noqa: E402
from openapi_parser import load_tools_auto  # noqa: E402


def load_tools(path: str) -> list:
    """
    Loads tools from a file — auto-detects a plain tool list,
    {"tools": [...]}, or a real OpenAPI spec (JSON or YAML).
    """
    return load_tools_auto(path)


def print_report(report: dict):
    print("=" * 70)
    print("PER-TOOL SCAN RESULTS")
    print("=" * 70)
    for r in report["per_tool_results"]:
        mark = "OK " if r["allowed"] else "XX "
        print(f"{mark} {r['name']}")
        if not r["text_scan"]["allowed"]:
            print(f"      text scan  -> BLOCKED: {r['text_scan']['reason']}")
        if r["image_scan"] and not r["image_scan"]["allowed"]:
            print(f"      image scan -> BLOCKED: {r['image_scan']['reason']}")

    print()
    print("=" * 70)
    print("CROSS-TOOL THRESHOLD POISONING CHECK")
    print("=" * 70)
    if not report["cross_tool_findings"]:
        print("No risky cross-tool capability combinations detected.")
    else:
        for finding in report["cross_tool_findings"]:
            print(f"FLAGGED combination: {' + '.join(finding['combination'])}")
            print(f"  {finding['explanation']}")
            for cap, tools in finding["contributing_tools"].items():
                print(f"    {cap:<20} <- {', '.join(tools)}")
            print()

    print("=" * 70)
    print("OVERALL VERDICT")
    print("=" * 70)
    if report["any_tool_blocked"] or report["cross_tool_risk_detected"]:
        print("UNSAFE — do not let the agent load this toolset as-is.")
    else:
        print("No issues detected in this toolset.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sanitize_tools.py <tools.json>")
        sys.exit(1)

    tools = load_tools(sys.argv[1])
    print(f"Loaded {len(tools)} tool(s) from {sys.argv[1]}\n")
    report = sanitize_toolset(tools)
    print_report(report)