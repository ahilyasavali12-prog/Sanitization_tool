"""
OpenAPI spec parser for the Tool Sanitization Sandbox.

Converts a parsed OpenAPI spec (JSON or YAML) into the same
{name, description, parameters} shape that sanitize_toolset() already
understands — one "tool" per API operation (path + HTTP method).

Why this matters for the sandbox: an agent using an OpenAPI-described
API reads each operation's summary/description to decide when to call
it, exactly like it reads an MCP tool's description. The same poisoning
attack (hidden instructions in the text an agent trusts) applies here
too — this just gets that text into the same pipeline.
"""

import json
from pathlib import Path

try:
    import yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False


def load_spec_file(path: str) -> dict:
    """Load an OpenAPI spec from a .json, .yaml, or .yml file."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")

    if p.suffix.lower() == ".json":
        return json.loads(text)

    if p.suffix.lower() in (".yaml", ".yml"):
        if not _HAVE_YAML:
            raise RuntimeError(
                "This is a YAML file, but PyYAML isn't installed. "
                "Run: pip install pyyaml   — or convert the spec to JSON instead."
            )
        return yaml.safe_load(text)

    # Unknown extension — try JSON first, then YAML if available, so a
    # spec saved without a proper extension still works.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        if _HAVE_YAML:
            return yaml.safe_load(text)
        raise RuntimeError(
            f"Couldn't parse {path} as JSON, and PyYAML isn't installed "
            "to try YAML. Run: pip install pyyaml"
        )


def is_openapi_spec(data) -> bool:
    """Heuristic: does this look like an OpenAPI/Swagger spec, not a plain tool list?"""
    return isinstance(data, dict) and ("openapi" in data or "swagger" in data) and "paths" in data


def openapi_to_tools(spec: dict) -> list:
    """
    Convert every operation in an OpenAPI spec's `paths` into a tool dict:
      {
        "name": "<operationId or method_path>",
        "description": "<summary + description>",
        "parameters": {"properties": {param_name: {"description": ...}}}
      }
    """
    tools = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            # skip non-HTTP-method keys OpenAPI allows at this level
            # (e.g. "parameters" shared across all methods on a path)
            if method.lower() not in ("get", "post", "put", "patch", "delete", "options", "head"):
                continue
            if not isinstance(op, dict):
                continue

            name = op.get("operationId") or f"{method.upper()}_{path}"
            summary = op.get("summary", "")
            description = op.get("description", "")
            combined_description = " ".join(part for part in [summary, description] if part)

            properties = {}
            for param in op.get("parameters", []):
                if isinstance(param, dict) and "name" in param:
                    properties[param["name"]] = {
                        "description": param.get("description", "")
                    }

            # request body descriptions (OpenAPI 3.x) can also carry text
            # an agent would read — pull those in too if present
            request_body = op.get("requestBody", {})
            if isinstance(request_body, dict) and "description" in request_body:
                combined_description += " " + str(request_body["description"])

            tools.append({
                "name": name,
                "description": combined_description,
                "parameters": {"properties": properties},
            })

    return tools


def load_tools_auto(path: str) -> list:
    """
    Load tools from a file, auto-detecting whether it's a plain tool
    list/{"tools": [...]}  or a real OpenAPI spec.
    """
    data = load_spec_file(path)

    if is_openapi_spec(data):
        return openapi_to_tools(data)

    if isinstance(data, dict) and "tools" in data:
        return data["tools"]

    if isinstance(data, list):
        return data

    raise ValueError(
        "Unrecognized file format — expected a plain JSON list of tools, "
        "{\"tools\": [...]}, or an OpenAPI spec with \"openapi\"/\"swagger\" "
        "and \"paths\" keys."
    )