#!/usr/bin/env python3
"""After Java file edits, remind the agent to apply Spotless before finishing."""

from __future__ import annotations

import json
import sys


def edited_path(payload: dict) -> str:
    for key in ("file_path", "filePath", "path"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    file_info = payload.get("file")
    if isinstance(file_info, dict):
        for key in ("path", "file_path", "filePath"):
            value = file_info.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("{}")
        return 0

    path = edited_path(payload)
    if not path.endswith(".java"):
        print("{}")
        return 0

    print(
        json.dumps(
            {
                "additional_context": (
                    f"Java file edited ({path}). Before finishing, run "
                    "`mvn -B spotless:apply` (or `/lint`) so Spotless Google "
                    "Java Format matches CI."
                )
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
