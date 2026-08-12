#!/usr/bin/env python3
"""Deny destructive git commands unless the user explicitly requested them."""

from __future__ import annotations

import json
import re
import sys

DENY_PATTERNS = [
    (
        re.compile(r"\bgit\s+push\b.*(--force|--force-with-lease|-f)\b"),
        "Blocked force push. Only run when the user explicitly requested it.",
    ),
    (
        re.compile(r"\bgit\s+reset\s+--hard\b"),
        "Blocked git reset --hard. Only run when the user explicitly requested it.",
    ),
]


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(json.dumps({"permission": "allow"}))
        return 0

    command = payload.get("command") or ""
    for pattern, message in DENY_PATTERNS:
        if pattern.search(command):
            print(
                json.dumps(
                    {
                        "permission": "deny",
                        "user_message": message,
                        "agent_message": message,
                    }
                )
            )
            return 0

    print(json.dumps({"permission": "allow"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
