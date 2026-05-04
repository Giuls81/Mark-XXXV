"""Security layer for Mark-XXXV (security-hardening fork).

Single chokepoint that wraps `executor._call_tool` to provide:
- policy_check : hard-block known-dangerous patterns
- is_destructive : classify a tool call as destructive
- confirm_action : interactive y/n prompt for the user
- audit_log : append-only JSONL log of every tool invocation
"""

import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_BASE_DIR = Path(__file__).resolve().parent.parent
_LOG_DIR = _BASE_DIR / "logs"
_LOG_DIR.mkdir(exist_ok=True)


DESTRUCTIVE_TOOLS = frozenset({
    "cmd_control",
    "code_helper",
    "dev_agent",
    "generated_code",
    "send_message",
})

DESTRUCTIVE_FILE_ACTIONS = frozenset({
    "delete", "move", "rename", "write", "organize_desktop",
})

DESTRUCTIVE_COMPUTER_ACTIONS = frozenset({
    "shutdown", "shut_down", "power_off", "turn_off_computer",
    "restart", "restart_computer", "reboot", "reboot_computer",
    "lock_screen", "lock",
    "toggle_wifi", "wifi", "wifi_toggle",
})


_log_lock = threading.Lock()
_allow_lock = threading.Lock()
_session_allow: set[str] = set()


def is_destructive(tool: str, parameters: dict | None) -> bool:
    if tool in DESTRUCTIVE_TOOLS:
        return True

    p = parameters or {}

    if tool == "file_controller":
        action = (p.get("action") or "").lower().strip()
        return action in DESTRUCTIVE_FILE_ACTIONS

    if tool == "computer_settings":
        action = (p.get("action") or "").lower().strip()
        if action in DESTRUCTIVE_COMPUTER_ACTIONS:
            return True
        desc = (p.get("description") or "").lower()
        triggers = ("shutdown", "restart", "reboot", "spegni", "riavvia", "lock screen")
        return any(t in desc for t in triggers)

    return False


def policy_check(tool: str, parameters: dict | None) -> tuple[bool, str]:
    """Hard-block obviously-bad invocations regardless of user opinion."""
    p = parameters or {}

    if tool == "cmd_control":
        try:
            from actions.cmd_control import _is_safe
        except Exception:
            return True, "policy module unavailable"
        for field in ("command", "task"):
            value = (p.get(field) or "").strip()
            if value:
                ok, reason = _is_safe(value)
                if not ok:
                    return False, reason

    return True, "ok"


def _summarize_for_user(tool: str, parameters: dict | None) -> str:
    p = parameters or {}
    if tool == "cmd_control":
        return f"Comando shell: {p.get('command') or p.get('task') or '(no detail)'}"
    if tool == "code_helper":
        action = p.get("action", "auto")
        desc = (p.get("description") or "")[:160]
        return f"Code helper [{action}]: {desc}"
    if tool == "dev_agent":
        return f"Dev agent (multi-file project): {(p.get('description') or '')[:160]}"
    if tool == "generated_code":
        return f"Codice Python generato per: {(p.get('description') or '')[:160]}"
    if tool == "file_controller":
        action = p.get("action", "?")
        path = p.get("path", "")
        name = p.get("name", "")
        target = f"{path}/{name}".rstrip("/")
        return f"File [{action}]: {target}"
    if tool == "computer_settings":
        return f"System action: {p.get('action') or p.get('description') or '?'}"
    if tool == "send_message":
        return f"Messaggio a {p.get('to') or '?'}: {(p.get('text') or '')[:80]}"
    return f"{tool}: {json.dumps(p, ensure_ascii=False)[:200]}"


def confirm_action(tool: str, parameters: dict | None) -> bool:
    key = f"{tool}:{(parameters or {}).get('action', '')}"
    with _allow_lock:
        if key in _session_allow:
            return True

    summary = _summarize_for_user(tool, parameters)
    sys.stdout.write("\n" + "─" * 64 + "\n")
    sys.stdout.write(f"⚠️  CONFERMA RICHIESTA — {tool}\n")
    sys.stdout.write(f"   {summary}\n")
    sys.stdout.write("─" * 64 + "\n")
    sys.stdout.write("[Y]es / [N]o / [A]llow always for this session: ")
    sys.stdout.flush()

    try:
        answer = input().strip().lower()
    except EOFError:
        answer = "n"

    if answer == "a":
        with _allow_lock:
            _session_allow.add(key)
        return True
    return answer in ("y", "yes", "s", "si", "sì")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(x) for x in value[:50]]
    if isinstance(value, str) and len(value) > 1000:
        return value[:1000] + f"...<truncated {len(value)} chars>"
    return value


def audit_log(
    tool: str,
    parameters: dict | None,
    phase: str,
    result: Any = None,
) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "phase": phase,
        "parameters": _redact(parameters or {}),
    }
    if result is not None:
        record["result"] = _redact(result)

    log_path = _LOG_DIR / f"audit-{datetime.now().strftime('%Y%m%d')}.jsonl"
    line = json.dumps(record, ensure_ascii=False, default=str) + "\n"

    with _log_lock:
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            print(f"[Security] audit log write failed: {e}", file=sys.stderr)
