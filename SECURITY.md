# Security Model — Mark-XXXV (security-hardening fork)

This fork of [FatihMakes/Mark-XXXV](https://github.com/FatihMakes/Mark-XXXV)
adds a security layer on top of the upstream voice assistant. **Level: Medium.**
Shell and code execution remain functional; every potentially-destructive action
prompts the user and is recorded to an append-only audit log.

## What's hardened vs. upstream

| Area | Upstream | This fork |
|---|---|---|
| Dependency versions | unpinned (latest of everything) | upper-bounded ranges |
| Secrets | `config/api_keys.json` in repo path | `.env` (gitignored) with legacy fallback |
| Tool dispatch | direct LLM → action | wrapped with `policy_check + confirm + audit_log` |
| Shell command blocklist | basic | extended (PowerShell encoded cmds, curl-pipe-shell, vssadmin, etc.) |
| Shell visibility | LLM controls | always visible — user sees the cmd window |
| Code execution preview | none | full code printed to console before `_run_file` |
| Code execution timeout | 30–120s | 15–30s |
| File deletion confirmation | `confirm` param controlled by LLM | user prompt at executor wrap (LLM cannot bypass) |
| Audit trail | none | `logs/audit-YYYYMMDD.jsonl` append-only |

## How the security wrap works

Every tool call from the LLM passes through `agent/executor.py:_call_tool()`,
which is now a thin wrapper around the original dispatch logic
(`_call_tool_impl`). For each invocation:

1. **`audit_log(phase="request")`** — record what the LLM wants to do.
2. **`policy_check`** — hard-block obvious bad patterns (currently delegates to
   `actions/cmd_control._is_safe()` for shell commands). On block:
   `audit_log(phase="denied")` and return without ever reaching the action.
3. **`is_destructive`** — classify the call. Destructive tools and sub-actions
   are listed in `agent/security.py`.
4. **`confirm_action`** — interactive y/n on stdin showing a redacted summary.
   `[A]llow always` whitelists `tool:action` for the rest of the session.
5. **dispatch** to the original `_call_tool_impl`.
6. **`audit_log(phase="completed"|"error")`** — record the outcome.

## Destructive classification

Always destructive (every invocation prompts):
- `cmd_control`, `code_helper`, `dev_agent`, `generated_code`, `send_message`

Conditionally destructive:
- `file_controller` when `action ∈ {delete, move, rename, write, organize_desktop}`
- `computer_settings` when `action` matches shutdown/restart/lock/wifi or
  `description` contains those triggers

## Audit log

`logs/audit-YYYYMMDD.jsonl` — one JSON object per line, four phases per call
(`request`, `allowed` / `denied`, `completed` / `error`). Long string values
truncate at 1000 chars. The log is append-only; rotate or archive manually.

To inspect:
```bash
type logs\audit-20260505.jsonl | findstr "denied"
```

## Residual risks (NOT addressed by this fork)

1. **Continuous microphone streaming to Google.** This is upstream's design —
   audio is sent to Gemini Live in real time. To mitigate, mute via the F4 key
   when not actively prompting.
2. **LLM-composed shell commands can bypass the blocklist.** The blocklist is
   regex-based and not semantically exhaustive. A creative attacker / faulty
   prompt injection could craft a command that slips through.
3. **Webcam and screen capture remain available.** Screenshots and webcam
   frames go to Gemini for vision analysis.
4. **Memory extraction.** Upstream extracts personal info (names, preferences,
   relationships) automatically and writes it to `memory/`. Review what's
   stored periodically.
5. **Alert fatigue.** With `[A]llow always` it's tempting to bypass
   confirmations. The session whitelist resets each restart; that's intentional.
6. **Pinned versions age.** Run `pip list --outdated` periodically and bump
   pins after testing.

## How to disable individual protections

If a protection is too noisy:

- **Skip confirmation for a specific tool**: edit `DESTRUCTIVE_TOOLS` /
  `DESTRUCTIVE_FILE_ACTIONS` / `DESTRUCTIVE_COMPUTER_ACTIONS` in
  `agent/security.py`.
- **Disable the wrap entirely**: in `agent/executor.py:_call_tool`, replace
  the body with `return _call_tool_impl(tool, parameters, speak)`. (Not
  recommended.)
- **Suppress audit log**: replace the body of `audit_log` in
  `agent/security.py` with `pass`. (Not recommended — you lose forensic
  capability.)

## Reporting issues

If you find a way to bypass `policy_check` or `confirm_action`, open a private
issue or contact the fork maintainer directly — do not publish working
exploits while users may be running this code on their primary machines.
