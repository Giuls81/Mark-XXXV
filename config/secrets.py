"""Centralized secrets bootstrap for Mark-XXXV (security-hardening fork).

Reads GEMINI_API_KEY from .env and ensures the legacy config/api_keys.json file
exists and is up-to-date so all upstream code keeps working unmodified.

Resolution order:
  1. GEMINI_API_KEY environment variable (loaded from .env if present)
  2. Legacy config/api_keys.json (backward compatibility)
"""

import json
import os
from pathlib import Path

_BASE_DIR = Path(__file__).resolve().parent.parent
_ENV_PATH = _BASE_DIR / ".env"
_LEGACY_JSON = _BASE_DIR / "config" / "api_keys.json"


def _load_env() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    if _ENV_PATH.exists():
        load_dotenv(_ENV_PATH)


def _read_legacy_key() -> str:
    if not _LEGACY_JSON.exists():
        return ""
    try:
        with open(_LEGACY_JSON, "r", encoding="utf-8") as f:
            return (json.load(f).get("gemini_api_key") or "").strip()
    except (json.JSONDecodeError, OSError):
        return ""


def bootstrap() -> None:
    """Load .env, mirror env value into legacy api_keys.json, fail fast if no key."""
    _load_env()

    env_key = (os.getenv("GEMINI_API_KEY") or "").strip()
    legacy_key = _read_legacy_key()

    api_key = env_key or legacy_key
    if not api_key:
        raise SystemExit(
            "\n[CONFIG] GEMINI_API_KEY non configurata.\n"
            "  Crea un file .env nella root del progetto con:\n"
            "      GEMINI_API_KEY=la_tua_chiave\n"
            "  Ottienila gratis su https://aistudio.google.com/apikey\n"
        )

    if env_key and env_key != legacy_key:
        _LEGACY_JSON.parent.mkdir(parents=True, exist_ok=True)
        with open(_LEGACY_JSON, "w", encoding="utf-8") as f:
            json.dump({"gemini_api_key": env_key}, f)


def get_api_key() -> str:
    bootstrap()
    return (os.getenv("GEMINI_API_KEY") or _read_legacy_key()).strip()
