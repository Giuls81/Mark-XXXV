"""setup.py — Mark-XXXV (security-hardening fork) installer.

Installs Python dependencies, Playwright browsers, creates the audit log
directory, and seeds the .env file from .env.example if it doesn't exist.
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_PATH = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"
LOGS_DIR = ROOT / "logs"


def main() -> int:
    print("[setup] Installing Python requirements...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
        check=True,
    )

    print("[setup] Installing Playwright browsers...")
    subprocess.run(
        [sys.executable, "-m", "playwright", "install"],
        check=True,
    )

    LOGS_DIR.mkdir(exist_ok=True)
    print(f"[setup] Audit log directory: {LOGS_DIR}")

    if not ENV_PATH.exists():
        if ENV_EXAMPLE.exists():
            shutil.copy(ENV_EXAMPLE, ENV_PATH)
            print(f"[setup] Created .env from .env.example — apri e inserisci la tua GEMINI_API_KEY")
        else:
            print("[setup] WARNING: missing .env and .env.example — create .env with GEMINI_API_KEY=...")

    print()
    print("=" * 64)
    print("Setup completato.")
    print()
    print("CAVEAT DI SICUREZZA (fork hardened, livello Medio):")
    print("  - shell e code execution restano attivi")
    print("  - verra' chiesta conferma per ogni azione potenzialmente distruttiva")
    print("  - ogni azione viene registrata in logs/audit-YYYYMMDD.jsonl")
    print("  - leggi SECURITY.md per i rischi residui")
    print()
    print("Avvia con:  python main.py")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
