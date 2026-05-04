@echo off
title Mark-XXXV (security-hardening fork)
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo.
    echo ERRORE: virtualenv mancante.
    echo Esegui prima:  python setup.py
    echo.
    pause
    exit /b 1
)

if not exist ".env" (
    echo.
    echo ERRORE: file .env mancante.
    echo Copia .env.example in .env e inserisci la tua GEMINI_API_KEY.
    echo.
    pause
    exit /b 1
)

echo ================================================================
echo   Mark-XXXV (security-hardening fork)
echo ================================================================
echo   Conferme: appaiono come popup nella UI
echo   Audit log: logs\audit-YYYYMMDD.jsonl
echo   F4: muta/smuta microfono
echo   X sulla UI: chiude tutto
echo ================================================================
echo.

.venv\Scripts\python.exe main.py

echo.
echo === Mark e' terminato ===
pause
