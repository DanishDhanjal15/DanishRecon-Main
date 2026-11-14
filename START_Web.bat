@echo off
:: DanishRecon web dashboard (Windows) - http://127.0.0.1:8787, this machine only.
:: Requires:  pip install "danishrecon[web]"
setlocal
if not defined GOPATH set "GOPATH=%USERPROFILE%\go"
set "PATH=%PATH%;C:\Program Files\Go\bin;%GOPATH%\bin;C:\Program Files\Wireshark"
cd /d "%~dp0"
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -m danishrecon.webapp.server %*
) else (
    python -m danishrecon.webapp.server %*
)
pause
endlocal
