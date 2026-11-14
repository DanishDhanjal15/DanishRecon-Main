@echo off
:: DanishRecon desktop GUI (Windows). Requires:  pip install "danishrecon[gui]"
setlocal
if not defined GOPATH set "GOPATH=%USERPROFILE%\go"
set "PATH=%PATH%;C:\Program Files\Go\bin;%GOPATH%\bin;C:\Program Files\Wireshark"
for /d %%D in ("%USERPROFILE%\Downloads\strawberry-perl*") do set "PATH=%PATH%;%%D\perl\bin;%%D\c\bin"
cd /d "%~dp0"
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -m danishrecon.gui
) else (
    python -m danishrecon.gui
)
pause
endlocal
