@echo off
:: DanishRecon web dashboard (Windows) - http://127.0.0.1:8787, this machine only.
:: Uses the danishrecon you installed with:  pip install "danishrecon[web]"
setlocal
cd /d "%~dp0"

if not defined GOPATH set "GOPATH=%USERPROFILE%\go"
set "PATH=%PATH%;%GOPATH%\bin;C:\Program Files\Wireshark"
for /d %%D in ("%USERPROFILE%\Downloads\strawberry-perl*") do set "PATH=%PATH%;%%D\perl\bin;%%D\c\bin"

where danishrecon-web >nul 2>&1
if not errorlevel 1 (
    danishrecon-web %*
    goto :end
)
python -c "import danishrecon.webapp.server" >nul 2>&1
if not errorlevel 1 (
    python -m danishrecon.webapp.server %*
    goto :end
)
echo DanishRecon is not installed. Install it with:
echo     pip install "danishrecon[web]"
echo     danishrecon setup
pause

:end
endlocal
