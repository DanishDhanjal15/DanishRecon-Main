@echo off
:: DanishRecon desktop GUI (Windows).
:: Uses the danishrecon you installed with:  pip install "danishrecon[gui]"
:: Scan results and history are kept in the folder this file is in (results\).
setlocal
cd /d "%~dp0"

:: Tools that are usually installed outside Python
if not defined GOPATH set "GOPATH=%USERPROFILE%\go"
set "PATH=%PATH%;%GOPATH%\bin;C:\Program Files\Wireshark"
for /d %%D in ("%USERPROFILE%\Downloads\strawberry-perl*") do set "PATH=%PATH%;%%D\perl\bin;%%D\c\bin"

where danishrecon-gui >nul 2>&1
if not errorlevel 1 (
    start "" danishrecon-gui
    goto :end
)
python -c "import danishrecon.gui" >nul 2>&1
if not errorlevel 1 (
    start "" pythonw -m danishrecon.gui
    goto :end
)
echo DanishRecon is not installed. Install it with:
echo     pip install "danishrecon[gui]"
echo     danishrecon setup
echo Full guide: https://github.com/DanishDhanjal15/DanishRecon-Main/blob/main/docs/SETUP.md
pause

:end
endlocal
