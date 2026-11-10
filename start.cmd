@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
    python scripts\team.py %*
) else (
    py -3 scripts\team.py %*
)
set "QUT_EXIT=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %QUT_EXIT%
