@echo off
REM ---------------------------------------------------------------------------
REM  Double-click this file to scan a site from this machine.
REM
REM  Use this instead of the web tool for any site behind Cloudflare. The hosted
REM  scanner runs from a cloud server, and Cloudflare challenges cloud traffic
REM  at random, so it can report "not reachable" for a site that is perfectly
REM  healthy. Requests from this computer are treated as ordinary traffic.
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

echo.
echo   GEO Scanner - local scan
echo   ------------------------
echo.

set "SITE="
set /p SITE=  Website address (e.g. jeeves-solutions.com):
if "%SITE%"=="" (
  echo.
  echo   No address entered. Nothing to scan.
  echo.
  pause
  exit /b 1
)

echo.
echo   Scanning... this usually takes 5-30 seconds.
echo.

node scan.js "%SITE%" --pdf
if errorlevel 1 (
  echo.
  echo   The scan did not complete. If this keeps happening, copy the message
  echo   above and send it over.
  echo.
  pause
  exit /b 1
)

echo.
echo   Done. The PDF is in this folder:
echo   %CD%
echo.
pause
