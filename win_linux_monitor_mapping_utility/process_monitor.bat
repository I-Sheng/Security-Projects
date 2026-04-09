@echo off
echo ================================
echo   PROCESS MONITORING - WINDOWS
echo ================================

echo.
echo [1] Process info with resource usage:
tasklist /v

echo.
echo [2] Detailed listing:
wmic process list full

echo.
echo [3] Scheduled tasks and timers:
schtasks

echo.
echo Script Completed.
pause
