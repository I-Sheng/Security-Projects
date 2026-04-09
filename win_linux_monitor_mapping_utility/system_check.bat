@echo off
echo =================================
echo      SYSTEM CHECK - WINDOWS
echo =================================

echo.
echo [1] Full System Info:
systeminfo

echo.
echo [2] Installed Updates:
wmic qfe get hotfixid

echo.
echo [3] OS Version:
ver

echo.
echo [4] Timezone Info:
wmic timezone

echo.
echo [5] Network Interfaces and IP:
ipconfig

echo.
echo System Check Completed.
pause

