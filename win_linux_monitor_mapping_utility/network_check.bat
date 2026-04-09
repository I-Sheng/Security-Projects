@echo off
echo ================================
echo        NETWORK CHECK - WINDOWS
echo ================================

echo.
echo [1] Active Connections (with PIDs):
netstat -anbo

echo.
echo [2] NetBIOS Sessions:
nbtstat -s

echo.
echo [3] Current Samba Sessions:
net session

echo.
echo [4] Shared Directories:
net share

echo.
echo [5] Firewall Settings:
netsh advfirewall show allprofiles

echo.
echo [6] Network Interfaces:
ipconfig /all

echo.
echo Script Completed.
pause
