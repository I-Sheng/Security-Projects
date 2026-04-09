@echo off
echo =================================
echo  USER ACCOUNTS & PERMISSIONS - WINDOWS
echo =================================

echo.
echo [1] Account Policies:
net accounts

echo.
echo [2] User List:
net user

echo.
echo [3] User Identity and Group Membership:
whoami /all

echo.
echo [4] Full User Account Info:
wmic useraccount list full

echo.
echo [5] Group Information:
wmic group list full

echo.
echo User Check Completed.
pause

