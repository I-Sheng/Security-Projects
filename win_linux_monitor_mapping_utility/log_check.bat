@echo off
echo =================================
echo          EVENT LOGS - WINDOWS
echo =================================

echo.
echo [1] Available Event Logs:
wevtutil el

echo.
echo [2] Export Application Event Log:
wevtutil epl Application %USERPROFILE%\Desktop\ApplicationLog.evtx

echo.
echo [3] GUI Viewer (manual):
echo Open "FullEventLogView" if installed or use Event Viewer (eventvwr.msc)

echo.
echo Log Check Completed.
pause

