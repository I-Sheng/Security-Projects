
#!/bin/bash
echo "================================"
echo "   PROCESS MONITORING - LINUX    "
echo "================================"

echo
echo "[1] Process info with resource usage:"
ps aux

echo
echo "[2] Detailed listing:"
ps -eo pid,ppid,cmd,%mem,%cpu

echo
echo "[3] Scheduled tasks and timers:"
 systemctl list-timers

echo
echo "Script Completed."
