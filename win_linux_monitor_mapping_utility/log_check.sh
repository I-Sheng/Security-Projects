#!/bin/bash
echo "================================"
echo "         EVENT LOGS - LINUX"
echo "================================"

echo
echo "[1] System Log Overview (Boot Sessions):"
journalctl --list-boots

echo
echo "[2] Log Files in /var/log:"
ls -lh /var/log

echo
echo "[3] Export Authentication Log to ~/authlog_copy.log:"
if [ -f /var/log/auth.log ]; then
    cp /var/log/auth.log ~/authlog_copy.log
    echo "auth.log copied to ~/authlog_copy.log"
else
    echo "/var/log/auth.log not found (may vary by distro)"
fi

echo
echo "[4] GUI Log Viewers (if installed):"
if command -v ksystemlog &> /dev/null; then
    echo "KSystemLog is installed"
else
    echo "KSystemLog not installed"
fi

if command -v gnome-logs &> /dev/null; then
    echo "gnome-logs is installed"
else
    echo "gnome-logs not installed"
fi

echo
echo "Log Check Completed."

