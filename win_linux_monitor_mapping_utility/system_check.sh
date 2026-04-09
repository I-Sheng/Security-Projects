#!/bin/bash
echo "================================"
echo "     SYSTEM CHECK - LINUX"
echo "================================"

echo
echo "[1] Full System Info:"
uname -a
hostnamectl

echo
echo "[2] Installed Updates:"
if command -v dpkg &> /dev/null; then
    dpkg -l | less
elif command -v yum &> /dev/null; then
    yum list installed | less
elif command -v dnf &> /dev/null; then
    dnf history
else
    echo "No package manager info available"
fi

echo
echo "[3] OS Version:"
lsb_release -a 2>/dev/null || cat /etc/os-release

echo
echo "[4] Timezone Info:"
timedatectl
date

echo
echo "[5] Network Interfaces and IP:"
ip a

echo
echo "System Check Completed."

