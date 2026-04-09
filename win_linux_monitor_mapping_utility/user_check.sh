#!/bin/bash
echo "================================"
echo " USER ACCOUNTS & PERMISSIONS - LINUX"
echo "================================"

echo
echo "[1] List Users:"
cat /etc/passwd

echo
echo "[2] User Account Details:"
getent passwd

echo
echo "[3] Group Information:"
getent group

echo
echo "[4] Current User Identity and Groups:"
whoami
id
groups

echo
echo "[5] Account Policies (for each user):"
for user in $(cut -d: -f1 /etc/passwd); do
    echo "---- $user ----"
    passwd -S $user 2>/dev/null
    chage -l $user 2>/dev/null
done

echo
echo "User Check Completed."

