
#!/bin/bash
echo "================================"
echo "     NETWORK CHECK - LINUX"
echo "================================"

echo
echo "[1] Active Connections with PIDs:"
ss -tunap

echo
echo "[2] Listening Ports:"
netstat -tulnp

echo
echo "[3] Firewall Rules (ufw or iptables):"
if command -v ufw &> /dev/null; then
    sudo ufw status verbose
else
    sudo iptables -L -v
fi

echo
echo "[4] Shared Folders (Samba):"
if command -v smbstatus &> /dev/null; then
    sudo smbstatus
else
    echo "smbstatus not installed. Run 'sudo apt install samba' to check Samba shares."
fi

echo
echo "[5] Network Interfaces:"
ip addr show

echo
echo "Script Completed."
