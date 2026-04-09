
#!/bin/bash
echo "=============================================="
echo "     Hidden Execution File Search - LINUX     "
echo "=============================================="

echo
echo "[1] Search for huidden/system files"
find / -type f \( -name "*.sh" -o -name "*.bin" \) -exec ls -lA {} +

echo
echo "Script Completed."
