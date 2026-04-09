# 🐧 Linux Counterparts to Windows Command Line Tools

This document provides a Linux counterpart (both command-line and GUI) for commonly used Windows command-line and GUI tools in system and network monitoring, analysis, and forensics.

---

# 🧠 Network Tools

| **Windows** | **Linux Equivalent** | **Notes** |
| --- | --- | --- |
| `netstat -anbo` | `ss -tunap`, `netstat -tulnp` | Active connections with PID info |
| `net session` |  | For Samba sessions |
| `nbtstat -s` |  | NetBIOS info |
| `net share` |  | Shared directories |
| `netsh advfirewall show allprofiles` | `iptables -L -v`, `ufw status verbose` | Firewall configuration |
| **tcpview**, **cport** (GUI) | `Wireshark`, `EtherApe`, `Zenmap` | Network analysis and visualization |
- 📊 **Comparison Summary: Windows vs. Linux Network Diagnostics**
    
    
    | **Category** | **Windows Output** | **Linux Output** | **Key Differences** |
    | --- | --- | --- | --- |
    | **1. Active Connections** | `netstat -anbo` (Requires admin) | `ss -tunap` / `netstat -tulnp` (Requires `sudo` for full PID info) | Windows needs elevation to access PID-bound sockets; Linux hides process info without root |
    | **2. NetBIOS/Samba Sessions** | `nbtstat -s` shows no active connections | `smbstatus` not installed (no output) | Windows uses NetBIOS over TCP/IP; Linux uses Samba tools (not preinstalled) |
    | **3. Current Samba Sessions** | `net session` denied (needs admin) | `smbstatus` not found | Windows has native `net session`; Linux requires installing `samba` manually |
    | **4. Shared Folders** | Shows `C$`, `ADMIN$`, etc. via `net share` | Not available unless Samba is configured | Windows shows default admin shares; Linux doesn't auto-share unless configured |
    | **5. Firewall Status** | `netsh advfirewall` – detailed per profile | `ufw` or `iptables` – shows status, but was **inactive** | Windows firewall is enabled by default; Linux firewall (UFW) is often off unless configured manually |
    | **6. Network Interfaces** | `ipconfig /all` – shows all virtual, physical, disconnected interfaces | `ip addr` – shows active interfaces only | Windows shows more detail (DHCP, DNS, leases); Linux shows essential data, less verbose |
    | **Permissions** | Needed for most tools (`netstat -anbo`, `net session`) | Needed for full info (`ss -tunap`, `ufw`, `iptables`) | Both OSs restrict key network info to admin/root access |
    | **Virtual Adapters** | Shows WSL, Bluetooth, VMWare, multiple Wi-Fi | Shows Hyper-V (eth0), loopback | Windows CMD shows extensive adapter list; Linux under WSL is minimal (Hyper-V interface only) |

---

# ⚙️ Process Monitoring

| **Windows** | **Linux Equivalent** | **Notes** |
| --- | --- | --- |
| `tasklist /v` | `ps aux`, `top`, `htop` | Process info with resource usage |
| `wmic process list full` | `ps -eo pid,ppid,cmd,%mem,%cpu` | Detailed listing |
| `schtasks` |  `systemctl list-timers` | Scheduled tasks and timers |
| **Autoruns** (GUI) | `systemctl` | Autostart entries |
| **Process Explorer** (GUI) | `htop` | Interactive process tree |
| **WinPrefetchView** (GUI) | `auditd`, `atop` | No direct equivalent; audit logs |
| **cprocess** (GUI) | `lsof -p [pid]` | Inspect process libraries |
- 📊 **Comparison Summary: Windows vs. Linux Process Diagnostics**
    
    
    | **Category** | **Windows Output** | **Linux Output** | **Key Differences** |
    | --- | --- | --- | --- |
    | **1. Command Used** | `tasklist`, WMI (`Get-WmiObject`) | `ps aux`, `ps -eo`, `systemctl list-timers` | Windows uses GUI-friendly tools; Linux relies on traditional CLI commands |
    | **2. Process User Info** | Shows full username (e.g., `LAPTOP\isheng`) | Shows Unix-style users (`root`, `daemon`) | Linux includes kernel processes under `root` |
    | **3. Kernel Threads** | Not visible | Visible (e.g., `[kthreadd]`, `[rcu_gp]`) | Linux exposes kernel threads; Windows abstracts them |
    | **4. Memory Info** | `Mem Usage` in KB; also shows PrivatePageCount, WorkingSetSize | `VSZ`, `RSS` in KB/MB | Both report memory but in different formats; Windows provides more detailed memory statistics via WMI |
    | **5. CPU Usage** | `CPU Time` (total processor time used) | `%CPU` (current usage %) | Linux shows real-time %CPU, Windows shows cumulative time |
    | **6. Process Tree** | Not shown | Available via `ppid` in `ps -eo` | Linux supports parent-child tracking via PPID |
    | **7. TTY/Session** | Shows `Session Name` and `Session#` | Shows `TTY` (e.g., `?`, `pts/0`) | Both show process session origin, format differs |
    | **8. Detailed Info** | Available via WMI (`HandleCount`, `PageFaults`, etc.) | Available via `ps`, `top`, `systemctl` | Windows offers more system-level metrics through WMI |
    | **9. Services and Timers** | Partially visible via `svchost.exe` | `systemctl list-timers` lists services & timers | Linux explicitly reports timers; Windows runs services under shared host processes |

---

# 🔏 Signature Verification

| **Windows** | **Linux Equivalent** | **Notes** |
| --- | --- | --- |
| `sigverif` |  | Package and binary integrity |

### 🤔 Why Not a Direct Equivalent?

On Windows:

- Most system files are signed by Microsoft.
- `sigverif` scans `.sys`, `.dll`, etc., and checks against a central certificate trust store.

On Linux:

- Software is **installed through package managers** (`apt`, `snap`, `flatpak`, etc.), and **signatures are checked at install time**.
- After installation, **individual binaries usually aren’t signed**, unless the developer has implemented something custom (like GPG or `codesign` style).

---

# 🕵️ Hidden Execution File Search

| **Windows** | **Linux Equivalent** | **Notes** |
| --- | --- | --- |
| `dir *.exe;*.bat;*.cmd /AS /AH /S /TC` | `find / -type f \( -name "*.sh" -o -name "*.bin" \) -exec ls -lA {} +` | Search for huidden/system files |
- 📊 **Comparison Summary: Windows vs. Linux Hidden File Diagnostics**
    
    
    | **Category** | **Windows Output (Updated)** | **Linux Output** | **Key Differences** |
    | --- | --- | --- | --- |
    | **1. Script Logic** | `dir` command filters for `.exe`, `.bat`, `.cmd` + hidden/system attributes | `find` with `-name "*.sh"` or `-name "*.bin"` | Windows filters by file types and metadata flags; Linux by name patterns |
    | **2. Targeted File Types** | `.exe`, `.bat`, `.cmd` only | `.sh`, `.bin` | File type targets differ based on OS conventions |
    | **3. Hidden/System Detection** | Uses `/AS /AH` to include hidden & system files | No system attribute concept; uses naming/location (e.g., dotfiles or `/etc`) | Windows has file metadata; Linux does not natively label “system” files |
    | **4. Timestamp Shown** | `/TC` shows **Creation Time** | `ls -lA` shows **Last Modified Time** | Different default timestamp displays |
    | **5. Recursive Search** | Yes, with `/S` | Yes, with `find /` | Both search through full directory trees |
    | **6. Output Results** | One result: `LineUpdater.exe` in LINE folder | Multiple `.sh` and `.bin` files found across system | Linux shows broader system interaction; Windows script is more targeted |
    | **7. Permission Handling** | No access errors reported | Many `Permission denied` messages | Linux needs root for full visibility; Windows ran in user space successfully |

---

# 🖥️ System Information

| **Windows** | **Linux Equivalent** | **Info Obtained** |
| --- | --- | --- |
| `systeminfo` | `uname -a`, `lshw`, `hostnamectl` | Hostname, CPU, memory, architecture |
| `wmic qfe get hotfixid` | `dpkg -l`, `yum list installed`, `dnf history` | Patches and package updates
 |
| `ver` | `lsb_release -a`, `cat /etc/os-release` | OS name, version, codename
 |
| `wmic timezone` | `timedatectl` , `date` | Timezone info |
| `ipconfig` | `ip a`, `ifconfig` | IP addresses, interfaces, DNS, gateway |

Even though **Windows and Linux use different commands**, they can both provide the **same types of system information**. The **syntax, tools, and output format** differ, but the **core data (like OS version, updates, IP, time zone, etc.)** is accessible on both systems.

---

# 👤 User Accounts & Permissions

| **Windows** | **Linux Equivalent** | **Notes** |
| --- | --- | --- |
| `net accounts` | `chage -l <user>`, `passwd -S` | Account policies |
| `net user` | `cat /etc/passwd` | User list |
| `whoami /all` | `id`, `groups`, `whoami` | User identity and groups |
| `wmic useraccount list full` | `getent passwd` | User account details |
| `wmic group list full` | `getent group` | Group info |

## 👤 User Accounts & Permissions — Command Comparison

| **Feature** | **Windows Command** | **Linux Command** | **Observed Differences** |
| --- | --- | --- | --- |
| 🔒 **Account Policies** | `net accounts` | `chage -l <user>` or `passwd -S <user>` | Windows shows **system-wide** policy (lockout, password rules); Linux shows **per-user** policy |
| 👥 **User List** | `net user` | `cat /etc/passwd` |  |
| 👤 **User Identity & Groups** | `whoami /all` | `id`, `groups`, `whoami` | Both show current user & groups; Windows adds **SIDs**, privilege states |
| 📝 **Full User Info** | `wmic useraccount list full` | `getent passwd`, `getent shadow` | Windows has **enabled/disabled**, SID, status fields; Linux includes **UID/GID/home shell** |
| 📦 **Group Info** | `wmic group list full` | `getent group` | Windows includes **group attributes**, SIDs, roles (like `docker-users`); Linux lists **group members** only |

---

# 📜 Event Logs

| **Windows** | **Linux Equivalent** | **Notes** |
| --- | --- | --- |
| `wevtutil el` | `journalctl --list-boots`, `ls /var/log` | Log overview |
| `wevtutil epl` | `cp /var/log/auth.log ~/logcopy.log` | Export logs |
| **FullEventLogView** (GUI) | `KSystemLog`, `gnome-logs` | GUI log viewers |

## 📜 Event Logs – Command Behavior Comparison

| **Function** | **Windows Command** | **Linux Equivalent** | **Result Differences & Insights** |
| --- | --- | --- | --- |
| 🔍 **Log Overview** | `wevtutil el` | `journalctl --list-boots`, `ls /var/log` | **Windows** lists hundreds of named logs (e.g. `Application`, `System`, `Intel-*`, `MediaFoundation-*`), many of them **specific to services/hardware vendors**. **Linux** gives logs **by session** with `journalctl --list-boots` and **by file** in `/var/log` (e.g. `syslog`, `auth.log`, `kern.log`). |
| 📤 **Export Logs** | `wevtutil epl Application Application.evtx` | `cp /var/log/auth.log ~/logcopy.log` | Windows exports logs in `.evtx` format (requires Event Viewer or log parsers). Linux uses plain text (easily parsed, grep-able, editable). |

---