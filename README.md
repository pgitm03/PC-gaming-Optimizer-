[GAMING-OPTIMIZER-README(2).md](https://github.com/user-attachments/files/25537916/GAMING-OPTIMIZER-README.2.md)
# 🎮 Windows PC Gaming Optimizer

A comprehensive PowerShell script that fully optimizes Windows 10 & 11 for gaming performance, privacy, and a clean install experience. Inspired by Chris Titus Tech's WinUtil. The script asks **yes or no before every single change** so you stay in full control — nothing happens without your approval.

> ⚠️ Must be run as Administrator. A system restore point is automatically created before any changes are made.

---

## 📋 What It Does

### 🗑️ Bloatware Removal
- Removes 30+ pre-installed Microsoft apps (Bing apps, Skype, Xbox overlays, Teams, Clipchamp, and more)
- Optional OneDrive removal
- Optional Cortana disable

### 🔒 Privacy & Telemetry
- Disables Windows telemetry and data collection
- Disables advertising ID and targeted ads
- Disables activity history and timeline tracking
- Disables location tracking
- Disables Wi-Fi Sense (automatic Wi-Fi password sharing)

### ⚡ Gaming Performance Tweaks
| Tweak | What It Does |
|-------|-------------|
| Ultimate Performance Power Plan | Unlocks the highest performance power mode Windows has |
| Game Mode | Dedicates more CPU/GPU resources to your active game |
| Disable Game Bar & DVR | Stops background recording that eats into FPS |
| Disable Fullscreen Optimizations | Fixes frame pacing and stuttering issues in many games |
| GPU & CPU Scheduling Priority | Sets games to HIGH priority so the OS doesn't bottleneck them |
| Hardware-Accelerated GPU Scheduling (HAGS) | Reduces input lag on supported GPUs (Windows 11) |
| Disable Mouse Acceleration | Enables raw mouse input for more accurate aim |
| Disable Nagle's Algorithm | Reduces latency in online multiplayer games |
| TCP/IP Optimization | Tunes network stack settings for lower ping |
| Disable Delivery Optimization | Stops Windows from using your bandwidth to share updates with strangers |
| Visual Effects | Turns off animations and shadows for max frame rates |

### 🔧 Unnecessary Services
Lets you individually disable:
- Windows Telemetry (DiagTrack)
- SysMain / Superfetch (wasteful on SSDs)
- Windows Search Indexing (causes micro-stutters)
- Xbox Live services (Auth, Game Save, Networking)
- Remote Registry (security risk)
- Fax Service
- WAP Push Routing Service

### 🧹 Cleanup
- Clears system and user temp files
- Flushes DNS cache
- Runs Disk Cleanup silently (removes Windows Update cache and old system files)

---

## 🚀 How to Use

### 1. Download the script
Click the green **Code** button and select **Download ZIP**, or clone the repo:
```bash
git clone https://github.com/pgitm03/windows-gaming-optimizer.git
```

### 2. Open PowerShell as Administrator
- Press `Windows + S` and search for **PowerShell**
- Right-click and select **Run as Administrator**

### 3. Allow script execution (one time only)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Type `Y` and press Enter.

### 4. Run the script
```powershell
cd C:\path\to\script
.\PC-Gaming-Optimizer.ps1
```

Or use the bypass method if you get a security error:
```powershell
PowerShell -ExecutionPolicy Bypass -File "C:\path\to\PC-Gaming-Optimizer.ps1"
```

### 5. Answer yes or no for each tweak
The script walks through every change one at a time. Type `y` to apply or `n` to skip.

---

## 🛡️ Safety First

- **A system restore point is created automatically before anything runs.** If something goes wrong, you can roll back:
  - `Start Menu` → Search **"Create a restore point"** → Click **System Restore**
- Every tweak is **optional** — nothing is forced on you
- No third-party tools or downloads required — pure PowerShell built into Windows

---

## 📸 Example Output

```
============================================================
  SECTION 3 — GAMING PERFORMANCE TWEAKS
============================================================

Set power plan to Ultimate Performance (best for gaming)? (y/n): y
[*] Enabling Ultimate Performance power plan...
[+] Ultimate Performance power plan activated.

Enable Windows Game Mode? (y/n): y
[+] Game Mode enabled.

Disable Xbox Game Bar and Game DVR? (y/n): y
[+] Game Bar and Game DVR disabled.

Disable mouse acceleration (raw input for better aim)? (y/n): y
[+] Mouse acceleration disabled. Raw input enabled.
```

---

## ✅ After Running the Script

1. **Restart your PC** — required for most changes to take effect
2. Open **Task Manager → Startup tab** and disable anything you don't need at boot
3. Update your **GPU drivers** directly from NVIDIA or AMD's website
4. In your games, **disable Motion Blur and V-Sync** for lower input lag
5. In your **BIOS**, enable **XMP / DOCP** so your RAM runs at its rated speed — this alone can give a big FPS boost in CPU-heavy games

---

## ⚙️ Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later (built into Windows — no install needed)
- Administrator privileges

---

## 📚 What I Learned Building This

This project gave me real hands-on experience with:
- **PowerShell scripting** — functions, registry edits, service management, error handling
- **Windows internals** — how services, scheduled tasks, and the registry control system behavior
- **Networking concepts** — TCP/IP tuning, Nagle's Algorithm, DNS, Delivery Optimization
- **Security principles** — reducing attack surface by disabling unused services and remote access
- **System administration** — automating tasks that IT pros and sysadmins perform daily

---

## 🤝 Contributing

Pull requests are welcome! If you know a tweak that should be added, open an issue or submit a PR.

---

## 📄 License

MIT License — free to use, share, and modify.

---

*Built by Patrick Moreno 
