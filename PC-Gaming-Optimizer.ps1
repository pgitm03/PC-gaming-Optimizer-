# =============================================================================
# PC-Gaming-Optimizer.ps1
# Full Windows PC Optimization — Debloat, Gaming Tweaks, Privacy & Performance
# Author: Patrick Moreno | github.com/pgitm03
# Compatible with Windows 10 & Windows 11
# Must be run as Administrator
# =============================================================================

#Requires -RunAsAdministrator

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Info    { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Skip    { param($msg) Write-Host "[~] Skipped." -ForegroundColor Gray }
function Write-Fail    { param($msg) Write-Host "[-] FAILED: $msg" -ForegroundColor Red }
function Write-Section { param($msg) 
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "  $msg" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host ""
}

function Ask {
    param([string]$question)
    $answer = Read-Host "$question (y/n)"
    return $answer -eq 'y'
}

function Set-RegistryValue {
    param($Path, $Name, $Value, $Type = "DWord")
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        return $true
    } catch {
        return $false
    }
}

# ── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ██████╗  ██████╗    ██████╗ ██████╗ ████████╗" -ForegroundColor Cyan
Write-Host "  ██╔══██╗██╔════╝   ██╔═══██╗██╔══██╗╚══██╔══╝" -ForegroundColor Cyan
Write-Host "  ██████╔╝██║        ██║   ██║██████╔╝   ██║   " -ForegroundColor Cyan
Write-Host "  ██╔═══╝ ██║        ██║   ██║██╔═══╝    ██║   " -ForegroundColor Cyan
Write-Host "  ██║     ╚██████╗   ╚██████╔╝██║        ██║   " -ForegroundColor Cyan
Write-Host "  ╚═╝      ╚═════╝    ╚═════╝ ╚═╝        ╚═╝   " -ForegroundColor Cyan
Write-Host ""
Write-Host "       Windows PC Gaming Optimizer v2.0" -ForegroundColor White
Write-Host "       By Patrick Moreno | github.com/pgitm03" -ForegroundColor Gray
Write-Host ""
Write-Host "  This script will ask before making each change." -ForegroundColor Yellow
Write-Host "  A system restore point will be created first." -ForegroundColor Yellow
Write-Host ""

$go = Read-Host "Ready to start? (y/n)"
if ($go -ne 'y') { Write-Host "Exited." -ForegroundColor Gray; exit }

# ── Create Restore Point ──────────────────────────────────────────────────────
Write-Info "Creating a system restore point before making any changes..."
try {
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description "Before PC-Gaming-Optimizer" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
    Write-Success "Restore point created. You can roll back via: System Properties > System Protection."
} catch {
    Write-Host "[!] Could not create restore point automatically. Consider creating one manually before continuing." -ForegroundColor Yellow
}

# =============================================================================
# SECTION 1 — BLOATWARE REMOVAL
# =============================================================================
Write-Section "SECTION 1 — BLOATWARE REMOVAL"

$bloatwareApps = @(
    "Microsoft.3DBuilder",
    "Microsoft.BingFinance",
    "Microsoft.BingNews",
    "Microsoft.BingSports",
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MixedReality.Portal",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.Print3D",
    "Microsoft.SkypeApp",
    "Microsoft.Todos",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "MicrosoftTeams",
    "Microsoft.Clipchamp",
    "Microsoft.WindowsCommunicationsApps",
    "Microsoft.MicrosoftEdge.Stable"
)

if (Ask "Remove Microsoft bloatware apps (Bing, Skype, Xbox overlays, Teams, etc.)?") {
    Write-Info "Removing bloatware apps..."
    $removed = 0
    foreach ($app in $bloatwareApps) {
        $pkg = Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue
        if ($pkg) {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                Write-Host "    [+] Removed: $app" -ForegroundColor Green
                $removed++
            } catch {
                Write-Host "    [-] Could not remove: $app" -ForegroundColor Red
            }
        }
    }
    Write-Success "Removed $removed bloatware apps."
} else { Write-Skip "Bloatware removal" }

# Disable OneDrive
if (Ask "Disable and remove OneDrive?") {
    Write-Info "Disabling OneDrive..."
    try {
        taskkill /f /im OneDrive.exe 2>$null
        Start-Sleep -Seconds 2
        $onedrive = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
        if (-not (Test-Path $onedrive)) { $onedrive = "$env:SystemRoot\System32\OneDriveSetup.exe" }
        if (Test-Path $onedrive) { & $onedrive /uninstall | Out-Null }
        Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
        Write-Success "OneDrive disabled."
    } catch { Write-Fail $_ }
} else { Write-Skip "OneDrive" }

# Disable Cortana
if (Ask "Disable Cortana?") {
    Write-Info "Disabling Cortana..."
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
    Set-RegistryValue "HKCU:\Software\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
    Write-Success "Cortana disabled."
} else { Write-Skip "Cortana" }

# =============================================================================
# SECTION 2 — PRIVACY & TELEMETRY
# =============================================================================
Write-Section "SECTION 2 — PRIVACY & TELEMETRY"

if (Ask "Disable Windows telemetry and data collection?") {
    Write-Info "Disabling telemetry..."
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0
    # Disable telemetry scheduled tasks
    $tasks = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    )
    foreach ($task in $tasks) {
        try { Disable-ScheduledTask -TaskPath (Split-Path $task) -TaskName (Split-Path $task -Leaf) -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
    Write-Success "Telemetry disabled."
} else { Write-Skip "Telemetry" }

if (Ask "Disable advertising ID and targeted ads?") {
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1
    Write-Success "Advertising ID disabled."
} else { Write-Skip "Advertising ID" }

if (Ask "Disable activity history and timeline tracking?") {
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
    Write-Success "Activity history disabled."
} else { Write-Skip "Activity history" }

if (Ask "Disable location tracking?") {
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "Deny" -Type String
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1
    Write-Success "Location tracking disabled."
} else { Write-Skip "Location" }

if (Ask "Disable Wi-Fi Sense (auto-sharing Wi-Fi passwords)?") {
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0
    Write-Success "Wi-Fi Sense disabled."
} else { Write-Skip "Wi-Fi Sense" }

# =============================================================================
# SECTION 3 — GAMING PERFORMANCE TWEAKS
# =============================================================================
Write-Section "SECTION 3 — GAMING PERFORMANCE TWEAKS"

if (Ask "Set power plan to Ultimate Performance (best for gaming)?") {
    Write-Info "Enabling Ultimate Performance power plan..."
    try {
        powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>$null
        $ultimate = powercfg /list | Select-String "Ultimate Performance"
        if ($ultimate) {
            $guid = ($ultimate -split "\s+")[3]
            powercfg /setactive $guid
            Write-Success "Ultimate Performance power plan activated."
        } else {
            powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
            Write-Success "High Performance power plan activated."
        }
    } catch { Write-Fail $_ }
} else { Write-Skip "Power plan" }

if (Ask "Enable Windows Game Mode?") {
    Set-RegistryValue "HKCU:\Software\Microsoft\GameBar" "AllowAutoGameMode" 1
    Set-RegistryValue "HKCU:\Software\Microsoft\GameBar" "AutoGameModeEnabled" 1
    Write-Success "Game Mode enabled."
} else { Write-Skip "Game Mode" }

if (Ask "Disable Xbox Game Bar and Game DVR (frees up resources while gaming)?") {
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled" 0
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_Enabled" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0
    Write-Success "Game Bar and Game DVR disabled."
} else { Write-Skip "Game Bar/DVR" }

if (Ask "Disable fullscreen optimizations globally (fixes frame pacing issues)?") {
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_FSEBehaviorMode" 2
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_HonorUserFSEBehaviorMode" 1
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_FSEBehavior" 2
    Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_DXGIHonorFSEWindowsCompatible" 1
    Write-Success "Fullscreen optimizations disabled."
} else { Write-Skip "Fullscreen optimizations" }

if (Ask "Set GPU and CPU scheduling priority to HIGH for games?") {
    Write-Info "Boosting game scheduling priority..."
    $gamePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Set-RegistryValue $gamePath "Affinity" 0
    Set-RegistryValue $gamePath "Background Only" "False" -Type String
    Set-RegistryValue $gamePath "Clock Rate" 10000
    Set-RegistryValue $gamePath "GPU Priority" 8
    Set-RegistryValue $gamePath "Priority" 6
    Set-RegistryValue $gamePath "Scheduling Category" "High" -Type String
    Set-RegistryValue $gamePath "SFIO Priority" "High" -Type String
    # Also set system responsiveness
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 0xffffffff
    Write-Success "Game scheduling priority set to HIGH."
} else { Write-Skip "Game priority" }

if (Ask "Enable Hardware-Accelerated GPU Scheduling / HAGS (Windows 11 - reduces input lag)?") {
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "HwSchMode" 2
    Write-Success "HAGS enabled. Restart required."
} else { Write-Skip "HAGS" }

if (Ask "Disable mouse acceleration (raw input for better aim)?") {
    Set-RegistryValue "HKCU:\Control Panel\Mouse" "MouseSpeed" 0
    Set-RegistryValue "HKCU:\Control Panel\Mouse" "MouseThreshold1" 0
    Set-RegistryValue "HKCU:\Control Panel\Mouse" "MouseThreshold2" 0
    Write-Success "Mouse acceleration disabled. Raw input enabled."
} else { Write-Skip "Mouse acceleration" }

if (Ask "Disable Nagle's Algorithm (reduces latency in online games that use TCP)?") {
    Write-Info "Detecting your IP address..."
    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.*" -and $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress
        Write-Info "Found IP: $ip — applying Nagle's disable to adapter..."
        $interfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        foreach ($iface in $interfaces) {
            $ifaceIP = (Get-ItemProperty -Path $iface.PSPath -ErrorAction SilentlyContinue).DhcpIPAddress
            if ($ifaceIP -eq $ip) {
                Set-ItemProperty -Path $iface.PSPath -Name "TcpAckFrequency" -Value 1 -Type DWord -Force
                Set-ItemProperty -Path $iface.PSPath -Name "TCPNoDelay" -Value 1 -Type DWord -Force
            }
        }
        Write-Success "Nagle's Algorithm disabled."
    } catch { Write-Fail "Could not disable Nagle's: $_" }
} else { Write-Skip "Nagle's Algorithm" }

if (Ask "Optimize TCP/IP settings for gaming (lower latency, better throughput)?") {
    $tcpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Set-RegistryValue $tcpPath "DefaultTTL" 64
    Set-RegistryValue $tcpPath "GlobalMaxTcpWindowSize" 65535
    Set-RegistryValue $tcpPath "MaxUserPort" 65534
    Set-RegistryValue $tcpPath "Tcp1323Opts" 1
    Set-RegistryValue $tcpPath "TcpMaxDupAcks" 2
    Set-RegistryValue $tcpPath "TCPTimedWaitDelay" 30
    Write-Success "TCP/IP settings optimized."
} else { Write-Skip "TCP/IP" }

if (Ask "Disable visual effects for max performance (animations, shadows, etc.)?") {
    Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2
    Write-Success "Visual effects set to best performance."
} else { Write-Skip "Visual effects" }

if (Ask "Disable Delivery Optimization (stops Windows using your bandwidth to share updates with others - reduces ping)?") {
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0
    Write-Success "Delivery Optimization disabled."
} else { Write-Skip "Delivery Optimization" }

# =============================================================================
# SECTION 4 — UNNECESSARY SERVICES
# =============================================================================
Write-Section "SECTION 4 — DISABLE UNNECESSARY SERVICES"

$services = @(
    @{Name="DiagTrack";        Desc="Connected User Experiences and Telemetry"},
    @{Name="dmwappushservice"; Desc="WAP Push Message Routing (telemetry)"},
    @{Name="SysMain";          Desc="SysMain / Superfetch (unnecessary on SSD)"},
    @{Name="WSearch";          Desc="Windows Search indexing (can cause stutters)"},
    @{Name="TabletInputService";Desc="Touch Keyboard and Handwriting Panel"},
    @{Name="Fax";              Desc="Fax Service"},
    @{Name="RemoteRegistry";   Desc="Remote Registry (security risk)"},
    @{Name="XboxGipSvc";       Desc="Xbox Accessory Management"},
    @{Name="XblAuthManager";   Desc="Xbox Live Auth Manager"},
    @{Name="XblGameSave";      Desc="Xbox Live Game Save"},
    @{Name="XboxNetApiSvc";    Desc="Xbox Live Networking"}
)

foreach ($svc in $services) {
    if (Ask "Disable '$($svc.Desc)'?") {
        try {
            $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if ($s) {
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Success "$($svc.Desc) disabled."
            } else {
                Write-Host "    [~] Service not found on this system." -ForegroundColor Gray
            }
        } catch { Write-Fail $_ }
    } else { Write-Skip $svc.Desc }
}

# =============================================================================
# SECTION 5 — CLEANUP
# =============================================================================
Write-Section "SECTION 5 — CLEANUP"

if (Ask "Clear temp files and flush DNS?") {
    Write-Info "Clearing temp files..."
    $tempPaths = @("$env:TEMP", "$env:SystemRoot\Temp", "$env:SystemRoot\Prefetch")
    $count = 0
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try { Remove-Item $_.FullName -Force -Recurse -ErrorAction SilentlyContinue; $count++ } catch {}
            }
        }
    }
    Write-Success "Cleared $count temp items."

    Write-Info "Flushing DNS cache..."
    ipconfig /flushdns | Out-Null
    Write-Success "DNS cache flushed."
} else { Write-Skip "Cleanup" }

if (Ask "Run Disk Cleanup silently (removes Windows Update cache, old files)?") {
    Write-Info "Running Disk Cleanup..."
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        $cleanupKeys = Get-ChildItem $regPath
        foreach ($key in $cleanupKeys) {
            Set-ItemProperty -Path $key.PSPath -Name "StateFlags0001" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        }
        Start-Process -FilePath cleanmgr.exe -ArgumentList "/sagerun:1" -Wait -NoNewWindow
        Write-Success "Disk Cleanup complete."
    } catch { Write-Fail "Could not run Disk Cleanup: $_" }
} else { Write-Skip "Disk Cleanup" }

# =============================================================================
# DONE
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ALL DONE! Here's what to do next:" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. RESTART your PC for all changes to take effect." -ForegroundColor White
Write-Host "  2. Check Task Manager > Startup tab and disable" -ForegroundColor White
Write-Host "     anything you don't need launching at boot." -ForegroundColor White
Write-Host "  3. Update your GPU drivers (NVIDIA/AMD) manually" -ForegroundColor White
Write-Host "     from the manufacturer's website for best results." -ForegroundColor White
Write-Host "  4. In your game, turn off Motion Blur and V-Sync" -ForegroundColor White
Write-Host "     for lower input lag." -ForegroundColor White
Write-Host "  5. In BIOS, enable XMP/DOCP so your RAM runs at" -ForegroundColor White
Write-Host "     its rated speed (big FPS boost in CPU-heavy games)." -ForegroundColor White
Write-Host ""
Write-Host "  If anything breaks, restore via:" -ForegroundColor Yellow
Write-Host "  Start > Create a restore point > System Restore" -ForegroundColor Yellow
Write-Host ""
Write-Host "  github.com/pgitm03 | Made by Patrick Moreno" -ForegroundColor Gray
Write-Host ""
