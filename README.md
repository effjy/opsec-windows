<div align="center">

<a href="https://github.com/effjy/opsec-windows/"><img src="titles/opsec-windows-title.svg" height="52" alt="OpSec Windows"></a>

# 🪟 Windows OpSec Hardening Guide

> A complete, paranoid-grade guide to hardening a Windows 10/11 workstation or Server. Extensive PowerShell examples, real commands, defense-in-depth.

![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?logo=windows&logoColor=white)
![Shell](https://img.shields.io/badge/shell-PowerShell-5391FE?logo=powershell&logoColor=white)
![Security](https://img.shields.io/badge/focus-OpSec%20%26%20Hardening-red?logo=hackthebox&logoColor=white)
![Threat Model](https://img.shields.io/badge/threat%20model-Paranoid-black)
![Baseline](https://img.shields.io/badge/baseline-CIS%20%7C%20Microsoft%20SCT-orange)
![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?logo=github)

</div>

---

> ⚠️ **Disclaimer**: This guide is for hardening systems you **own** or are **authorized** to administer. Test every change in a VM or pilot group first — several steps (BitLocker, AppLocker, firewall lockdown, RDP changes) can lock you out or break apps. **Run an elevated PowerShell** (`Run as Administrator`) for most commands, and **create a System Restore point / full backup first**.

```powershell
# Create a restore point before you begin
Enable-ComputerRestore -Drive "C:\"
Checkpoint-Computer -Description "Pre-Hardening" -RestorePointType "MODIFY_SETTINGS"
```

---

## 📑 Table of Contents

1. [Threat Modeling](#1--threat-modeling)
2. [Baselines & Tooling](#2--baselines--tooling)
3. [Disk Encryption (BitLocker)](#3--disk-encryption-bitlocker)
4. [User Accounts & Authentication](#4--user-accounts--authentication)
5. [Windows Defender & Attack Surface Reduction](#5--windows-defender--attack-surface-reduction)
6. [Windows Firewall & Network](#6--windows-firewall--network)
7. [Application Control (AppLocker / WDAC)](#7--application-control)
8. [Service & Feature Minimization](#8--service--feature-minimization)
9. [Privacy & Telemetry](#9--privacy--telemetry)
10. [Auditing, Logging & Monitoring](#10--auditing-logging--monitoring)
11. [Remote Access (RDP / WinRM) Hardening](#11--remote-access-hardening)
12. [Updates & Patch Management](#12--updates--patch-management)
13. [Physical & Boot Security](#13--physical--boot-security)
14. [Verification & Hardening Checklist](#14--verification--hardening-checklist)

---

<!-- SECTIONS-START -->

## 1. 🎯 Threat Modeling

Hardening without a threat model is theater. Before touching a setting, answer four questions:

| Question | Example answers |
|----------|-----------------|
| **What am I protecting?** | Credentials, browser sessions, documents, crypto wallets, domain access, your identity |
| **Who is the adversary?** | Commodity ransomware, info-stealers, a thief who grabs the laptop, an insider, a nation-state |
| **What are their capabilities?** | Phishing, malicious macros, USB drops, credential theft, lateral movement, 0-days |
| **What happens if I lose?** | Data leak, encrypted disk (ransom), financial loss, domain compromise |

### Tiers of paranoia

- **Tier 1 — Hygiene:** updates, Defender on, standard (non-admin) user, firewall. Stops the bulk of commodity malware.
- **Tier 2 — Hardened:** ASR rules, AppLocker, audit logging, telemetry off, SmartScreen. Stops targeted opportunists.
- **Tier 3 — Paranoid:** BitLocker + TPM+PIN, WDAC, Credential Guard, removable-media lockdown, air-gaps, hardware tokens. Raises cost against advanced adversaries.

> 🔑 **Rule of thumb:** the single biggest Windows win is **not running as a local administrator** day-to-day. Most malware inherits *your* privileges — so don't hand it admin.

## 2. 🧰 Baselines & Tooling

Don't hand-roll everything — start from a vetted baseline, then customize.

### Official baselines

- **Microsoft Security Compliance Toolkit (SCT)** — GPO baselines for Windows 10/11 & Server, plus the **Policy Analyzer** and **LGPO.exe** to apply them on non-domain machines.
- **CIS Benchmarks** + **CIS-CAT** scanner for scored auditing.
- **Microsoft Defender for Endpoint** security baseline (if licensed).

```powershell
# Apply a downloaded Microsoft baseline to a standalone PC with LGPO
# (extract the SCT + baseline GPO backup first)
.\LGPO.exe /g ".\GPOs\{GUID}"        # import a GPO backup
gpupdate /force                      # apply
```

### Quick audit & community tooling

```powershell
# HardeningKitty — audit/harden against a CSV finding list (HailMary applies)
Import-Module .\HardeningKitty.psm1
Invoke-HardeningKitty -Mode Audit -Log -Report
# Invoke-HardeningKitty -Mode HailMary -FileFindingList .\lists\finding_list_cis_*.csv

# Built-in security state snapshots
Get-MpComputerStatus | Select AMRunningMode, RealTimeProtectionEnabled, AntivirusEnabled
Get-Tpm | Select TpmPresent, TpmReady, TpmEnabled
Get-BitLockerVolume | Select MountPoint, ProtectionStatus, EncryptionPercentage
secedit /export /cfg C:\baseline-secpol.cfg   # export local security policy
```

> 🧠 **Paranoid extra:** keep your applied baseline and a `secedit`/`LGPO` export under version control so every change is diffable and reversible. Re-scan with **Policy Analyzer** after each Windows feature update — upgrades silently reset policies.

## 3. 💽 Disk Encryption (BitLocker)

Encryption at rest is the foundation of physical security. Use **TPM + PIN** so a stolen laptop can't boot straight into your data.

### Pre-flight checks

```powershell
Get-Tpm                              # TpmPresent / TpmReady must be True
Get-BitLockerVolume                  # current state per volume
manage-bde -status                   # classic CLI view
```

### Enable BitLocker with TPM + PIN (XTS-AES-256)

```powershell
# Require a startup PIN in addition to the TPM (blocks cold-boot / DMA-into-OS)
# Set via policy first so a PIN is allowed:
#   gpedit.msc → Computer Config → Admin Templates → Windows Components →
#   BitLocker Drive Encryption → Operating System Drives →
#   "Require additional authentication at startup" = Enabled, Require PIN.

# Strongest cipher for the OS drive
Enable-BitLocker -MountPoint "C:" `
  -EncryptionMethod XtsAes256 `
  -UsedSpaceOnly:$false `
  -TpmAndPinProtector `
  -SkipHardwareTest

# Add a recovery password and EXPORT it — store OFFLINE, never only on the disk
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
(Get-BitLockerVolume -MountPoint "C:").KeyProtector |
  Where-Object KeyProtectorType -eq 'RecoveryPassword' |
  Select KeyProtectorId, RecoveryPassword
```

### Encrypt fixed & removable data drives

```powershell
Enable-BitLocker -MountPoint "D:" -EncryptionMethod XtsAes256 `
  -PasswordProtector -UsedSpaceOnly:$false

# Auto-unlock data drives once the OS drive is unlocked
Enable-BitLockerAutoUnlock -MountPoint "D:"

# Force BitLocker To Go (encryption) on all removable media via policy:
#   ...BitLocker Drive Encryption → Removable Data Drives →
#   "Deny write access to removable drives not protected by BitLocker" = Enabled
```

### Harden the recovery story

```powershell
# Watch progress
manage-bde -status C:

# Back up recovery keys to AD/Azure AD (enterprise) instead of paper-only
# BackupToAAD-BitLockerKeyProtector / Backup-BitLockerKeyProtector
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId "{GUID}"
```

> 🧠 **Paranoid extra:** enable **TPM + PIN + USB startup key** (three-factor boot), set a **TPM lockout** for brute-forced PINs, and turn on **Kernel DMA Protection** (`Get-CimInstance Win32_DeviceGuard`) plus disabling new DMA devices on the lock screen to defeat Thunderbolt/PCIe attacks. Disable Standby (S3) sleep in favor of hibernate so keys aren't left in RAM.

## 4. 👤 User Accounts & Authentication

### Run as a standard user (the #1 control)

```powershell
# Audit who is a local admin — the list should be SHORT
Get-LocalGroupMember -Group "Administrators"

# Create a separate standard account for daily use; keep admin for elevation only
New-LocalUser -Name "daily" -FullName "Daily Driver" -Description "Standard user"
Add-LocalGroupMember -Group "Users" -Member "daily"

# Rename & disable the built-in Administrator and Guest accounts
Rename-LocalUser -Name "Administrator" -NewName "BreakGlass"
Disable-LocalUser -Name "BreakGlass"
Disable-LocalUser -Name "Guest"
```

### User Account Control (UAC) — max prompting

```powershell
$uac = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty $uac EnableLUA 1                  # UAC on
Set-ItemProperty $uac ConsentPromptBehaviorAdmin 2 # always prompt on secure desktop
Set-ItemProperty $uac PromptOnSecureDesktop 1
Set-ItemProperty $uac ConsentPromptBehaviorUser 0  # deny elevation to standard users
Set-ItemProperty $uac FilterAdministratorToken 1   # admin Approval Mode for built-in admin
```

### Password & lockout policy

```powershell
# Account lockout (blunt brute-force)
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
# Password strength & history
net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:24

# Enforce complexity via security policy export/import
secedit /export /cfg C:\sec.cfg
# edit: PasswordComplexity = 1 ; then re-import:
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\sec.cfg
```

### Passwordless / phishing-resistant sign-in

```powershell
# Prefer Windows Hello for Business (TPM-bound biometric/PIN) or FIDO2 keys
# over passwords. Enforce via policy; disable weak fallbacks.

# Block storing reversible passwords & LM hashes, require NTLMv2 only
$lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty $lsa NoLMHash 1
Set-ItemProperty $lsa LmCompatibilityLevel 5       # send NTLMv2 only, refuse LM/NTLM
```

### Credential protection

```powershell
# Enable Credential Guard (VBS-isolated LSA — defeats Mimikatz-style dumping)
$dg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
New-Item $dg -Force | Out-Null
Set-ItemProperty $dg EnableVirtualizationBasedSecurity 1
Set-ItemProperty $dg RequirePlatformSecurityFeatures 3   # Secure Boot + DMA
$lc = "$dg\Scenarios\CredentialGuard"
New-Item $lc -Force | Out-Null
Set-ItemProperty $lc Enabled 1
# Verify after reboot:
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
```

> 🧠 **Paranoid extra:** require a **FIDO2 hardware key** (YubiKey) for sign-in, enable **LSA Protection** (`RunAsPPL`), and use **LAPS** (Local Administrator Password Solution) so every machine has a unique, rotated local-admin password.

## 5. 🛡️ Windows Defender & Attack Surface Reduction

Microsoft Defender is genuinely strong when fully configured. Turn on the features that ship *off* by default.

### Core Defender configuration

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced              # cloud-delivered protection
Set-MpPreference -SubmitSamplesConsent SendAllSamples
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -CloudExtendedTimeout 50
Set-MpPreference -PUAProtection Enabled               # block potentially-unwanted apps
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -EnableNetworkProtection Enabled     # block malicious URLs/IPs
Set-MpPreference -DisableRemovableDriveScanning $false

# Tamper Protection (set in Windows Security UI or via Intune — blocks malware
# from disabling Defender). Verify:
Get-MpComputerStatus | Select IsTamperProtected
```

### Attack Surface Reduction (ASR) rules

ASR blocks the techniques malware actually uses (malicious macros, LOLBins, credential theft). Enable the high-value rules:

```powershell
# Helper: 1 = Block, 2 = Audit (test first!), 6 = Warn
$asr = @{
  # Block Office apps creating child processes
  "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1
  # Block Office creating executable content
  "3B576869-A4EC-4529-8536-B80A7769E899" = 1
  # Block Office injecting into other processes
  "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1
  # Block obfuscated JS/VBS/PS scripts
  "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1
  # Block JS/VBS launching downloaded executables
  "D3E037E1-3EB8-44C8-A917-57927947596D" = 1
  # Block credential stealing from LSASS
  "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 1
  # Block process creations from PSExec/WMI
  "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = 1
  # Block untrusted/unsigned processes from USB
  "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = 1
  # Block executables unless prevalence/age/trusted criteria met
  "01443614-CD74-433A-B99E-2ECDC07BFC25" = 1
  # Block Office comms apps creating child processes
  "26190899-1602-49E8-8B27-EB1D0A1CE869" = 1
  # Block persistence via WMI event subscription
  "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = 1
  # Advanced ransomware protection
  "C1DB55AB-C21A-4637-BB3F-A12568109D35" = 1
}
foreach ($id in $asr.Keys) {
  Add-MpPreference -AttackSurfaceReductionRules_Ids $id `
    -AttackSurfaceReductionRules_Actions $asr[$id]
}
# Review current state
Get-MpPreference | Select -Expand AttackSurfaceReductionRules_Ids
```

> 💡 Roll ASR out in **Audit (2)** mode first, watch `Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational` for would-be blocks, then flip to **Block (1)**.

### Controlled Folder Access (anti-ransomware) & on-demand scans

```powershell
Set-MpPreference -EnableControlledFolderAccess Enabled
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Users\daily\Documents"
# Allow a trusted app if it gets blocked:
# Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Path\app.exe"

Update-MpSignature
Start-MpScan -ScanType FullScan
```

> 🧠 **Paranoid extra:** enable the full **Exploit Protection** suite (DEP, ASLR force-relocation, CFG, SEHOP) via `Get-ProcessMitigation -System` / `Set-ProcessMitigation`, and consider **Smart App Control** (clean install of Win11) which blocks untrusted apps system-wide.

## 6. 🧱 Windows Firewall & Network

Default-deny inbound on every profile, log drops, and kill legacy protocols.

### Lock down all three profiles

```powershell
# Block inbound by default, allow outbound (tighten to deny outbound if paranoid)
Set-NetFirewallProfile -Profile Domain,Public,Private `
  -Enabled True `
  -DefaultInboundAction Block `
  -DefaultOutboundAction Allow `
  -AllowInboundRules True `
  -NotifyOnListen True

# Enable drop logging per profile
Set-NetFirewallProfile -Profile Domain,Public,Private `
  -LogBlocked True -LogMaxSizeKilobytes 16384 `
  -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"

Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction, DefaultOutboundAction
```

### Example rules

```powershell
# Allow RDP ONLY from a management subnet (if RDP is needed at all — see §11)
New-NetFirewallRule -DisplayName "RDP-Allow-Mgmt" -Direction Inbound `
  -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.0.0/24 -Action Allow

# Block inbound SMB from the internet-facing perspective
New-NetFirewallRule -DisplayName "Block-SMB-In" -Direction Inbound `
  -Protocol TCP -LocalPort 445 -Action Block

# Review existing allow rules — prune anything you don't recognize
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
  Select DisplayName, Profile | Sort DisplayName
```

### Kill legacy / insecure protocols

```powershell
# Disable SMBv1 (WannaCry/EternalBlue surface)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
# Require SMB signing & encryption
Set-SmbServerConfiguration -RequireSecuritySignature $true -EncryptData $true -Force

# Disable LLMNR, NetBIOS-NS & mDNS (spoofing/credential-relay vectors)
$dnsClient = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
New-Item $dnsClient -Force | Out-Null
Set-ItemProperty $dnsClient EnableMulticast 0           # LLMNR off
# NetBIOS over TCP/IP off on all adapters:
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
  ForEach-Object { $_.SetTnetbiosOptions(2) } 2>$null

# Disable WPAD (proxy auto-discovery abuse)
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" Start 4
```

### DNS privacy (DoH)

```powershell
# Force encrypted DNS (Windows 11) to a trusted resolver
netsh dns add encryption server=9.9.9.9 dohtemplate=https://dns.quad9.net/dns-query
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 9.9.9.9,149.112.112.112
Get-DnsClientDohServerAddress
```

> 🧠 **Paranoid extra:** set outbound default to **Block** and build an application allow-list of outbound rules — this strangles malware C2 and exfil. Pair with disabling IPv6 if unused and randomizing the Wi-Fi MAC (`Settings → Wi-Fi → Random hardware addresses`).

## 7. 🔐 Application Control

Stop unauthorized binaries and scripts from ever executing — the strongest defense against malware and LOLBins.

### AppLocker (Enterprise/Education)

```powershell
# Generate a starter policy from the current "known good" system
Get-AppLockerFileInformation -Directory "C:\Program Files\" -Recurse `
  -FileType Exe, Script |
  New-AppLockerPolicy -RuleType Publisher, Hash -User Everyone `
  -Optimize -Xml > C:\AppLocker.xml

# Default rules: allow Windows + Program Files, deny user-writable paths
# (TEST in Audit mode via Group Policy before enforcing!)
Set-AppLockerPolicy -XmlPolicy C:\AppLocker.xml

# The Application Identity service must run for AppLocker to enforce
Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc

# Review what WOULD be blocked (audit events)
Get-AppLockerFileInformation -EventLog -LogPath "Microsoft-Windows-AppLocker/EXE and DLL" |
  Select -First 20
```

> ⚠️ Block **user-writable directories** (`%TEMP%`, `%APPDATA%`, `Downloads`) — that's where droppers land. Watch out for documented AppLocker bypass paths and add DLL rules for full coverage.

### WDAC (Windows Defender Application Control) — kernel-enforced

```powershell
# Build a policy from a clean reference machine
New-CIPolicy -FilePath C:\WDAC\Policy.xml -Level Publisher -UserPEs -ScanPath C:\ -Fallback Hash

# Audit mode first (logs, doesn't block)
Set-RuleOption -FilePath C:\WDAC\Policy.xml -Option 3    # Audit Mode

# Compile to binary and deploy
ConvertFrom-CIPolicy -XmlFilePath C:\WDAC\Policy.xml -BinaryFilePath C:\WDAC\Policy.cip
# Deploy via CiTool (Win11) or copy to CodeIntegrity & reboot
CiTool --update-policy C:\WDAC\Policy.cip
```

> 🧠 **Paranoid extra:** deploy **WDAC in enforced mode** with Microsoft's recommended **block-list** (vulnerable drivers + LOLBins like `mshta`, `wmic`, `bginfo`), enable **HVCI / Memory Integrity** for kernel code-integrity, and require WHQL-signed drivers only.

## 8. ✂️ Service & Feature Minimization

The smallest attack surface is the code you never run.

### Disable risky services & features

```powershell
# Audit what's running and listening
Get-Service | Where-Object Status -eq 'Running' | Select Name, DisplayName | Sort Name
Get-NetTCPConnection -State Listen |
  Select LocalAddress, LocalPort, OwningProcess |
  Sort LocalPort

# Commonly-disabled-if-unused services (verify you don't need each!)
$disable = @(
  "RemoteRegistry",   # remote registry editing
  "Fax",
  "XblAuthManager","XblGameSave","XboxNetApiSvc",  # Xbox
  "RetailDemo",
  "MapsBroker",       # downloaded maps
  "WMPNetworkSvc",    # media sharing
  "PhoneSvc",
  "WpcMonSvc"
)
foreach ($s in $disable) {
  Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
  Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
}

# Remove optional features you don't use
Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -NoRestart  # legacy PSv2
```

### Disable script-host & macro abuse vectors

```powershell
# Disable Windows Script Host (kills many .vbs/.js droppers)
$wsh = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
New-Item $wsh -Force | Out-Null
Set-ItemProperty $wsh Enabled 0

# Block Office macros from the internet (Mark-of-the-Web enforced)
$off = "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0"
"Word","Excel","PowerPoint" | ForEach-Object {
  $p = "$off\$_\Security"
  New-Item $p -Force | Out-Null
  Set-ItemProperty $p "blockcontentexecutionfrominternet" 1
  Set-ItemProperty $p "vbawarnings" 4     # disable all macros w/o notification
}
```

### Remove bloatware & enforce PowerShell logging

```powershell
# Strip provisioned consumer apps (review the list first!)
Get-AppxPackage -AllUsers | Where-Object {$_.Name -match "Xbox|Bing|Zune|SolitaireCollection|GetHelp|Feedback"} |
  Remove-AppxPackage -ErrorAction SilentlyContinue

# Constrained Language Mode + full PowerShell logging (forensics & anti-LOLBin)
$psl = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $psl -Force | Out-Null
Set-ItemProperty $psl EnableScriptBlockLogging 1
$psm = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item $psm -Force | Out-Null
Set-ItemProperty $psm EnableModuleLogging 1
```

> 🧠 **Paranoid extra:** disable **autorun/autoplay** entirely, block removable storage via policy, and run untrusted documents/browsing inside **Windows Sandbox** or an **MDAG (Application Guard)** container.

## 9. 🕵️ Privacy & Telemetry

Cut the data Windows phones home, and shrink your forensic footprint.

### Minimize telemetry & ad tracking

```powershell
# Telemetry to Security/lowest supported (Enterprise can use 0=Security)
$dc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
New-Item $dc -Force | Out-Null
Set-ItemProperty $dc AllowTelemetry 0
Set-ItemProperty $dc DoNotShowFeedbackNotifications 1

# Disable the advertising ID
$ad = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
New-Item $ad -Force | Out-Null
Set-ItemProperty $ad DisabledByGroupPolicy 1

# Disable Cortana & web search in Start
$srch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
New-Item $srch -Force | Out-Null
Set-ItemProperty $srch AllowCortana 0
Set-ItemProperty $srch ConnectedSearchUseWeb 0

# Disable activity history & clipboard cloud sync
$sys = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
New-Item $sys -Force | Out-Null
Set-ItemProperty $sys EnableActivityFeed 0
Set-ItemProperty $sys PublishUserActivities 0
Set-ItemProperty $sys UploadUserActivities 0
Set-ItemProperty $sys AllowClipboardHistory 0
Set-ItemProperty $sys AllowCrossDeviceClipboard 0
```

### Block telemetry services & tighten location

```powershell
# Connected User Experiences and Telemetry (DiagTrack) + dmwappushservice
Set-Service DiagTrack -StartupType Disabled; Stop-Service DiagTrack -Force -EA SilentlyContinue
Set-Service dmwappushservice -StartupType Disabled -EA SilentlyContinue

# Disable location, camera, mic at policy level if not needed
$cap = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
Set-ItemProperty "$cap\location" Value Deny -EA SilentlyContinue
```

> 🧠 **Paranoid extra:** use a **local account** (not a Microsoft account) so OneDrive/sync/recovery-key escrow don't leave the box, disable **OneDrive** and **Recall** (Win11 AI screenshots), and consider an O&O ShutUp10++-style review — but verify each toggle, don't blindly apply.

## 10. 📋 Auditing, Logging & Monitoring

You can't respond to what you can't see. Turn on the advanced audit policy and grow the logs.

### Advanced audit policy

```powershell
# High-value categories (Success+Failure where it matters)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

# Record full command lines with process-creation events (Event ID 4688)
$audit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item $audit -Force | Out-Null
Set-ItemProperty $audit ProcessCreationIncludeCmdLine_Enabled 1

auditpol /get /category:* | Out-String   # review effective policy
```

### Grow & protect the event logs

```powershell
# Bigger logs so attackers can't roll them over quickly (bytes)
wevtutil sl Security /ms:1073741824      # 1 GB
wevtutil sl System   /ms:268435456       # 256 MB
wevtutil sl Application /ms:268435456
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456

# Query recent security-relevant events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 |  # failed logons
  Select TimeCreated, @{n='User';e={$_.Properties[5].Value}}
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 20    # new processes
```

### Sysmon + forwarding (deep visibility)

```powershell
# Sysmon (Sysinternals) with a community config = rich, filtered telemetry
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml   # e.g. SwiftOnSecurity / Olaf Hartong config
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10

# Ship logs OFF-BOX with Windows Event Forwarding (WEF) to a collector,
# so an intruder can't simply clear local logs.
wecutil qc /q                                       # enable collector service
```

> 🧠 **Paranoid extra:** forward all logs in **real time** to a separate, hardened collector or SIEM, alert on **Event ID 1102** (Security log cleared) and **4719** (audit policy changed), and keep **append-only** retention off the host.

## 11. 🖥️ Remote Access Hardening

Remote access is the #1 way attackers move in and around. If you don't need it, **disable it**.

### RDP — disable, or harden hard

```powershell
# If RDP is NOT needed, turn it off entirely:
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" fDenyTSConnections 1
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"

# If RDP IS needed — require NLA, strong encryption, and restrict the source:
$ts = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
Set-ItemProperty $ts UserAuthentication 1     # Network Level Authentication required
Set-ItemProperty $ts SecurityLayer 2          # TLS
Set-ItemProperty $ts MinEncryptionLevel 3     # High (128-bit)
# Idle/disconnect timeouts
Set-ItemProperty $ts MaxIdleTime 900000        # 15 min
Set-ItemProperty $ts MaxDisconnectionTime 60000

# Limit who can RDP (replace the broad "Remote Desktop Users" defaults)
# Add only specific accounts:
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "daily" -EA SilentlyContinue

# Lock the firewall rule to a management subnet (see §6) — never expose 3389 publicly.
```

### WinRM / PowerShell Remoting

```powershell
# If unused, disable it:
Disable-PSRemoting -Force
Stop-Service WinRM; Set-Service WinRM -StartupType Disabled

# If needed: HTTPS only, no Basic/unencrypted, restrict hosts
Set-Item WSMan:\localhost\Service\Auth\Basic $false
Set-Item WSMan:\localhost\Service\AllowUnencrypted $false
# Create an HTTPS listener bound to a cert, and firewall it to mgmt hosts only.
winrm enumerate winrm/config/listener
```

### Harden against credential relay & lateral movement

```powershell
# Block remote logons by local accounts (stops pass-the-hash lateral movement)
$lsa = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# Deny "Access this computer from the network" + "Remote Desktop" for local accounts
# via secpol: SeDenyNetworkLogonRight / SeDenyRemoteInteractiveLogonRight = Local account

# Disable WDigest (no cleartext creds in memory) — default off on modern Windows, enforce it
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential 0
```

> 🧠 **Paranoid extra:** never expose RDP/WinRM to the internet — front them with a **VPN (WireGuard/Always-On VPN)** or **RD Gateway + MFA**. Use **Restricted Admin / Remote Credential Guard** so credentials never land on the remote host.

## 12. 🔄 Updates & Patch Management

Unpatched software is the most common breach vector. Patch the OS **and** third-party apps.

```powershell
# Ensure Windows Update is active and pulling everything (incl. other MS products)
Set-Service wuauserv -StartupType Manual
$au = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
New-Item $au -Force | Out-Null
Set-ItemProperty $au NoAutoUpdate 0
Set-ItemProperty $au AUOptions 4            # auto download + scheduled install
Set-ItemProperty $au ScheduledInstallTime 3 # 03:00

# Manual check / install via the PSWindowsUpdate module
Install-Module PSWindowsUpdate -Scope CurrentUser -Force
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll -AutoReboot

# Verify patch level & recent hotfixes
Get-HotFix | Sort InstalledOn -Descending | Select -First 10
```

### Third-party patching (the part everyone forgets)

```powershell
# Use winget to keep all installed apps current (browsers, readers, runtimes)
winget upgrade --all --include-unknown --silent --accept-package-agreements

# List what's outdated
winget upgrade
```

> 🧠 **Paranoid extra:** subscribe to vendor security advisories, enable **automatic driver/firmware (UEFI)** updates from your OEM, and pilot feature updates in a test ring before broad rollout — major upgrades silently reset hardening policies (re-run your baseline after each).

## 13. 🔌 Physical & Boot Security

If an attacker can touch the machine, prepare accordingly.

### Secure Boot, TPM & virtualization-based security

```powershell
# Verify firmware security state
Confirm-SecureBootUEFI                       # True = Secure Boot on
Get-Tpm                                       # TPM present/ready/enabled
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus

# Enable HVCI / Memory Integrity (kernel code-integrity in VBS)
$hvci = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
New-Item $hvci -Force | Out-Null
Set-ItemProperty $hvci Enabled 1
```

- In **UEFI/BIOS**: set a **supervisor password**, enable **Secure Boot**, disable boot from USB/PXE, and enable **TPM** + **Kernel DMA Protection**.
- Keep firmware updated; old UEFI has its own CVEs.

### Lock screen, autoplay & removable media

```powershell
# Auto-lock after inactivity (machine inactivity limit, seconds)
$sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty $sys InactivityTimeoutSecs 600
Set-ItemProperty $sys DontDisplayLastUserName 1   # don't reveal usernames
Set-ItemProperty $sys legalnoticecaption "Authorized Use Only"

# Disable AutoRun/AutoPlay everywhere
$exp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
New-Item $exp -Force | Out-Null
Set-ItemProperty $exp NoDriveTypeAutoRun 255
Set-ItemProperty $exp NoAutorun 1

# Deny all access to removable storage (USB exfil / BadUSB)
$rs = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
New-Item $rs -Force | Out-Null
Set-ItemProperty $rs "Deny_All" 1
```

> 🧠 **Paranoid extra:** disable the **camera/microphone in firmware**, block new **DMA devices on the lock screen**, configure **TPM lockout** for guessed PINs, and use tamper-evident seals on a high-risk laptop. For data destruction, BitLocker crypto-erase (delete the key) beats wiping.

## 14. ✅ Verification & Hardening Checklist

Don't trust — verify. Re-run after every change and on a schedule.

### Automated audit

```powershell
# HardeningKitty audit against a CIS finding list (read-only)
Invoke-HardeningKitty -Mode Audit -Log -Report -ReportFile C:\hhc-report.csv

# Microsoft Policy Analyzer / CIS-CAT for scored benchmark comparison.
# Defender + key states at a glance:
Get-MpComputerStatus | Select RealTimeProtectionEnabled, IsTamperProtected, AMRunningMode
Get-BitLockerVolume   | Select MountPoint, ProtectionStatus, EncryptionMethod
Confirm-SecureBootUEFI
(Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
```

### Manual spot-checks

```powershell
Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction
Get-LocalGroupMember Administrators                # short list?
Get-NetTCPConnection -State Listen | Select LocalPort, OwningProcess | Sort LocalPort
Get-MpPreference | Select -Expand AttackSurfaceReductionRules_Ids   # ASR active?
auditpol /get /category:*                          # audit policy on?
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 5  # log cleared?
```

### ✔️ Final checklist

- [ ] Threat model documented & reviewed; restore point taken
- [ ] Baseline (CIS / MS SCT) applied and version-controlled
- [ ] BitLocker XTS-AES-256 + TPM&PIN; recovery key stored **offline**
- [ ] Daily account is **standard** (non-admin); built-in Admin/Guest disabled
- [ ] UAC at max; strong password/lockout policy; NTLMv2-only, no LM hash
- [ ] Credential Guard + LSA Protection enabled
- [ ] Defender fully on: cloud, PUA, network protection, Tamper Protection
- [ ] ASR rules in **Block**; Controlled Folder Access on
- [ ] Firewall default-deny inbound on all profiles, drop logging on
- [ ] SMBv1/LLMNR/NetBIOS/WPAD disabled; SMB signing+encryption on
- [ ] AppLocker/WDAC enforcing; user-writable paths blocked
- [ ] Unneeded services/features/bloatware removed; WSH off; macros blocked
- [ ] Telemetry minimized; DiagTrack off; local account; Recall/OneDrive off
- [ ] Advanced audit policy + cmdline logging + PowerShell logging on
- [ ] Logs enlarged and **forwarded off-box**; alert on 1102 / 4719
- [ ] RDP/WinRM disabled or behind VPN/MFA with NLA + source restriction
- [ ] Windows **and** third-party apps auto-updating (winget)
- [ ] Secure Boot + TPM + HVCI on; UEFI password; DMA protection
- [ ] AutoRun off; removable storage locked down; auto-lock on
- [ ] HardeningKitty/CIS-CAT scan reviewed; findings triaged
- [ ] Backups encrypted, tested, and **offline** (3-2-1 rule)

---

> 🧠 **Remember:** hardening is a *process*, not a one-time task. Windows feature updates silently revert policies — re-audit after every major update, every new app, and on a recurring schedule. The goal isn't a perfect score; it's making yourself a more expensive target than the attacker is willing to pay for.

<!-- SECTIONS-END -->

## 📜 License

MIT — see [LICENSE](LICENSE).
