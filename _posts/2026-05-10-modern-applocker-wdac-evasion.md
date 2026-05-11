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

> **Lab disclaimer:** The techniques discussed here are intended strictly for authorized security assessments, adversary simulation, and controlled lab environments. The defensive guidance and detection notes are especially relevant for blue teams looking to validate or improve their AppLocker and WDAC monitoring, policy design, and response coverage.

> **OpSec scope:** This article focuses on the application control side of the problem. I’m not covering EDR evasion techniques such as AMSI patching, ETW tampering, syscall stub generation, sleep masking, or script block logging bypasses. Those are separate layers with their own detection surface and operational trade-offs. In practice, mature payloads combine both: one set of techniques to achieve code execution under AppLocker or WDAC, and another to reduce visibility once execution is obtained. Treat the material here as the execution half of the equation, not the stealth half.

## I. Intro

When people talk about “application allowlisting” on Windows, they’re usually referring to one of three things:
- **SmartScreen.** Microsoft’s reputation-based protection layer. In many environments, it can be bypassed with trusted signing, reputation building, or Mark-of-the-Web tricks. That’s not what this article is about.
- **AppLocker.** A user-mode allowlisting solution built around path, hash, and publisher rules. It relies on a service and filter driver, is easy to deploy through Group Policy, and is still extremely common in enterprise environments.
- **WDAC (Windows Defender Application Control.** A much stricter, kernel-backed enforcement model handled by `CI.dll`. WDAC has two separate enforcement components:
  - **UMCI** (User-Mode Code Integrity) for userland binaries and scripts
  - **KMCI** (Kernel-Mode Code Integrity) for drivers
  Each can idependently run in Off, Audit, or Enforce mode.

The distinction that matters operationally is this: KMCI is common. Most organizations want to stop untrusted drivers from loading. Full UMCI enforcement, however, is still relatively uncommon because it is harder to manage operationally and usually comes bundled with a mature security stack: EDR, MDM, Managed Installer policies, and restricted scripting environments like PowerShell CLM. Once you land on a box with UMCI enforced, HVCI enabled, and constrained scripting, every stage of execution becomes significantly more difficult.

On the other hand, if only KMCI is enforced, AppLocker often becomes the primary obstacle rather than WDAC itself.

For the rest of this article, assume two things:

- Initial execution is as a standard user
- No administrative privileges unless explicitly stated

One important point before diving deeper: bypassing AppLocker is not the same thing as bypassing EDR.

A lot of the classic LOLBin techniques still technically work against weak allowlisting policies. Utilities like `InstallUtil`, `MSBuild`, `regasm`, or `MSHTA` can still result in code execution under certain configurations. The problem is that in 2026, these binaries are among the most heavily monitored execution paths in enterprise telemetry. Using them may get you past the application control policy, but it will also generate immediate high-confidence alerts in most modern EDR platforms. In practice, that means successful execution and SOC visibility often happen at the exact same moment.

## II. Enumeration

Before attempting anything, understand the policy you’re dealing with. Blindly testing execution paths is one of the fastest ways to generate noisy telemetry and burn access. Every denied execution attempt can produce logs, alerts, or behavioral signals for the SOC. Good operators enumerate first and touch the policy only when they understand what is actually being enforced.

### AppLocker

```powershell
Get-AppLockerPolicy -Effective -Xml | Out-File C:\Users\Public\al.xml
```

The first step is understanding what the policy actually enforces instead of guessing from failed executions.

There are three things worth checking immediately:

1. **Which rule collections are enabled**  
    Look for collections such as `Exe`, `Dll`, `Script`, `Msi`, and `Appx`, and check whether they are running in **Enforce** or **AuditOnly** mode.
    
    Audit mode is extremely useful from an operator perspective. You can safely test execution paths and see what _would_ have been blocked without actually triggering enforcement.
    
2. **Path rules pointing to writable locations**  
    Misconfigured path rules are still one of the most common weaknesses in AppLocker deployments. Pay attention to anything user-writable:
    
    - `%TEMP%\*`
    - `C:\Builds\*`
    - developer tooling directories
    - package cache locations
    - CI/CD artifact paths
    
    Any writable allowlisted directory becomes a potential execution staging area.
    
3. **Whether DLL rules are disabled or unconfigured**  
    In many environments, the `Dll` rule collection is left as `NotConfigured`.
    
    That usually comes down to operational overhead. DLL enforcement adds noticeable performance cost and tends to break legacy applications, so many organizations simply skip it. When DLL rules are absent, DLL hijacking often becomes the lowest-effort and most reliable execution path available on the host.
    

From a telemetry perspective:

- **8003 / 8006** → Audit-mode events
- **8004 / 8007** → Enforcement blocks

Most SOCs actively monitor and alert on `8004` events because they represent actual policy violations. Audit events (`8003`) are frequently collected but receive far less attention, especially in noisy enterprise environments.

### WDAC

```powershell
$dg = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard
$dg | Format-List CodeIntegrityPolicyEnforcementStatus,
                  UsermodeCodeIntegrityPolicyEnforcementStatus,
                  SecurityServicesRunning
```

This gives a quick snapshot of how aggressively the system is enforcing code integrity.

The important fields are:

- `CodeIntegrityPolicyEnforcementStatus`
- `UsermodeCodeIntegrityPolicyEnforcementStatus`

The values decode as:

- `0` → Off
- `1` → Audit
- `2` → Enforce

`SecurityServicesRunning` tells you which additional protections are active:

- `1` → Credential Guard
- `2` → HVCI (Hypervisor-Protected Code Integrity)

HVCI matters because it significantly raises the cost of driver abuse and many traditional BYOVD approaches. A lot of older offensive assumptions around vulnerable driver loading stop working once HVCI is enabled.

You should also check the active policy store:

```powershell
dir C:\Windows\System32\CodeIntegrity\CIPolicies\Active\
```

If you see multiple `.cip` files, the system is likely using a base WDAC policy with supplemental policies layered on top. That distinction matters operationally because supplemental policies create an entirely separate attack surface depending on how trust relationships were configured.

The other immediate signal is PowerShell language mode:

```powershell
$ExecutionContext.SessionState.LanguageMode
```

If the result is `ConstrainedLanguage`, UMCI is actively restricting unsigned script execution. Under CLM, a large amount of public PowerShell tradecraft simply stops working or breaks in unreliable ways. Reflection-heavy tooling, inline C# compilation, dynamic method generation, and many common offensive frameworks become unusable without additional bypasses.

From a logging perspective, the key WDAC events are:

- **3076** → Audit-mode “would have blocked”
- **3077** → Enforcement block
- **3099** → Policy refresh or policy load event

Event `3099` becomes especially important when supplemental policies are involved because it can reveal when a new policy was added or refreshed on the system. Mature SOC pipelines typically monitor all three.

## III. AppLocker

Most successful bypasses are not about "breaking" AppLocker or WDAC directly. They’re about finding execution paths Microsoft already trusts and using those trust relationships against the policy. In practice, the best technique is usually not the most advanced one, it’s the one that achieves execution with the lowest operational cost and the least visibility. Every additional LOLBin, child process, policy violation, or scripting engine you touch increases telemetry. Treat bypass selection as a trade-off between capability and detection surface, and always choose the cheapest option your target environment allows.

### InstallUtil and MSBuild

`InstallUtil` and `MSBuild` still work in some environments, but they are no longer quiet techniques. Modern EDR products such as Defender for Endpoint, CrowdStrike, and SentinelOne commonly detect this activity without custom tuning.

The detection is usually not based on the binary name alone. It is based on behaviour and process lineage. For example, `installutil.exe` spawning `cmd.exe` is a much stronger signal than `installutil.exe` existing on disk.

Because of that, I rarely use these as a first option anymore. They are fallback techniques for situations where cleaner paths are unavailable, such as when no suitable Electron application exists and DLL hijacking does not produce a reliable route.

A minimal `InstallUtil` test looks like this:

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

`MSBuild` gives you a similar outcome through inline C# tasks. Instead of executing a compiled binary directly, the code is compiled and executed inside `MSBuild.exe`:

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

Both `InstallUtil` and `MSBuild` are included in Microsoft’s recommended block guidance. The problem is that not every WDAC policy actually includes those recommended blocks. Always verify the policy instead of assuming they are covered.
### DLL hijacking

When the `Dll` rule collection is left as `NotConfigured`, DLL-based execution becomes one of the most useful paths to check.

There are two practical approaches I rely on most often:

- **Phantom hijacking**  
    Use Procmon to identify DLL load attempts that return `NAME NOT FOUND` from an allowlisted executable. If the missing DLL path is writable, placing a DLL there can give you execution when the application starts.
- **Proxy DLL sideloading**  
    Place a proxy DLL next to a trusted or portable application. The application continues to work because the proxy forwards the expected exports to the legitimate DLL, while your code executes during load.

A simplified proxy DLL pattern looks like this:

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

Useful tooling for this includes **SharpDLLProxy**, **Spartacus**, and **Robber**. The best choice usually comes down to what is easiest to set up on your operator workstation and how cleanly it handles the target DLL’s exports.

From a detection perspective, this is usually lower signal than classic LOLBin execution if the target is an application the user naturally launches. It becomes much louder when the sideload happens from obvious staging locations such as `%TEMP%`, `Downloads`, or other user-writable scratch paths.

WDAC changes the equation if DLL enforcement is enabled. In that configuration, unsigned proxy DLLs are denied at load time, which effectively kills this route. In practice, though, DLL enforcement is still uncommon in many WDAC deployments because of the operational impact and application compatibility issues.

### Electron, the practical AppLocker bypass

This is one of the more useful paths on real engagements. Electron applications are everywhere: Slack, Teams, VS Code, Discord, Obsidian, and plenty of internal enterprise apps. They are often trusted by policy, frequently installed in user-writable locations, and each one brings a full Node.js runtime that is not affected by PowerShell CLM.

There are four reliable places to look:

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

ASAR tampering is the persistence angle. If you modify the application’s JavaScript, the user’s next normal launch runs your code inside the already trusted Electron process.

```powershell
$asar = "$env:LOCALAPPDATA\slack\app-4.42.0\resources\app.asar"
npx --yes asar extract $asar app_src

Add-Content .\app_src\dist\preload.js -Value @"
const { exec } = require('child_process');
exec('cmd /c whoami > C:\\Users\\Public\\proof.txt');
"@

npx --yes asar pack app_src $asar
```

Placement matters. Modern Electron applications usually run with `nodeIntegration: false` and `contextIsolation: true`, which means renderer JavaScript cannot simply call `require`. The better targets are usually the **preload script** or the **main process**. The preload script runs in a privileged isolated context and may still have access to Node. The main process, commonly referenced as `main.js` in `package.json`, is Node-enabled by design.

Electron 22 and later also support an ASAR integrity fuse. Many vendors still do not enable it because it complicates post-install updates and patching, but it is worth checking before spending time unpacking and modifying the archive.

The reason this remains practical in 2026 is simple: many detections still focus on suspicious child processes such as `cmd.exe` or `powershell.exe`. From Node, you can perform a lot of post-exploitation logic directly in JavaScript: file operations, registry access through modules, HTTP communication, raw sockets, and data handling without spawning a shell. `ELECTRON_RUN_AS_NODE` also avoids PowerShell CLM entirely because the code is not running inside PowerShell.

The main things that expose this technique are suspicious Electron command-line flags such as `--inspect`, or the presence of the `ELECTRON_RUN_AS_NODE` environment variable. Most EDRs collect command-line arguments consistently. Fewer expose environment variables with the same level of visibility.

### Developer workstations

Engineering workstations are usually the weakest point in application control deployments. The allowlist is designed around keeping developers productive, which means the environment ends up trusting a large number of runtimes, build systems, package managers, and scripting paths by default.

That creates execution opportunities that blend into normal developer activity.

| Surface                          | What you abuse                                                                          |
| -------------------------------- | --------------------------------------------------------------------------------------- |
| VS Code `tasks.json`             | `Ctrl+Shift+B` executes whatever command is defined in the build task                   |
| VS Code extensions               | JavaScript execution inside the extension host with the same trust boundary as Electron |
| npm `preinstall` / `postinstall` | Automatic shell execution during `npm install`                                          |
| Python venv activate             | Writable `activate.bat` / `Activate.ps1` scripts inside the venv                        |
| NuGet `BeforeBuild` target       | Arbitrary `<Exec>` actions during `dotnet build`                                        |
| Self-hosted CI runners           | Workflow definitions execute automatically; a merged PR can become code execution       |
| Git hooks                        | `pre-commit`, `post-checkout` , and similar hooks trigger during routine Git operations |

What makes these valuable is that they align with expected developer workflows. Build systems spawning shells, package managers running scripts, or VS Code launching helper processes are all normal behaviour on engineering systems.

Because of that, telemetry in this space is often weak unless the organization has a mature engineering security program with strong CI/CD monitoring, developer workstation baselining, and behavioural analytics around build tooling.

## IV. WDAC

What still matters in 2026 is a much smaller set of techniques that survive real WDAC deployments:

- **Managed Installer abuse** — probably the most overlooked trust boundary in WDAC environments
- **ISG (Intelligent Security Graph)** trust decisions and reputation inheritance
- **Supplemental policy** design mistakes and policy layering issues
- **Operating effectively under Constrained Language Mode (CLM)**
- **BYOVD** in environments where HVCI and vulnerable driver blocklists are inconsistently enforced

These are the areas that still show up in real enterprise environments because they target operational complexity rather than simple policy gaps. Most organizations can block `MSHTA`. Far fewer can deploy WDAC at scale without accidentally creating trusted execution paths through software distribution systems, developer tooling, or policy management workflows.

### Managed Installer Abuse
Managed Installer (MI) exists because large enterprises cannot realistically maintain explicit WDAC allow rules for every application they deploy through SCCM, Intune, MECM, or third-party software distribution systems. At scale, software changes too frequently. Without some kind of inherited trust model, WDAC becomes operationally unmanageable.

The solution Microsoft implemented was Managed Installer trust.

Administrators designate specific installer processes as trusted deployment mechanisms. Any file those processes write to disk is then implicitly trusted by WDAC without requiring separate publisher or hash rules for every binary.

The implementation detail that matters is how that trust is stored.

When a Managed Installer writes a file, the AppLocker filter driver (`appid.sys`) attaches an NTFS extended attribute called:

```powershell
$KERNEL.SMARTLOCKER.ORIGINCLAIM
```

At execution time, WDAC checks for that attribute to determine whether the file originated from a trusted deployment path.

The important detail is that the `$KERNEL.` namespace is kernel-controlled. User-mode processes can read these extended attributes, but they cannot forge or arbitrarily create them. That EA becomes the actual trust root.

You can inspect it directly:

```powershell
fsutil file queryEa "C:\Windows\CCMCache\<package-guid>\setup.exe"
# Ea Name: $KERNEL.SMARTLOCKER.ORIGINCLAIM ...
```

The operational behaviour of the EA (Extended Attribute) matters because the trust follows the file itself, not its contents.

| Operation                         | EA survives?                       |
| --------------------------------- | ---------------------------------- |
| Rename / move / copy on NTFS      | yes                                |
| Copy across NTFS volumes          | Usually yes                        |
| Copy to FAT32, exFAT              | no                                 |
| SMB share to non-NTFS / older SMB | no                                 |
| `tar`, `zip`                      | no                                 |
| `7z` with NTFS streams flag       | sometimes                          |
| Browser download                  | no, browsers don't have MI context |

That last point is important: browsers do not run with Managed Installer context, so downloaded files do not inherit MI trust.

The key implication is that the trust is attached to the file metadata, not validated against the current file contents. If an MI-tagged binary is modified in place, the EA can still indicate that the file originated from SCCM or another trusted deployment system. That behaviour underpins most practical MI abuse scenarios.

The patterns I actually see in real environments are usually:

- **Living off pre-tagged binaries**  
    Anything already deployed under locations such as `C:\Windows\CCM\` or `C:\Windows\CCMCache\` may carry Managed Installer trust. If DLL enforcement is weak or absent, DLL sideloading against those binaries becomes interesting because the trusted application itself already satisfies policy requirements.
- **Supply-chain style deployment abuse**  
    If an attacker gains access to packaging infrastructure or deployment workflows, software can be distributed fleet-wide with valid MI trust attached automatically. This is outside the scope of most assessments, but it is one of the more realistic high-impact WDAC trust failures.
- **Overly broad Managed Installer publisher rules**  
    Some organizations trust entire publisher identities rather than tightly scoped deployment processes. If a publisher rule trusts everything signed by a specific organization, weak signing practices, development certificates, or test-signing workflows can unintentionally expand the trusted surface dramatically.

From a detection perspective, this space is difficult because most of the activity resembles legitimate software deployment behaviour. Without strong integrity monitoring around deployment infrastructure and managed package paths, much of it blends into normal SCCM or Intune operations.

### ISG (Intelligent Security Graph)

ISG extends WDAC trust decisions into Microsoft’s cloud reputation system. Instead of relying only on explicit allow rules, WDAC can allow binaries that Microsoft considers reputable based on factors such as prevalence, signing reputation, and install history.

In practice, this means some binaries execute without a direct publisher, hash, or path rule because the trust decision comes from cloud reputation rather than enterprise policy.

That distinction matters because defenders often assume “allowed by WDAC” means “explicitly approved internally,” which is not always true when ISG is enabled.

From an offensive perspective, directly abusing ISG is not a realistic day-to-day technique for most engagements. Building reputation around a payload takes time, infrastructure, and usually access to legitimate signing material. But it does explain why signed-and-aged malware campaigns continue to work against otherwise hardened environments.

Several mature threat actors have operationalized this model by:

- signing binaries with legitimate or stolen certificates,
- abusing compromised vendor build pipelines,
- or allowing payloads to age quietly before deployment.

The goal is not to bypass WDAC directly, but to look indistinguishable from software the reputation system already trusts.

ISG is enabled through WDAC policy option 14:

```
Enabled:Intelligent Security Graph Authorization
```

You can check whether it is present with:

```powershell
CiTool.exe --list-policies --json | ConvertFrom-Json |
  ForEach-Object { $_.PolicyOptions } |
  Where-Object { $_ -match 'Intelligent' }
```

For defenders, the key point is that ISG is not a replacement for strong allowlisting. It is a convenience layer. It reduces operational friction, but it also expands the trust decision from “what did we explicitly approve?” to “what does cloud reputation currently consider acceptable?”

That trade-off should be intentional, not accidental.
### Supplemental policies

WDAC policies are usually structured around a single base policy with one or more supplemental policies layered on top.

The important design detail is that supplemental policies can only expand trust. They can add additional allow rules, but they cannot introduce new deny rules or weaken existing enforcement decisions from the base policy.

Active policy files live under:

```powershell
C:\Windows\System32\CodeIntegrity\CIPolicies\Active\
```

The kernel loads them during boot, or dynamically when policy refresh is triggered with:

```powershell
CiTool.exe --update-policy
```

Where this becomes operationally interesting is policy signing.

A supplemental policy must be signed by a certificate the base policy already trusts. In properly hardened environments, this trust is tightly scoped to specific internal signing certificates or dedicated policy-signing infrastructure.

In weaker deployments, administrators sometimes trust broad commercial code-signing roots instead. That creates a much larger trust boundary than intended.

For example, if the base policy accepts supplementals signed under common public CAs such as DigiCert or Sectigo, then any actor with a valid certificate chaining to those roots may be able to introduce additional trust rules through a supplemental policy.

That turns supplemental policies into a policy-extension mechanism rather than a tightly controlled administrative workflow.

In practice, I have seen organizations accidentally create this condition while trying to simplify policy management across development teams or third-party vendors.

If administrative access is available and the signing requirements are weak enough, the workflow looks like:

```powershell
ConvertFrom-CIPolicy -XmlFilePath supp.xml -BinaryFilePath supp.cip
signtool sign /v /f attacker.pfx /p ... supp.cip
copy supp.cip C:\Windows\System32\CodeIntegrity\CIPolicies\Active\
CiTool.exe --update-policy
```

When the policy refresh occurs, WDAC generates event **3099**.

That event is important because it indicates:

- policy refresh,
- policy load,
- or supplemental policy activation.

In many environments, defenders monitor enforcement failures aggressively but pay far less attention to policy lifecycle events like `3099`. That creates a blind spot around unexpected policy changes or unauthorized supplemental loading.

### Working under CLM

Once UMCI is enforced, PowerShell usually drops into `ConstrainedLanguage` mode. That breaks a huge amount of public offensive tooling because many common techniques rely on unrestricted .NET access, reflection, inline C#, or dynamic method generation.

At that point, the problem becomes less about “bypassing PowerShell” and more about identifying trusted execution paths that still expose dangerous functionality.

A few areas still matter operationally:

---

#### Runspaces and trusted cmdlets

The classic CLM bypass used to be creating a new runspace and manually setting:

```powershell
SessionStateProxy.LanguageMode = "FullLanguage"
```

That stopped working reliably after WMF 5.1. The setter now throws when CLM is enforced.

The modern angle is more subtle.

Signed modules can still expose cmdlets that internally execute script blocks in a FullLanguage context. If a trusted signed cmdlet accepts a `[ScriptBlock]` parameter and later calls `.Invoke()`, the caller may effectively regain unrestricted execution through the trusted module.

That is one of the more interesting modern CLM research areas because the trust boundary shifts from the PowerShell host itself to the behaviour of signed modules.

A useful starting point is enumerating trusted signed modules:

```powershell
Get-Module -ListAvailable | ForEach-Object {    
  if ((Get-AuthenticodeSignature $_.Path).Status -eq 'Valid') {        
    $_    
  }
} | Select-Object Name, Path
```

From there, reviewing `.psm1` implementations for cmdlets that accept or invoke script blocks becomes the real work.

---

#### PowerShell v2 downgrade

PowerShell v2 predates CLM entirely.

Surprisingly, it is still present on some legacy enterprise systems, especially environments that were upgraded in place over many years instead of being regularly re-imaged.

If PowerShell v2 is installed and enabled, launching it can restore FullLanguage functionality:

```powershell
powershell.exe -Version 2 -Command "$ExecutionContext.SessionState.LanguageMode"
```

Operationally, though, this is noisy:

- the command line is obvious,
- EDR products commonly monitor it,
- and many environments now disable the v2 engine explicitly.

Still, it remains worth checking during enumeration because older finance, healthcare, and industrial environments occasionally still expose it.

---

#### WMI / CIM process creation

CLM restricts PowerShell language features, but it does not automatically constrain every Windows subsystem PowerShell can talk to.

For example, WMI and CIM process creation can still launch external processes:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create `    -Arguments @{        CommandLine = 'cmd /c whoami > C:\Users\Public\proof.txt'    }
```

The spawned process still inherits UMCI enforcement for whatever binaries it executes, but it does not inherit PowerShell’s language restrictions themselves.

That distinction matters:

- CLM constrains PowerShell semantics,
- UMCI constrains executable trust.

They are related, but separate enforcement layers.

---

#### COM automation

Many COM objects remain accessible even under CLM through:

```powershell
New-Object -ComObject <ProgID>
```

Depending on the environment and PowerShell version, objects such as:

- `WScript.Shell`
- `Shell.Application`
- `MMC20.Application`

may still expose useful functionality.

Microsoft has tightened COM behaviour under CLM over time, so reliability depends heavily on:

- the exact ProgID,
- PowerShell version,
- WDAC policy design,
- and whether additional hardening is enabled.

In practice, COM remains situational rather than universally reliable, but it is still worth checking during constrained environments because many enterprise applications continue to depend on legacy automation interfaces.
### BYOVD

WDAC’s enforcement decisions ultimately depend on kernel-mode code integrity. The relevant enforcement state lives in the kernel, inside `CI.dll`, in the structure commonly referred to as `g_CiOptions`.

From user mode, you cannot simply modify those values. You need kernel read/write access.

That is where BYOVD comes in.

The idea is to load a legitimate, signed, but vulnerable driver that KMCI still accepts. Once loaded, the driver’s vulnerability can provide a kernel primitive such as arbitrary read/write, physical memory access, or model-specific register access. With that primitive, attackers have historically attempted to tamper with code integrity state, load unsigned kernel modules, interfere with EDR callbacks, or perform other actions that require kernel-level control.

This is not a standard-user technique. Loading a driver requires administrative privileges and `SeLoadDriverPrivilege`.

So in practical terms, BYOVD means:

> “I already have admin, but kernel-mode code integrity or EDR is still blocking what I want to do next.”

The main public reference point for this ecosystem is **LOLDrivers**, originally started by Michael Haag, Jose Hernandez, and Olaf Hartong in 2022. It tracks vulnerable and malicious driver abuse data useful to both red and blue teams.

For each entry, the project commonly records details such as:

- SHA256 and Authentihash values,
- original filenames and observed renamed copies,
- signing chains,
- vulnerability category,
- MITRE ATT&CK mapping,
- and detection content such as YARA, Sigma, KQL, and Splunk SPL.

That makes LOLDrivers one of the rare community projects that genuinely helps both sides: defenders use it to block and detect known-bad drivers, while red teams use it to understand which drivers are still relevant in specific environments.

Some recurring drivers seen in public reporting and incident response include:

| Driver | Vendor | Capability | Status |
|---|---|---|---|
| RTCore64.sys | MSI Afterburner | Arbitrary MSR + kernel R/W | Blocked. Renames everywhere |
| gdrv.sys | Gigabyte | Phys mem R/W | Blocked. Featured in Robbinhood / Baltimore |
| AsrDrv101.sys / AsIO3.sys | ASRock / Asus | Phys mem R/W | Partial, vendors keep shipping new versions |
| iqvw64e.sys | Intel | Arbitrary kernel R/W | Blocked. KDMapper still uses it |
| ene.sys | ENE RGB | Phys mem R/W | Added 2024, present on lots of gaming laptops |

The major wall in 2026 is **HVCI**.

When Memory Integrity is enabled, the kernel pages backing sensitive code integrity structures are protected through virtualization-based security. Even with a kernel write primitive, attempts to modify protected regions can trap into the hypervisor rather than succeeding normally.

That breaks a large amount of public BYOVD tooling.

In other words, the older model of “load a vulnerable driver, get kernel R/W, patch CI, win” is no longer reliable on properly configured modern Windows systems. Against HVCI, the realistic path moves toward hypervisor-level vulnerabilities, which is far beyond normal red team tradecraft and closer to nation-state capability.

A few practical engagement notes:

- Microsoft’s Vulnerable Driver Blocklist is separate from the broader recommended WDAC block rules. Some organizations deploy one but not the other.
- Driver load activity generates Code Integrity telemetry, including events such as **3023** and **3024** under `Microsoft-Windows-CodeIntegrity/Operational`.
- EDR products commonly match against LOLDrivers hashes, Authentihashes, filenames, and driver load behaviour.
- Always verify whether the driver still works on the target Windows build. Kernel structures and mitigation behaviour change between major Windows releases.

## V. Detections

| Technique | Primary signal | Hardness to evade |
|---|---|---|
| InstallUtil `/U` | `installutil.exe` spawning child processes, suspicious .NET assembly loads | Easy to detect, hard to evade |
| MSBuild inline task | `msbuild.exe` outside normal developer workflow, inline C# compilation, .NET JIT telemetry | Easy to detect, hard to evade |
| DLL hijack (phantom) | Unsigned DLL load from user-writable path | Medium, depends heavily on the parent EXE |
| DLL hijack (proxy sideload) | Legitimate signed app loading unexpected or unsigned DLLs | Medium-high |
| Electron `--inspect` | Suspicious Electron command-line flags | Low-medium, depends on CLI visibility |
| `ELECTRON_RUN_AS_NODE` | Environment variable present on Electron process | High, many EDRs expose CLI better than env vars |
| Electron ASAR tamper | `app.asar` modification timestamps, integrity-fuse failures | High, rarely monitored |
| Managed Installer abuse | Unexpected SCCM/Intune package behaviour or trusted-package drift | Very high, difficult to baseline correctly |
| ISG reputation abuse | Newly introduced binaries allowed through cloud reputation | Very high, blends into legitimate software reputation |
| Supplemental policy abuse | WDAC policy refresh event `3099` | High, few SOCs monitor policy lifecycle events |
| BYOVD driver load | New kernel driver load, LOLDrivers hash matches, Code Integrity events | Easy to detect on modern EDR stacks |
| BYOVD CI tampering | Attempts to modify `CI.dll` structures or kernel protections | Easy on mature EDR-protected systems |
| PowerShell v2 downgrade | `-Version 2` visible in command line | Very easy to detect |
The pattern across all of these is consistent:

- Older LOLBin execution paths are usually high-confidence detections now.
- Trust-boundary abuse tends to be quieter than direct execution abuse.
- Most organizations monitor enforcement failures better than they monitor trust inheritance or policy changes.
- Kernel-level abuse has become significantly harder to hide after widespread adoption of vulnerable-driver blocklists and HVCI.

In practice, the quieter techniques in 2026 are usually the ones that blend into legitimate operational workflows:

- software deployment,
- trusted runtimes,
- developer tooling,
- or existing enterprise applications.

That is where most of the remaining attack surface still lives.

## VI. Real-world context

None of these techniques are theoretical. Variations of the same primitives continue to appear in real intrusions because they abuse trusted execution paths rather than exploiting the operating system itself.

Public reporting has repeatedly documented:

- FIN7 using `MSBuild` inline-task execution,
- Lazarus Group deploying signed .NET loaders and vulnerable drivers,
- BlackByte using BYOVD techniques to interfere with security tooling,
- and Raspberry Robin abusing trusted Windows components, installer chains, and DLL sideloading.

The common pattern across all of them is not zero-days or exotic malware. It is abusing trust relationships that already exist inside enterprise environments:

- trusted binaries,
- signed software,
- deployment tooling,
- and operational exceptions created for usability.

That is why application control remains difficult to deploy correctly even in 2026.

## VII. Defensive notes

What actually makes a Windows target expensive for an operator, roughly in order of impact:

1. **Strong WDAC policy design and supplemental-policy hygiene**  
    Keep supplemental-policy trust tightly scoped to dedicated internal signing infrastructure. Avoid broad commercial CA trust where possible, and monitor WDAC policy lifecycle events such as `3099`.
2. **HVCI, Secure Boot, and the Microsoft Vulnerable Driver Blocklist**  
    This combination removes most practical BYOVD tradecraft from the table. Public vulnerable-driver tooling becomes unreliable very quickly once Memory Integrity is consistently enforced.
3. **Microsoft Recommended Block Rules combined with DLL enforcement**  
    DLL enforcement has operational overhead, but it closes a large amount of practical sideloading and proxy-DLL abuse. Many organizations enable executable enforcement while leaving DLL loading largely unprotected.
4. **Constrained Language Mode, PowerShell v2 removal, and signed-module auditing**  
    CLM alone is not enough. Removing legacy PowerShell engines and auditing trusted signed modules significantly reduces the amount of public PowerShell tradecraft that still works reliably.
5. **Inventory and monitor Electron applications**  
    Electron apps effectively ship trusted JavaScript runtimes into enterprise environments. Baseline `app.asar` integrity where possible, review preload scripts, and restrict dangerous execution modes such as `ELECTRON_RUN_AS_NODE` if the platform supports environment-variable policy enforcement.
6. **Prioritize behavioural detection over pure allowlisting**  
    AppLocker and WDAC define what _may_ execute. EDR telemetry, ETW, command-line visibility, process lineage, module loads, and behavioural analytics reveal what is _actually happening_. Modern operators usually fail at the behavioural layer, not the policy layer.
7. **Treat enforcement and policy-change events as high-signal telemetry**  
    Events such as:
    
    - `8004` (AppLocker block),
    - `3077` (WDAC enforcement block),
    - and `3099` (policy refresh / supplemental load)
    
    should receive the same operational attention as other high-confidence security signals. They often indicate either active intrusion activity or policy tampering attempts.

## VIII. Closing

A few things remain true regardless of which technique is popular.

First, WDAC genuinely reduces attack surface. Properly deployed UMCI and HVCI force operators into a much narrower set of options than older AppLocker-only environments. It is one of the few Windows hardening controls that consistently changes attacker behaviour in practice.

Second, trusted execution remains the weak point. Almost every technique in this article works by abusing something the policy already trusts:

- signed software,
- deployment tooling,
- trusted runtimes,
- or operational exceptions created for usability.

The pattern changes less than the tooling does.

Finally, modern detection is mostly behavioural. The interesting question is no longer “can this execute?” but “what telemetry does it generate, and does anyone monitor it?”

The best way to answer that is not reading another bypass blog. It is building a small lab with your own WDAC policy, testing a few realistic techniques, and validating whether your detections actually fire. That exercise usually reveals more than the policy itself.

### References

- [LOLBAS](https://lolbas-project.github.io) and [LOLDrivers](https://loldrivers.io).
- [Microsoft WDAC documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/), policy authoring, recommended block list, MI / ISG / supplementals.
- [Microsoft Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules), separate from the user-mode block list.
- Matt Graeber, Bohops, Olaf Hartong, NetSPI for WDAC research.
- Casey Smith for the original AppLocker LOLBin posts.