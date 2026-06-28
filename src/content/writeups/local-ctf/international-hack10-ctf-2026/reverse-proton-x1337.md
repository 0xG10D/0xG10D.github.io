---
title: "Proton X1337"
summary: "International HACK@10 CTF 2026 hack10, forensics, reverse engineering writeup covering Proton X1337 with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - hack10
  - forensics
  - reverse-engineering
  - malware-analysis
  - binary-exploitation
  - mobile
  - network
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://instagram.fkul11-2.fna.fbcdn.net/v/t51.82787-19/641307447_17850468132650020_693182401274637569_n.jpg?stp=dst-jpg_s150x150_tt6&efg=eyJ2ZW5jb2RlX3RhZyI6InByb2ZpbGVfcGljLmRqYW5nby4xMDgwLmMyIn0&_nc_ht=instagram.fkul11-2.fna.fbcdn.net&_nc_cat=104&_nc_oc=Q6cZ2gGY8elv-2_ffeNAnV1zev1x6qjeFXKSTkqJPt8hLvpW4r7SjGcF8yWitQhjEUVMFOlCO1QdwosRBu2_nqdaMwi1&_nc_ohc=V5UmcoEFIBIQ7kNvwH4oZxS&_nc_gid=nKZjHtkfrQHa4bxkteBcUA&edm=APoiHPcBAAAA&ccb=7-5&oh=00_Af_eyJvKyalWBh43tjTkFFQWtcGJPfalqqEqSEqMK-rTpQ&oe=6A3A2E75&_nc_sid=22de04"
---
# Challenge Overview

**Challenge Name:** Proton X1337
**Category:** Reverse Engineering / Android Malware Analysis
**Points:** 500
**Flag Format:** `HACK10{}`
**Provided File:** `ProtonX1337.apk`
**Goal:** Reverse engineer the APK, identify the command-and-control server, and recover the real flag.

The challenge description states that the file appears normal and safe, but secretly transmits data to a C2 server. This indicates that the intended solution is not brute force or network scanning. The correct approach is static reverse engineering of the APK to identify suspicious code, extract the C2 endpoint, and inspect the server response.

---

# Initial Analysis

The provided file is an Android APK, so the first step is to identify its type and inspect its structure.

```bash
file ProtonX1337.apk
```

Expected output:

```text
ProtonX1337.apk: Android package (APK), with ...
```

A basic APK listing can be done with:

```bash
unzip -l ProtonX1337.apk | head
```

Since Android APKs usually store executable logic inside `classes.dex`, the next step is to inspect DEX strings:

```bash
unzip -p ProtonX1337.apk classes.dex | strings | grep -Ei 'HACK10|appsecmy|liga|telegram|tdata|backup|SESSION|http|post'
```

The important findings from reverse engineering were:

```text
Telegram Documents/tdata_backup.txt
SESSION_TOKEN=[REDACTED_TOKEN]
https://appsecmy.com/
pages/liga-ctf-2026
```

This shows two important things:

1. The APK creates a fake Telegram-related file path.

2. The APK contains a decoy flag-like token.

3. The APK contains a remote C2 destination.


To properly confirm the logic, the APK should be decompiled with JADX:

```bash
jadx -d jadx_out ProtonX1337.apk
```

Then search the decompiled source:

```bash
grep -RniE 'initializeMediaStorage|backdoorC2|appsecmy|liga-ctf|tdata_backup|SESSION_TOKEN|HACK10' jadx_out/
```

The decompiled code reveals a method named similar to:

```java
initializeMediaStorage()
```

This method creates a fake Telegram-like directory structure and writes a decoy token into:

```text
Telegram Documents/tdata_backup.txt
```

The decoy content is:

```text
SESSION_TOKEN=[REDACTED_TOKEN]
```

Another method, named similar to:

```java
backdoorC2()
```

reads that file, wraps the data into a JSON request, and sends it to the C2 server using an HTTP POST request with:

```text
Content-Type: application/json
```

The C2 endpoint is constructed from:

```text
https://appsecmy.com/
pages/liga-ctf-2026
```

So the final endpoint is:

```text
https://appsecmy.com/pages/liga-ctf-2026
```

---

# Vulnerability / Weakness Identification

The weakness is not a traditional software vulnerability. Instead, this challenge is solved through **static analysis of hardcoded malware indicators**.

The APK exposes the C2 configuration directly inside the application logic:

```text
https://appsecmy.com/pages/liga-ctf-2026
```

The APK also contains a misleading fake flag:

```text
HACK10{n0t_A_Fl4g}
```

This is intentionally placed to distract solvers. The real flag is not the local token inside the APK. The real flag is hidden on the C2 server.

The C2 page returns normal HTML content, but near the end of the HTML source there is an HTML comment containing the actual flag. The captured server response shows the page returning HTTP 200 and the flag placed in an HTML comment near the bottom of the response.

---

# Exploitation Strategy

The solving strategy is:

1. Confirm the file is an APK.

2. Extract strings from `classes.dex`.

3. Identify suspicious strings:

    - Telegram-like path

    - Decoy session token

    - C2 base URL

    - C2 path

4. Decompile with JADX to confirm behavior.

5. Reconstruct the full C2 URL.

6. Fetch the C2 page.

7. Search the HTML source for the real flag.

8. Ignore the decoy flag inside the APK.


No brute forcing is required. No scanning is required. The C2 address is already present in the APK.

---

# Proof of Concept

## Step 1: Extract suspicious strings from APK

```bash
unzip -p ProtonX1337.apk classes.dex | strings | grep -Ei 'HACK10|appsecmy|liga|telegram|tdata|backup|SESSION|http|post'
```

Expected important output:

```text
Telegram Documents/tdata_backup.txt
SESSION_TOKEN=[REDACTED_TOKEN]
https://appsecmy.com/
pages/liga-ctf-2026
```

The value below is a decoy:

```text
HACK10{n0t_A_Fl4g}
```

## Step 2: Reconstruct the C2 endpoint

Base URL:

```text
https://appsecmy.com/
```

Path:

```text
pages/liga-ctf-2026
```

Full C2 endpoint:

```text
https://appsecmy.com/pages/liga-ctf-2026
```

## Step 3: Fetch the C2 page

```bash
curl -i https://appsecmy.com/pages/liga-ctf-2026
```

The response returns:

```text
HTTP/2 200
content-type: text/html
```

This confirms that the endpoint is valid and reachable.

## Step 4: Extract the real flag

```bash
curl -s https://appsecmy.com/pages/liga-ctf-2026 | grep -o 'HACK10{[^}]*}'
```

Expected output:

```text
HACK10{j3mpu7_s3r74_0W4SP_C7F}
```

For stronger evidence, save the page and inspect the bottom of the HTML:

```bash
curl -s https://appsecmy.com/pages/liga-ctf-2026 > c2.html
tail -n 20 c2.html
```

Expected important output:

```html
<!-- HACK10{j3mpu7_s3r74_0W4SP_C7F} -->
```

---

# Full Python Solver

```python
#!/usr/bin/env python3
"""
Proton X1337 CTF Solver

This script solves the challenge by:
1. Optionally extracting suspicious strings from the APK.
2. Finding the C2 endpoint.
3. Fetching the C2 page.
4. Extracting the real HACK10{} flag.

Usage:
    python3 solve_proton_x1337.py ProtonX1337.apk

Alternative:
    python3 solve_proton_x1337.py --url https://appsecmy.com/pages/liga-ctf-2026

Offline HTML mode:
    python3 solve_proton_x1337.py --html c2.html
"""

import argparse
import re
import sys
import zipfile
import urllib.request
from pathlib import Path
from urllib.parse import urljoin


FLAG_RE = re.compile(r"HACK10\{[^}]+\}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


DECOY_FLAGS = {
    "HACK10{n0t_A_Fl4g}",
}


def extract_printable_strings_from_bytes(data: bytes) -> list[str]:
    """
    Extract ASCII printable strings from raw bytes.
    Similar idea to the Linux `strings` command.
    """
    results = []

    for match in PRINTABLE_RE.findall(data):
        try:
            results.append(match.decode("utf-8", errors="ignore"))
        except UnicodeDecodeError:
            continue

    return results


def extract_strings_from_apk(apk_path: Path) -> list[str]:
    """
    Read important files inside the APK and extract printable strings.
    Focuses mainly on .dex files because app logic is usually stored there.
    """
    all_strings = []

    with zipfile.ZipFile(apk_path, "r") as apk:
        for name in apk.namelist():
            lower_name = name.lower()

            # DEX contains compiled Android app code.
            # XML / JSON / TXT may contain useful config or metadata.
            interesting = (
                lower_name.endswith(".dex")
                or lower_name.endswith(".xml")
                or lower_name.endswith(".json")
                or lower_name.endswith(".txt")
                or lower_name.endswith(".properties")
            )

            if not interesting:
                continue

            try:
                data = apk.read(name)
            except Exception:
                continue

            extracted = extract_printable_strings_from_bytes(data)
            all_strings.extend(extracted)

    return all_strings


def find_c2_endpoint(strings: list[str]) -> str | None:
    """
    Attempt to reconstruct the C2 endpoint from extracted APK strings.

    In this challenge, the APK stores:
        base = https://appsecmy.com/
        path = pages/liga-ctf-2026
    """
    urls = []
    paths = []

    for s in strings:
        urls.extend(URL_RE.findall(s))

        if "liga-ctf-2026" in s:
            paths.append(s.strip())

    # Prefer the known suspicious domain from the challenge.
    base_url = None
    for url in urls:
        if "appsecmy.com" in url:
            base_url = url
            break

    # Find the path containing liga-ctf-2026.
    c2_path = None
    for p in paths:
        if "pages/liga-ctf-2026" in p:
            c2_path = "pages/liga-ctf-2026"
            break
        if "liga-ctf-2026" in p:
            c2_path = p
            break

    if base_url and c2_path:
        return urljoin(base_url, c2_path)

    # Fallback if the APK string extraction does not recover separated strings cleanly.
    if base_url and "liga-ctf-2026" in base_url:
        return base_url

    return None


def fetch_url(url: str, timeout: int = 15) -> str:
    """
    Fetch a URL using Python standard library.
    No external dependencies are required.
    """
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 CTF-Solver",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read()
        return data.decode("utf-8", errors="replace")


def extract_flags(text: str) -> list[str]:
    """
    Extract HACK10{} flags and remove known decoys.
    """
    found = FLAG_RE.findall(text)

    # Preserve order while removing duplicates.
    unique = []
    for flag in found:
        if flag not in unique:
            unique.append(flag)

    real_candidates = [flag for flag in unique if flag not in DECOY_FLAGS]
    return real_candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Solver for Proton X1337 CTF challenge")
    parser.add_argument(
        "apk",
        nargs="?",
        help="Path to ProtonX1337.apk",
    )
    parser.add_argument(
        "--url",
        help="C2 URL to fetch directly",
    )
    parser.add_argument(
        "--html",
        help="Offline mode: parse a saved C2 HTML file instead of fetching the URL",
    )

    args = parser.parse_args()

    c2_url = args.url

    if args.html:
        html_path = Path(args.html)

        if not html_path.exists():
            print(f"[-] HTML file not found: {html_path}")
            return 1

        print(f"[+] Reading offline HTML file: {html_path}")
        html = html_path.read_text(encoding="utf-8", errors="replace")

        flags = extract_flags(html)
        if flags:
            print("[+] Flag candidate(s) found:")
            for flag in flags:
                print(f"    {flag}")
            return 0

        print("[-] No real flag found in HTML file.")
        return 1

    if args.apk:
        apk_path = Path(args.apk)

        if not apk_path.exists():
            print(f"[-] APK file not found: {apk_path}")
            return 1

        print(f"[+] Extracting strings from APK: {apk_path}")
        apk_strings = extract_strings_from_apk(apk_path)

        interesting_keywords = [
            "HACK10",
            "appsecmy",
            "liga-ctf",
            "Telegram",
            "tdata",
            "SESSION_TOKEN",
        ]

        print("[+] Interesting strings:")
        for s in apk_strings:
            if any(keyword.lower() in s.lower() for keyword in interesting_keywords):
                print(f"    {s}")

        if not c2_url:
            c2_url = find_c2_endpoint(apk_strings)

    if not c2_url:
        # Known endpoint recovered from reverse engineering.
        # This fallback keeps the solver usable even if APK string extraction fails.
        c2_url = "https://appsecmy.com/pages/liga-ctf-2026"
        print("[!] C2 URL was not automatically recovered from APK strings.")
        print(f"[!] Using known reversed endpoint: {c2_url}")
    else:
        print(f"[+] Discovered C2 endpoint: {c2_url}")

    print(f"[+] Fetching C2 page: {c2_url}")

    try:
        html = fetch_url(c2_url)
    except Exception as error:
        print(f"[-] Failed to fetch C2 page: {error}")
        print("[*] Try saving the page manually and using:")
        print("    python3 solve_proton_x1337.py --html c2.html")
        return 1

    flags = extract_flags(html)

    if not flags:
        print("[-] No real flag found in C2 response.")
        print("[*] Try inspecting the response manually:")
        print(f"    curl -s {c2_url} | grep -i -C 3 'HACK10'")
        return 1

    print("[+] Flag candidate(s) found:")
    for flag in flags:
        print(f"    {flag}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

# Walkthrough

## 1. Prepare tools

On Kali Linux:

```bash
sudo apt update
sudo apt install jadx apktool unzip curl python3 -y
```

## 2. Confirm the APK type

```bash
file ProtonX1337.apk
```

## 3. Extract quick evidence from DEX strings

```bash
unzip -p ProtonX1337.apk classes.dex | strings | grep -Ei 'HACK10|appsecmy|liga|telegram|tdata|backup|SESSION|http|post'
```

This should reveal the fake Telegram path, the decoy flag, and the C2 endpoint components.

## 4. Decompiled source review

```bash
jadx -d jadx_out ProtonX1337.apk
```

Search suspicious logic:

```bash
grep -RniE 'initializeMediaStorage|backdoorC2|appsecmy|liga-ctf|tdata_backup|SESSION_TOKEN|HACK10' jadx_out/
```

The important methods are:

```text
initializeMediaStorage()
backdoorC2()
```

The first method creates the fake data file. The second method sends data to the C2.

## 5. Run the Python solver

Save the script as:

```bash
solve_proton_x1337.py
```

Run:

```bash
python3 solve_proton_x1337.py ProtonX1337.apk
```

Expected output:

```text
[+] Extracting strings from APK: ProtonX1337.apk
[+] Interesting strings:
    SESSION_TOKEN=[REDACTED_TOKEN]
    https://appsecmy.com/
    pages/liga-ctf-2026
[+] Discovered C2 endpoint: https://appsecmy.com/pages/liga-ctf-2026
[+] Fetching C2 page: https://appsecmy.com/pages/liga-ctf-2026
[+] Flag candidate(s) found:
    HACK10{j3mpu7_s3r74_0W4SP_C7F}
```

## 6. Alternative direct mode

Because the C2 URL is known after reverse engineering:

```bash
python3 solve_proton_x1337.py --url https://appsecmy.com/pages/liga-ctf-2026
```

## 7. Offline mode

Save the C2 response:

```bash
curl -s https://appsecmy.com/pages/liga-ctf-2026 > c2.html
```

Then parse it offline:

```bash
python3 solve_proton_x1337.py --html c2.html
```

## Troubleshooting

If `jadx` is not installed:

```bash
sudo apt install jadx -y
```

If the Python script cannot fetch the page, test manually:

```bash
curl -i https://appsecmy.com/pages/liga-ctf-2026
```

If the page is reachable but the script does not find the flag, inspect the bottom of the response:

```bash
curl -s https://appsecmy.com/pages/liga-ctf-2026 | tail -n 20
```

---

# Flag

The real flag is found in the C2 server HTML source as an HTML comment:

```html
<!-- HACK10{j3mpu7_s3r74_0W4SP_C7F} -->
```

Final flag:

```text
HACK10{j3mpu7_s3r74_0W4SP_C7F}
```

---

# Conclusion

The challenge is solved by reverse engineering the Android APK and identifying its hardcoded C2 behavior. The local flag-like value inside the APK is a decoy:

```text
HACK10{n0t_A_Fl4g}
```

The real objective is to trace the malware’s exfiltration endpoint:

```text
https://appsecmy.com/pages/liga-ctf-2026
```

After fetching the C2 page, the real flag is discovered in an HTML comment.

The key lesson is that malware analysis should not stop at obvious embedded strings. Decoy indicators are common. A proper workflow requires understanding the program logic, identifying network destinations, reconstructing endpoints, and validating the server-side response.
