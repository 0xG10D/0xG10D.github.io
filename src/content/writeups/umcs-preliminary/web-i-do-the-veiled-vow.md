---
slug: "local-ctf/umcs-preliminary/web-i-do-the-veiled-vow"
event: "umcs-preliminary"
title: "I DO: The Veiled Vow"
summary: "UMCS Preliminary umcs preliminary, web, forensics writeup covering I DO: The Veiled Vow with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - web
  - forensics
  - reverse-engineering
  - cryptography
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** I-DO: The Veiled Vow
**Category:** Web / Crypto
**Points:** 430
**Flag Format:** `UMCS{...}`
**Target:** Instance-hosted web service
**Recovered Flag:** `UMCS{e4ef8a5e-985f-400a-a54a-62b801fafa9a}`

The challenge presented an OmniCorp wedding-themed employee portal. Standard users could view a public memo, while VIP users were supposed to receive access to an encrypted archive. The goal was to bypass the guest-list restriction, obtain the VIP archive, decrypt it, and recover the flag.

The public page exposed a memo at:

```text
/public/invite.txt
```

The memo contained:

```text
You are cordially invited to the wedding of the OmniCorp CEO.
Date: November 15
Venue: OmniCorp Grand Ballroom
Dress Code: Strictly Black Tie
```

During exploitation, an IDOR was found. Changing the object identifier to `0` allowed access to the VIP archive, named:

```text
vip_invite.zip
```

The final archive decryption and flag extraction were confirmed from the terminal output.

# Initial Analysis

The first step was to inspect the exposed web service.

```bash
BASE="http://e8ebae1c-b4e8-45a0-b8e2-354d4b0c9571.chal.umcybersec.site:8001"

curl -i "$BASE/"
curl -i "$BASE/login"
curl -i "$BASE/public/invite.txt"
curl -i "$BASE/robots.txt"
curl -i "$BASE/sitemap.xml"
```

The root page returned a wedding-themed HTML page with links to:

```text
/login
/public/invite.txt
```

The `/login` page contained a simple username/password form:

```html
<form method="POST">
    <input type="text" name="user">
    <input type="password" name="pass">
</form>
```

The public memo was accessible without authentication and had a content length of `141` bytes. The service also revealed a Werkzeug/Python backend from the HTTP headers. Several guessed VIP/archive/download paths returned `404`, including `/vip`, `/archive`, `/download`, and `/public/vip.zip`.

After further testing, the important discovery was that changing an IDOR-controlled identifier to `0` returned the VIP archive:

```text
vip_invite.zip
```

The ZIP file was inspected:

```bash
zipinfo vip_invite.zip
file vip_invite.zip
```

Output:

```text
Archive:  vip_invite.zip
Zip file size: 554 bytes, number of entries: 2
-rw-r--r--  3.0 unx      141 BX stor 26-Apr-25 10:55 invite.txt
-rw-r--r--  3.0 unx       43 BX stor 26-Apr-25 10:55 flag.txt
2 files, 184 bytes uncompressed, 184 bytes compressed:  0.0%

vip_invite.zip: Zip archive data
```

Important observations:

```text
File 1: invite.txt
Size:   141 bytes
Method: Store

File 2: flag.txt
Size:   43 bytes
Method: Store
```

The `Store` compression method means the files were not compressed before encryption. This is critical because the plaintext of `invite.txt` was already publicly known from `/public/invite.txt`.

# Vulnerability / Weakness Identification

The challenge relied on two weaknesses.

## 1. Insecure Direct Object Reference

The web application exposed a user-controllable object identifier. By changing the identifier to `0`, the application returned a VIP-only archive.

This is an IDOR because authorization was not properly enforced on the server side. The application trusted the requested object identifier instead of checking whether the current user was allowed to access that object.

Conceptually, the vulnerable behavior was:

```text
Normal guest object  -> public/standard data
Object changed to 0  -> VIP archive returned
```

## 2. Weak ZIP Encryption with Known Plaintext

The archive used legacy ZipCrypto encryption. The encrypted ZIP contained:

```text
invite.txt
flag.txt
```

The plaintext of `invite.txt` was already known because the same invitation text was available publicly at `/public/invite.txt`.

Because the ZIP used `Store`, the plaintext did not need to be compressed before use in the attack. The exact public memo could be used directly as known plaintext.

This allows a known-plaintext attack against ZipCrypto. Once the internal ZipCrypto keys are recovered from `invite.txt`, the same keys can decrypt `flag.txt`.

# Exploitation Strategy

The complete strategy was:

1. Visit the public web page.

2. Read `/public/invite.txt`.

3. Identify the IDOR-controlled object identifier.

4. Change the identifier to `0`.

5. Download `vip_invite.zip`.

6. Inspect the ZIP archive.

7. Confirm that:

    - it uses ZipCrypto,

    - `invite.txt` is encrypted,

    - `invite.txt` is stored without compression,

    - public `invite.txt` and archive `invite.txt` are both 141 bytes.

8. Recreate the exact public memo locally as `known_invite.txt`.

9. Use `bkcrack` to recover ZipCrypto internal keys.

10. Use the recovered keys to decrypt the archive.

11. Extract `flag.txt`.

12. Read the flag.


The simplest reliable method is the ZipCrypto known-plaintext attack. Brute-forcing the ZIP password with `rockyou.txt` was attempted, but no password was recovered.

# Proof of Concept

## Step 1: Create the Known Plaintext

The public invitation was recreated exactly as a byte string:

```bash
python3 - << 'PY'
data = b"""You are cordially invited to the wedding of the OmniCorp CEO.
Date: November 15
Venue: OmniCorp Grand Ballroom
Dress Code: Strictly Black Tie"""
open("known_invite.txt", "wb").write(data)
print(len(data))
PY
```

Expected output:

```text
141
```

This length is important. It must match the encrypted `invite.txt` entry.

## Step 2: List the ZIP Entries

```bash
bkcrack -L vip_invite.zip
```

Output:

```text
Archive: vip_invite.zip
Index Encryption Compression CRC32    Uncompressed  Packed size Name
----- ---------- ----------- -------- ------------ ------------ ----------------
    0 ZipCrypto  Store       865a4329          141          153 invite.txt
    1 ZipCrypto  Store       25946cb8           43           55 flag.txt
```

This confirms:

```text
Encryption:  ZipCrypto
Compression: Store
Known file:  invite.txt
Target file: flag.txt
```

## Step 3: Recover ZipCrypto Keys

```bash
bkcrack -C vip_invite.zip -c invite.txt -p known_invite.txt
```

Output:

```text
Keys: 2eba9177 307b0708 7d6c750c
```

The recovered internal keys were:

```text
2eba9177 307b0708 7d6c750c
```

## Step 4: Decrypt the Archive

```bash
bkcrack -C vip_invite.zip \
-k 2eba9177 307b0708 7d6c750c \
-D unlocked.zip
```

Expected output:

```text
Writing decrypted archive unlocked.zip
100.0 % (2 / 2)
```

## Step 5: Extract the Flag

```bash
mkdir -p unlocked
unzip -o unlocked.zip -d unlocked
cat unlocked/flag.txt
```

Output:

```text
UMCS{e4ef8a5e-985f-400a-a54a-62b801fafa9a}
```

The successful recovery of the keys, decrypted archive, and final flag output are shown in the captured terminal output.

# Full Python Solver

The exact IDOR endpoint was instance-specific and was not preserved in the terminal log. Therefore, the solver supports two workflows:

1. Use a local `vip_invite.zip` that was already obtained through IDOR.

2. Download the archive from a supplied URL, such as the final IDOR URL with the identifier changed to `0`.


The solver automates the crypto portion using `bkcrack`.

```python
#!/usr/bin/env python3
"""
I-DO: The Veiled Vow Solver

This solver performs the offline ZipCrypto known-plaintext attack after the
VIP archive has been obtained through the IDOR vulnerability.

Usage:

    # If vip_invite.zip already exists locally:
    python3 solve.py --zip vip_invite.zip

    # If you know the final IDOR URL that returns the ZIP:
    python3 solve.py --url "http://target:8001/some/path?id=0"

Requirements:

    - Python 3
    - bkcrack installed and available in PATH
"""

import argparse
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from zipfile import ZipFile


KNOWN_INVITE = (
    b"You are cordially invited to the wedding of the OmniCorp CEO.\n"
    b"Date: November 15\n"
    b"Venue: OmniCorp Grand Ballroom\n"
    b"Dress Code: Strictly Black Tie"
)


def run_command(command, check=True):
    """
    Execute a system command and return its combined stdout/stderr output.
    """
    print(f"[+] Running: {' '.join(command)}")

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    if result.stdout:
        print(result.stdout)

    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed with exit code {result.returncode}: {' '.join(command)}"
        )

    return result.stdout


def require_tool(tool_name):
    """
    Ensure a required external binary exists.
    """
    if shutil.which(tool_name) is None:
        raise RuntimeError(
            f"Required tool '{tool_name}' was not found in PATH.\n"
            f"Install bkcrack first, then rerun this solver."
        )


def download_archive(url, output_path):
    """
    Download the ZIP archive from a provided URL.
    """
    print(f"[+] Downloading archive from: {url}")
    urllib.request.urlretrieve(url, output_path)

    if not output_path.exists() or output_path.stat().st_size == 0:
        raise RuntimeError("Downloaded archive is missing or empty.")

    print(f"[+] Archive saved to: {output_path}")


def prepare_archive(args, workdir):
    """
    Either copy a local ZIP file or download it from a supplied URL.
    """
    zip_path = workdir / "vip_invite.zip"

    if args.url:
        download_archive(args.url, zip_path)
    else:
        source = Path(args.zip)

        if not source.exists():
            raise FileNotFoundError(f"ZIP file not found: {source}")

        shutil.copyfile(source, zip_path)
        print(f"[+] Copied local archive to: {zip_path}")

    return zip_path


def write_known_plaintext(workdir):
    """
    Write the known plaintext invite text to disk.
    The content must match invite.txt byte-for-byte.
    """
    known_path = workdir / "known_invite.txt"
    known_path.write_bytes(KNOWN_INVITE)

    print(f"[+] Wrote known plaintext to: {known_path}")
    print(f"[+] Known plaintext length: {known_path.stat().st_size} bytes")

    if known_path.stat().st_size != 141:
        raise RuntimeError(
            "Known plaintext length is not 141 bytes. "
            "The text may not match the public invite exactly."
        )

    return known_path


def list_archive(zip_path):
    """
    List ZIP entries with bkcrack.
    """
    print("[+] Listing encrypted ZIP entries")
    return run_command(["bkcrack", "-L", str(zip_path)])


def recover_keys(zip_path, known_plaintext_path):
    """
    Recover ZipCrypto internal keys using known plaintext.
    """
    print("[+] Recovering ZipCrypto keys with known plaintext")

    output = run_command([
        "bkcrack",
        "-C", str(zip_path),
        "-c", "invite.txt",
        "-p", str(known_plaintext_path)
    ])

    match = re.search(
        r"Keys:\s*([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})",
        output
    )

    if not match:
        raise RuntimeError(
            "Could not parse keys from bkcrack output. "
            "Verify that known_invite.txt exactly matches invite.txt."
        )

    keys = match.groups()
    print(f"[+] Recovered keys: {' '.join(keys)}")

    return keys


def decrypt_archive(zip_path, keys, workdir):
    """
    Create a decrypted copy of the encrypted ZIP.
    """
    unlocked_zip = workdir / "unlocked.zip"

    print("[+] Decrypting ZIP archive")

    run_command([
        "bkcrack",
        "-C", str(zip_path),
        "-k", keys[0], keys[1], keys[2],
        "-D", str(unlocked_zip)
    ])

    if not unlocked_zip.exists():
        raise RuntimeError("Decrypted ZIP was not created.")

    print(f"[+] Decrypted archive written to: {unlocked_zip}")
    return unlocked_zip


def extract_flag(unlocked_zip, workdir):
    """
    Extract the decrypted archive and read flag.txt.
    """
    output_dir = workdir / "unlocked"
    output_dir.mkdir(exist_ok=True)

    print(f"[+] Extracting decrypted archive to: {output_dir}")

    with ZipFile(unlocked_zip, "r") as zip_file:
        zip_file.extractall(output_dir)

    flag_path = output_dir / "flag.txt"

    if not flag_path.exists():
        raise RuntimeError("flag.txt was not found in the decrypted archive.")

    flag = flag_path.read_text(errors="replace").strip()

    print(f"[+] Recovered flag: {flag}")

    return flag


def main():
    parser = argparse.ArgumentParser(
        description="Solver for I-DO: The Veiled Vow"
    )

    parser.add_argument(
        "--zip",
        help="Path to local vip_invite.zip"
    )

    parser.add_argument(
        "--url",
        help="Direct URL to download the VIP ZIP archive"
    )

    parser.add_argument(
        "--workdir",
        default="solve_output",
        help="Working directory for generated files"
    )

    args = parser.parse_args()

    if not args.zip and not args.url:
        print("[-] Provide either --zip vip_invite.zip or --url <IDOR ZIP URL>.")
        sys.exit(1)

    require_tool("bkcrack")

    workdir = Path(args.workdir)
    workdir.mkdir(exist_ok=True)

    zip_path = prepare_archive(args, workdir)
    known_plaintext_path = write_known_plaintext(workdir)

    list_archive(zip_path)

    keys = recover_keys(zip_path, known_plaintext_path)
    unlocked_zip = decrypt_archive(zip_path, keys, workdir)

    flag = extract_flag(unlocked_zip, workdir)

    if not flag.startswith("UMCS{"):
        print("[!] Warning: extracted output does not look like a UMCS flag.")

    print("[+] Solver completed successfully.")


if __name__ == "__main__":
    main()
```

# Walkthrough

## 1. Save the Solver

Save the script as:

```bash
solve.py
```

## 2. Install Dependencies

The script requires `bkcrack`.

On Kali, `bkcrack` may not be available through `apt`. Build it manually:

```bash
sudo apt update
sudo apt install -y git cmake build-essential

cd /opt
sudo git clone https://github.com/kimci86/bkcrack.git
sudo chown -R "$USER:$USER" bkcrack

cd /opt/bkcrack
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j"$(nproc)"
```

The correct binary path is:

```text
/opt/bkcrack/build/src/cli/bkcrack
```

Create a symlink:

```bash
sudo rm -f /usr/local/bin/bkcrack
sudo ln -sf /opt/bkcrack/build/src/cli/bkcrack /usr/local/bin/bkcrack
hash -r
bkcrack -h
```

This was necessary because `/opt/bkcrack/build/src/bkcrack` was a directory, not the executable. The working binary was confirmed at `/opt/bkcrack/build/src/cli/bkcrack`.

## 3. Obtain the ZIP Through IDOR

After identifying the vulnerable object identifier, change it to:

```text
0
```

Download the archive as:

```text
vip_invite.zip
```

The exact endpoint may vary by instance, so the command pattern is:

```bash
curl -o vip_invite.zip "http://TARGET/path/to/archive?id=0"
```

## 4. Run the Solver Locally

```bash
python3 solve.py --zip vip_invite.zip
```

Expected important output:

```text
[+] Known plaintext length: 141 bytes
[+] Recovered keys: 2eba9177 307b0708 7d6c750c
[+] Recovered flag: UMCS{e4ef8a5e-985f-400a-a54a-62b801fafa9a}
```

## 5. Alternative: Run Solver With Direct URL

If the direct IDOR URL is known:

```bash
python3 solve.py --url "http://TARGET/path/to/archive?id=0"
```

## Troubleshooting

If key recovery fails, verify the known plaintext size:

```bash
wc -c solve_output/known_invite.txt
```

Expected:

```text
141 solve_output/known_invite.txt
```

Do not create the plaintext using `echo`, because it can introduce extra newline characters.

If `bkcrack` is not found:

```bash
find /opt/bkcrack/build -type f -executable -name bkcrack -ls
```

Then symlink the actual executable:

```bash
sudo ln -sf /opt/bkcrack/build/src/cli/bkcrack /usr/local/bin/bkcrack
hash -r
```

# Flag

The flag was recovered from `flag.txt` after decrypting `vip_invite.zip`:

```text
UMCS{e4ef8a5e-985f-400a-a54a-62b801fafa9a}
```

# Conclusion

The challenge combined a web vulnerability with a cryptographic weakness.

The web issue was an **IDOR**, where changing a user-controlled identifier to `0` allowed access to the VIP archive. The cryptographic weakness was the use of legacy **ZipCrypto** encryption. Since the encrypted archive contained `invite.txt`, and the exact plaintext of that file was publicly available, a known-plaintext attack could recover the internal ZIP encryption keys.

The main lesson is that sensitive files must not be protected only by obscured identifiers or weak encryption. Server-side authorization must be enforced for every object, and legacy encryption schemes such as ZipCrypto should not be used for confidential data.
