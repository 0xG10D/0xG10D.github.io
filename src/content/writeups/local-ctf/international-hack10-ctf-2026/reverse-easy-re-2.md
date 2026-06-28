---
title: "Easy RE 2"
summary: "International HACK@10 CTF 2026 hack10, forensics, reverse engineering writeup covering Easy RE 2 with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - hack10
  - forensics
  - reverse-engineering
  - malware-analysis
  - cryptography
  - binary-exploitation
  - mobile
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://instagram.fkul11-2.fna.fbcdn.net/v/t51.82787-19/641307447_17850468132650020_693182401274637569_n.jpg?stp=dst-jpg_s150x150_tt6&efg=eyJ2ZW5jb2RlX3RhZyI6InByb2ZpbGVfcGljLmRqYW5nby4xMDgwLmMyIn0&_nc_ht=instagram.fkul11-2.fna.fbcdn.net&_nc_cat=104&_nc_oc=Q6cZ2gGY8elv-2_ffeNAnV1zev1x6qjeFXKSTkqJPt8hLvpW4r7SjGcF8yWitQhjEUVMFOlCO1QdwosRBu2_nqdaMwi1&_nc_ohc=V5UmcoEFIBIQ7kNvwH4oZxS&_nc_gid=nKZjHtkfrQHa4bxkteBcUA&edm=APoiHPcBAAAA&ccb=7-5&oh=00_Af_eyJvKyalWBh43tjTkFFQWtcGJPfalqqEqSEqMK-rTpQ&oe=6A3A2E75&_nc_sid=22de04"
---
# Challenge Overview

Challenge Name: Easy RE 2
Category: Reverse Engineering
Points: 493
Flag Format: `hack10{...}`

The challenge provided an Android APK and related extracted files. The goal was to reverse the challenge assets and recover the hidden flag.

The important provided files were:

```text
chall.apk
background.txt
background.bkp
background.txt.decrypted.dex
image_check.py
```

The final flag was hidden inside an encrypted image asset.

# Initial Analysis

The challenge looked like a simple reverse engineering warm-up. Instead of complex binary exploitation, the key observation was that the provided files included suspicious background-related assets:

```text
background.txt
background.bkp
```

A helper script, `image_check.py`, also showed that the challenge likely involved XOR-based image recovery. The script checked whether XORing file bytes could produce valid image headers such as PNG or JPG.

Important image headers:

```text
JPG: ff d8 ff
PNG: 89 50 4e 47 0d 0a 1a 0a
```

Since `background.bkp` did not open normally as an image, it was likely encrypted or obfuscated.

# Vulnerability / Weakness Identification

The weakness was weak single-byte XOR encryption.

The file `background.bkp` was not strongly encrypted. Every byte was XORed with the same key:

```text
0xEF
```

Single-byte XOR is trivial to brute-force because there are only 256 possible keys.

Once the correct key is used, the decrypted output starts with a valid JPG header:

```text
ff d8 ff
```

# Exploitation Strategy

The solving plan:

1. Read the suspicious files as raw bytes.

2. Try every possible single-byte XOR key from `0x00` to `0xFF`.

3. XOR the file content with each key.

4. Check whether the decrypted result starts with a known image header.

5. Save the valid recovered image.

6. Open the recovered image and read the flag visually.


This works because image formats have predictable magic bytes at the beginning of the file.

# Proof of Concept

Minimal proof of concept:

```bash
python3 - <<'PY'
data = open("background.bkp", "rb").read()
decoded = bytes(b ^ 0xEF for b in data)
open("recovered.jpg", "wb").write(decoded)
print("[+] Wrote recovered.jpg")
PY

file recovered.jpg
```

Expected output:

```text
[+] Wrote recovered.jpg
recovered.jpg: JPEG image data
```

Then open the recovered image:

```bash
xdg-open recovered.jpg
```

# Full Python Solver

```python
#!/usr/bin/env python3
from pathlib import Path

# Files to test
INPUT_FILES = [
    "background.bkp",
    "background.txt",
]

# Common image magic headers
MAGIC_HEADERS = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"BM": "bmp",
}


def detect_file_type(data: bytes):
    """
    Check whether decrypted data starts with a known image header.
    """
    for magic, extension in MAGIC_HEADERS.items():
        if data.startswith(magic):
            return extension
    return None


def xor_single_byte(data: bytes, key: int) -> bytes:
    """
    XOR every byte with a single-byte key.
    """
    return bytes(byte ^ key for byte in data)


def brute_force_xor(filename: str):
    """
    Try all possible single-byte XOR keys against a file.
    Save the file if a valid image header is found.
    """
    path = Path(filename)

    if not path.exists():
        print(f"[-] File not found: {filename}")
        return False

    data = path.read_bytes()
    print(f"[*] Testing {filename} ({len(data)} bytes)")

    for key in range(256):
        decrypted = xor_single_byte(data, key)
        extension = detect_file_type(decrypted)

        if extension:
            output_name = f"{path.stem}_xor_{key:02x}.{extension}"
            Path(output_name).write_bytes(decrypted)

            print(f"[+] Valid {extension.upper()} found")
            print(f"[+] Source file : {filename}")
            print(f"[+] XOR key     : 0x{key:02X}")
            print(f"[+] Saved as    : {output_name}")
            return True

    print(f"[-] No valid image found in {filename}")
    return False


def main():
    found = False

    for filename in INPUT_FILES:
        if brute_force_xor(filename):
            found = True

    if not found:
        print("[-] No encrypted image recovered.")
        return

    print("\n[+] Open the recovered image to read the flag.")
    print("[+] Useful result for this challenge: background.bkp XOR 0xEF")


if __name__ == "__main__":
    main()
```

# Walkthrough

Save the solver:

```bash
nano solve.py
```

Run it:

```bash
python3 solve.py
```

Expected output:

```text
[*] Testing background.bkp (...)
[+] Valid JPG found
[+] Source file : background.bkp
[+] XOR key     : 0xEF
[+] Saved as    : background_xor_ef.jpg
```

Verify the recovered file:

```bash
file background_xor_ef.jpg
```

Expected result:

```text
background_xor_ef.jpg: JPEG image data
```

Open it:

```bash
xdg-open background_xor_ef.jpg
```

Troubleshooting:

```bash
ls -lah
```

Make sure these files are in the same folder:

```text
solve.py
background.bkp
background.txt
```

No external Python packages are required.

# Flag

The recovered image reveals the flag:

```text
hack10{minato_namikaze}
```

# Conclusion

The challenge used weak XOR obfuscation to hide an image inside `background.bkp`. Because the same single-byte key was reused for the whole file, the key space was only 256 possibilities.

The key lesson is that file magic bytes are powerful indicators during reverse engineering and forensics. When a suspicious file does not open normally, checking for XOR-obfuscated headers is a fast and reliable first step.
