---
slug: "international-ctf/cybergame-sk/lesser-less"
event: "cybergame-sk"
title: "Lesser Less"
summary: "CyberGame.SK cybergame sk, forensics, reverse engineering writeup covering Lesser Less with analysis, solution steps, and final recovery notes."
date: 2026-05-02
tags:
  - ctf
  - cybergame-sk
  - forensics
  - reverse-engineering
  - malware-analysis
  - boot2root
category: "international-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://scontent.fkul11-2.fna.fbcdn.net/v/t39.30808-1/638315334_912211214722245_1753300060671872827_n.jpg?stp=dst-jpg_tt6&cstp=mx180x180&ctp=s180x180&_nc_cat=105&ccb=1-7&_nc_sid=2d3e12&_nc_ohc=tmZZ3tgT6bwQ7kNvwGoDB83&_nc_oc=AdoJZqRKxReRj76CRTP46td-B7AaAkrMrDS2ghidHSGCPZQNz6wXSKnMjvyeQ-UJgSHUwYcx5DrUHcoHmVsz8zFB&_nc_zt=24&_nc_ht=scontent.fkul11-2.fna&_nc_gid=y1Q08Jq9DhDlqGjKjQUDEg&_nc_ss=7b289&oh=00_Af_Ow3s347ZkjkRHjGV77tVd8INvQ45jyBC3iw6yTuzRqA&oe=6A3ACF21"
---
## 1. Challenge Overview

**Challenge Name:** Lesser less
**Points:** 471
**Category:** Reverse Engineering / Binary Analysis
**Provided File:** `less`

The challenge gives a lightweight version of the Linux `less` command. At first glance, it behaves like a terminal pager, but analysis shows that it contains hidden functionality that reconstructs and executes a secret command.

The goal is to reverse the binary logic and recover the hidden flag.

---

## 2. Reconnaissance and Initial Observations

First, inspect the file type:

```bash
file less
```

Output:

```bash
less: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

Important details:

```text
64-bit ELF binary
PIE enabled
Dynamically linked
Not stripped
```

Because the binary is **not stripped**, function names are still available.

Check symbols:

```bash
nm -C less | grep -E "decode|execute|sha|TARGET|main"
```

Interesting output:

```text
0000000000007020 d TARGET_HASHES
00000000000039de T decode_phrase_from_file
0000000000003be8 T execute_phrase_command
0000000000003c1f T main
00000000000036f1 t sha256_hex
```

This immediately reveals suspicious logic:

```text
decode_phrase_from_file()
execute_phrase_command()
TARGET_HASHES
sha256_hex()
system()
```

Check strings:

```bash
strings -a less | grep -E "^[0-9a-f]{64}$"
```

There are exactly **40 SHA-256 hashes** inside the binary.

---

## 3. Technical Analysis

The binary behaves like a fake `less` clone, but before entering pager mode, it performs hidden decoding.

The important function is:

```c
decode_phrase_from_file(filename, output_buffer, output_size);
```

From disassembly, the logic is:

```c
for each target_hash in TARGET_HASHES:
    for each adjacent 2-byte chunk in input_file:
        hash = sha256(chunk)

        if hash == target_hash:
            append those 2 bytes into output_buffer
            break
```

Then the decoded phrase is passed into:

```c
execute_phrase_command(output_buffer);
```

The `execute_phrase_command()` function does this:

```c
system(output_buffer);
```

So the binary:

1. Reads the user-provided file.

2. Searches for 40 required 2-byte chunks.

3. Reconstructs an 80-byte shell command.

4. Executes that command using `system()`.


The hidden command is not stored directly in plaintext. Instead, each 2-byte block is protected by SHA-256.

However, this is weak because each unknown block is only 2 bytes.

Total brute-force space:

```text
2 bytes = 16 bits = 65536 possibilities
```

So every hash can be cracked instantly offline.

---

## 4. Root Cause / Vulnerability

The main weakness is **weak hash-based obfuscation**.

The binary uses SHA-256, but only hashes **2-byte chunks**. SHA-256 itself is not broken, but the input space is tiny.

This means the attacker can brute-force every possible 2-byte value:

```text
00 00
00 01
00 02
...
ff ff
```

For each pair, compute SHA-256 and compare it with the target hashes.

The second issue is the use of:

```c
system(decoded_phrase);
```

This creates a hidden command execution path. In this challenge, the command contains the flag inside a shell comment.

---

## 5. Exploitation Plan

The exploitation strategy is:

1. Extract all 64-character SHA-256 hashes from the binary.

2. Generate all possible 2-byte values.

3. Compute SHA-256 for each 2-byte value.

4. Match each target hash to its original 2-byte plaintext.

5. Rebuild the hidden command in order.

6. Extract the flag from the recovered command.


No memory corruption is needed. This is a pure reverse-engineering and brute-force recovery challenge.

---

## 6. Proof of Concept

A minimal proof is to brute-force one hash:

```python
import hashlib

target = "1eb85f4d6a3234ce7acb8c51c75930f12e952517e2e389914a6ca8f89a881a0d"

for i in range(65536):
    pair = i.to_bytes(2, "big")
    if hashlib.sha256(pair).hexdigest() == target:
        print(pair)
        break
```

This proves the hashes are reversible because the original input space is only 2 bytes.

After cracking all 40 hashes, the recovered command is:

```bash
echo 'where is the flag?' > flag.txt # SK-CERT{l99k1n6_f0r_h1dd3n_func710n4l17y}
```

The flag is hidden after `#`, which makes it a shell comment.

---

## 7. Full Python Exploit / Solver

Save this as `solve.py`:

```python
#!/usr/bin/env python3
import hashlib
import re
import sys
from pathlib import Path


def extract_hashes(binary_data: bytes) -> list[str]:
    """
    Extract 64-character lowercase hexadecimal SHA-256 strings from the binary.
    Duplicates are removed while preserving order.
    """
    raw_hashes = re.findall(rb"[0-9a-f]{64}", binary_data)

    hashes = []
    seen = set()

    for h in raw_hashes:
        decoded = h.decode()

        if decoded not in seen:
            seen.add(decoded)
            hashes.append(decoded)

    return hashes


def build_sha256_lookup() -> dict[str, bytes]:
    """
    Build a lookup table of:
        sha256(two_bytes) -> original two_bytes

    Since the input size is only 2 bytes, there are only 65536 possibilities.
    """
    lookup = {}

    for value in range(65536):
        pair = value.to_bytes(2, "big")
        digest = hashlib.sha256(pair).hexdigest()
        lookup[digest] = pair

    return lookup


def recover_command(target_hashes: list[str], lookup: dict[str, bytes]) -> bytes:
    """
    Recover the hidden command by resolving each target SHA-256 hash
    back to its original 2-byte chunk.
    """
    recovered = b""

    for index, target_hash in enumerate(target_hashes):
        if target_hash not in lookup:
            raise ValueError(f"Could not recover hash #{index}: {target_hash}")

        recovered += lookup[target_hash]

    return recovered


def extract_flag(command: bytes) -> str | None:
    """
    Extract the SK-CERT flag from the recovered command.
    """
    match = re.search(rb"SK-CERT\{[^}]+\}", command)

    if not match:
        return None

    return match.group().decode(errors="replace")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} ./less")
        sys.exit(1)

    binary_path = Path(sys.argv[1])

    if not binary_path.exists():
        print(f"[-] File not found: {binary_path}")
        sys.exit(1)

    binary_data = binary_path.read_bytes()

    print("[+] Extracting SHA-256 hashes from binary...")
    target_hashes = extract_hashes(binary_data)

    if not target_hashes:
        print("[-] No SHA-256 hashes found.")
        sys.exit(1)

    print(f"[+] Found {len(target_hashes)} unique SHA-256 hashes")

    print("[+] Building 2-byte SHA-256 lookup table...")
    lookup = build_sha256_lookup()

    print("[+] Recovering hidden command...")
    command = recover_command(target_hashes, lookup)

    print("\n[+] Recovered command:")
    print(command.decode(errors="replace"))

    flag = extract_flag(command)

    if flag:
        print("\n[+] Flag recovered:")
        print(flag)
    else:
        print("\n[-] Flag pattern was not found in the recovered command.")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 8. Running the Solver

No external Python packages are required.

```bash
python3 solve.py ./less
```

Expected output:

```text
[+] Extracting SHA-256 hashes from binary...
[+] Found 40 unique SHA-256 hashes
[+] Building 2-byte SHA-256 lookup table...
[+] Recovering hidden command...

[+] Recovered command:
echo 'where is the flag?' > flag.txt # SK-CERT{l99k1n6_f0r_h1dd3n_func710n4l17y}

[+] Flag recovered:
SK-CERT{l99k1n6_f0r_h1dd3n_func710n4l17y}
```

---

## 9. Commands to Reproduce

Full command sequence:

```bash
chmod +x less

file less

nm -C less | grep -E "decode|execute|sha|TARGET|main"

strings -a less | grep -E "^[0-9a-f]{64}$"

python3 solve.py ./less
```

Optional proof that the binary executes the decoded command:

```bash
python3 - <<'PY'
cmd = b"echo 'where is the flag?' > flag.txt # SK-CERT{l99k1n6_f0r_h1dd3n_func710n4l17y}"
open("trigger.txt", "wb").write(cmd)
PY

./less trigger.txt
cat flag.txt
```

Output:

```text
where is the flag?
```

The flag does not appear in `flag.txt` because it is placed after `#`, making it a shell comment.

---

## 10. Final Flag Extraction Explanation

The binary hides a shell command by splitting it into 40 two-byte chunks and storing only the SHA-256 hash of each chunk.

Because each chunk is only 2 bytes, we can brute-force every possible chunk and reconstruct the full command.

Recovered command:

```bash
echo 'where is the flag?' > flag.txt # SK-CERT{l99k1n6_f0r_h1dd3n_func710n4l17y}
```

The shell ignores everything after `#`, but the flag is still visible in the recovered command.

Final flag:

```text
SK-CERT{l99k1n6_f0r_h1dd3n_func710n4l17y}
```
