---
slug: "local-ctf/umcs-preliminary/forensics-the-winning-shot"
event: "umcs-preliminary"
title: "The Winning Shot"
summary: "UMCS Preliminary umcs preliminary, forensics, reverse engineering writeup covering The Winning Shot with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - forensics
  - reverse-engineering
  - cryptography
  - boot2root
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** The Winning Shot
**Category:** Reverse Engineering / Forensics
**Points:** 390
**Flag Format:** `UMCS{}`
**Provided File:** `8_b411_p00l_1s_7un.zip`

The challenge provides a Linux executable, an image-like file named `pool`, and a Linux core dump. The story hints at reading a “table” and recovering a hidden “final move,” which maps well to memory forensics: the final secret is not directly printed, but it remains recoverable from process memory.

The goal is to analyze the executable behavior, identify where the encrypted flag is stored, recover the encryption key from the core dump, and decrypt the flag.

---

# Initial Analysis

First, extract the archive:

```bash
unzip 8_b411_p00l_1s_7un.zip
ls -lah
```

Expected files:

```text
pool
winning_shot
core.170390
```

Check file types:

```bash
file pool winning_shot core.170390
```

Output:

```text
pool:         JPEG image data, JFIF standard 1.01, 225x225
winning_shot: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
core.170390:  ELF 64-bit LSB core file, x86-64, from './winning_shot'
```

Important observations:

1. `pool` is a valid JPEG image, but it may contain appended data.

2. `winning_shot` is a 64-bit Linux ELF binary.

3. `core.170390` is a memory dump from running `./winning_shot`.


Running `strings` gives useful hints:

```bash
strings -a winning_shot | grep -E 'UMCS|CUE|WINSHOT|pool|urandom'
```

Notable strings:

```text
CUE_BALL_STATE_V1
/dev/urandom
pool
WINSHOT
[!] Shot taken. The Flag is cryptographically pocketed.
[!] Process PID: %d. Waiting in memory...
```

This tells us several things:

- The binary uses `/dev/urandom`, likely to generate a key.

- It writes to a file called `pool`.

- It uses a marker called `WINSHOT`.

- It stores some useful runtime state in memory using the marker `CUE_BALL_STATE_V1`.


Next, check where `WINSHOT` appears inside `pool`:

```bash
grep -abo 'WINSHOT' pool
```

Output:

```text
4842:WINSHOT
```

This means the JPEG has extra data appended at offset `4842`. Everything after `WINSHOT` is suspicious and likely encrypted.

---

# Vulnerability / Weakness Identification

The weakness is that the program encrypts the flag with a repeating XOR key, but the key remains recoverable from the provided core dump.

From disassembly of `winning_shot`, the program performs roughly this logic:

```c
key = malloc(0x3c);                    // 60-byte key
memcpy(key - 0x20, "CUE_BALL_STATE_V1", 0x11);
read(open("/dev/urandom"), key, 0x3c);

for (int i = 0; i <= 14; i++) {
    key[i * 4] = i + 1;
}

cipher[i] = flag[i] ^ key[i % 60];

fwrite("WINSHOT", 1, 7, pool);
fwrite(cipher, 1, flag_len, pool);
```

The key details are:

- The XOR key is 60 bytes long.

- It is generated using `/dev/urandom`.

- Every fourth byte is overwritten with a known pattern:


```text
key[0]  = 1
key[4]  = 2
key[8]  = 3
...
key[56] = 15
```

- The marker `CUE_BALL_STATE_V1` is written exactly `0x20` bytes before the key.

- The ciphertext is appended to `pool` after the marker `WINSHOT`.

- The program clears the flag and ciphertext from the stack, but it does not wipe the heap key.

- Because a core dump is provided, the heap memory still contains the key.


Therefore, the challenge is solvable by:

1. Extracting ciphertext from `pool`.

2. Searching the core dump for `CUE_BALL_STATE_V1`.

3. Reading 60 bytes at `marker_offset + 0x20`.

4. Validating the key using the known every-fourth-byte pattern.

5. XORing the ciphertext with the recovered key.


---

# Exploitation Strategy

The exploitation strategy is offline and does not require interacting with a remote service.

The plan:

1. Read `pool` as raw bytes.

2. Locate the marker:


```text
WINSHOT
```

3. Treat all bytes after `WINSHOT` as ciphertext.

4. Read `core.170390` as raw bytes.

5. Search for:


```text
CUE_BALL_STATE_V1
```

6. For every occurrence, extract 60 bytes starting `0x20` bytes after the marker.

7. Validate the key candidate using the known pattern:


```python
key[i * 4] == i + 1
```

for `i = 0` through `14`.

8. Decrypt:


```python
plaintext[i] = ciphertext[i] ^ key[i % len(key)]
```

9. Search decrypted plaintext for the flag format:


```text
UMCS{...}
```

This works because XOR encryption is reversible:

```text
cipher = plaintext XOR key
plaintext = cipher XOR key
```

So once the key is recovered from the core dump, decryption is immediate.

---

# Proof of Concept

Check the appended ciphertext location:

```bash
grep -abo 'WINSHOT' pool
```

Output:

```text
4842:WINSHOT
```

The marker length is 7 bytes:

```text
WINSHOT
```

So the ciphertext starts at:

```text
4842 + 7 = 4849
```

The file size is 4894 bytes, so the ciphertext length is:

```text
4894 - 4849 = 45 bytes
```

Now check the core dump for the heap marker:

```bash
grep -abo 'CUE_BALL_STATE_V1' core.170390
```

Output:

```text
5120:CUE_BALL_STATE_V1
14056:CUE_BALL_STATE_V1
```

There are two occurrences:

- One is likely from the binary’s string table or mapped read-only memory.

- One is the heap marker placed before the key.


The correct one is identified by checking the bytes at `marker + 0x20`. The valid key candidate must match:

```text
key[0]  = 0x01
key[4]  = 0x02
key[8]  = 0x03
...
key[56] = 0x0f
```

After extracting that key and XORing the ciphertext, the plaintext becomes:

```text
UMCS{k1n3t1c_3n3rgy_r3c0v3r3d_fr0m_c0r3_dump}
```

---

# Full Python Solver

```python
#!/usr/bin/env python3
from pathlib import Path
import argparse
import re
import sys


def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt repeating-key XOR.
    Since XOR is symmetric, encryption and decryption are the same operation.
    """
    return bytes(
        c ^ key[i % len(key)]
        for i, c in enumerate(ciphertext)
    )


def find_ciphertext(pool_data: bytes, marker: bytes = b"WINSHOT") -> bytes:
    """
    Locate the WINSHOT marker inside the pool file.
    Everything after this marker is treated as encrypted flag data.
    """
    offset = pool_data.find(marker)

    if offset == -1:
        raise ValueError("WINSHOT marker was not found in pool file")

    ciphertext_start = offset + len(marker)
    ciphertext = pool_data[ciphertext_start:]

    if not ciphertext:
        raise ValueError("WINSHOT marker found, but no ciphertext exists after it")

    print(f"[+] WINSHOT marker offset: {offset}")
    print(f"[+] Ciphertext offset     : {ciphertext_start}")
    print(f"[+] Ciphertext length     : {len(ciphertext)} bytes")

    return ciphertext


def is_valid_key_candidate(key: bytes) -> bool:
    """
    The binary overwrites every fourth byte of the 60-byte key:

        key[0]  = 1
        key[4]  = 2
        key[8]  = 3
        ...
        key[56] = 15

    This gives us a reliable way to identify the correct key in memory.
    """
    if len(key) != 60:
        return False

    for i in range(15):
        expected = i + 1
        actual = key[i * 4]

        if actual != expected:
            return False

    return True


def recover_keys_from_core(
    core_data: bytes,
    marker: bytes = b"CUE_BALL_STATE_V1",
    key_offset_from_marker: int = 0x20,
    key_length: int = 60,
) -> list[tuple[int, bytes]]:
    """
    Search the core dump for CUE_BALL_STATE_V1.

    The key is stored 0x20 bytes after this marker.
    Multiple marker occurrences may exist, so each candidate is validated.
    """
    candidates = []
    search_start = 0

    while True:
        marker_offset = core_data.find(marker, search_start)

        if marker_offset == -1:
            break

        key_start = marker_offset + key_offset_from_marker
        key_end = key_start + key_length
        key = core_data[key_start:key_end]

        print(f"[*] Found marker at core offset: {hex(marker_offset)}")

        if is_valid_key_candidate(key):
            print(f"[+] Valid key candidate at core offset: {hex(key_start)}")
            candidates.append((marker_offset, key))
        else:
            print("[-] Marker found, but nearby bytes do not match key pattern")

        search_start = marker_offset + 1

    return candidates


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Solve The Winning Shot CTF challenge by recovering XOR key from core dump."
    )

    parser.add_argument(
        "--pool",
        default="pool",
        help="Path to the pool file. Default: pool",
    )

    parser.add_argument(
        "--core",
        default="core.170390",
        help="Path to the core dump file. Default: core.170390",
    )

    args = parser.parse_args()

    pool_path = Path(args.pool)
    core_path = Path(args.core)

    if not pool_path.is_file():
        print(f"[-] Pool file not found: {pool_path}", file=sys.stderr)
        return 1

    if not core_path.is_file():
        print(f"[-] Core file not found: {core_path}", file=sys.stderr)
        return 1

    pool_data = pool_path.read_bytes()
    core_data = core_path.read_bytes()

    ciphertext = find_ciphertext(pool_data)
    key_candidates = recover_keys_from_core(core_data)

    if not key_candidates:
        print("[-] No valid key candidates found in core dump", file=sys.stderr)
        return 1

    for marker_offset, key in key_candidates:
        plaintext = xor_decrypt(ciphertext, key)

        print(f"[*] Trying key from marker offset {hex(marker_offset)}")
        print(f"[*] Plaintext preview: {plaintext!r}")

        match = re.search(rb"UMCS\{[^}]+\}", plaintext)

        if match:
            flag = match.group().decode(errors="replace")
            print(f"[+] FLAG: {flag}")
            return 0

    print("[-] Decryption completed, but no UMCS{} flag was found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

---

# Walkthrough

Save the script as:

```bash
solve_winning_shot.py
```

Make sure the extracted files are in the same directory:

```bash
ls
```

Expected:

```text
core.170390
pool
winning_shot
solve_winning_shot.py
```

Run the solver:

```bash
python3 solve_winning_shot.py
```

Expected output:

```text
[+] WINSHOT marker offset: 4842
[+] Ciphertext offset     : 4849
[+] Ciphertext length     : 45 bytes
[*] Found marker at core offset: 0x1400
[-] Marker found, but nearby bytes do not match key pattern
[*] Found marker at core offset: 0x36e8
[+] Valid key candidate at core offset: 0x3708
[*] Trying key from marker offset 0x36e8
[*] Plaintext preview: b'UMCS{k1n3t1c_3n3rgy_r3c0v3r3d_fr0m_c0r3_dump}'
[+] FLAG: UMCS{k1n3t1c_3n3rgy_r3c0v3r3d_fr0m_c0r3_dump}
```

No external Python libraries are required. The script only uses the Python standard library.

Troubleshooting:

If Python cannot find `pool` or `core.170390`, pass the paths manually:

```bash
python3 solve_winning_shot.py --pool ./pool --core ./core.170390
```

If the binary is not executable, the hint says to use:

```bash
chmod +x winning_shot
```

However, running the binary is not required for the final solve because the challenge already provides the useful core dump.

---

# Flag

The recovered flag is:

```text
UMCS{k1n3t1c_3n3rgy_r3c0v3r3d_fr0m_c0r3_dump}
```

---

# Conclusion

The challenge hides the flag by XOR-encrypting it and appending the ciphertext to a JPEG file after the marker `WINSHOT`. The intended weakness is poor secret handling: the encryption key remains in process memory and is recoverable from the provided core dump.

The key lesson is that encryption is only as strong as key protection. Even if plaintext is wiped after use, sensitive heap data such as encryption keys must also be securely cleared. In this case, the core dump preserved the XOR key, making the encrypted flag fully recoverable.
