---
title: "Varsity Lake Sonata"
summary: "UMCS Preliminary umcs preliminary, forensics, reverse engineering writeup covering Varsity Lake Sonata with analysis, solution steps, and final recovery notes."
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

**Challenge Name:** Varsity Lake Sonata
**Category:** Reverse Engineering
**Points:** 470
**Flag Format:** `UMCS{}`
**Provided File:** `Varsity_Lake_Sonata.bin`

The challenge provides a Linux binary. The goal is to reverse the binary, understand how it validates user input, and recover the correct flag.

The challenge description gives the hint:

> “The lake's surface can be deceiving. Dig deeper.”

This suggests that visible strings or surface-level analysis may be misleading. In this case, the binary contains fake flags and is packed, so the real validation logic must be recovered by unpacking and reversing the program.

Final recovered flag:

```text
UMCS{t4sik_v4rs1ty_pi4n0_x0r_m3l0dy}
```

---

# Initial Analysis

First, inspect the provided file.

```bash
file Varsity_Lake_Sonata.bin
```

Expected output:

```text
Varsity_Lake_Sonata.bin: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), statically linked, no section header
```

The binary is a 64-bit Linux ELF. The phrase `no section header` is suspicious because normal compiled binaries usually contain section headers. This often happens when a binary is packed or intentionally stripped to slow down reversing.

Next, check the hash for reference:

```bash
sha256sum Varsity_Lake_Sonata.bin
```

Observed hash:

```text
924784da843c6d8e4166fc8ccc97bc6e3353177e9951372dc898829d826e6cca
```

Run `strings`:

```bash
strings -a Varsity_Lake_Sonata.bin
```

Interesting strings appear:

```text
UMCS{f4k3_fl4g_h1dd3n_...}
[HINT 1]
dynamic XOR
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $
```

There are two important observations:

1. The visible `UMCS{...}` string is a fake flag.

2. The binary is packed with UPX.


The string `dynamic XOR` is also a strong hint that the actual flag validation uses XOR-based logic.

---

# Vulnerability / Weakness Identification

This is not a software vulnerability in the usual web or pwn sense. The weakness is in the challenge’s flag validation design.

The binary validates the flag locally using a reversible XOR transformation. Once the comparison array and transformation logic are recovered, the flag can be reconstructed without brute force.

After unpacking and reversing the validator, the core logic is equivalent to:

```c
previous = 0x13;

for (i = 0; i < length; i++) {
    transformed = (input[i] ^ 0x4d) ^ i ^ previous;

    if (transformed != target[i]) {
        fail();
    }

    previous = input[i];
}
```

The important weakness is that XOR is reversible.

The check is:

```text
target[i] = input[i] ^ 0x4d ^ i ^ previous
```

Therefore, the original character can be recovered using:

```text
input[i] = target[i] ^ 0x4d ^ i ^ previous
```

Because `previous` starts with the known constant `0x13`, and then becomes the previously recovered plaintext character, the full flag can be recovered from left to right.

---

# Exploitation Strategy

The solving strategy is:

1. Identify that the binary is packed with UPX.

2. Unpack the binary.

3. Open the unpacked binary in a reversing tool such as Ghidra, Cutter, IDA Free, or radare2.

4. Locate the input validation function.

5. Extract the target byte array.

6. Rebuild the XOR transformation in Python.

7. Reverse the algorithm byte by byte.

8. Print the recovered flag.


The extracted target array is:

```python
target = [
    0x0b, 0x54, 0x41, 0x5e, 0x61, 0x47,
    0x0b, 0x0d, 0x5f, 0x46, 0x73, 0x6f,
    0x03, 0x06, 0x42, 0x00, 0x18, 0x51,
    0x79, 0x71, 0x40, 0x05, 0x01, 0x04,
    0x3a, 0x73, 0x1f, 0x14, 0x7c, 0x62,
    0x0d, 0x0d, 0x31, 0x38, 0x72, 0x6a
]
```

The array has 36 bytes, so the expected flag length is 36 characters.

---

# Proof of Concept

First, confirm the file is packed:

```bash
strings -a Varsity_Lake_Sonata.bin | grep -i upx
```

Expected output:

```text
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $
```

Install UPX if needed:

```bash
sudo apt update
sudo apt install upx-ucl
```

Unpack the binary:

```bash
upx -d Varsity_Lake_Sonata.bin -o Varsity_Lake_Sonata_unpacked
```

Then inspect the unpacked binary:

```bash
file Varsity_Lake_Sonata_unpacked
strings -a Varsity_Lake_Sonata_unpacked | grep -i xor
```

Open it in Ghidra or Cutter and locate the function that checks user input. The validation logic uses a rolling XOR state:

```c
previous = 0x13;

for each input byte:
    calculated = input[i] ^ 0x4d ^ i ^ previous
    compare calculated with target[i]
    previous = input[i]
```

Because XOR reverses itself, the exploit does not need to execute the binary. It only needs to invert the transformation.

For each byte:

```python
plain = encrypted ^ 0x4d ^ index ^ previous
```

Then update:

```python
previous = plain
```

This recovers the flag sequentially.

---

# Full Python Solver

```python
#!/usr/bin/env python3

"""
Solver for Varsity Lake Sonata

The binary validates the flag using a rolling XOR transformation:

    target[i] = input[i] ^ 0x4d ^ i ^ previous

Where:
    previous starts as 0x13
    previous becomes input[i] after each round

Since XOR is reversible:

    input[i] = target[i] ^ 0x4d ^ i ^ previous

This script reconstructs the original flag from the extracted target array.
"""

def recover_flag():
    # Target bytes extracted from the unpacked binary's validation routine.
    target = [
        0x0b, 0x54, 0x41, 0x5e, 0x61, 0x47,
        0x0b, 0x0d, 0x5f, 0x46, 0x73, 0x6f,
        0x03, 0x06, 0x42, 0x00, 0x18, 0x51,
        0x79, 0x71, 0x40, 0x05, 0x01, 0x04,
        0x3a, 0x73, 0x1f, 0x14, 0x7c, 0x62,
        0x0d, 0x0d, 0x31, 0x38, 0x72, 0x6a
    ]

    xor_key = 0x4d
    previous = 0x13

    recovered = []

    for index, encrypted_byte in enumerate(target):
        # Reverse:
        # encrypted_byte = plain ^ xor_key ^ index ^ previous
        plain_byte = encrypted_byte ^ xor_key ^ index ^ previous

        recovered.append(plain_byte)

        # The algorithm uses the current plaintext byte as the next state.
        previous = plain_byte

    flag = bytes(recovered).decode("ascii")
    return flag


def main():
    flag = recover_flag()

    print("[+] Recovered flag:")
    print(flag)

    if flag.startswith("UMCS{") and flag.endswith("}"):
        print("[+] Flag format looks valid.")
    else:
        print("[-] Warning: flag format does not look valid.")


if __name__ == "__main__":
    main()
```

---

# Walkthrough

Save the solver as:

```bash
nano solve_varsity_lake_sonata.py
```

Paste the Python code, then run:

```bash
python3 solve_varsity_lake_sonata.py
```

Expected output:

```text
[+] Recovered flag:
UMCS{t4sik_v4rs1ty_pi4n0_x0r_m3l0dy}
[+] Flag format looks valid.
```

No external Python libraries are required. The script only uses built-in Python functionality.

Troubleshooting notes:

If `upx` is not available:

```bash
sudo apt install upx-ucl
```

If UPX refuses to unpack, use a debugger-based dump method instead:

```bash
chmod +x Varsity_Lake_Sonata.bin
gdb ./Varsity_Lake_Sonata.bin
```

Then break after unpacking and dump the memory region containing the unpacked program. However, for this challenge, the simpler UPX unpacking path is the most reliable method.

If the solver prints non-readable bytes, check that the target array was copied correctly. One wrong byte will corrupt the rolling XOR chain because every recovered byte affects the next byte.

---

# Flag

The recovered flag is:

```text
UMCS{t4sik_v4rs1ty_pi4n0_x0r_m3l0dy}
```

---

# Conclusion

The challenge hides the real validation logic behind UPX packing and fake visible strings. The fake `UMCS{...}` value is a decoy designed to punish shallow `strings`-only analysis.

After unpacking the binary, the real check is a rolling XOR transformation. Because XOR is reversible and the initial state is hardcoded as `0x13`, the target array can be inverted byte by byte to recover the original input.

Key lesson:

Do not trust visible strings in packed reversing challenges. Always verify the binary structure, unpack if necessary, and reverse the actual comparison logic.
