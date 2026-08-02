---
slug: "local-ctf/iboh25/hi"
event: "iboh-2025"
title: "Hi"
summary: "IBOH25 iboh25, forensics, reverse engineering writeup covering Hi with analysis, solution steps, and final recovery notes."
date: 2026-05-18
tags:
  - ctf
  - iboh25
  - forensics
  - reverse-engineering
  - cryptography
  - boot2root
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://www.crest-approved.org/wp-content/uploads/2025/11/International-Battle-of-Hackers-IBOH-2025.png"
---
## Challenge Overview

- Challenge Name: Hi
- Category: Reverse Engineering
- Difficulty / Points: Not specified
- Flag Format: `BOH25{...}`
- Provided Materials: `o.exe`

The objective of this challenge was to reverse engineer the provided executable and recover the hidden flag. Although the file used the `.exe` extension, analysis showed that it was not a Windows PE binary.

## Initial Analysis

The first step was to identify the file type.

```bash
file o.exe
```

The output showed that the file was an ELF 64-bit Linux executable:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

Because the binary was not stripped, useful symbols were still available. Symbol inspection revealed several important functions:

```bash
readelf -s o.exe
```

Important symbols included:

```text
secret_func
prompt_name
main
obf
```

The `main()` function only called `prompt_name()`, meaning the flag-printing function was hidden and not executed during normal program flow.

## Vulnerability / Weakness Identification

The main weakness was that the binary contained a hidden function named `secret_func()` and an obfuscated flag stored in the `.rodata` section.

The flag was protected using a reversible XOR-based obfuscation routine. Since the obfuscated bytes and decoding logic were both stored inside the binary, the flag could be recovered through static analysis.

## Exploitation Strategy

The solving strategy was:

1. Inspect the binary metadata.
2. Locate useful symbols.
3. Identify the hidden `secret_func()` function.
4. Extract the obfuscated bytes from `.rodata`.
5. Reconstruct the XOR key used by the binary.
6. Decode the flag manually using Python.

The key was derived from the runtime address of `secret_func()`.

## Step-by-Step Walkthrough

1. Inspect the file type.

```bash
file o.exe
```

2. Confirm that the binary is not stripped and contains symbols.

```bash
readelf -s o.exe
```

3. Locate the hidden function.

```bash
readelf -s o.exe | grep secret_func
```

4. Dump the `.rodata` section to locate the obfuscated flag bytes.

```bash
objdump -s -j .rodata o.exe
```

5. Analyze the hidden decoding logic.

The function copied 51 obfuscated bytes from `.rodata`, generated a 4-byte XOR key from the runtime address of `secret_func()`, and decoded the bytes using a repeating XOR operation.

6. Rebuild the decoding process with Python.

## Important Commands / Code Snippets

```bash
file o.exe
strings o.exe
readelf -s o.exe
objdump -d o.exe
objdump -s -j .rodata o.exe
```

Python decoder:

```python
obf = bytes.fromhex(
    "101a1da2672e11a1360a20cf216539e6"
    "61310af9260a22a1653d65e5650a16d8"
    "336212c0650a6acf056664a10d1165fe"
    "617428"
)

addr = 0x555555555208

key = [
    (addr >> 8) & 0xff,
    (addr >> 16) & 0xff,
    (addr >> 24) & 0xff,
    (addr >> 5) & 0xff,
]

flag = bytes([b ^ key[i % 4] for i, b in enumerate(obf)])
print(flag.decode())
```

## Proof of Concept

The obfuscated bytes were XORed with a repeating 4-byte key derived from the address of `secret_func()`.

Using the expected runtime address:

```text
0x555555555208
```

The derived key was:

```text
[0x52, 0x55, 0x55, 0x90]
```

Running the decoder produced the final flag.

## Flag

```text
BOH25{D1d_u_s0lv3d_it_w17h0u7_CHa7GP7_?_W311_D0n3!}
```

## Lessons Learned

This challenge demonstrates the importance of checking hidden functions during reverse engineering. Even when the main function does not directly reveal the flag, useful routines may still exist inside the binary.

It also shows that XOR-based obfuscation is reversible when both the encrypted data and decoding logic are stored in the same executable. Static analysis with tools such as `file`, `readelf`, `objdump`, and a short Python decoder is often enough to recover the flag.
