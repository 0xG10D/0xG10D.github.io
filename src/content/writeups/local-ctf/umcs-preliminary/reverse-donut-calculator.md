---
title: "Donut Calculator"
summary: "UMCS Preliminary umcs preliminary, forensics, reverse engineering writeup covering Donut Calculator with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - forensics
  - reverse-engineering
  - malware-analysis
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** Donut Calculator
**Category:** Reverse / Malware Analysis
**Points:** 330
**Flag Format:** `UMCS{}`
**Provided File:** `Donut_calculator.7z`
**Archive Password:[REDACTED_PASSWORD]infected`

The challenge provides a password-protected archive containing a Windows executable named `calculator.exe`. The challenge description says:

```text
I swear it's just a calculator, boss!

password : [REDACTED_PASSWORD]

Warning : Ensure all analysis is performed in a virtual machine.
```

The warning is important. The executable is not treated as a normal calculator binary. It should be analyzed statically inside a VM or malware-analysis environment.

The goal is to reverse engineer the executable and recover the hidden flag.

---

# Initial Analysis

First, extract the archive using the provided password:

```bash
7z x Donut_calculator.7z -pinfected
```

This gives:

```text
calculator.exe
```

Basic file triage:

```bash
file calculator.exe
```

Expected result:

```text
calculator.exe: PE32+ executable (GUI) x86-64, for MS Windows
```

A quick strings check already gives suspicious indicators:

```bash
strings -a calculator.exe | grep -Ei "notepad|VirtualAlloc|WriteProcessMemory|CreateRemoteThread|Hidden|number"
```

Important observations:

```text
notepad.exe
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
Hidden
number
```

This is not normal calculator behavior.

Opening the binary in Ghidra or IDA shows a function named approximately:

```text
Hidden()
```

Inside `Hidden()`, the binary performs process injection logic:

```text
CreateProcessA("notepad.exe", ...)
VirtualAllocEx(...)
WriteProcessMemory(...)
CreateRemoteThread(...)
```

The payload written into the remote process is a large byte array named:

```text
number
```

with size:

```text
0x253c9
```

That size and behavior strongly indicate a Donut shellcode payload.

Donut is commonly used to convert PE/.NET/script payloads into position-independent shellcode. The shellcode normally carries an encrypted module and decrypts it at runtime before executing it.

---

# Vulnerability / Weakness Identification

This is not a traditional memory corruption vulnerability. The weakness is the malware-style packing design itself.

The executable hides the real payload in this flow:

```text
calculator.exe
→ Hidden()
→ injects byte array `number`
→ Donut shellcode decrypts embedded payload
→ recovered payload contains XOR-obfuscated flag parts
```

The important weaknesses are:

1. **The Donut shellcode is embedded directly inside the executable.**
    The byte array `number` is stored in the PE file and can be extracted statically.

2. **The Donut payload contains all decryption material needed at runtime.**
    Donut decrypts its embedded module using data stored inside the shellcode. Therefore, a static unpacker can recover the inner module without executing the malware.

3. **The final flag is only split and XOR-obfuscated.**
    After unpacking the Donut payload, the flag parts are protected with short repeating XOR keys:


```text
[REDACTED_PASSWORD]
nPcF1aG
```

The decoded strings are:

```text
$flag_part1 = 'UMCS{Ap1_HaSH1n5_Pr0c3ss_Ha'
11owInG_D0nuT_sHellcode}
```

Combining them gives the final flag.

---

# Exploitation Strategy

The safest and most reliable strategy is static analysis only.

The plan:

1. Extract `calculator.exe` from the archive.

2. Open the executable in Ghidra or IDA.

3. Locate the suspicious `Hidden()` function.

4. Confirm that it creates `notepad.exe` and injects shellcode into it.

5. Identify the injected shellcode byte array named `number`.

6. Dump the `number` blob with length `0x253c9`.

7. Unpack or emulate the Donut shellcode to recover the embedded module.

8. Search the recovered module for short XOR keys and encrypted blobs.

9. Decode the blobs using repeating-key XOR.

10. Combine the two decoded flag fragments.


The key point is that the executable does not need to be run. Running it would trigger the injection behavior, which is unnecessary and unsafe.

---

# Proof of Concept

## 1. Extract the challenge file

```bash
7z x Donut_calculator.7z -pinfected
```

Output:

```text
Extracting archive: Donut_calculator.7z
Everything is Ok

Files: 1
Size: ...
Name: calculator.exe
```

## 2. Confirm the file type

```bash
file calculator.exe
```

Expected output:

```text
calculator.exe: PE32+ executable (GUI) x86-64, for MS Windows
```

## 3. Check suspicious imports and strings

```bash
strings -a calculator.exe | grep -Ei "notepad|VirtualAlloc|WriteProcessMemory|CreateRemoteThread"
```

Expected indicators:

```text
notepad.exe
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
```

These APIs are common in process injection:

|API|Purpose|
|---|---|
|`CreateProcessA`|Starts a target process, here `notepad.exe`|
|`VirtualAllocEx`|Allocates memory inside another process|
|`WriteProcessMemory`|Writes shellcode into that process|
|`CreateRemoteThread`|Executes the injected shellcode|

## 4. Reverse the `Hidden()` function

In Ghidra, `Hidden()` shows logic similar to:

```c
CreateProcessA(NULL, "notepad.exe", ...);
VirtualAllocEx(process_handle, NULL, 0x253c9, ...);
WriteProcessMemory(process_handle, remote_memory, number, 0x253c9, ...);
CreateRemoteThread(process_handle, NULL, 0, remote_memory, NULL, 0, NULL);
```

The important part is:

```text
number
size = 0x253c9
```

That is the embedded shellcode.

## 5. Dump the shellcode blob

In Ghidra, use the address of `number` and dump `0x253c9` bytes.

Example Ghidra Python snippet:

```python
# Run inside Ghidra's Python console.
# Replace the address with the actual address of `number`.

addr = toAddr(0x1400ABCDE)
size = 0x253c9

data = getBytes(addr, size)

with open("number.bin", "wb") as f:
    f.write(bytearray(data))

print("[+] Dumped number.bin")
```

After this, `number.bin` contains the Donut shellcode.

## 6. Recover the Donut module

A Donut unpacker or emulator can be used to recover the embedded module from `number.bin`.

Conceptually:

```bash
python3 donut_unpacker.py number.bin recovered_module.bin
```

The exact unpacker name may differ depending on your toolkit, but the goal is the same:

```text
number.bin
→ Donut decrypt/unpack
→ recovered_module.bin
```

## 7. Decode the final XOR strings

Inside the recovered module, two XOR keys are found:

```text
[REDACTED_PASSWORD]
nPcF1aG
```

Decoding the encrypted data gives:

```text
$flag_part1 = 'UMCS{Ap1_HaSH1n5_Pr0c3ss_Ha'
11owInG_D0nuT_sHellcode}
```

Combine:

```text
UMCS{Ap1_HaSH1n5_Pr0c3ss_Ha11owInG_D0nuT_sHellcode}
```

---

# Full Python Solver

The script below performs the final static decoding step.

It supports two modes:

1. **Automatic scan mode:** provide the recovered Donut module using `--module`.

2. **Known challenge constants mode:** if no module is provided, it decodes the extracted encrypted blobs from this challenge.


```python
#!/usr/bin/env python3
"""
Donut Calculator - Static flag decoder

This script decodes the final XOR-obfuscated flag fragments found after
unpacking the Donut shellcode payload.

Usage examples:

    python3 solve_donut_calculator.py

or, after dumping/unpacking the Donut module:

    python3 solve_donut_calculator.py --module recovered_module.bin
"""

import argparse
import re
from pathlib import Path


KEY_PART1 = b"[REDACTED_PASSWORD]"
KEY_PART2 = b"nPcF1aG"

# These are the encrypted blobs recovered from the unpacked Donut module.
# They decode using repeating-key XOR.
ENC_PART1 = bytes([
    0x4a, 0x36, 0x0f, 0x32, 0x02, 0x1c, 0x02, 0x04,
    0x26, 0x1a, 0x61, 0x43, 0x6e, 0x45, 0x64, 0x27,
    0x28, 0x17, 0x3d, 0x2b, 0x22, 0x23, 0x54, 0x1c,
    0x3a, 0x04, 0x07, 0x26, 0x61, 0x0d, 0x66, 0x3a,
    0x13, 0x00, 0x55, 0x37, 0x5d, 0x23, 0x10, 0x0c,
    0x2d, 0x22, 0x55
])

ENC_PART2 = bytes([
    0x5f, 0x61, 0x0c, 0x31, 0x78, 0x0f, 0x00, 0x31,
    0x14, 0x53, 0x28, 0x44, 0x35, 0x18, 0x1d, 0x18,
    0x06, 0x2a, 0x5d, 0x02, 0x28, 0x0a, 0x35, 0x1e
])


def xor_repeating(data: bytes, key: bytes) -> bytes:
    """
    Decode bytes using repeating-key XOR.
    """
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def printable_ascii(data: bytes) -> bool:
    """
    Check whether decoded bytes are mostly printable ASCII.
    """
    return all(byte in b"\r\n\t" or 0x20 <= byte <= 0x7e for byte in data)


def decode_known_blobs() -> str:
    """
    Decode the known encrypted blobs recovered from the unpacked payload.
    """
    decoded1 = xor_repeating(ENC_PART1, KEY_PART1).decode(errors="replace")
    decoded2 = xor_repeating(ENC_PART2, KEY_PART2).decode(errors="replace")

    print("[+] Decoded part 1:")
    print(decoded1)

    print("[+] Decoded part 2:")
    print(decoded2)

    # Part 1 is stored as a PowerShell-style assignment:
    # $flag_part1 = 'UMCS{...'
    match = re.search(r"(UMCS\{[A-Za-z0-9_]+)", decoded1)
    if not match:
        raise RuntimeError("Could not extract UMCS{... fragment from part 1")

    flag_part1 = match.group(1)
    flag_part2 = decoded2.strip()

    flag = flag_part1 + flag_part2

    return flag


def scan_module_for_xor_strings(module_path: Path) -> None:
    """
    Optional helper:
    Scan a recovered module for strings that appear after XOR-decoding
    with the known keys.

    This is useful when validating the result against recovered_module.bin.
    """
    data = module_path.read_bytes()

    print(f"[+] Loaded module: {module_path}")
    print(f"[+] Size: {len(data)} bytes")

    keys = [KEY_PART1, KEY_PART2]
    interesting = [
        b"UMCS{",
        b"flag_part",
        b"Donut",
        b"D0nuT",
        b"shellcode",
        b"sHellcode",
    ]

    found_any = False

    for key in keys:
        print(f"\n[+] Scanning with XOR key: {key.decode()}")

        # Try every key alignment. This helps when the encrypted blob starts
        # in the middle of a repeating XOR cycle.
        for phase in range(len(key)):
            decoded = bytearray()

            for i, byte in enumerate(data):
                decoded.append(byte ^ key[(i - phase) % len(key)])

            # Extract printable regions from the decoded stream.
            for match in re.finditer(rb"[\x20-\x7e]{8,}", bytes(decoded)):
                candidate = match.group(0)

                if any(token in candidate for token in interesting):
                    found_any = True
                    start = match.start()
                    preview = candidate[:200].decode(errors="replace")

                    print(f"[candidate offset=0x{start:x}, phase={phase}]")
                    print(preview)

    if not found_any:
        print("[-] No obvious XOR-decoded flag strings found.")
        print("[*] Make sure you are scanning the recovered Donut module, not the outer calculator.exe.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Solve Donut Calculator by decoding the final XOR flag fragments."
    )

    parser.add_argument(
        "--module",
        type=Path,
        help="Optional recovered Donut module to scan for XOR-decoded strings."
    )

    args = parser.parse_args()

    if args.module:
        if not args.module.exists():
            raise FileNotFoundError(f"Module not found: {args.module}")

        scan_module_for_xor_strings(args.module)

    print("\n[+] Decoding known challenge blobs...")
    flag = decode_known_blobs()

    print("\n[+] FLAG:")
    print(flag)


if __name__ == "__main__":
    main()
```

---

# Walkthrough

## 1. Prepare a safe environment

Use a Windows or Linux VM. Do not run `calculator.exe` on your host machine.

Recommended tools:

```bash
sudo apt install p7zip-full binutils file
```

Useful reversing tools:

```text
Ghidra
IDA Free
x64dbg
Detect It Easy
PE-bear
strings
```

## 2. Extract the archive

```bash
7z x Donut_calculator.7z -pinfected
```

You should get:

```text
calculator.exe
```

## 3. Perform static triage

```bash
file calculator.exe
strings -a calculator.exe | grep -Ei "notepad|VirtualAlloc|WriteProcessMemory|CreateRemoteThread"
```

Expected suspicious indicators:

```text
notepad.exe
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
```

## 4. Analyze in Ghidra

Open `calculator.exe` in Ghidra.

Look for the function:

```text
Hidden()
```

The function injects the byte array:

```text
number
```

into:

```text
notepad.exe
```

The shellcode size is:

```text
0x253c9
```

## 5. Dump the Donut shellcode

Use Ghidra Python:

```python
addr = toAddr(0x1400ABCDE)  # replace with address of number
size = 0x253c9

data = getBytes(addr, size)

with open("number.bin", "wb") as f:
    f.write(bytearray(data))
```

This creates:

```text
number.bin
```

## 6. Unpack the Donut shellcode

Use any Donut unpacking workflow to recover the embedded module:

```bash
python3 donut_unpacker.py number.bin recovered_module.bin
```

The recovered payload contains the final XOR-obfuscated strings.

## 7. Run the solver

Save the Python solver as:

```text
solve_donut_calculator.py
```

Run:

```bash
python3 solve_donut_calculator.py
```

Expected output:

```text
[+] Decoded part 1:
$flag_part1 = 'UMCS{Ap1_HaSH1n5_Pr0c3ss_Ha'

[+] Decoded part 2:
11owInG_D0nuT_sHellcode}

[+] FLAG:
UMCS{Ap1_HaSH1n5_Pr0c3ss_Ha11owInG_D0nuT_sHellcode}
```

You can also scan the recovered module:

```bash
python3 solve_donut_calculator.py --module recovered_module.bin
```

Expected useful output should include strings similar to:

```text
$flag_part1 = 'UMCS{Ap1_HaSH1n5_Pr0c3ss_Ha'
11owInG_D0nuT_sHellcode}
```

## Troubleshooting

If `strings` does not show the final flag, that is expected. The flag is not stored plainly in the outer executable.

If the solver does not find anything with `--module`, check that you are scanning the recovered Donut module, not `calculator.exe`.

If Ghidra does not show `Hidden()` immediately, search for references to:

```text
notepad.exe
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
```

If the address of `number` is different, that is normal. Use the actual address shown by your disassembler.

---

# Flag

The recovered fragments are:

```text
UMCS{Ap1_HaSH1n5_Pr0c3ss_Ha
```

and:

```text
11owInG_D0nuT_sHellcode}
```

Final flag:

```text
UMCS{Ap1_HaSH1n5_Pr0c3ss_Ha11owInG_D0nuT_sHellcode}
```

---

# Conclusion

The challenge disguises itself as a calculator, but the executable contains a hidden process-injection routine. The function `Hidden()` starts `notepad.exe`, writes a large shellcode blob named `number` into it, and executes it remotely.

The shellcode is a Donut payload. Donut encrypts the real module, but the shellcode must contain everything needed to decrypt that module at runtime. By dumping and unpacking the shellcode statically, the embedded payload can be recovered without executing the malware.

The final protection layer is simple repeating-key XOR using hardcoded keys. Once decoded, the two flag fragments combine into the final flag.

Key lesson:

```text
Packing, shellcode injection, and XOR obfuscation slow down analysis,
but they do not protect secrets when the decryption logic and keys are
shipped with the binary.
```
