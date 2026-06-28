---
title: "Detonator"
summary: "International HACK@10 CTF 2026 hack10, forensics, reverse engineering writeup covering Detonator with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - hack10
  - forensics
  - reverse-engineering
  - malware-analysis
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://instagram.fkul11-2.fna.fbcdn.net/v/t51.82787-19/641307447_17850468132650020_693182401274637569_n.jpg?stp=dst-jpg_s150x150_tt6&efg=eyJ2ZW5jb2RlX3RhZyI6InByb2ZpbGVfcGljLmRqYW5nby4xMDgwLmMyIn0&_nc_ht=instagram.fkul11-2.fna.fbcdn.net&_nc_cat=104&_nc_oc=Q6cZ2gGY8elv-2_ffeNAnV1zev1x6qjeFXKSTkqJPt8hLvpW4r7SjGcF8yWitQhjEUVMFOlCO1QdwosRBu2_nqdaMwi1&_nc_ohc=V5UmcoEFIBIQ7kNvwH4oZxS&_nc_gid=nKZjHtkfrQHa4bxkteBcUA&edm=APoiHPcBAAAA&ccb=7-5&oh=00_Af_eyJvKyalWBh43tjTkFFQWtcGJPfalqqEqSEqMK-rTpQ&oe=6A3A2E75&_nc_sid=22de04"
---
# Challenge Overview

**Challenge Name:** Detonator
**Category:** Reversing
**Points:** 496
**Flag Format:** `HACK10{}`
**Author:** Jebat

The challenge provides a Windows executable named `detonator.exe`. The description hints at malware analysis, where an analyst may either statically reverse the binary or execute it inside a sandbox.

The goal is to reverse engineer the executable and recover the correct flag.

---

# Initial Analysis

The provided file is a Windows PE executable.

Initial triage was performed using `strings`:

```bash
strings detonator.exe
````

Interesting output included:

```text
C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt
HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}
File not found. Keep looking...
Here is the flag: HACK10{
```

At first glance, the binary contains a flag-like string:

```text
HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}
```

However, the string clearly contains `f4k3_fl4g`, indicating that it is intentionally placed as a decoy.

The executable was then opened in Ghidra for static analysis.

---

# Vulnerability / Weakness Identification

This is not a traditional software vulnerability. The weakness is the binary’s exposed logic and embedded strings.

The important function is:

```cpp
check_flag()
```

Inside `check_flag()`, the program creates two strings:

```cpp
"C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt"
```

and:

```cpp
"HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}"
```

The program checks whether the path exists using `_stat64i32()`.

If the file exists, it prints:

```text
Here is the flag: HACK10{
```

Then it calls an internal `md5()` function and prints the result followed by `}`.

The key assembly confirms the input to `md5()`:

```asm
140001a9f: lea -0x30(%rbp), %rax   ; output string
140001aa3: lea -0x60(%rbp), %rdx   ; input = path string
140001aaa: call 140001450 <md5(...)>
```

This proves that the real flag is:

```text
HACK10{MD5(path_string)}
```

The MD5 input is the full path string, not the fake flag.

---

# Exploitation Strategy

The simplest reliable method is static reconstruction.

Instead of detonating the executable inside a sandbox, we can reproduce the flag generation logic manually.

The program hashes this string:

```text
C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt
```

Then the result is wrapped inside:

```text
HACK10{<md5_hash>}
```

Therefore, the exploitation strategy is:

1. Extract the MD5 input string from the binary.

2. Confirm the MD5 function is standard MD5.

3. Hash the path string.

4. Wrap the digest with `HACK10{}`.


---

# Proof of Concept

The logic can be reproduced with Python:

```python
import hashlib

path = r"C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt"
digest = hashlib.md5(path.encode()).hexdigest()

print(f"HACK10{{{digest}}}")
```

Expected output:

```text
HACK10{be029cf0e9f2eaa5f80489343630befb}
```

---

# Full Python Solver

```python
#!/usr/bin/env python3
import hashlib

def main():
    # This is the real string passed into the binary's md5() function.
    # The visible HACK10{f4k3...} string is only bait.
    path_string = r"C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt"

    # Compute standard MD5 digest.
    md5_hash = hashlib.md5(path_string.encode()).hexdigest()

    # The binary prints: HACK10{ + md5_hash + }
    flag = f"HACK10{{{md5_hash}}}"

    print(flag)

if __name__ == "__main__":
    main()
```

---

# Walkthrough

Save the script:

```bash
nano solve.py
```

Paste the solver code, then run:

```bash
python3 solve.py
```

Expected output:

```text
HACK10{be029cf0e9f2eaa5f80489343630befb}
```

No external dependencies are required because `hashlib` is included in Python’s standard library.

Troubleshooting:

- Use a raw string with `r"..."` so Windows backslashes are preserved correctly.

- Do not hash the fake flag string.

- Hash the full path string exactly as shown.


---

# Flag

```text
HACK10{be029cf0e9f2eaa5f80489343630befb}
```

---

# Conclusion

The challenge uses a fake embedded flag to mislead analysts. Static analysis shows that the real flag is generated by hashing a hardcoded Windows path using MD5.

The key lesson is to avoid trusting visible strings blindly. In reversing challenges, the correct answer usually comes from following the actual data flow and understanding which value is passed into the important function.
