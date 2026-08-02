---
slug: "local-ctf/international-hack10-ctf-2026/crypto-baby-crypto"
event: "international-hack10-ctf-2026"
title: "Baby Crypto"
summary: "International HACK@10 CTF 2026 hack10, forensics, reverse engineering writeup covering Baby Crypto with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - hack10
  - forensics
  - reverse-engineering
  - cryptography
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://instagram.fkul11-2.fna.fbcdn.net/v/t51.82787-19/641307447_17850468132650020_693182401274637569_n.jpg?stp=dst-jpg_s150x150_tt6&efg=eyJ2ZW5jb2RlX3RhZyI6InByb2ZpbGVfcGljLmRqYW5nby4xMDgwLmMyIn0&_nc_ht=instagram.fkul11-2.fna.fbcdn.net&_nc_cat=104&_nc_oc=Q6cZ2gGY8elv-2_ffeNAnV1zev1x6qjeFXKSTkqJPt8hLvpW4r7SjGcF8yWitQhjEUVMFOlCO1QdwosRBu2_nqdaMwi1&_nc_ohc=V5UmcoEFIBIQ7kNvwH4oZxS&_nc_gid=nKZjHtkfrQHa4bxkteBcUA&edm=APoiHPcBAAAA&ccb=7-5&oh=00_Af_eyJvKyalWBh43tjTkFFQWtcGJPfalqqEqSEqMK-rTpQ&oe=6A3A2E75&_nc_sid=22de04"
---
# Challenge Overview

**Challenge Name:** Baby Crypto
**CTF:** International HACK@10 CTF 2026
**Category:** Crypto
**Points:** 415
**Flag Format:** `hack10{...}`
**Provided Files:** `chal.py`, `output`

The challenge provides a Python encryption script and an output file. The goal is to reverse the custom encryption logic and recover the original flag.

The encryption script processes the flag in 2-byte chunks, hashes each chunk with SHA-512, takes a random slice of the hash, inserts random junk before it, and writes the final hex-decoded data into `output`.

---

# Initial Analysis

The important part of `chal.py` is:

```python
for i in range(0,len(flag),2):
    a = random.randint(90, 128)
    b = random.randint(1,15)
    cipher = hashlib.sha512(flag[i:i+2]).hexdigest()
    encrypted += binascii.hexlify(os.urandom(random.randint(0, 31))).decode('utf-8')
    encrypted += cipher[b:a]
```

This means:

1. The flag is split into 2-byte chunks.

2. Each chunk is hashed using SHA-512.

3. Only `cipher[b:a]` is leaked.

4. Random garbage is inserted before every leaked hash slice.

5. The result is written as raw bytes into `output`.


The encryption does **not** store the flag directly, but it leaks long substrings of SHA-512 hashes for each 2-byte chunk.

---

# Vulnerability / Weakness Identification

The weakness is the extremely small plaintext space.

Each flag chunk is only 2 bytes. That means the maximum brute-force space is:

```text
256 * 256 = 65536 possibilities
```

Since the flag format is known as `hack10{...}`, and the recovered content appears to be lowercase hexadecimal, the search space becomes even smaller.

SHA-512 itself is not broken. The issue is that the program leaks a large substring of:

```text
sha512(two_byte_chunk).hexdigest()
```

Because SHA-512 is deterministic, we can hash every possible 2-byte candidate and search for matching hash slices inside the output.

---

# Exploitation Strategy

The plan is:

1. Read `output` as bytes.

2. Convert it back into a hex string.

3. Generate possible 2-byte flag chunks.

4. For each candidate chunk:

    - Calculate SHA-512.

    - Generate all possible slices where:

        - `b` ranges from `1` to `15`

        - `a` ranges from `90` to `128`

5. Search those slices inside the output stream.

6. Recover the original flag chunks in order.

7. Join all recovered chunks to get the full flag.


This works because the random junk only appears **before** valid leaked hash slices. The valid leaked slices still appear in the correct order.

---

# Proof of Concept

A simple proof of concept is:

```python
import hashlib

chunk = b"ha"
digest = hashlib.sha512(chunk).hexdigest()

print(digest)
```

If part of this digest exists inside the hex version of `output`, then the chunk `b"ha"` is confirmed.

Example recovered chunks:

```text
[+] Found chunk: b'ha'
[+] Found chunk: b'ck'
[+] Found chunk: b'10'
[+] Found chunk: b'{a'
```

This confirms that the flag is reconstructed 2 bytes at a time.

---

# Full Python Solver

```python
#!/usr/bin/env python3
import hashlib
import string
from pathlib import Path

OUTPUT_FILE = "output"

# Known flag prefix
KNOWN_PREFIX = b"hack10{"

# Based on recovered output, the flag body is hex-like
HEX_CHARS = b"0123456789abcdef"

def generate_hash_slices(chunk: bytes):
    """
    Generate all possible hash slices based on the challenge logic:
        b = random.randint(1, 15)
        a = random.randint(90, 128)
        cipher[b:a]
    """
    digest = hashlib.sha512(chunk).hexdigest().encode()

    slices = []
    for b in range(1, 16):
        for a in range(90, 129):
            if a > b:
                slices.append(digest[b:a])

    return slices


def build_candidate_chunks():
    """
    Build possible 2-byte chunks.

    The flag starts with hack10{ and the body appears to be hexadecimal.
    We include:
    - known prefix chunks
    - hex pairs
    - boundary chunks involving { and }
    """
    candidates = set()

    # Known prefix chunks: ha ck 10 {x
    for i in range(0, len(KNOWN_PREFIX), 2):
        candidates.add(KNOWN_PREFIX[i:i+2])

    # Hexadecimal body chunks
    for a in HEX_CHARS:
        for b in HEX_CHARS:
            candidates.add(bytes([a, b]))

    # Opening and closing brace boundary chunks
    for c in HEX_CHARS:
        candidates.add(b"{" + bytes([c]))
        candidates.add(bytes([c]) + b"}")

    return sorted(candidates)


def find_first_match(data_hex: bytes, cursor: int, chunk: bytes):
    """
    Search for the earliest matching hash slice of a candidate chunk
    after the current cursor.
    """
    slices = generate_hash_slices(chunk)

    best = None

    for s in slices:
        position = data_hex.find(s, cursor)

        if position == -1:
            continue

        end = position + len(s)

        if best is None or position < best[0]:
            best = (position, end, s)

    return best


def main():
    raw = Path(OUTPUT_FILE).read_bytes()
    data_hex = raw.hex().encode()

    candidates = build_candidate_chunks()

    recovered = []
    cursor = 0

    while True:
        best_match = None

        for chunk in candidates:
            result = find_first_match(data_hex, cursor, chunk)

            if result is None:
                continue

            start, end, matched_slice = result

            if best_match is None or start < best_match[0]:
                best_match = (start, end, chunk, matched_slice)

        if best_match is None:
            print("[-] No more chunks found.")
            break

        start, end, chunk, matched_slice = best_match

        recovered.append(chunk)
        cursor = end

        print(f"[+] Found chunk: {chunk!r}")

        if chunk.endswith(b"}"):
            break

        if len(recovered) > 200:
            raise RuntimeError("Too many chunks recovered. Parsing may have drifted.")

    flag = b"".join(recovered)

    print("\n[+] Recovered flag:")
    print(flag.decode(errors="replace"))


if __name__ == "__main__":
    main()
```

---

# Walkthrough

Place the solver in the same directory as `output`:

```bash
ls
```

Expected files:

```text
chal.py
output
solve.py
```

Run the solver:

```bash
python3 solve.py
```

Expected output:

```text
[+] Found chunk: b'ha'
[+] Found chunk: b'ck'
[+] Found chunk: b'10'
[+] Found chunk: b'{a'
...
[+] Recovered flag:
hack10{...}
```

No external Python libraries are required.

Troubleshooting:

If the script fails, check that:

```bash
file output
ls -lah output
```

The `output` file must be the original binary output generated by the challenge.

---

# Flag

Recovered flag:

```text
hack10{a88dacd5fb88dc4973bb3a56fff9be940bb1f1b83c2b82f3f6daa256267c9786f4cdc70255079e3cfaea9956211e615fe78ee9d5a95a832afff2f09b05c39db4}
```

---

# Conclusion

The root cause of this challenge is the misuse of hashing as an encryption mechanism.

Although SHA-512 is cryptographically secure, the challenge leaks large portions of the hash of very small 2-byte plaintext chunks. Since each chunk has a tiny brute-force space, the original flag can be recovered by precomputing possible hashes and matching leaked substrings.

Key lesson:

```text
Hashing small plaintext chunks and leaking partial digests is not secure encryption.
```
