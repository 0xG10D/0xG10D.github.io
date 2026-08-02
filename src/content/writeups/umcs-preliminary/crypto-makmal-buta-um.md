---
slug: "local-ctf/umcs-preliminary/crypto-makmal-buta-um"
event: "umcs-preliminary"
title: "Makmal Buta, UM"
summary: "UMCS Preliminary umcs preliminary, forensics, reverse engineering writeup covering Makmal Buta, UM with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - forensics
  - reverse-engineering
  - cryptography
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview
**Challenge Name:** Makmal Buta, UM
**Category:** Misc / Crypto
**Points:** 490
**Flag Format:** `UMCS{}`

The challenge provides a long Braille-encoded message and two useful files:

- `output.txt` — a recovered terminal output showing `arkib_makmal_buta.txt`, containing many log entries with hexadecimal IDs.

- `loganathan_translated_to_py3.py` — a partially corrupted Python 3 translation of an old script.


The goal is to recover the hidden room number / flag from the archive logs.

The important evidence is that the archive contains hundreds of `ID: 0x........` values, while the corrupted Python script references extracting IDs, a `.submit()` method, prediction, XOR, and ASCII conversion.

# Initial Analysis

The Braille text translates into an urgent message explaining that an old Python script was recovered, but most of it was corrupted. The message also says the log IDs are hexadecimal and that a “hex number generator” style function is probably needed.

The recovered Python script contains the key skeleton:

```python
import re
# another import but couldn't find out what

def solve():
    with open("arkib_makmal_buta.txt", "r") as f:
        content = f.read()

    ids = re(r"ID: (0x[0-9a-fA-F]{8})", content)

    for i in range():
        # something here
        # some type cast maybe here
        # some .submit method

    encrypted = ids['''some integer here''':]
    room_number = ""

    for x in room_number:
        # something about predicting
        # type cast
        # variables with ^ being used
        room_number = room_number + '''corrupted variable(s)'''

    return room_number
```

Several parts are damaged, but the intent is clear:

1. Read the archive file.

2. Extract all 32-bit hex IDs.

3. Submit some IDs into a predictor.

4. Treat the remaining IDs as encrypted data.

5. Predict values.

6. XOR encrypted values with predicted values.

7. Convert the result into ASCII characters.


The `.submit()` hint is very strong. In CTF crypto challenges, this commonly points to `randcrack`, a Python library used to clone Python’s MT19937 random generator after seeing 624 outputs.

# Vulnerability / Weakness Identification

The weakness is improper use of **MT19937** as an encryption keystream.

MT19937 is the pseudorandom number generator used by Python’s `random` module. It is not cryptographically secure. Its internal state consists of **624 32-bit values**.

If an attacker observes 624 consecutive 32-bit outputs, they can reconstruct the full internal PRNG state. After that, every future output is predictable.

In this challenge:

- Each archive `ID` is a 32-bit hexadecimal value.

- The first 624 IDs are leaked MT19937 outputs.

- The remaining IDs are encrypted flag characters.

- Encryption is effectively:


```python
cipher_value = ord(flag_char) ^ random.getrandbits(32)
```

Therefore decryption is:

```python
flag_char = cipher_value ^ predicted_random_value
```

The recovered log contains 637 IDs total:

```text
624 PRNG state outputs
+ 13 encrypted values
= 637 total IDs
```

The flag length is 13 characters, matching:

```text
UMCS{NMBRXD3}
```

# Exploitation Strategy

The exploitation plan is:

1. Extract every hexadecimal ID from `output.txt`.

2. Convert each ID from hex string to integer.

3. Use the first 624 integers to reconstruct the MT19937 internal state.

4. Predict the next 13 outputs.

5. XOR each encrypted ID from index 624 onward with the predicted PRNG output.

6. Convert the XOR result into characters.

7. Join the characters to recover the flag.


This works because XOR is reversible:

```python
cipher = plaintext ^ key
plaintext = cipher ^ key
```

Since MT19937 can be cloned after 624 outputs, the “key” stream can be predicted exactly.

# Proof of Concept

First, extract the IDs:

```bash
python3 - <<'PY'
import re

content = open("output.txt", "r", encoding="utf-8", errors="ignore").read()
ids = re.findall(r"ID:\s*(0x[0-9a-fA-F]{8})", content)

print("Total IDs:", len(ids))
print("First ID:", ids[0])
print("ID 624:", ids[623])
print("First encrypted ID:", ids[624])
PY
```

Expected result:

```text
Total IDs: 637
First ID: 0x75ae1757
ID 624: 0x088c3d6b
First encrypted ID: 0xcb7cd75e
```

The first 624 IDs are enough to clone MT19937. The remaining 13 IDs are decrypted by XORing them with predicted future outputs.

# Full Python Solver

This solver is dependency-free. It does not require `randcrack`; it implements MT19937 state recovery directly.

Save it as:

```bash
solve_makmal_buta.py
```

```python
#!/usr/bin/env python3
import re
import sys

MASK_32 = 0xFFFFFFFF


def undo_right_shift_xor(y: int, shift: int) -> int:
    """
    Reverse: y = x ^ (x >> shift)

    For right-shift XOR, recover bits from MSB to LSB because each
    lower bit depends on a higher bit.
    """
    x = 0

    for i in range(31, -1, -1):
        shifted_bit = ((x >> (i + shift)) & 1) if (i + shift) < 32 else 0
        bit = ((y >> i) & 1) ^ shifted_bit
        x |= bit << i

    return x & MASK_32


def undo_left_shift_xor_and(y: int, shift: int, mask: int) -> int:
    """
    Reverse: y = x ^ ((x << shift) & mask)

    For left-shift XOR, recover bits from LSB to MSB because each
    higher bit depends on a lower bit.
    """
    x = 0

    for i in range(32):
        shifted_bit = ((x >> (i - shift)) & 1) if (i - shift) >= 0 else 0
        mask_bit = (mask >> i) & 1
        bit = ((y >> i) & 1) ^ (shifted_bit & mask_bit)
        x |= bit << i

    return x & MASK_32


def temper(y: int) -> int:
    """
    MT19937 tempering function.
    This is applied before an internal state value is returned as output.
    """
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & MASK_32


def untemper(y: int) -> int:
    """
    Reverse MT19937 tempering.

    Given an observed 32-bit output, recover the corresponding internal
    state value.
    """
    y = undo_right_shift_xor(y, 18)
    y = undo_left_shift_xor_and(y, 15, 0xEFC60000)
    y = undo_left_shift_xor_and(y, 7, 0x9D2C5680)
    y = undo_right_shift_xor(y, 11)
    return y & MASK_32


class MT19937Clone:
    """
    Minimal MT19937 predictor.

    After receiving exactly 624 observed 32-bit outputs, this class rebuilds
    the internal state and predicts future outputs.
    """

    N = 624
    M = 397
    MATRIX_A = 0x9908B0DF
    UPPER_MASK = 0x80000000
    LOWER_MASK = 0x7FFFFFFF

    def __init__(self, observed_outputs):
        if len(observed_outputs) != self.N:
            raise ValueError(f"Need exactly {self.N} observed outputs")

        self.state = [untemper(value) for value in observed_outputs]
        self.index = self.N

    def twist(self):
        """
        Generate the next MT19937 state block.
        """
        for i in range(self.N):
            y = (
                (self.state[i] & self.UPPER_MASK)
                | (self.state[(i + 1) % self.N] & self.LOWER_MASK)
            )

            self.state[i] = self.state[(i + self.M) % self.N] ^ (y >> 1)

            if y & 1:
                self.state[i] ^= self.MATRIX_A

            self.state[i] &= MASK_32

        self.index = 0

    def predict_getrandbits_32(self) -> int:
        """
        Predict the next 32-bit output.
        Equivalent to random.getrandbits(32) for this cloned state.
        """
        if self.index >= self.N:
            self.twist()

        y = self.state[self.index]
        self.index += 1

        return temper(y)


def solve(path: str) -> str:
    """
    Recover the flag from the archive output.

    The first 624 IDs are leaked MT19937 outputs.
    The remaining IDs are encrypted characters.
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    ids = [
        int(value, 16)
        for value in re.findall(r"ID:\s*(0x[0-9a-fA-F]{8})", content)
    ]

    print(f"[*] Extracted {len(ids)} IDs")

    if len(ids) < 625:
        raise ValueError("Not enough IDs to clone MT19937 and decrypt data")

    known_outputs = ids[:624]
    encrypted_values = ids[624:]

    print(f"[*] Using first 624 IDs to clone MT19937")
    print(f"[*] Decrypting {len(encrypted_values)} encrypted values")

    predictor = MT19937Clone(known_outputs)

    recovered = ""

    for cipher_value in encrypted_values:
        key = predictor.predict_getrandbits_32()
        plain_value = cipher_value ^ key

        if plain_value > 0x10FFFF:
            raise ValueError(f"Invalid decoded character: {plain_value:#x}")

        recovered += chr(plain_value)

    return recovered


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "output.txt"
    flag = solve(path)
    print(f"[+] Recovered flag: {flag}")


if __name__ == "__main__":
    main()
```

# Walkthrough

Place the solver in the same directory as `output.txt`:

```bash
ls
```

Expected:

```text
output.txt
loganathan_translated_to_py3.py
solve_makmal_buta.py
```

Run the solver:

```bash
python3 solve_makmal_buta.py output.txt
```

Expected output:

```text
[*] Extracted 637 IDs
[*] Using first 624 IDs to clone MT19937
[*] Decrypting 13 encrypted values
[+] Recovered flag: UMCS{NMBRXD3}
```

No external Python packages are required.

If using the simpler `randcrack` method, the equivalent logic would be:

```python
from randcrack import RandCrack
import re

content = open("output.txt", "r", encoding="utf-8", errors="ignore").read()
ids = [int(x, 16) for x in re.findall(r"ID:\s*(0x[0-9a-fA-F]{8})", content)]

rc = RandCrack()

for value in ids[:624]:
    rc.submit(value)

flag = ""

for value in ids[624:]:
    flag += chr(value ^ rc.predict_getrandbits(32))

print(flag)
```

Install dependency only if using this shorter version:

```bash
pip3 install randcrack
```

# Flag

The recovered flag is:

```text
UMCS{NMBRXD3}
```

# Conclusion

The challenge hides the flag behind a predictable PRNG-based XOR scheme. The archive leaks exactly enough MT19937 output to reconstruct the full generator state. Once the first 624 log IDs are submitted into an MT19937 predictor, the future keystream values are predictable, allowing the remaining encrypted IDs to be XOR-decrypted into the flag.

Key lesson:

> MT19937 is suitable for simulation and general randomness, but it must never be used for cryptographic encryption, token generation, or secret keystreams. Once enough outputs are exposed, the entire future sequence becomes predictable.
