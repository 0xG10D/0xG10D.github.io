---
slug: "local-ctf/bahtera-3108-2025/adi-rasa"
event: "bahtera-3108-2025"
title: "ADI RaSA"
summary: "Bahtera 3108 2025 cryptography writeup covering a three-prime RSA modulus, factorization, private-key recovery, and flag decryption."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - cryptography
  - rsa
  - factorization
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Challenge Overview

Adi Putra terkenal dengan kehebatan matematik beliau sejak kecil. Berinspirasikan beliau, cabaran ini menggunakan formula baharu untuk menyulitkan maklumat misteri. Sebelum nilai kriptografi diberikan, peserta perlu menjawab kuiz mengenai Adi Putra.

![ADI RaSA quiz and generated values](/images/writeups/local-ctf/bahtera-3108-2025/adi-rasa/quiz-and-values.png)

Selepas semua jawapan betul, cabaran memaparkan:

```text
Tahniah! Anda telah menjawab semua soalan dengan betul.
Nilai N anda ialah: 293492960412007278668808616766320338991219616990905534338059009987
Nilai c anda ialah: 145104198865749436686383467165820612598723883288622970363127633064
```

Cabaran turut menyediakan `chall.py`. Pautan sementara yang rosak dalam nota asal tidak diperlukan kerana kod sumbernya telah disertakan di bawah.

## Challenge Source

```python
from sympy import randprime
from pathlib import Path
from secret import FLAG

LOW = 2**72
HIGH = 2**73 - 1

p = randprime(LOW, HIGH)
q = randprime(LOW, HIGH)
r = randprime(LOW, HIGH)

while q == p:
    q = randprime(LOW, HIGH)
while r == p or r == q:
    r = randprime(LOW, HIGH)

N = p * q * r
e = 65537

m = int.from_bytes(FLAG, "big")

c = pow(m, e, N)

print(f"N = {N}")
print(f"e = {e}")
print(f"c = {c}")
```

## Weakness

This is RSA with a modulus made from three primes:

```text
N = p * q * r
```

Once `N` is factored, Euler's totient can be calculated as `(p - 1)(q - 1)(r - 1)`. The private exponent is then the modular inverse of `e` modulo that totient, allowing the ciphertext to be decrypted.

## Solver

```python
from sympy import factorint, mod_inverse

# Challenge values
N = 293492960412007278668808616766320338991219616990905534338059009987
e = 65537
c = 145104198865749436686383467165820612598723883288622970363127633064

# 1. Factor N
factors = factorint(N)
print("[+] Factors:", factors)

p, q, r = list(factors.keys())

# 2. Compute phi(N)
phi = (p - 1) * (q - 1) * (r - 1)

# 3. Compute private key d
d = mod_inverse(e, phi)

# 4. Decrypt ciphertext
m = pow(c, d, N)

# 5. Convert back to bytes
flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
print("[+] Flag:", flag.decode(errors="ignore"))
```

Running the solver produced:

```console
$ python3 solver.py
[+] Factors: {8269102763695880823611: 1, 5430897953231074212767: 1, 6535332035423657364551: 1}
[+] Flag: g3n1uS_m4th3MAT1K_D1lUp4k4N
```

## Flag

```text
3108{g3n1uS_m4th3MAT1K_D1lUp4k4N}
```

## Key Takeaway

RSA depends on the difficulty of factoring its modulus. Here, the generated primes were small enough for `factorint()` to recover all three factors, after which the standard RSA private-key calculation revealed the plaintext.
