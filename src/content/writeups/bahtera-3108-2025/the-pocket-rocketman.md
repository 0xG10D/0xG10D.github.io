---
slug: "local-ctf/bahtera-3108-2025/the-pocket-rocketman"
event: "bahtera-3108-2025"
title: "The Pocket Rocketman"
summary: "Bahtera 3108 2025 cryptography writeup covering RSA with consecutive close primes, Fermat factorization, and plaintext recovery."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - cryptography
  - rsa
  - fermat-factorization
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Challenge Overview

Azizulhasni Awang, legenda lumba basikal trek Malaysia, digelar **The Pocket Rocketman** kerana tubuhnya kecil tetapi kuasanya luar biasa. Dalam perlumbaan keirin, strategi, ketepatan, dan fokus menjadi senjata utama beliau.

The supplied challenge document is available here: [The Pocket Rocketman challenge PDF](/images/writeups/local-ctf/bahtera-3108-2025/the-pocket-rocketman/the-pocket-rocketman.pdf).

![The Pocket Rocketman challenge document](/images/writeups/local-ctf/bahtera-3108-2025/the-pocket-rocketman/challenge-document.png)

The challenge uses RSA, but generates `q` as the next prime after `p`.

## Challenge Source

```python
from sympy import nextprime
from random import randint


def readFlag():
    with open("flag.txt", "r") as f:
        return f.readline().strip()


def main():
    size = 4096

    # Generate p near 2^size, then q as the next prime after p
    p = nextprime(randint(2**size, 2**(size + 1)))
    q = nextprime(p)

    n = p * q
    e = 65537

    print("n:", n)
    print("e:", e)

    flag = readFlag()
    message = int.from_bytes(flag.encode(), "big")

    ciphertext = pow(message, e, n)

    with open("output.txt", "w") as f:
        f.write(f"n: {n}\n")
        f.write(f"e: {e}\n")
        f.write(f"ciphertext: {ciphertext}\n")

    print("done output.txt")


if __name__ == "__main__":
    main()
```

The challenge output contained the large modulus `n`, the public exponent `e = 65537`, and the ciphertext:

![RSA modulus, exponent, and ciphertext](/images/writeups/local-ctf/bahtera-3108-2025/the-pocket-rocketman/rsa-output.png)

## Weakness and Solution

The key-generation line is the weakness:

```python
q = nextprime(p)
```

This guarantees that `p` and `q` are extremely close. Fermat factorization searches for two squares where:

```text
n = a^2 - b^2 = (a - b)(a + b)
```

Because the factors are close, the search begins near `sqrt(n)` and reaches the correct pair quickly. After recovering `p` and `q`, the usual RSA calculations recover `d` and decrypt the ciphertext.

The recorded solver run confirms that the 8194-bit modulus was factored using this method:

![Fermat factorization solver output](/images/writeups/local-ctf/bahtera-3108-2025/the-pocket-rocketman/fermat-solver-output.png)

```text
[*] n bit-length: 8194
[*] Starting Fermat factorization... (this should be fast for nextprime(p) scheme)
[+] Factored n
[*] Computed d.
[+] Flag (utf-8): 3108{Muh4mm4d_Az1zulH4sn1_Th3_P0ck3t_R0ck3tm4n_88}
```

## Flag

```text
3108{Muh4mm4d_Az1zulH4sn1_Th3_P0ck3t_R0ck3tm4n_88}
```

## Key Takeaway

Large RSA keys are not automatically secure. If the two primes are generated too close together, Fermat factorization can recover them efficiently even when the modulus is thousands of bits long.
