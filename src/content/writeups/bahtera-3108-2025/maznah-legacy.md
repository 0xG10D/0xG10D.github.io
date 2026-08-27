---
slug: "local-ctf/bahtera-3108-2025/maznah-legacy"
event: "bahtera-3108-2025"
title: "Maznah Legacy"
summary: "Reverse the kunci_diraja validation routine and brute-force its printable input characters to recover the accepted flag."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - reverse-engineering
  - python
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Maznah Legacy

## Challenge Overview

- **Event:** Bahtera 3108 2025
- **Category:** Reverse Engineering
- **Points:** 100
- **Provided materials:** `kunci_diraja` and `output.txt`

> Iron Lady? Adakah itu Iron Man versi wanita? 🤔 Ataupun sebenarnya tokoh lain yang cukup terkenal di Malaysia?
>
> Hanya dengan bedah program ini, anda akan tahu kebenarannya disebalik sosok misteri tersebut...

The challenge directory contained the binary, an IDA database, the text output, and the solver created during analysis.

![Maznah Legacy challenge files](/images/writeups/local-ctf/bahtera-3108-2025/maznah-legacy/challenge-files.png)

The values in `output.txt` were:

```text
[93, 92, 92, 101, 42, 0, 100, 29, 18, 9, 35, 29, 34, 45, 24, 10, 45, 107, 35, 112, 50, 111, 51, 33, 7, 45, 55, 121, 49, 123, 40, 15, 54, 123, 59, 125, 60, 57, 78]
```

## Analyzing the Binary

I opened `kunci_diraja` in IDA and inspected the decompiled `main` function. The program processes each character of the supplied argument together with its index and compares the calculated result with the corresponding value in a 39-byte target array.

![IDA decompilation of the kunci_diraja main function](/images/writeups/local-ctf/bahtera-3108-2025/maznah-legacy/ida-main-decompilation.png)

Because the validation operation is deterministic, I reversed it by trying every printable ASCII character for each target value. The following decoder reproduces the calculation from the decompiled program and keeps the character whose result matches:

```python
key = [
    93, 92, 92, 101, 42, 0, 100, 29, 18, 9,
    35, 29, 34, 45, 24, 10, 45, 107, 35, 112,
    50, 111, 51, 33, 7, 45, 55, 121, 49, 123,
    40, 15, 54, 123, 59, 125, 60, 57, 78,
]


def reverse_char(v9, i):
    # Brute-force all printable ASCII
    for c in range(32, 127):
        v8 = (33818641 * (c + i + 42)) >> 32
        v9_calc = c + i + 42 - 127 * (
            (v8 + ((c + i + 42 - v8) >> 1)) >> 6
        )
        if v9_calc == v9:
            return chr(c)
    return "?"  # fallback if no match


result = "".join(reverse_char(k, i) for i, k in enumerate(key))
print("Recovered input:", result)
```

I saved the script as `decoder.py` and ran it with Python 3:

```bash
python3 decoder.py
```

The decoder returned:

```text
Recovered input: 3108{P4k_Ungku_Pr0f3s0r_Dir4j4_Ek0n0mi}
```

## Flag

```text
3108{P4k_Ungku_Pr0f3s0r_Dir4j4_Ek0n0mi}
```
