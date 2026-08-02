---
slug: "international-ctf/umassctf2026/ninja-nerds"
event: "umassctf-2026"
title: "Ninja Nerds"
summary: "UMassCTF 2026 umassctf2026, forensics writeup covering Ninja Nerds with analysis, solution steps, and final recovery notes."
date: 2026-04-13
tags:
  - ctf
  - umassctf2026
  - forensics
category: "international-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://ctftime.org/media/cache/79/b7/79b74059c595f25e04e10771c11c039d.png"
---
This write-up covers the **Ninja-Nerds** challenge from UMassCTF 2026. The challenge initially appears to be a typical steganography problem, but it is designed to mislead solvers with multiple false positives and noisy outputs.

## Challenge Overview

- **Category:** Forensics
- **Difficulty:** Medium
- **Given:** `challenge.png`

The goal is to extract the hidden flag from the provided image.

---

## Initial Analysis

First, basic file inspection was performed:

```bash
exiftool challenge.png
pngcheck -v challenge.png
````

Results:

- Valid PNG file

- No suspicious metadata

- No hidden chunks (`tEXt`, `zTXt`, etc.)


---

## Binwalk Analysis

```bash
binwalk challenge.png
```

Output showed:

- PNG header

- Zlib compressed data

- Suspicious `JBOOT STAG` signature (likely false positive)


At this stage, no direct extraction was possible.

---

## Zsteg Enumeration

Using `zsteg` for LSB-based analysis:

```bash
zsteg -a challenge.png
```

This produced many results such as:

- OpenPGP keys

- MPEG data

- Zlib compressed streams

- WBStego-like structure


However, most of these were **false positives**.

> This is a common anti-analysis technique where challenges intentionally generate noisy outputs.
> {: .prompt-warning }

---

## False Lead: WBStego

One notable output:

```
wbStego size=0x676e
```

But:

```
hdr=nil enc=nil controlbyte=nil
```

This indicates:

- Structure resembles WBStego

- But **not a valid implementation**


Conclusion:

> ❌ WBStego path is a decoy

---

## False Lead: Zlib Extraction

Attempted extraction:

```bash
zsteg challenge.png -E b7,b,lsb,Xy,prime > zlib_candidate.bin
```

Followed by decompression attempts:

```python
zlib.decompress(...)
```

Result:

- No successful decompression


Conclusion:

> ❌ Zlib stream is either corrupted or misinterpreted

---

## Key Insight

At this point:

- No valid file carving

- No working decompression

- No password-based extraction


This strongly suggests:

> 🔍 The data is hidden using **raw bit-level encoding**, not a standard stego tool.

---

## Final Approach: Manual Bit Extraction

Instead of relying on tools, we directly extracted bits from pixel data.

### Python Script

```python
from PIL import Image
import numpy as np

img = Image.open("challenge.png")
arr = np.array(img)

# Flatten blue channel
ch = arr[:,:,2].flatten()

# Extract LSB (bit 0)
bits = ''.join(format(p & 1, '01b') for p in ch)

# Convert bitstream to bytes
out = bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-8,8))

# Search for flag
idx = out.lower().find(b'umass')
if idx != -1:
    print(out[idx:idx+60])
```

---

## Flag Found

Output:

```
UMASS{perfectly-hidden-ready-to-strike}
```

---

## Explanation

- Data was hidden in the **least significant bit (LSB)**

- Specifically in the **blue channel**

- Stored as a **continuous bitstream**

- No encryption, no compression

- Just raw ASCII encoded in bits


---

## Why Tools Failed

|Tool|Reason|
|---|---|
|`zsteg`|Produced noisy false positives|
|`binwalk`|Misidentified patterns|
|`zlib`|Not actually compressed|
|`OpenStego`|Not used in challenge|

---

## Key Takeaways

- Not all `zsteg` outputs are valid — verify structure

- High entropy does not always mean encryption

- Always consider **manual bit extraction**

- LSB stego can be implemented without standard tools


> Sometimes the simplest encoding is hidden behind the most noise.
> {: .prompt-tip }

---
## References

Full analysis and command history available in the working notes:

---

## Final Flag

```
UMASS{perfectly-hidden-ready-to-strike}
