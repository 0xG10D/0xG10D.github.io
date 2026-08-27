---
slug: "local-ctf/bahtera-3108-2025/komik"
event: "bahtera-3108-2025"
title: "Komik"
summary: "Bahtera 3108 2025 miscellaneous writeup for Komik, using Unicode steganography to recover the hidden flag from a short text passage."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - miscellaneous
  - steganography
  - unicode
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Challenge Overview

- **Challenge:** Komik
- **Category:** Miscellaneous
- **Points:** 100

> Dalam ni ada Flag, tinggal copy paste dan ____ je.

The challenge pointed to [dCode](https://www.dcode.fr/) and provided a file named `Komik.txt` containing this passage:

```text
Korang‌‌‌‌‌﻿‌﻿ tau tak ‌‌‌‌‌﻿‌‍pasal ‌‌‌‌‌﻿‌‌buku yang‌‌‌‌‌﻿‬‌ bertajuk Fried‌‌‌‌‍﻿‬﻿ ‌‌‌‌‍‬‍‍Rice ‌‌‌‌‌﻿‌‍‌‌‌‌‍﻿‌﻿dari Erica Eng? ‌‌‌‌‍‬﻿‬‌‌‌‌‍‬‍‍buku ni‌‌‌‌‍﻿‌‬ dapat anugerah Eisner‌‌‌‌‍‍﻿﻿. Nak tahu gempak tak gempak‌‌‌‌‍﻿‌‬ ‌‌‌‌‌﻿‌‍boleh katakan ‌‌‌‌‍‬‌﻿anugerah ‌‌‌‌‌﻿‌﻿eisner ni‌‌‌‌‍‍﻿﻿ macam‌‌‌‌‍‬‌‬ anugerah oscar‌‌‌‌‌﻿‌‌ tapi‌‌‌‌‌﻿‌‌‌‌‌‌‍‬‬﻿ dalam industri komik‌‌‌‌‍﻿﻿‍. Kalau korang minat boleh lah beli, tah mahal pun dalam bawah RM40 camtu.
```

## Solution

The text contains invisible Unicode characters. Paste the full passage into the [Unicode Steganography decoder](https://330k.github.io/misc_tools/unicode_steganography.html) to reveal the concealed message.

![Unicode steganography decoder output](/images/writeups/local-ctf/bahtera-3108-2025/komik/unicode-steganography-decoder.png)

## Flag

```text
3108{e1sner_r1c3_b00k}
```
