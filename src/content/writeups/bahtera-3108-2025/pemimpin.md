---
slug: "local-ctf/bahtera-3108-2025/pemimpin"
event: "bahtera-3108-2025"
title: "Pemimpin"
summary: "Bahtera 3108 2025 web writeup for Pemimpin, completing the Malaysian prime-minister identification quiz and reviewing the answers to reveal the flag."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - web-exploitation
  - quiz
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Challenge Overview

- **Challenge:** Pemimpin
- **Category:** Web
- **Points:** 100
- **Historical challenge URL:** `https://pemimpin.bahterasiber.my/`

> Perdana Menteri merupakan ketua kerajaan Malaysia dan memainkan peranan penting dalam menentukan hala tuju negara dan memastikan tanah air terus melangkah ke arah pembangunan serta kesejahteraan rakyat sejak detik kemerdekaan. Persoalannya, adakah anda kenal siapa mereka semua?

![Pemimpin challenge page](/images/writeups/local-ctf/bahtera-3108-2025/pemimpin/challenge-page.png)

## Solution

Work through the quiz and identify the Malaysian prime ministers shown by the application.

![Pemimpin quiz screen one](/images/writeups/local-ctf/bahtera-3108-2025/pemimpin/quiz-screen-01.png)

![Pemimpin quiz screen two](/images/writeups/local-ctf/bahtera-3108-2025/pemimpin/quiz-screen-02.png)

![Pemimpin quiz screen three](/images/writeups/local-ctf/bahtera-3108-2025/pemimpin/quiz-screen-03.png)

After answering the questions, go back and select **Semak Semula** to reveal the result.

![Pemimpin completed result](/images/writeups/local-ctf/bahtera-3108-2025/pemimpin/completed-result.png)

## Flag

```text
3108{p3m1mp1n_m4l4y5I4}
```
