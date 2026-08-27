---
slug: "local-ctf/bahtera-3108-2025/malayan-heroine"
event: "bahtera-3108-2025"
title: "Malayan Heroine"
summary: "Use the nickname You Loy-De to identify a Malayan heroine, then research her children to construct the flag."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - osint
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Malayan Heroine

## Challenge Overview

- **Event:** Bahtera 3108 2025
- **Category:** OSINT
- **Points:** 100

The challenge supplied two clues:

> Her husband's nickname was “You Loy-De”.

```text
3108{the heroine daughter}
```

Spaces were to be replaced with underscores.

## Identifying the Heroine

Searching for the nickname led to [Sybil Kathigasu](https://en.wikipedia.org/wiki/Sybil_Kathigasu). The source states that the local Chinese community knew her husband, Dr. Kathigasu, by the Hakka nickname **You Loy-De**.

![You Loy-De nickname clue in the Sybil Kathigasu article](/images/writeups/local-ctf/bahtera-3108-2025/malayan-heroine/you-loy-de-clue.png)

## Finding Her Daughter

The family information listed the following children:

1. William Pillay (25 October 1918), adopted
2. Michael Kathigasu (26 August 1919), who died 19 hours after birth
3. Olga Kathigasu (26 February 1921 – 6 September 2014)
4. Dawn Kathigasu (21 September 1936 – unknown), who married William Bruce Spalding in London on 1 September 1956 and later had children

Using the heroine's daughter named in the source and replacing the space with an underscore produced the recorded flag.

## Flag

```text
3108{Dawn_Kathigasu}
```
