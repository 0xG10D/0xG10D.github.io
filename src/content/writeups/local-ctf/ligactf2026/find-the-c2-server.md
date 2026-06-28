---
title: "Find The C2 Server"
summary: "LigaCTF 2026 ligactf2026, forensics, reverse engineering writeup covering Find The C2 Server with analysis, solution steps, and final recovery notes."
date: 2026-05-31
tags:
  - ctf
  - ligactf2026
  - forensics
  - reverse-engineering
  - malware-analysis
  - mobile
  - network
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://owasp.org/www-chapter-kuala-lumpur/owaspmy.jpeg"
---
## Challenge Info

**Challenge:** Find the C2 Server
**Category:** Mobile / Malware Analysis
**Difficulty:** Medium
**Flag Format:** `OWASPKL{xxx}`

## Description

The challenge provides a malicious APK. The goal is to identify the C2 server contacted by the application and retrieve the flag.

## Methodology

The APK was analyzed using static analysis only. The file was not executed because it was described as malicious.

## Step 1: Extract APK Content

```bash
mkdir apk_out
unzip -q malapk.apk -d apk_out
```

APK files are ZIP archives, so extracting the file allows inspection of resources, DEX files, and metadata.

## Step 2: Search for Network Indicators

```bash
strings -a malapk.apk | grep -Ei 'http|https|c2|server|liga|appsecmy|OWASPKL'
```

This revealed a suspicious URL split into parts:

```text
https://appsecmy.com/
pages/liga-ctf-2026
```

After combining both parts, the C2 endpoint becomes:

```text
https://appsecmy.com/pages/liga-ctf-2026
```

## Step 3: Inspect the C2 Page

The C2 page was downloaded and inspected:

```bash
curl -s https://appsecmy.com/pages/liga-ctf-2026 | grep -i OWASPKL
```

This revealed a hidden HTML comment near the bottom of the page.

## Step 4: Extract the Flag

The HTML comment contains:

```html
<!-- OWASPKL{https://chat.whatsapp.com/KAdpus4R0pb895ulC2jo8p} This is the FL4G. But feel free to join our Community Group-->
```

Therefore, the real flag is:

```text
OWASPKL{https://chat.whatsapp.com/KAdpus4R0pb895ulC2jo8p}
```

## Decoy Flag

A fake flag was also found:

```text
OWASPKL{n0t_A_Fl4g}
```

This was a decoy and should not be submitted.

## Final Answer

**C2 Server:**

```text
https://appsecmy.com/pages/liga-ctf-2026
```

**Flag:**

```text
OWASPKL{https://chat.whatsapp.com/KAdpus4R0pb895ulC2jo8p}
```
