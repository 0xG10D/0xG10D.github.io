---
slug: "local-ctf/bahtera-3108-2025/commander"
event: "bahtera-3108-2025"
title: "COMMANDer"
summary: "Bahtera 3108 2025 web writeup for COMMANDer, inspecting the pilihan API response and submitting the recovered command to the check endpoint."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - web-exploitation
  - api
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Challenge Overview

- **Challenge:** COMMANDer
- **Category:** Web
- **Points:** 100

> Terminal lama ini menyimpan biodata seseorang bersama rahsianya. Namun, rahsia itu hanya akan terbuka kepada mereka yang tahu menggunakan arahan yang tepat. Mampukah anda menguasai terminal ini untuk membongkar kebenaran?

![COMMANDer terminal page](/images/writeups/local-ctf/bahtera-3108-2025/commander/terminal-page.png)

![COMMANDer terminal interaction](/images/writeups/local-ctf/bahtera-3108-2025/commander/terminal-interaction.png)

## Inspect the API

Open the browser's developer tools, select the **Network** tab, refresh the page, and inspect the request to `/api/pilihan`. The required value is present in its JSON response.

![The api-pilihan JSON response](/images/writeups/local-ctf/bahtera-3108-2025/commander/api-pilihan-response.png)

## Submit the Command

Send the recovered command to `/api/check` as JSON:

```bash
curl -s -X POST http://<TARGET>/api/check \
  -H "Content-Type: application/json" \
  -d '{"command":"RAHSIA: OperationOatmeal","step":1}'
```

![COMMANDer flag response](/images/writeups/local-ctf/bahtera-3108-2025/commander/flag-response.png)

## Flag

```text
3108{0p3R4T10n_O@Tm34l_1bR4h1M_1sM@1L}
```
