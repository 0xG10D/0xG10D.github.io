---
slug: "hackthebox/machines/sample-htb-cicada-notes"
event: "hack-the-box-machines"
title: "Sample HTB Cicada Notes"
summary: "A clean example writeup showing frontmatter, commands, tables, images, code blocks, and Obsidian wikilinks."
date: 2026-06-18
tags: ["nmap", "smb", "windows", "active-directory"]
category: "active-directory"
difficulty: "easy"
platform: "hack-the-box"
draft: true
---

# Sample HTB Cicada Notes

This writeup is a publishing test case for 0xG10D blog. It demonstrates headings,
frontmatter, Bash commands, PowerShell commands, Python code, tables, blockquotes,
images, and Obsidian wikilinks such as [[sample-htb-cicada-notes|this internal writeup link]].

## Lab Scope

The target is a retired-style lab scenario used to validate the publishing workflow.
The goal is to show a clean writeup structure, not to disclose an active-box solution.

| Item | Value |
| --- | --- |
| Platform | Hack The Box |
| Category | Active Directory |
| Difficulty | easy |
| Goal | Enumeration, evidence capture, and privilege escalation notes |

> Keep CTF writeups structured around evidence. Commands are useful, but the reasoning is what makes the post valuable.

## Visual Notes

Obsidian image embeds work too. Store the image under
`public/images/writeups/sample-htb-cicada-notes/`, then reference it like this:

![[scan-overview.svg]]

## Enumeration

Start with a safe service scan and save output into a predictable folder.

```bash
mkdir -p scans
nmap -sC -sV -oN scans/initial.txt [REDACTED_TARGET_IP]
```

If SMB is open, enumerate shares and anonymous access.

```powershell
net view \\[REDACTED_TARGET_IP] /all
```

## Python Helper

Small scripts are easier to review when they are short and named by purpose.

```python
from pathlib import Path

for line in Path("scans/initial.txt").read_text().splitlines():
    if "open" in line:
        print(line)
```

## Findings

| Port | Service | Note |
| --- | --- | --- |
| 53 | DNS | Domain controller signal |
| 88 | Kerberos | AD authentication |
| 445 | SMB | Share enumeration target |

The finding table should stay short. Put raw output in fenced code blocks, then explain
why the service matters.

## Privilege Escalation Notes

Document every assumption before running exploit tooling. For example:

1. Confirm the user context.
2. Check group memberships.
3. Capture exact command output.
4. Explain why the path works.

## Lessons Learned

Use frontmatter as the control plane for filters. If `difficulty` is written as `Easy`
instead of `easy`, the build fails so the taxonomy stays clean.

Use `draft: true` while a writeup is still being cleaned up. Flip it to `draft: false`
only when the post is ready to appear on the writeups page and receive its own route.
