---
slug: "hackthebox/sherlocks/htb-sherlock-kitsunehook"
event: "hack-the-box-sherlocks"
title: "HTB Sherlock KitsuneHook"
summary: "Threat intelligence attribution exercise tracing a Winnti/APT41 campaign (RevivalStone and Operation CuckooBees) across vendor reporting, MITRE ATT&CK mappings, and malware tooling."
date: 2026-07-08
tags:
  - htb
  - sherlock
  - threat-intel
  - apt41
  - winnti
  - mitre-attack
  - malware-analysis
  - osint
category: "research"
difficulty: "info"
platform: "hackthebox"
draft: false
boxImage: "https://cdn.services-k8s.prod.aws.htb.systems/content/sherlocks/avatar/a1df7e83-5433-45af-9a13-a6692fff492c-1779812723.png"
---

**Scenario:** Threat Intelligence Analyst assignment. SOC detected suspicious activity targeting manufacturing and energy companies; the only lead is that **Winnti** is behind it. Goal: attribute the actor, map the campaign, and enumerate the tooling.

**Status:** All 15 tasks answered and verified against primary sources (LAC, Cybereason, MITRE ATT&CK). Two answers commonly gotten wrong (Task 8, Task 13) and one attribution trap (Task 1) are flagged below.

---

## Answer Key (TL;DR)

| # | Task | Answer |
|---|---|---|
| 1 | Primary APT designation (active since 2012) | **APT41** (MITRE G0096) |
| 2 | Symantec's name for the group | **Blackfly** |
| 3 | Campaign vs. manufacturing/materials/energy | **RevivalStone** |
| 4 | Security-contractor leak (Linux controller) | **i-Soon leak** (aka Anxun leak) |
| 5 | Geology-themed Linux C2 control panel | **TreadStone** |
| 6 | Latest malware version designation in samples | **StoneV5** (→ Winnti v5.0) |
| 7 | Initial-access vulnerability type | **SQL injection (SQLi)** |
| 8 | Third web shell (besides China Chopper, Behinder) | **sqlmap file uploader** |
| 9 | Behinder key = first 16 chars of MD5 of… | **rebeyond** |
| 10 | Malware using MS Graph API for email C2 | **CUNNINGPIGEON** |
| 11 | Loader + kernel rootkit | **PRIVATELOG** (loader) → **WINNKIT** (rootkit) |
| 12 | Service abused for DLL side-loading (TSMSISrv.dll) | **SessionEnv** |
| 13 | AES mode for DAT file decryption | **OFB** (Output Feedback) |
| 14 | 2021 campaign (prntvpt.dll timestamps) | **Operation CuckooBees** |
| 15 | Rootkit sound/hardware device object | **`\Device\Beep`** |

---

## Detailed Findings

### Task 1 — APT designation number

**Answer: APT41 (MITRE ATT&CK G0096)**

The wording _"active since at least 2012"_ is the exact descriptor on APT41's MITRE page. This is a deliberate disambiguation clue: MITRE dates the **Winnti Group (G0044) to 2010**, and **APT41 (G0096) to 2012**. Since the question pins 2012, the intended answer is APT41. RevivalStone's actor is assessed as a subset of APT41.

> **Trap:** It is easy to answer `G0044` because the scenario keeps saying "Winnti." The date clue rules that out. Winnti Group is a cluster that overlaps with / is tracked under APT41.

- https://attack.mitre.org/groups/G0096/ (APT41 — "Active since at least 2012")
- https://attack.mitre.org/groups/G0044/ (Winnti Group — "active since at least 2010")

### Task 2 — Symantec's name

**Answer: Blackfly**

Vendor name-mapping for this actor: Symantec = **Blackfly**, Trend Micro = Earth Freybug, Cybereason = Operation CuckooBees, Microsoft = Brass Typhoon (formerly BARIUM), Mandiant = APT41 / Wicked Panda.

- https://thehackernews.com/2025/02/winnti-apt41-targets-japanese-firms-in.html
- https://attack.mitre.org/groups/G0044/ (MITRE lists Blackfly as a G0044 alias)

### Task 3 — Campaign name

**Answer: RevivalStone**

LAC (Japanese security firm) named the March 2024 campaign targeting Japanese manufacturing, materials, and energy companies **RevivalStone**. It also overlaps with Earth Freybug (Trend Micro) and Operation CuckooBees (Cybereason).

- https://www.lac.co.jp/lacwatch/report/20250213_004283.html (primary)
- https://thehackernews.com/2025/02/winnti-apt41-targets-japanese-firms-in.html

### Task 4 — Contractor leak

**Answer: i-Soon leak (aka Anxun / Anxun Information Technology leak)**

Internal documents from Chinese security contractor **i-Soon** were uploaded to GitHub in Feb 2024. They exposed a Linux malware control panel (TreadStone) tied to the Winnti toolset, giving rare visibility into China's private-sector hacking industry.

- https://www.lac.co.jp/lacwatch/report/20250213_004283.html
- https://thehackernews.com/2025/02/winnti-apt41-targets-japanese-firms-in.html

### Task 5 — Linux C2 control panel (geology-themed codename)

**Answer: TreadStone**

**TreadStone** is a controller engineered to manage the Winnti malware ecosystem. LAC found references to it in RevivalStone; it also appeared in the i-Soon leak as a Linux malware control panel, and was named in the 2019 U.S. grand jury indictment of Chengdu 404 employees. ("Stone" = the geology theme.)

- https://www.lac.co.jp/lacwatch/report/20250213_004283.html
- https://thehackernews.com/2025/02/winnti-apt41-targets-japanese-firms-in.html

### Task 6 — Version designation

**Answer: StoneV5 (indicating Winnti v5.0)**

LAC found the string **StoneV5** in the samples, interpreted as **Winnti v5.0** — the latest iteration, featuring improved obfuscation, updated encryption, and enhanced evasion.

- https://www.lac.co.jp/lacwatch/report/20250213_004283.html

### Task 7 — Initial-access vulnerability

**Answer: SQL injection (SQLi)**

The attack chain began with a **SQL injection** vulnerability in a public-facing ERP system, allowing web shell deployment.

- https://thehackernews.com/2025/02/winnti-apt41-targets-japanese-firms-in.html
- https://www.lac.co.jp/lacwatch/report/20250213_004283.html

### Task 8 — Third web shell

**Answer: sqlmap file uploader**

The trio dropped after the ERP SQLi was **China Chopper, Behinder (IceScorpion), and the sqlmap file uploader**. Since the initial access vector was SQL injection, sqlmap's file-upload functionality is the logical third shell.

> **Correction:** Common wrong answers are _Godzilla_ and _b374k_ — both are hallucinations. Multiple independent outlets citing the LAC report explicitly list "sqlmap file uploader."

- https://cybersecuritynews.com/winnti-hackers-attacking-japanese-organizations/
- https://securityaffairs.com/174353/apt/china-linked-apt-group-winnti-targets-japanese-orgs.html
- https://gbhackers.com/winnti-hackers-attacking-japanese-organisations/

### Task 9 — Behinder hardcoded key word

**Answer: rebeyond**

Behinder (Bingxia / IceScorpion) uses a default AES key that is the first 16 chars of the MD5 hash of **"rebeyond"** (the tool's author), producing key `e45e329feb5d925b`.

- General Behinder/IceScorpion analysis (default key `md5("rebeyond")[:16]`), corroborated across web shell IR references.

### Task 10 — Graph API email C2 malware

**Answer: CUNNINGPIGEON**

**CUNNINGPIGEON** abuses the Microsoft Graph API to fetch commands from email messages, supporting file management and proxy operations.

- https://threats.wiz.io/all-incidents/revivalstone-campaign-by-winnti
- https://firexcore.com/blog/winnti-apt41-revivalstone/

### Task 11 — Loader + kernel rootkit

**Answer: Loader = PRIVATELOG, Rootkit = WINNKIT** (RAT in between = DEPLOYLOG)

The Winnti multi-stage chain: **PRIVATELOG** (loader) extracts and deploys **DEPLOYLOG** (the RAT / user-mode agent), which in turn installs **WINNKIT**, the kernel-level rootkit. WINNKIT is signed with a stolen (BenQ) certificate to bypass Driver Signature Enforcement and hooks TCP/IP by talking directly to the NIC.

Full chain: STASHLOG → SPARKLOG → PRIVATELOG → DEPLOYLOG → WINNKIT.

- https://www.cybereason.com/blog/operation-cuckoobees-a-winnti-malware-arsenal-deep-dive
- https://www.csoonline.com/article/572667/chinese-apt-group-winnti-stole-trade-secrets-in-years-long-undetected-campaign.html

### Task 12 — Service abused for DLL side-loading

**Answer: SessionEnv**

The malware persists via the **SessionEnv** service (Remote Desktop Configuration), which side-loads the malicious **TSMSISrv.dll**. LAC observed legitimate DLLs (e.g. `SessEnv.dll`) replaced with malicious counterparts to load the Winnti Loader.

- https://securityaffairs.com/174353/apt/china-linked-apt-group-winnti-targets-japanese-orgs.html
- https://cybercory.com/2025/02/18/revivalstone-campaign-unmasking-winnti-groups-latest-assault-on-japanese-organizations/

### Task 13 — AES mode for DAT decryption

**Answer: OFB (Output Feedback)**

DAT files are encrypted with AES + ChaCha20; keys are derived from the victim's IP address, MAC address, and network interface GUID. The AES decryption routine uses **OFB (Output Feedback) mode** with multiple SHA256 hash calculations.

> **Correction:** Common wrong answer is _AES-256-CBC_. LAC's report specifies **OFB**. (OFB turns AES into a stream cipher — no padding — which is why malware authors favor it for variable-length config blobs.)

- https://cybersecuritynews.com/winnti-hackers-attacking-japanese-organizations/

### Task 14 — 2021 campaign (prntvpt.dll)

**Answer: Operation CuckooBees**

The `prntvpt.dll` samples (May 12, 2021 and Aug 17, 2021) map to **Operation CuckooBees**, Cybereason's 2021 investigation of Winnti/APT41. In that chain, SPARKLOG drops PRIVATELOG as `prntvpt.dll` into the print-spooler drivers directory and abuses the PrintNotify service to side-load it.

- https://www.cybereason.com/blog/operation-cuckoobees-cybereason-uncovers-massive-chinese-intellectual-property-theft-operation
- https://www.cybereason.com/blog/operation-cuckoobees-a-winnti-malware-arsenal-deep-dive

### Task 15 — Rootkit sound/hardware device object

**Answer: `\Device\Beep`**

To detect whether the rootkit is already running, the loader (DEPLOYLOG) first tries to open a handle to the Beep device object — full form **`\\?\GLOBALROOT\Device\Beep`** — then sends a custom IOCTL. If that fails it falls back to `\Device\Null`. `\Device\Beep` is the PC-speaker/beeper, i.e. the hardware-level sound device. The two device strings in LAC's `Winnti_Rootkit` YARA rule are `\Device\Beep` and `\Device\Null`.

- https://www.cybereason.com/blog/operation-cuckoobees-a-winnti-malware-arsenal-deep-dive

---

## Analyst Note — Two Campaigns, One Actor

These tasks intentionally blend **two campaigns** by the same actor. Keep them separate to avoid mis-attributing IOCs:

| | **RevivalStone** (2024) | **Operation CuckooBees** (2021) |
|---|---|---|
| Reporter | LAC | Cybereason |
| Targets | Japanese manufacturing / materials / energy | Global tech & manufacturing IP |
| Initial access | SQLi in ERP | RCE in ERP + JSP web shells |
| Malware version | Winnti v5.0 / StoneV5 | — |
| Shared components | PRIVATELOG, DEPLOYLOG, WINNKIT, Winnti rootkit | PRIVATELOG, DEPLOYLOG, WINNKIT, Spyder Loader |

Tasks 11 and 15 draw on the CuckooBees deep-dive (component chain + device objects); Tasks 3–13 are RevivalStone-specific.

---

## Sources (by authority)

**Primary**

- LAC Watch — RevivalStone (original report): https://www.lac.co.jp/lacwatch/report/20250213_004283.html
- Cybereason — Operation CuckooBees (overview): https://www.cybereason.com/blog/operation-cuckoobees-cybereason-uncovers-massive-chinese-intellectual-property-theft-operation
- Cybereason — CuckooBees malware arsenal deep-dive: https://www.cybereason.com/blog/operation-cuckoobees-a-winnti-malware-arsenal-deep-dive
- MITRE ATT&CK — APT41 (G0096): https://attack.mitre.org/groups/G0096/
- MITRE ATT&CK — Winnti Group (G0044): https://attack.mitre.org/groups/G0044/

**Strong secondaries**

- The Hacker News: https://thehackernews.com/2025/02/winnti-apt41-targets-japanese-firms-in.html
- CybersecurityNews: https://cybersecuritynews.com/winnti-hackers-attacking-japanese-organizations/
- GBHackers: https://gbhackers.com/winnti-hackers-attacking-japanese-organisations/
- CSO Online (WINNKIT/DEPLOYLOG detail): https://www.csoonline.com/article/572667/chinese-apt-group-winnti-stole-trade-secrets-in-years-long-undetected-campaign.html
- Security Affairs: https://securityaffairs.com/174353/apt/china-linked-apt-group-winnti-targets-japanese-orgs.html

**Context / summaries**

- Wiz Threat Landscape: https://threats.wiz.io/all-incidents/revivalstone-campaign-by-winnti
- FireXCore: https://firexcore.com/blog/winnti-apt41-revivalstone/
- Cybercory: https://cybercory.com/2025/02/18/revivalstone-campaign-unmasking-winnti-groups-latest-assault-on-japanese-organizations/
- SC World: https://www.scworld.com/brief/winnti-attacks-set-sights-on-japan
