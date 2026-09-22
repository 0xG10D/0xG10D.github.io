---
slug: "hackthebox/sherlocks/htb-sherlock-bft"
event: "hack-the-box-sherlocks"
title: "HTB Sherlock BFT"
summary: "MFT (Master File Table) forensics with MFTECmd and TimeLine Explorer, tracing a phishing ZIP download through to the malicious stager file that connected to a C2 server."
date: 2026-08-20
tags:
  - htb
  - sherlock
  - dfir
  - mft
  - mftecmd
  - timeline-explorer
  - hex-editor
  - windows-forensics
category: "forensics"
difficulty: "easy"
platform: "hackthebox"
draft: false
boxImage: "https://cdn.services-k8s.prod.aws.htb.systems/content/sherlocks/avatar/9e4d9103-ce4d-4e57-b145-e8404e7accc2.png"
---

## Sherlock Scenario

**Sherlock Overview:**

In this Sherlock, you will become acquainted with MFT (Master File Table) forensics. You will be introduced to well-known tools and methodologies for analyzing MFT artifacts to identify malicious activity. During the analysis, the MFTECmd tool is used to parse the provided MFT file, TimeLine Explorer is used to open and analyze the results from the parsed MFT, and a hex editor is used to recover file contents from the MFT.

**Tools Used:**

- MFTECmd
- TimeLine Explorer
- HxD Hex Editor

```text
MFTECmd.exe -f "C:\Users\CyberJunkie\Desktop\C\$MFT" --csv "C:\Users\CyberJunkie\Desktop\" --csvf MFT_ANALYSIS.csv
```

The above command processes the MFT file located in `C:\Users\CyberJunkie\Desktop\C` and creates a CSV file named `MFT_ANALYSIS.csv` on the Desktop of the user `CyberJunkie`.

_Note: You will need to replace the file paths with your own._

Next, open the CSV file in TimeLine Explorer to begin the analysis.

Setup MFTECmd.exe and install file evidence and tools.

---

## Task 1

**Question:** Simon Stark was targeted by attackers on February 13. He downloaded a ZIP file from a link received in an email. What was the name of the ZIP file he downloaded from the link?

### Answer

```text
Stage-20240213T093324Z-001.zip
```

---

## Task 2

**Question:** Examine the Zone Identifier contents for the initially downloaded ZIP file. This field reveals the HostUrl from where the file was downloaded, serving as a valuable Indicator of Compromise (IOC) in our investigation/analysis. What is the full Host URL from where this ZIP file was downloaded?

### Answer

```text
hxxps[://]storage[.]googleapis[.]com/drive-bulk-export-anonymous/20240213T093324[.]039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser
```

---

## Task 3

**Question:** What is the full path and name of the malicious file that executed malicious code and connected to a C2 server?

### Answer

```text
.\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice\invoices
```

---

## Task 4

**Question:** Analyze the `$Created0x30` timestamp for the previously identified file. When was this file created on disk?

### Answer

```text
2024-02-13 16:38:39
```

---

## Task 5

**Question:** Finding the hex offset of an MFT record is beneficial in many investigative scenarios. Find the hex offset of the stager file from Question 3.

Source notes for this task end before an answer was recorded.

### Answer

Not recorded in the source notes.

---

## Note on Missing Evidence

The original notes referenced four screenshots (Obsidian embeds) documenting each task's TimeLine Explorer / hex editor view. Those attachment files were not present in the vault at import time, so they are omitted here rather than fabricated. See the validation report for the exact missing filenames.
