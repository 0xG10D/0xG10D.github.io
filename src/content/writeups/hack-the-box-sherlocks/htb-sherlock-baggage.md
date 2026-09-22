---
slug: "hackthebox/sherlocks/htb-sherlock-baggage"
event: "hack-the-box-sherlocks"
title: "HTB Sherlock Baggage"
summary: "Windows Shellbag analysis with SBECmd to reconstruct how an attacker searched for sensitive files, accessed a network share, staged the data, and compressed it for exfiltration."
date: 2026-09-09
tags:
  - htb
  - sherlock
  - dfir
  - shellbags
  - windows-registry
  - sbecmd
  - kape
  - powershell
  - data-exfiltration
category: "forensics"
difficulty: "easy"
platform: "hackthebox"
draft: false
boxImage: "https://cdn.services-k8s.prod.aws.htb.systems/content/sherlocks/avatar/a26e1014-0bf7-47bb-8f7b-ea251ad23d2d-1785935998.png"
---

## Introduction

Today I completed the **Baggage** Sherlock from Hack The Box.

This Sherlock is rated **Very Easy** and focuses mainly on **Windows Shellbag artifacts**.

The scenario is about a compromised Windows account where the attacker accessed sensitive folders, searched for important files, accessed a network share, staged collected data, and finally compressed it for possible exfiltration.

The main goal of this investigation was to reconstruct what the attacker did by analyzing Windows Registry artifacts.

---

# Challenge Information

**Platform:** Hack The Box
**Category:** Sherlock / DFIR
**Challenge:** Baggage
**Difficulty:** Very Easy
**Main Artifact:** Shellbags

---

# What Are Shellbags?

Before starting this challenge, one important term to understand is **Shellbags**.

Shellbags are Windows Registry artifacts created when a user browses folders using Windows Explorer.

They can contain information such as:

- Folder names
- Folder paths
- Network shares
- ZIP file contents
- USB/removable drive locations
- Folder interaction timestamps

Even if a folder is later deleted, Shellbag information may still remain inside the Registry.

This makes Shellbags useful in DFIR investigations because we can reconstruct where a user or attacker navigated.

---

# Important Registry Files

For this challenge, the important Registry hives were:

```text
NTUSER.DAT
UsrClass.dat
```

## NTUSER.DAT

`NTUSER.DAT` stores user-specific Windows Registry information.

It can contain artifacts related to:

- Explorer activity
- Recently used files
- Application usage
- User preferences
- Network locations

---

## UsrClass.dat

`UsrClass.dat` contains many Windows Explorer-related artifacts.

For Shellbag investigations, this file is especially useful because it contains the `BagMRU` and `Bags` structures.

Typical location:

```text
C:\Users\<username>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

---

# Tools Used

## KAPE

The evidence was collected using **KAPE**.

KAPE stands for:

```text
Kroll Artifact Parser and Extractor
```

It is commonly used in DFIR to quickly collect forensic artifacts from Windows systems.

From the provided acquisition log:

```text
--target RegistryHivesUser
```

KAPE collected Registry hives from the users:

```text
admin
steve
```

---

## SBECmd

The main tool I used for this challenge was **SBECmd** by Eric Zimmerman.

SBECmd parses Shellbag information from Windows Registry hives and exports the results into CSV files.

My version was:

```text
SBECmd 2026.5.0
```

---

## PowerShell

I also used PowerShell to:

- Search CSV output
- Filter Shellbag paths
- Check specific timestamps
- Search for ZIP files

---

# Starting the Investigation

The evidence contained Registry artifacts for multiple users.

The important directories included:

```text
C:\Users\admin
C:\Users\steve
```

At first, I parsed the `admin` user's `UsrClass.dat`.

I created an output folder:

```cmd
mkdir C:\Temp\shellbags
```

Then ran:

```cmd
SBECmd.exe -d "C:\Users\g01d\Desktop\Sherlock HTB\Baggage\C\Users\admin\AppData\Local\Microsoft\Windows" --csv "C:\Temp\shellbags"
```

SBECmd found:

```text
Total ShellBags found: 18
```

The output was:

```text
C:\Temp\shellbags\admin_UsrClass.csv
```

One important finding was that the `admin` Shellbags showed navigation into:

```text
C:\Users\steve
```

This made `steve` much more interesting for the investigation.

---

# Parsing Steve's Shellbags

I then parsed Steve's Registry files.

Because I was using PowerShell, executables in the current directory need `.\`.

Command:

```powershell
.\SBECmd.exe -d "C:\Users\g01d\Desktop\Sherlock HTB\Baggage\C\Users\steve" --csv "C:\Temp\steve_shellbags" --nl
```

SBECmd found:

```text
UsrClass.dat = 30 Shellbags
NTUSER.DAT   = 5 Shellbags
Total        = 35 Shellbags
```

The generated files were:

```text
steve_UsrClass.csv
steve_NTUSER.csv
```

This was where most of the useful evidence was found.

---

# Question 1 – What was the name of the archive file downloaded by the compromised account?

I searched the parsed Shellbag CSV files for archive extensions.

```powershell
Get-ChildItem "C:\Temp\steve_shellbags\*.csv" |
Select-String -Pattern '\.(zip|rar|7z)'
```

One of the results showed:

```text
Desktop\This PC\Downloads\1.zip
```

The important part is that the archive was located inside:

```text
Downloads
```

This strongly indicates that it was the downloaded archive mentioned in the question.

### Answer

```text
1.zip
```

---

# Question 2 – What utility did the attacker bring in to search for sensitive data?

While searching the Shellbag output, I found:

```text
Everything-1.4.1.1028.x64.zip
```

Path:

```text
C:\Users\steve\AppData\Local\Temp\Temp1_1.zip\1\Everything-1.4.1.1028.x64.zip
```

There was also Registry evidence referencing:

```text
C:\Users\steve\AppData\Local\Temp\Temp1_Everything-1.4.1.1028.x64.zip\everything.exe
```

## What is Everything?

**Everything** is a Windows file-search utility.

It can search filenames across a system extremely quickly.

For normal users it is useful, but an attacker can also use it to quickly search for files such as:

```text
password
vpn
backup
credentials
finance
confidential
```

### Answer

```text
Everything 1.4.1.1028
```

---

# Question 3 – When was the VPN folder accessed?

The sensitive VPN directory was:

```text
Desktop\This PC\Documents\OT Station 3 internal VPN
```

Initially, this question was slightly confusing because Shellbags contain several timestamps.

I used PowerShell to display all timestamps for the VPN path:

```powershell
Import-Csv "C:\Temp\steve_shellbags\steve_UsrClass.csv" |
Where-Object {$_.AbsolutePath -like '*OT Station 3 internal VPN*'} |
Select-Object AbsolutePath,ShellType,CreatedOn,ModifiedOn,AccessedOn,LastWriteTime,FirstInteracted,LastInteracted |
Format-List
```

The output showed:

```text
AbsolutePath    : Desktop\This PC\Documents\OT Station 3 internal VPN
ShellType       : Directory
CreatedOn       : 2025-09-03 07:10:58
ModifiedOn      : 2025-09-03 07:11:50
AccessedOn      : 2025-09-03 07:11:50
LastWriteTime   : 2025-09-03 07:31:05
FirstInteracted : 2025-09-03 07:31:05
LastInteracted  : 2025-09-03 07:31:05
```

The question specifically wanted the **Last Interacted** timestamp.

### What is LastInteracted?

`LastInteracted` represents the last time Windows Explorer interacted with that Shellbag entry.

This challenge taught me not to just choose any timestamp because fields such as:

```text
CreatedOn
AccessedOn
LastWriteTime
FirstInteracted
LastInteracted
```

can all contain different values.

### Answer

```text
2025-09-03 07:31:05
```

---

# Question 4 – What was the directory containing the victim's passwords?

Another suspicious directory was visible in Steve's Documents folder:

```text
Desktop\This PC\Documents\OnePassword MasterPass
```

The directory name clearly suggests that password-related information was stored there.

### Answer

```text
OnePassword MasterPass
```

---

# Question 5 – What network share did the attacker access?

Shellbags can also contain network locations.

The parsed data showed:

```text
Desktop\Computers and Devices\Prod-ns-2\Prod-ns-2\prodshare
```

The actual network location was:

```text
\\Prod-ns-2\prodshare
```

## What is a UNC Path?

UNC stands for:

```text
Universal Naming Convention
```

Windows uses UNC paths to access network resources.

The format usually looks like:

```text
\\SERVER\SHARE
```

For example:

```text
\\Prod-ns-2\prodshare
```

This means:

```text
Server = Prod-ns-2
Share  = prodshare
```

### Answer

```text
\\Prod-ns-2\prodshare
```

---

# Question 6 – When is the dam construction planned?

After accessing the network share, the attacker browsed:

```text
\\Prod-ns-2\prodshare\Construction 2027
```

Inside that folder was:

```text
Dam Construction Engineer Plans.zip
```

The directory name itself gives the planned year.

### Answer

```text
2027
```

---

# Question 7 – What archive file was present on the network share?

The Shellbag evidence showed:

```text
\\Prod-ns-2\prodshare\Construction 2027\Dam Construction Engineer Plans.zip
```

### Answer

```text
Dam Construction Engineer Plans.zip
```

---

# Question 8 – When was the archive from the network share accessed?

From the parsed Shellbag data, the network archive showed:

```text
Dam Construction Engineer Plans.zip
```

with:

```text
LastInteracted: 2025-09-03 07:34:04
```

### Answer

```text
2025-09-03 07:34:04
```

---

# Question 9 – What was the full path of the staging folder?

Later in the attacker's activity, Shellbags showed:

```text
C:\Users\steve\Pictures\a
```

The folder contained copies of sensitive directories including:

```text
Engineers Tab
OnePassword MasterPass
OT Station 3 internal VPN
```

This indicates that the attacker collected sensitive information into one location before compressing it.

### Answer

```text
C:\Users\steve\Pictures\a
```

---

# What is Data Staging?

**Data staging** is when an attacker collects files into one location before exfiltrating them.

For example:

```text
Sensitive folders
      ↓
C:\Users\steve\Pictures\a
      ↓
a.zip
      ↓
Possible exfiltration
```

Instead of stealing files one by one, the attacker gathers them together first.

---

# Question 10 – When was the exfiltration archive accessed?

After collecting the files into:

```text
C:\Users\steve\Pictures\a
```

the attacker compressed the directory into:

```text
C:\Users\steve\Pictures\a.zip
```

The Shellbag entry showed:

```text
Desktop\This PC\Pictures\a.zip
```

with:

```text
LastInteracted: 2025-09-03 07:34:30
```

### Answer

```text
2025-09-03 07:34:30
```

---

# What is Exfiltration?

**Data exfiltration** means transferring stolen information from the victim environment to somewhere controlled by the attacker.

Before exfiltration, attackers commonly compress files because it:

- Reduces the number of files
- Makes transferring easier
- Can reduce file size
- Makes collected data easier to manage

In this case, the activity looks like:

```text
Sensitive data discovered
        ↓
Sensitive directories accessed
        ↓
Network share accessed
        ↓
Files collected into staging folder
        ↓
C:\Users\steve\Pictures\a
        ↓
Compressed
        ↓
C:\Users\steve\Pictures\a.zip
        ↓
Prepared for exfiltration
```

---

# Reconstructed Attack Timeline

Based on the Shellbag evidence, the attacker's activity can roughly be reconstructed as:

```text
Attacker gains access to Steve's account
        ↓
Downloads 1.zip
        ↓
Brings in Everything search utility
        ↓
Searches for sensitive information
        ↓
Accesses sensitive folders
        │
        ├── Engineers Tab
        ├── OT Station 3 internal VPN
        └── OnePassword MasterPass
        ↓
Accesses network share
\\Prod-ns-2\prodshare
        ↓
Browses Construction 2027
        ↓
Finds Dam Construction Engineer Plans.zip
        ↓
Creates staging directory
C:\Users\steve\Pictures\a
        ↓
Collects sensitive data
        ↓
Creates a.zip
        ↓
Prepares data for exfiltration
```

---

# Useful Commands From This Investigation

## Parse Shellbags

```powershell
.\SBECmd.exe -d "PATH_TO_USER_DIRECTORY" --csv "C:\Temp\shellbags" --nl
```

---

## Search for ZIP/RAR/7z files

```powershell
Get-ChildItem "C:\Temp\steve_shellbags\*.csv" |
Select-String -Pattern '\.(zip|rar|7z)'
```

---

## Search a particular path

```powershell
Import-Csv "C:\Temp\steve_shellbags\steve_UsrClass.csv" |
Where-Object {$_.AbsolutePath -like '*OT Station 3 internal VPN*'}
```

---

## Display important Shellbag timestamps

```powershell
Import-Csv "C:\Temp\steve_shellbags\steve_UsrClass.csv" |
Where-Object {$_.AbsolutePath -like '*OT Station 3 internal VPN*'} |
Select-Object AbsolutePath,ShellType,CreatedOn,ModifiedOn,AccessedOn,LastWriteTime,FirstInteracted,LastInteracted |
Format-List
```

---

## Search Registry files for archive strings

```powershell
Get-ChildItem "C:\Users\g01d\Desktop\Sherlock HTB\Baggage\C\Users\steve" -Recurse -File |
Select-String -Pattern '\.(zip|rar|7z)' -ErrorAction SilentlyContinue
```

---

# Important Lesson From This Challenge

The biggest thing I learned from this Sherlock was that **Shellbags are not just folder history**.

From only Windows Registry artifacts, we were able to identify:

```text
Downloaded archive
↓
Attacker utility
↓
Sensitive folders
↓
Network share
↓
Sensitive network archive
↓
Staging directory
↓
Exfiltration archive
```

Another lesson was timestamps.

At first I looked at fields such as:

```text
CreatedOn
AccessedOn
FirstInteracted
```

but some questions specifically required:

```text
LastInteracted
```

So during DFIR investigations, it is important to understand **what each timestamp represents instead of choosing the first timestamp that looks correct**.

---

# Final Answers

| Question | Answer |
|---|---|
| Downloaded archive | `1.zip` |
| Search utility | `Everything 1.4.1.1028` |
| VPN folder LastInteracted | `2025-09-03 07:31:05` |
| Password directory | `OnePassword MasterPass` |
| Network share | `\\Prod-ns-2\prodshare` |
| Dam construction year | `2027` |
| Network archive | `Dam Construction Engineer Plans.zip` |
| Network archive accessed | `2025-09-03 07:34:04` |
| Staging folder | `C:\Users\steve\Pictures\a` |
| Exfiltration archive accessed | `2025-09-03 07:34:30` |

---

# Conclusion

**Baggage** was a simple but useful introduction to Shellbag analysis.

Using **SBECmd**, `UsrClass.dat`, `NTUSER.DAT`, and PowerShell, I was able to reconstruct how the attacker searched for sensitive files, accessed local and network resources, collected the information into a staging directory, and compressed it before exfiltration.

The challenge showed me that even something as simple as opening folders in Windows Explorer can leave useful forensic evidence behind.

For someone starting to learn DFIR, this Sherlock is a good practice for understanding **Shellbags, Registry artifacts, network shares, timestamps, data staging, and exfiltration**.
