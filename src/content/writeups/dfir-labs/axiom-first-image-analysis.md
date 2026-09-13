---
slug: "dfir/axiom-first-image-analysis"
event: "dfir-labs"
title: "DFIR First Image Analysis: Magnet AXIOM Walkthrough"
summary: "Magnet AXIOM examination of the Dell Latitude CPi image, covering OS and install artifacts, user attribution, network configuration, installed hacking tools, webmail, and malware triage."
date: 2026-08-13
tags:
  - dfir
  - magnet-axiom
  - disk-forensics
  - windows-xp
  - registry-analysis
  - user-attribution
  - malware-analysis
category: "forensics"
difficulty: "info"
platform: "other"
draft: false
boxImage: "/public/images/writeups/axiom-first-image-analysis/image.png"
---

# DFIR First Image Analysis — Magnet AXIOM

> **Tool:** Magnet AXIOM Examine v10.2.0.49217  
> **Evidence source:** `4Dell Latitude CPi.E01`  
> **Scope:** Q2–Q15 only. Q1 is intentionally omitted.

This write-up documents the findings obtained from the supplied forensic image using Magnet AXIOM. Each answer is supported by the AXIOM artifacts or file-system evidence shown in the accompanying screenshots.

---

## Quick Answer Summary

| Question | Answer |
|---|---|
| Q2 | Microsoft Windows XP, Version 5.1 |
| Q3 | 19 August 2004, 10:48:27 PM |
| Q4 | Greg Schardt |
| Q5 | `N-1A9ODN6ZXK4LQ` |
| Q6 | 27 August 2004, 3:46:33 PM |
| Q7 | 5 accounts |
| Q8 | Mr. Evil |
| Q9 | Xircom CardBus Ethernet 100 + Modem 56; Compaq WL110 Wireless LAN PC Card |
| Q10 | IP `192.168.1.111`; MAC `00:10:A4:93:3E:09` |
| Q11 | Multiple network, password-recovery, packet-capture and wireless-discovery tools were installed |
| Q12 | Forte Agent |
| Q13 | `whoknowsme@sbcglobal.net` |
| Q14 | 4 executable files |
| Q15 | Yes — `unix_hack.tgz` was identified as malicious/suspicious by multiple security engines |

---

## Q2. What operating system was used on the computer?

### Answer

**Microsoft Windows XP, Version 5.1**

### Investigation

In AXIOM Examine, I navigated to:

`Artifacts → Operating System → Operating System Information`

AXIOM parsed the Windows registry and displayed the operating-system information for the evidence source. The artifact identified the operating system as **Microsoft Windows XP** with version number **5.1**.

### Evidence

![screenshot-2026-08-13-090900](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-090900.png)

### Finding

The forensic image contains an installation of **Microsoft Windows XP**.

---

## Q3. When was the install date?

### Answer

**19 August 2004 at 10:48:27 PM**

### Investigation

The installation timestamp was available in the same **Operating System Information** artifact. AXIOM displayed:

`Installed/Updated Date/Time: 8/19/2004 10:48:27.000 PM`

The AXIOM interface in the supplied screenshot is configured to display timestamps in **UTC+00:00**.

### Evidence

![screenshot-2026-08-13-092404](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-092404.png)

### Finding

Windows was installed or updated on **19 August 2004 at 10:48:27 PM**.

---

## Q4. Who is the registered owner?

### Answer

**Greg Schardt**

### Investigation

Under **Operating System Information**, AXIOM recovered the registered owner from the Windows registry. The `Owner` field contains:

`Greg Schardt`

### Evidence

![screenshot-2026-08-13-092933](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-092933.png)

### Finding

The Windows installation is registered to **Greg Schardt**.

---

## Q5. What is the computer account name?

### Answer

`N-1A9ODN6ZXK4LQ`

### Investigation

The computer name was recovered from AXIOM's **Operating System Information** artifact.

The relevant field shows:

`Computer Name: N-1A9ODN6ZXK4LQ`

### Evidence

![screenshot-2026-08-13-093009-1](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-093009-1.png)
### Finding

The computer account/name is **`N-1A9ODN6ZXK4LQ`**.

---

## Q6. When was the last recorded computer shutdown date/time?

### Answer

**27 August 2004 at 3:46:33 PM**

### Investigation

The **Evidence Source Details** section contained the parsed shutdown timestamp:

`Last Shutdown Date/Time: 8/27/2004 3:46:33.000 PM`

### Evidence

![screenshot-2026-08-13-093030](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-093030.png)
### Finding

The last shutdown recorded by AXIOM occurred on **27 August 2004 at 3:46:33 PM**.

---

## Q7. How many accounts are recorded?

### Answer

**5 user accounts**

### Investigation

I navigated to the Windows user-account artifacts in AXIOM. Five accounts were recovered:

1. `Administrator`
2. `Guest`
3. `HelpAssistant`
4. `SUPPORT_388945a0`
5. `Mr. Evil`

### Evidence

![screenshot-2026-08-13-093300](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-093300.png)
### Finding

A total of **5 Windows user accounts** are recorded in the forensic image.

---

## Q8. Who was the last user to log on to the computer?

### Answer

**Mr. Evil**

### Investigation

I examined the Windows registry in AXIOM at:

`Microsoft\Windows NT\CurrentVersion\Winlogon`

The registry value:

`DefaultUserName`

contained:

`Mr. Evil`

### Evidence

![screenshot-2026-08-13-095241](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-095241.png)

### Finding

The registry evidence identifies **Mr. Evil** as the last/default interactive user associated with the Winlogon configuration.

---

## Q9. List the network cards used by this computer.

### Answer

Two network adapters were identified:

- **Xircom CardBus Ethernet 100 + Modem 56 (Ethernet Interface)**
- **Compaq WL110 Wireless LAN PC Card**

### Investigation

I navigated to:

`Artifacts → Operating System → Network Interfaces (Registry)`

AXIOM displayed both wired and wireless network-interface descriptions.

### Evidence

![screenshot-2026-08-13-095341](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-095341.png)

### Finding

The system had both a **Xircom wired Ethernet adapter** and a **Compaq WL110 wireless LAN adapter** configured.

---

## Q10. What is the IP address and MAC address of the computer?

### Answer

- **IP address:** `192.168.1.111`
- **MAC address:** `00:10:A4:93:3E:09`

### Investigation

The strongest evidence for the address used by the computer during the Look@LAN configuration was found in:

`C:\Program Files\Look@LAN\irunin.ini`

The file contained the following variables:

```ini
%LANIP%=192.168.1.111
%LANNIC%=0010a4933e09
```

The NIC value can be formatted as a standard MAC address:

`00:10:A4:93:3E:09`

### Evidence

![screenshot-2026-08-13-095748](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-095748.png)

AXIOM also recovered a registry network-interface entry containing the APIPA address `169.254.242.213`. This represents another DHCP/interface state. For this question, the Look@LAN configuration provides the IP/MAC pair associated with the program setup.

![screenshot-2026-08-13-100144](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-100144.png)

### Finding

The Look@LAN configuration associates the machine with **`192.168.1.111`** and MAC address **`00:10:A4:93:3E:09`**.

---

## Q11. Search for programs/tools that aided in the crime (Wireless Hacking).

### Answer

AXIOM recovered several installed programs that could support network reconnaissance, wireless discovery, packet capture, credential recovery, or anonymity:

- **123 Write All Stored Passwords**
- **Cain & Abel v2.5 beta45**
- **Anonymizer Bar 2.0**
- **Look@LAN 2.50 Build 29**
- **Ethereal 0.10.6**
- **Network Stumbler 0.4.0**
- **WinPcap 3.01 alpha**

### Investigation

I navigated to:

`Artifacts → Application Usage → Installed Programs`

AXIOM displayed the installed-program entries recovered from the Windows system.

### Evidence

![screenshot-2026-08-13-100319](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-100319.png)

### Forensic Significance

The combination of these programs is significant because the machine contains tools capable of:

- wireless network discovery,
- LAN reconnaissance,
- packet capture,
- credential/password recovery, and
- anonymized browsing.

The presence of a tool alone does not prove malicious use, but the collection is relevant to an investigation involving wireless hacking.

---

## Q12. Which email client is used by Mr. Evil?

### Answer

**Forte Agent**

### Investigation

The following file was examined:

`C:\Program Files\Agent\Data\AGENT.INI`

The configuration contains a profile with:

```ini
FullName="Mr Evil"
EmailAddress="whoknowsme@sbcglobal.net"
```

Because the profile is stored under the `Agent` application directory and directly identifies Mr. Evil, it provides evidence that **Forte Agent** was being used.

### Evidence

![screenshot-2026-08-13-101746](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-101746.png)

### Finding

The email/news client associated directly with the Mr. Evil profile is **Forte Agent**.

---

## Q13. What is the SMTP email address for Mr. Evil?

### Answer

`whoknowsme@sbcglobal.net`

### Investigation

The `AGENT.INI` file contains:

```ini
UserName="whoknowsme@sbcglobal.net"
SMTPUserName="whoknowsme@sbcglobal.net"
MailServer="smtp.sbcglobal.net"
SMTPPort=25
```

### Evidence

![screenshot-2026-08-13-101838](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-101838.png)

### Finding

The SMTP account associated with Mr. Evil is **`whoknowsme@sbcglobal.net`**.

---

## Q14. How many executable files are in the Recycle Bin?

### Answer

**4 executable files**

### Investigation

I navigated to:

`Artifacts → Operating System → Recycle Bin`

AXIOM recovered four deleted executable files:

1. `lalsetup250.exe`
2. `netstumblerinstaller_0_4_0.exe`
3. `WinPcap_3_01_a.exe`
4. `ethereal-setup-0.10.6.exe`

The original paths indicate that the files were deleted from the `Mr. Evil` user's Desktop.

### Evidence

![screenshot-2026-08-13-102032](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-102032.png)

### Finding

There are **4 executable files** recorded in the Recycle Bin artifacts.

---

## Q15. Is there any malware on the computer?

### Answer

**Yes. A suspicious/malicious archive named `unix_hack.tgz` was identified.**

### Investigation

The file was located at:

`C:\My Documents\FOOTPRINTING\UNIX\unix_hack.tgz`

AXIOM displayed the file as approximately **73,498,201 bytes**.

### Evidence — File Location

![screenshot-2026-08-13-103033](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-103033.png)

The AXIOM file artifact also displayed the following MD5 hash:

`3e1158bec295e21434f5ef4682d33ef4`

![screenshot-2026-08-13-103054-1](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-103054-1.png)

The supplied VirusTotal screenshot shows the archive being detected by **23 of 52 security vendors**. Detection labels shown include Trojan, Linux hacktool, suspicious archive, and related classifications.

The VirusTotal SHA-256 shown in the supplied evidence is:

`e7c615f1fc2e422e0a0cf00faf8abeb1fc3f7550200dd91ed40d17dd3ab2ca64`

### Evidence — VirusTotal

![screenshot-2026-08-13-103112](/images/writeups/axiom-first-image-analysis/screenshot-2026-08-13-103112.png)

### Finding

Based on the file location, hash analysis, and the multi-engine detections shown in the supplied VirusTotal evidence, **`unix_hack.tgz` should be treated as malicious or potentially malicious evidence** within this forensic image.
