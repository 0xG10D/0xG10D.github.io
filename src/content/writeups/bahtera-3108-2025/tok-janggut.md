---
slug: "local-ctf/bahtera-3108-2025/tok-janggut"
event: "bahtera-3108-2025"
title: "Tok Janggut"
summary: "Repair a corrupted JPEG header to recover Tok Janggut's historical image and the flag hidden inside it."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - forensics
  - file-recovery
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Tok Janggut

## Challenge Overview

- **Event:** Bahtera 3108 2025
- **Category:** Forensics
- **Points:** 100

> Pada tahun 1915, Tok Janggut bangkit menentang penjajahan British di Kelantan. Selepas pertempuran tragis di Pasir Puteh, satu-satunya gambar terakhir beliau disimpan dalam bentuk digital oleh seorang sejarawan moden.
>
> Namun, gambar bersejarah ini telah diubah oleh pihak tidak bertanggungjawab, dipercayai untuk memadam bukti perjuangan beliau.
>
> Sebagai penyiasat forensik, tugas anda adalah untuk membaik pulih fail ini dan mengesan mesej rahsia yang tersembunyi dalam gambar tersebut.

The supplied image would not open normally, so I inspected it in the [HexEd.it online hex editor](https://hexed.it/).

## Inspecting the File Header

The first bytes were clearly not a valid image signature. They began with the placeholder sequence `12 34 56 78 90 AB CD EF` even though the rest of the file contained JPEG-related data such as `JFIF` and `Exif`.

![Corrupted JPEG header in the hex editor](/images/writeups/local-ctf/bahtera-3108-2025/tok-janggut/corrupted-jpeg-header.png)

I compared the file against the [list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures). A JFIF JPEG should begin with the following bytes:

```text
FF D8 FF E0 00 10 4A 46 49 46 00 01
```

![JPEG JFIF signature reference](/images/writeups/local-ctf/bahtera-3108-2025/tok-janggut/jpeg-file-signature-reference.png)

## Repairing the JPEG

I replaced the corrupted opening bytes with the correct JFIF signature. The repaired header now began with `FF D8 FF E0` and retained the existing `JFIF` marker.

![Repaired JPEG header](/images/writeups/local-ctf/bahtera-3108-2025/tok-janggut/repaired-jpeg-header.png)

I then saved the repaired file with the `.jpeg` extension.

![Saving the repaired image as a JPEG](/images/writeups/local-ctf/bahtera-3108-2025/tok-janggut/save-repaired-jpeg.png)

Opening the repaired image revealed Tok Janggut's portrait and the flag printed across it.

![Recovered Tok Janggut image containing the flag](/images/writeups/local-ctf/bahtera-3108-2025/tok-janggut/tok-janggut-recovered.jpeg)

## Flag

```text
3108{T0K_J4NGGUT_P3JU4NG_J1H4D}
```
