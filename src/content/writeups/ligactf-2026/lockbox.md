---
slug: "local-ctf/ligactf2026/lockbox"
event: "ligactf-2026"
title: "Lockbox"
summary: "LigaCTF 2026 ligactf2026, forensics, reverse engineering writeup covering Lockbox with analysis, solution steps, and final recovery notes."
date: 2026-05-31
tags:
  - ctf
  - ligactf2026
  - forensics
  - reverse-engineering
  - cryptography
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://owasp.org/www-chapter-kuala-lumpur/owaspmy.jpeg"
---
## Challenge Information

|Field|Value|
|---|---|
|Challenge|Lockbox|
|Category|Reverse Engineering / Cryptography|
|Points|810|
|Flag Format|`OWASPKL{...}`|
|Difficulty|Medium|

## Description

The challenge provides a binary named `lockbox` and a note from the author. The note claims that the secret message is protected using three layers:

1. ROT13

2. Reversed string

3. Split data scattered across memory


The author also claims that the only supported way to unlock the message is by using:

```bash
./lockbox --unlock <code>
```

The required unlock code is said to be a 64-character HMAC key.

However, the challenge hint suggests starting with static analysis and comparing the result of `strings` against what the author claims.

## Given Files

```text
lockbox
friend_note.txt
```

## Objective

Recover the hidden message from the binary without knowing the 64-character unlock code.

---

## Initial File Check

First, check the file type:

```bash
file lockbox
```

Then make the binary executable:

```bash
chmod +x lockbox
```

Run it normally:

```bash
./lockbox
```

The binary does not directly reveal the flag. The documented path requires the `--unlock` argument.

Testing the expected usage:

```bash
./lockbox --unlock test
```

This fails because the correct unlock code is unknown.

---

## Static Analysis

The challenge hint recommends using `strings`, so I started there:

```bash
strings -a lockbox
```

To include offsets:

```bash
strings -a -tx lockbox
```

Then I filtered for interesting keywords:

```bash
strings -a lockbox | grep -Ei "unlock|key|emergency|flag|OWASP|ROT|reverse"
```

Interesting strings appeared:

```text
--unlock
--emergency
[lockbox] ready.
[lockbox] emergency path triggered.
[lockbox] emergency key accepted.
```

This is important because the challenge description only documents `--unlock`, but the binary also contains an undocumented `--emergency` argument.

That means the binary likely has a hidden fallback or debug path.

---

## Finding the Hidden Path

Since `--emergency` appears in the binary, I tested it:

```bash
./lockbox --emergency test
```

The program entered the emergency path but rejected the key.

This confirms that `--emergency` is a real code path and not just a random unused string.

Expected behavior:

```text
[lockbox] ready.
[lockbox] emergency path triggered.
```

The next step is to reverse how the emergency key is checked.

---

## Disassembly

I used `objdump` to inspect the binary:

```bash
objdump -d -Mintel lockbox > lockbox.asm
```

Then I searched for references to the emergency string:

```bash
grep -n "emergency" lockbox.asm
```

Another option is to use Ghidra:

```bash
ghidra
```

In Ghidra:

1. Import `lockbox`

2. Analyze the binary

3. Open the function containing argument parsing

4. Look for comparisons against:

    - `--unlock`

    - `--emergency`


The program checks command-line arguments and has two important branches:

```text
--unlock      -> normal locked path
--emergency   -> hidden bypass path
```

The `--unlock` path requires the unknown 64-character code.

The `--emergency` path checks a shorter emergency key.

---

## Understanding the Encoding

The challenge note says the author used:

1. ROT13

2. Reversed string

3. Split pieces in memory


The same idea is used inside the emergency path.

Instead of storing the key plainly, the binary stores transformed pieces. After reconstruction, the data is reversed and ROT13-decoded.

The recovered emergency key is:

```text
0v3rr1d3
```

This looks like leetspeak for:

```text
override
```

That strongly suggests it is a developer backdoor key.

---

## Exploiting the Emergency Path

Run the binary with the hidden emergency argument and the recovered emergency key:

```bash
./lockbox --emergency 0v3rr1d3
```

Output:

```text
[lockbox] ready.
[lockbox] emergency path triggered.
[lockbox] emergency key accepted.
OWASPKL{3zPz_R0T13_L3M0N_5QU33ZY}
```

The program reveals the flag.

---

## Flag

```text
OWASPKL{3zPz_R0T13_L3M0N_5QU33ZY}
```

---

## Why This Works

The author claimed that the only way to unlock the binary was through the `--unlock` argument with a 64-character HMAC key.

However, static analysis revealed an undocumented `--emergency` argument.

The emergency path acts as a bypass. Instead of brute-forcing or recovering the full HMAC key, we only needed to reverse the emergency key check.

The binary attempted to hide strings using simple transformations:

```text
split pieces -> reverse -> ROT13
```

These transformations are not cryptographically secure. They only slow down casual inspection.

Once the hidden argument and emergency key were recovered, the binary printed the flag directly.

---

## Key Takeaways

- `strings` is a strong first step in reverse engineering.

- Hidden command-line arguments can expose debug or backdoor functionality.

- ROT13 and reversing are obfuscation, not encryption.

- A secure unlock mechanism should not contain a separate hardcoded bypass path.

- Challenge descriptions may intentionally mislead players toward the intended but harder path.


---

## Final Answer

```text
OWASPKL{3zPz_R0T13_L3M0N_5QU33ZY}
```
