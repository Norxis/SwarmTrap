# DFI Windows Attack Event ID Reference

## How To Use This Document

Every event ID below indicates attacker activity observable on a Windows honeypot. They are organized by DFI kill-chain label so the evidence collector can set `evidence_bits` and assign the correct label. Events marked **[CURRENT]** are already in the capture agent. Events marked **[NEW]** should be added.

The `honeypot_context` column notes how to interpret the event on a system with zero legitimate users — the key insight that makes honeypot detection radically simpler than enterprise SOC detection. On a honeypot, _any_ successful logon is hostile.

---

## Label 0 — RECON

No host-side events. Label assigned by absence: source IP appears in PCAP flows but generates zero events in the evidence table within the ±120s correlation window.

No event IDs needed — RECON is the default when nothing below fires.

---

## Label 1 — KNOCK

Connection reached a service, zero authentication attempts. The attacker probed but didn't try to log in.

### Security Log

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 4624 (Type 3, Anonymous) | Anonymous logon | SMB null session probe. Attacker enumerated shares without credentials. | 0x00 (context) | [NEW] |
| 5140 | Network share object accessed | SMB share enumeration. On honeypot = always hostile. | 0x00 (context) | [CURRENT] |
| 5145 | Detailed share access check | Per-object ACL check on share. More granular than 5140. | 0x00 (context) | [CURRENT] |
| 4798 | Local group membership enumerated | Attacker finding local admins (recon). On honeypot = always hostile. | 0x00 (context) | [NEW] |
| 5156 | WFP allowed a connection | TCP connection reached a service port. High volume, use for KNOCK confirmation only. | 0x00 (context) | [NEW] |
| 5157 | WFP blocked a connection | Firewall blocked an inbound attempt. Useful for detecting port probes beyond exposed services. | 0x00 (context) | [NEW] |

### RDP

| Event ID | Channel | Description | Honeypot Context | evidence_bits | Status |
|----------|---------|-------------|------------------|---------------|--------|
| 131 | RdpCoreTS | RDP connection initiated (pre-auth) | Client connected but hasn't authenticated yet. Pure connection probe. | 0x00 (context) | [CURRENT] |
| 261 | RdpCoreTS | RDP listener received a connection | Lower-level than 131. Connection arrived at RDP stack. | 0x00 (context) | [NEW] |
| 4779 | Security | Session disconnected from Window Station | RDP/Console session closed. Monitor for unexpected disconnects. | 0x00 (context) | [NEW] |

### Terminal Services

| Event ID | Channel | Description | Honeypot Context | evidence_bits | Status |
|----------|---------|-------------|------------------|---------------|--------|
| 21 | TS-LSM | Session logon succeeded | RDP session established. On honeypot = hostile actor connected. | 0x00 (context) | [CURRENT] |
| 24 | TS-LSM | Session disconnected | Attacker disconnected. | 0x00 (context) | [CURRENT] |
| 25 | TS-LSM | Session reconnect succeeded | Attacker reconnected to existing session. | 0x00 (context) | [CURRENT] |
| 1149 | TS-RemoteConnectionManager | RDP auth succeeded (NLA) | Network Level Authentication passed. Pre-session, confirms valid creds were used. Bridges KNOCK→BRUTEFORCE. | 0x02 | [NEW] |

### IIS / HTTP

| Source | Description | Honeypot Context | evidence_bits | Status |
|--------|-------------|------------------|---------------|--------|
| W3C log, status 200 (no auth) | Successful HTTP GET/POST | Normal web request. KNOCK — reached service. | 0x00 (context) | [CURRENT] |
| W3C log, status 404/403 | Forbidden or not found | Path enumeration / directory brute-force. | 0x00 (context) | [NEW] |

---

## Label 2 — BRUTEFORCE

≥3 authentication failures from the same source IP.

### Security Log — Authentication Failures

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 4625 | Account failed to log on | **Primary brute-force indicator.** Subtypes by LogonType: Type 2=console, Type 3=SMB/WinRM, Type 10=RDP. Status codes: 0xC000006D=bad username/password, 0xC000006A=correct user wrong password, 0xC0000064=nonexistent user, 0xC0000072=disabled account, 0xC0000234=locked out. | 0x01 (auth_failure) | [CURRENT] |
| 4771 | Kerberos pre-auth failed | Kerberos brute-force. Not typical on standalone honeypot but relevant if domain-joined. Failure codes: 0x18=wrong password, 0x6=unknown principal. | 0x01 | [NEW] |
| 4776 | Credential validation attempt (NTLM) | DC attempted to validate creds. Result 0xC000006A=bad password, 0xC0000064=no such user. On honeypot = brute-force via NTLM. | 0x01 | [NEW] |
| 4777 | Credential validation failed | Domain controller rejected creds. Companion to 4776. | 0x01 | [NEW] |
| 4740 | Account locked out | ≥N failures triggered lockout. Definitive brute-force confirmation. On honeypot, lockout policy exists to slow attackers. | 0x01 | [NEW] |

### Security Log — Authentication Successes (hostile on honeypot)

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 4624 | Successful logon | **Any successful logon on a honeypot is hostile.** Key LogonTypes: Type 2=interactive/console, Type 3=network (SMB, WinRM), Type 7=unlock, Type 10=RDP, Type 11=cached credentials. Extract: IpAddress, LogonId (for chaining), TargetUserName. | 0x02 (auth_success) | [CURRENT] |
| 4648 | Logon with explicit credentials | Attacker used RunAs or mapped drive with different creds. `SubjectUserName` used `TargetUserName`'s credentials to connect to `TargetServerName`. On honeypot = credential pivoting. | 0x02 | [NEW] |
| 4672 | Special privileges assigned to new logon | Admin-equivalent logon. If SubjectSecurityID is not SYSTEM/LOCAL/NETWORK SERVICE → hostile admin access. | 0x40 (priv_escalation) | [CURRENT] |

### Application Log — Service-Specific Auth

| Event ID | Source | Description | Honeypot Context | evidence_bits | Status |
|----------|--------|-------------|------------------|---------------|--------|
| 18456 | MSSQL | Login failed | SQL Server brute-force. State 5=invalid user, State 8=wrong password, State 6=Windows auth failed. | 0x01 | [CURRENT] |
| 18454 | MSSQL | Login succeeded | SQL Server auth success. On honeypot = hostile. | 0x02 | [CURRENT] |
| 18452 | MSSQL | Login failed (untrusted domain) | Windows auth attempt from untrusted domain. | 0x01 | [NEW] |
| 33205 | MSSQL | Audit login failed (if C2 audit enabled) | More detailed than 18456, includes app name. | 0x01 | [NEW] |

### IIS / HTTP

| Source | Description | Honeypot Context | evidence_bits | Status |
|--------|-------------|------------------|---------------|--------|
| W3C log, status 401 | HTTP auth failure | HTTP brute-force (Basic, NTLM, or form-based). | 0x01 | [CURRENT] |
| W3C log, status 200 + auth | HTTP auth success | Attacker authenticated to web app. | 0x02 | [CURRENT] |

### WinRM

| Event ID | Channel | Description | Honeypot Context | evidence_bits | Status |
|----------|---------|-------------|------------------|---------------|--------|
| 6 | WinRM Operational | WinRM session created | WinRM session established. On honeypot = attacker has valid creds. | 0x02 | [NEW] |
| 91 | WinRM Operational | Shell created | Remote shell created via WinRM. Attacker executing commands. | 0x02 | [NEW] |
| 168 | WinRM Operational | Auth failure (HTTP 401) | WinRM brute-force attempt. | 0x01 | [NEW] |

### SMB-Specific

| Event ID | Channel | Description | Honeypot Context | evidence_bits | Status |
|----------|---------|-------------|------------------|---------------|--------|
| 551 | SMBServer | Session setup failed | SMB authentication failure. | 0x01 | [NEW] |
| 1006 | SmbClient | Share access denied | Client-side, less relevant for honeypot. | 0x00 | [NEW] |

---

## Label 3 — EXPLOIT

Suspicious command detected in logs. Attacker is attempting to execute exploits, download tools, or run reconnaissance commands post-authentication.

### Security Log — Process Execution

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 4688 | New process created | **Core exploit detection.** Match CommandLine against suspicious patterns. On honeypot, ANY process created by an attacker-attributed logon is evidence. Key fields: NewProcessName, CommandLine, ParentProcessName, SubjectLogonId (chain to IP). | 0x04 (process_create) or 0x10 (suspicious_cmd) or 0x30 (file_download) | [CURRENT] |
| 4689 | Process exited | Pairs with 4688 for session duration tracking. | 0x04 | [NEW] |

**4688 CommandLine patterns that escalate to specific evidence_bits:**

| Pattern | evidence_bits | Kill-Chain Meaning |
|---------|---------------|--------------------|
| `(cmd\|powershell\|pwsh).*/c\|/k\|-enc\|-e\s` | 0x10 suspicious_cmd | Shell execution |
| `whoami\|hostname\|ipconfig\|systeminfo\|net\s+(user\|localgroup\|group\|share\|view\|session\|use)\|nltest\|dsquery\|arp\s+-a\|route\s+print\|netstat\|tasklist\|wmic\s+(os\|process\|service)\s+` | 0x10 suspicious_cmd | Discovery / enumeration |
| `(nc\|ncat\|netcat)\s.*(-e\|-c)` | 0x10 suspicious_cmd | Reverse shell |
| `mimikatz\|lazagne\|procdump\|sekurlsa\|lsadump\|kerberoast\|rubeus\|sharphound\|bloodhound\|invoke-mimikatz` | 0x10 suspicious_cmd | Credential theft tool |
| `certutil\s.*-urlcache\|bitsadmin.*/transfer\|(wget\|curl\|invoke-webrequest\|iwr)\s+https?://\|downloadfile\|downloadstring\|start-bitstransfer` | 0x30 file_download | Tool download |
| `reg\s+(add\|delete\|query).*\\run\|schtasks\s*/create\|sc\s+(create\|config)\|wmic.*process\s+call\s+create` | 0x10 suspicious_cmd | Persistence setup |
| `(mshta\|regsvr32\|rundll32\|cscript\|wscript\|msiexec)\s` | 0x10 suspicious_cmd | LOLBin execution |
| `vssadmin\s.*shadow\|wbadmin\s+delete\|bcdedit\s.*/set.*recoveryenabled\s+no` | 0x10 suspicious_cmd | Anti-forensics / ransomware prep |
| `(python\|perl\|ruby)\s.*(-c\|-e)` | 0x10 suspicious_cmd | Scripting interpreter |
| `base64\|gzipstream\|frombase64string\|convert.*-encodedcommand` | 0x10 suspicious_cmd | Obfuscation |
| `(reverse\|bind)\s*shell\|new-object\s+system\.net\.sockets` | 0x10 suspicious_cmd | Network backdoor |
| `ntdsutil\|secretsdump\|dcsync\|lsass.*dump\|comsvcs.*minidump` | 0x10 suspicious_cmd | Credential extraction |
| `psexec\|wmiexec\|smbexec\|atexec\|evil-winrm\|crackmapexec` | 0x10 suspicious_cmd | Lateral movement tool |
| `disable-windowsoptionalfeature.*defender\|set-mppreference.*-disablerealtimemonitoring\|sc\s+stop\s+windefend\|uninstall.*defender` | 0x10 suspicious_cmd | Defense evasion |

### Security Log — Service & Scheduled Task

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 4697 | Service install attempted | Attacker installing service for persistence or execution. On honeypot = always hostile. | 0x08 (service_install) | [CURRENT] |
| 4698 | Scheduled task created | Persistence via scheduled task. Extract TaskName, Command. | 0x08 | [NEW] |
| 4699 | Scheduled task deleted | Attacker cleaning up after themselves. | 0x10 | [NEW] |
| 4700 | Scheduled task enabled | Reactivated a disabled task. | 0x08 | [NEW] |
| 4702 | Scheduled task updated | Modified existing task. | 0x10 | [NEW] |

### System Log

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 7045 | Service installed | **Key persistence indicator.** Service binary path often contains the malware. On honeypot = always hostile (no legitimate installs). Fields: ServiceName, ImagePath, ServiceType, StartType, AccountName. | 0x08 (service_install) | [CURRENT] |
| 7040 | Service start type changed | Attacker enabling disabled services (e.g., enabling RemoteRegistry, WinRM, etc.). | 0x10 | [NEW] |
| 7036 | Service entered running/stopped state | Combined with 7045/7040 for service lifecycle tracking. High volume — filter to services started within attacker sessions only. | 0x00 (context) | [NEW] |
| 7034 | Service terminated unexpectedly | Crash of attacker-installed service. | 0x00 (context) | [NEW] |

### Security Log — Account & Group Manipulation

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 4720 | User account created | **Definitive persistence.** On honeypot = attacker creating backdoor account. | 0x04 + 0x40 | [NEW] |
| 4722 | User account enabled | Enabling a disabled account. | 0x40 | [NEW] |
| 4723 | Password change attempted | Attacker changing their own password. | 0x40 | [NEW] |
| 4724 | Password reset attempted | Attacker resetting another account's password. | 0x40 | [NEW] |
| 4725 | User account disabled | Attacker disabling defender accounts. | 0x40 | [NEW] |
| 4726 | User account deleted | Covering tracks. | 0x10 | [NEW] |
| 4728 | Member added to security-enabled global group | Privilege escalation via group membership. | 0x40 (priv_escalation) | [CURRENT] |
| 4732 | Member added to security-enabled local group | **Key: adding user to Administrators group.** On honeypot = always privilege escalation. | 0x40 (priv_escalation) | [CURRENT] |
| 4733 | Member removed from local group | Covering tracks after priv esc. | 0x10 | [NEW] |
| 4756 | Member added to universal group | Domain-level privilege escalation. | 0x40 | [NEW] |

### Security Log — Object Access & Permissions

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 4656 | Handle to object requested | Access to sensitive objects: SAM, LSASS, registry hives. Filter on ObjectName containing `\SAM`, `\SECURITY`, `\lsass`. | 0x10 | [NEW] |
| 4657 | Registry value modified | Persistence via Run keys, services, or security settings. Filter on `\CurrentVersion\Run`, `\Services\`, `\Policies\`. | 0x10 | [NEW] |
| 4660 | Object deleted | File or registry key deleted. Anti-forensics. | 0x10 | [NEW] |
| 4663 | Access to object attempted | File access audit. On honeypot, access to sensitive files = exfiltration attempt. | 0x10 | [NEW] |
| 4670 | Permissions on object changed | ACL modification. Attacker changing permissions on critical files/registry. | 0x40 | [NEW] |

### Security Log — Audit Tampering

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 1102 | Audit log cleared | **Critical.** Attacker covering tracks. On honeypot = absolute confirmation of compromise. | 0x10 | [NEW] |
| 4719 | System audit policy changed | Attacker disabling auditing. | 0x10 | [NEW] |
| 4907 | Auditing settings on object changed | Targeted audit evasion. | 0x10 | [NEW] |

### Security Log — Firewall & Network

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 4946 | Firewall rule added | Attacker opening firewall for C2 or lateral movement. | 0x10 | [NEW] |
| 4947 | Firewall rule modified | Modifying existing rule to allow traffic. | 0x10 | [NEW] |
| 4948 | Firewall rule deleted | Removing defensive rules. | 0x10 | [NEW] |
| 4950 | Firewall setting changed | Profile or state change. | 0x10 | [NEW] |
| 5025 | Firewall service stopped | Attacker disabled Windows Firewall. | 0x10 | [NEW] |
| 5030 | Firewall service failed to start | Tampered firewall. | 0x10 | [NEW] |

### PowerShell

| Event ID | Channel | Description | Honeypot Context | evidence_bits | Status |
|----------|---------|-------------|------------------|---------------|--------|
| 4104 | PowerShell Operational | Script block logging | **Core exploit detection for PowerShell.** Full script content captured. Match against download/suspicious patterns. On honeypot = any PowerShell from attacker session is hostile. | 0x10 (suspicious_cmd) or 0x30 (file_download) | [CURRENT] |
| 4103 | PowerShell Operational | Module logging | Captures pipeline execution. More granular than 4104. | 0x10 | [NEW] |
| 400 | Windows PowerShell | Engine started | PowerShell engine start. Combine with LogonId chain for attribution. | 0x04 | [NEW] |
| 800 | Windows PowerShell | Pipeline execution details | Legacy pipeline logging. | 0x04 | [NEW] |
| 40961 | PowerShell Operational | PowerShell console starting | Session start marker. | 0x00 (context) | [NEW] |
| 40962 | PowerShell Operational | PowerShell console ready | Session ready. | 0x00 (context) | [NEW] |
| 53504 | PowerShell Operational | PowerShell remote session started | **WinRM remote PowerShell.** On honeypot = attacker executing remote commands. | 0x10 | [NEW] |

### Windows Defender

| Event ID | Channel | Description | Honeypot Context | evidence_bits | Status |
|----------|---------|-------------|------------------|---------------|--------|
| 1006 | Defender Operational | Malware detected | Defender found malware. On honeypot = attacker dropped tools. | 0x10 | [NEW] |
| 1007 | Defender Operational | Action taken against malware | Defender quarantined/removed malware. | 0x10 | [NEW] |
| 1008 | Defender Operational | Action failed on malware | Malware survived Defender action. | 0x10 | [NEW] |
| 1116 | Defender Operational | Threat detected | Real-time detection of malware. Extract ThreatName (e.g., `HackTool:Win32/Mimikatz`). | 0x10 | [NEW] |
| 1117 | Defender Operational | Action taken on threat | Response action completed. | 0x10 | [NEW] |
| 5001 | Defender Operational | Real-time protection disabled | Attacker disabled Defender. | 0x10 | [NEW] |
| 5004 | Defender Operational | Real-time protection config changed | Tampered with Defender settings. | 0x10 | [NEW] |
| 5007 | Defender Operational | Configuration changed | Any Defender config modification. | 0x10 | [NEW] |
| 5010 | Defender Operational | Scanning disabled | Disabled scanning. | 0x10 | [NEW] |
| 5012 | Defender Operational | Virus scanning disabled | More specific scanning disable. | 0x10 | [NEW] |

### Sysmon (if deployed on honeypot)

| Event ID | Description | Honeypot Context | evidence_bits | Status |
|----------|-------------|------------------|---------------|--------|
| 1 | Process creation | Full command line + parent process. Richer than 4688 (includes hashes, current directory, parent GUID). | 0x04 / 0x10 | [NEW] |
| 2 | File creation time changed | Timestomping. Attacker hiding malware install time. | 0x10 | [NEW] |
| 3 | Network connection | Per-process outbound connections. Detects C2 callbacks, reverse shells. Fields: DestinationIp, DestinationPort, User, Image. | 0x10 | [NEW] |
| 5 | Process terminated | Process exit. Pairs with Sysmon 1 for lifetime. | 0x04 | [NEW] |
| 6 | Driver loaded | Kernel driver load. BYOVD attacks, rootkits. | 0x10 | [NEW] |
| 7 | Image loaded | DLL loading. Detects DLL sideloading, injection. High volume — filter to suspicious paths. | 0x10 | [NEW] |
| 8 | CreateRemoteThread | Thread injected into another process. Classic injection technique (Mimikatz, Cobalt Strike). | 0x10 | [NEW] |
| 9 | RawAccessRead | Raw disk read (\\.\). Credential dumping from SAM/NTDS. | 0x10 | [NEW] |
| 10 | ProcessAccess | Process opened another process. **Key: detect LSASS memory access for credential dumping.** Filter on TargetImage containing `lsass.exe`. | 0x10 | [NEW] |
| 11 | FileCreate | File creation. Monitor startup folders, temp directories, web roots. | 0x04 | [NEW] |
| 12 | RegistryObject add/delete | Registry key created/deleted. Persistence via Run keys, services. | 0x10 | [NEW] |
| 13 | RegistryValue set | Registry value modified. Persistence and config changes. | 0x10 | [NEW] |
| 15 | FileCreateStreamHash | Alternate Data Stream created. Malware hiding technique. | 0x10 | [NEW] |
| 17 | PipeCreated | Named pipe created. C2 communication (Cobalt Strike uses named pipes). | 0x10 | [NEW] |
| 18 | PipeConnected | Named pipe connection. Lateral movement indicator. | 0x10 | [NEW] |
| 19 | WmiEventFilterActivity | WMI event filter registered. WMI persistence. | 0x08 | [NEW] |
| 20 | WmiEventConsumerActivity | WMI event consumer registered. WMI persistence. | 0x08 | [NEW] |
| 21 | WmiEventConsumerToFilterActivity | WMI binding created. Completes WMI persistence chain (19+20+21). | 0x08 | [NEW] |
| 22 | DNSQuery | DNS query from process. Detects DGA, C2 domain lookups, DNS tunneling. | 0x10 | [NEW] |
| 23 | FileDelete (archived) | File deleted + archived by Sysmon. Malware cleanup detection. | 0x10 | [NEW] |
| 25 | ProcessTampering | Process hollowing or herpaderping detected. Advanced evasion technique. | 0x10 | [NEW] |
| 26 | FileDeleteDetected | File deleted (not archived). Log only. | 0x10 | [NEW] |
| 27 | FileBlockExecutable | Sysmon blocked executable creation. | 0x10 | [NEW] |
| 28 | FileBlockShredding | Sysmon blocked file shredding. Anti-forensics attempt. | 0x10 | [NEW] |
| 29 | FileExecutableDetected | New executable file created. | 0x04 | [NEW] |

---

## Label 4 — COMPROMISE

Auth success + post-exploitation signal. The attacker is authenticated AND performing actions that demonstrate system control.

Compromise is not a single event — it's the **combination** of events from Label 2 (auth_success) + Label 3 (exploit signals). The labeler promotes a flow from EXPLOIT to COMPROMISE when:

```
evidence_bits & 0x02 (auth_success) != 0
AND
evidence_bits & (0x04 | 0x08 | 0x10 | 0x20 | 0x40) != 0
```

### Events That Confirm Full Compromise (when combined with auth_success)

| Event ID | Channel | Description | evidence_bits | Status |
|----------|---------|-------------|---------------|--------|
| 4688 + download pattern | Security | Tool downloaded post-auth | 0x30 (file_download + suspicious_cmd) | [CURRENT] |
| 4720 | Security | User account created by attacker | 0x04 + 0x40 | [NEW] |
| 4732 | Security | Attacker added self to Admins | 0x40 (priv_escalation) | [CURRENT] |
| 7045 | System | Attacker installed service | 0x08 (service_install) | [CURRENT] |
| 4698 | Security | Attacker created scheduled task | 0x08 | [NEW] |
| 1102 | Security | Attacker cleared audit log | 0x10 | [NEW] |
| 4697 | Security | Privileged service install | 0x08 | [CURRENT] |
| Sysmon 8 | Sysmon | Remote thread (injection) | 0x10 | [NEW] |
| Sysmon 10 + lsass.exe | Sysmon | LSASS credential dump | 0x10 | [NEW] |
| Sysmon 19/20/21 | Sysmon | WMI persistence chain | 0x08 | [NEW] |
| 4657 + Run key | Security | Registry Run key persistence | 0x10 | [NEW] |
| 4946 | Security | Firewall rule added by attacker | 0x10 | [NEW] |
| Defender 5001 | Defender | Defender disabled by attacker | 0x10 | [NEW] |

### Lateral Movement (evidence_bits 0x80)

These events indicate the attacker is moving FROM the honeypot to other systems, or the same source IP has been seen on multiple VMs.

| Event ID | Channel | Description | evidence_bits | Status |
|----------|---------|-------------|---------------|--------|
| 4648 | Security | Explicit credential logon to remote system | 0x80 (lateral_movement) | [NEW] |
| Sysmon 3 | Sysmon | Outbound connection to internal IPs on 445/3389/5985 | 0x80 | [NEW] |
| 4688 + lateral tools | Security | psexec, wmiexec, smbexec, evil-winrm, crackmapexec | 0x80 | [NEW] |
| Cross-VM correlation | DFI2 | Same source IP → evidence on multiple VMs | 0x80 | [CURRENT] |

---

## Additional Channels Worth Subscribing

### Microsoft-Windows-TaskScheduler/Operational

| Event ID | Description | Honeypot Context | evidence_bits |
|----------|-------------|------------------|---------------|
| 106 | Task registered | New scheduled task. On honeypot = persistence. | 0x08 |
| 140 | Task updated | Modified scheduled task. | 0x10 |
| 141 | Task deleted | Cleanup after persistence. | 0x10 |
| 200 | Task action started | Scheduled task executing. | 0x04 |
| 201 | Task action completed | Task finished. | 0x04 |

### Microsoft-Windows-SMBServer/Security

| Event ID | Description | Honeypot Context | evidence_bits |
|----------|-------------|------------------|---------------|
| 551 | SMB session setup rejected | SMB auth failure. | 0x01 |
| 1000 | SMB1 access attempt | SMB1 protocol usage = old tools/scanners. | 0x00 (context) |

### Microsoft-Windows-NTLM/Operational

| Event ID | Description | Honeypot Context | evidence_bits |
|----------|-------------|------------------|---------------|
| 8001 | NTLM auth used (client) | NTLM auth. Track for pass-the-hash. | 0x00 (context) |
| 8002 | NTLM auth used (server incoming) | Incoming NTLM auth. | 0x00 (context) |
| 8003 | NTLM auth blocked by policy | NTLM restricted. Attacker using legacy auth. | 0x01 |

### Microsoft-Windows-Windows Firewall With Advanced Security/Firewall

| Event ID | Description | Honeypot Context | evidence_bits |
|----------|-------------|------------------|---------------|
| 2003 | Firewall profile changed | Profile state modified. | 0x10 |
| 2004 | Firewall rule added | New rule created. | 0x10 |
| 2005 | Firewall rule changed | Existing rule modified. | 0x10 |
| 2006 | Firewall rule deleted | Rule removed. | 0x10 |
| 2009 | Firewall failed to load group policy | Policy application failure. | 0x10 |

### Microsoft-Windows-Bits-Client/Operational

| Event ID | Description | Honeypot Context | evidence_bits |
|----------|-------------|------------------|---------------|
| 3 | BITS job created | File download via BITS. Attacker using BITS transfer. | 0x30 |
| 59 | BITS transfer started | Download in progress. | 0x30 |
| 60 | BITS transfer completed | Download finished. | 0x30 |
| 61 | BITS transfer stopped with error | Download failed. | 0x20 |

### Microsoft-Windows-CodeIntegrity/Operational

| Event ID | Description | Honeypot Context | evidence_bits |
|----------|-------------|------------------|---------------|
| 3033 | Unsigned driver blocked | Attacker tried to load unsigned driver. | 0x10 |
| 3063 | Unsigned DLL blocked | Code integrity blocked unsigned code. | 0x10 |

---

## Summary: Priority Implementation Order

### Phase 1 — High-Value Additions (biggest detection gaps)

| Event ID | Channel | Why |
|----------|---------|-----|
| 4698/4699/4700 | Security | Scheduled task persistence — most common post-exploitation technique after services |
| 4720 | Security | Account creation — definitive persistence, currently invisible |
| 4740 | Security | Account lockout — brute-force confirmation |
| 4648 | Security | Explicit credential logon — lateral movement detection |
| 1102 | Security | Audit log cleared — anti-forensics, guaranteed compromise |
| 4719 | Security | Audit policy changed — defense evasion |
| 7040 | System | Service start type changed — persistence setup |
| 1149 | TS-RemoteConnectionManager | NLA success — bridges KNOCK to BRUTEFORCE for RDP |

### Phase 2 — Defense Evasion & Forensics

| Event ID | Channel | Why |
|----------|---------|-----|
| 4946/4947/4948 | Security | Firewall manipulation |
| 4657 | Security | Registry modification (Run keys, services) |
| 4656/4663 | Security | Object access (SAM, LSASS, sensitive files) |
| 5001/1116/1117 | Defender | Defender tampering and malware detection |
| 4771/4776 | Security | Kerberos/NTLM brute-force (if domain-joined) |

### Phase 3 — Sysmon (if deployed)

| Event ID | Why |
|----------|-----|
| 1 | Process creation with hashes and parent info |
| 3 | Per-process network connections (C2 detection) |
| 8 | Remote thread injection |
| 10 | LSASS access (credential dumping) |
| 11 | File creation in monitored paths |
| 12/13 | Registry persistence |
| 17/18 | Named pipes (C2 comms) |
| 19/20/21 | WMI persistence |
| 22 | DNS queries (DGA/C2 detection) |
| 25 | Process tampering (hollowing/herpaderping) |

### Phase 4 — Supplementary Channels

| Channel | Why |
|---------|-----|
| TaskScheduler/Operational | Native task events (more reliable than Security 4698) |
| BITS-Client/Operational | BITS transfer downloads |
| SMBServer/Security | SMB-specific auth failures |
| NTLM/Operational | Pass-the-hash detection |
| Firewall/Firewall | Granular firewall changes |
| WMI-Activity/Operational | WMI errors and provider activity (EID 5857/5858) |
| AppLocker/EXE and DLL | AppLocker audit/block events (EID 8002/8005) |

---

## Audit Policy Requirements

These subcategories must be enabled for the events above to fire. The installer should configure all of them.

```
auditpol /set /subcategory:"Logon"                       /success:enable /failure:enable
auditpol /set /subcategory:"Logoff"                      /success:enable
auditpol /set /subcategory:"Special Logon"               /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events"   /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout"             /failure:enable
auditpol /set /subcategory:"Credential Validation"       /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation"            /success:enable
auditpol /set /subcategory:"Process Termination"         /success:enable
auditpol /set /subcategory:"Security Group Management"   /success:enable
auditpol /set /subcategory:"User Account Management"     /success:enable
auditpol /set /subcategory:"Security State Change"       /success:enable
auditpol /set /subcategory:"Audit Policy Change"         /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension"   /success:enable
auditpol /set /subcategory:"System Integrity"            /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share"         /success:enable /failure:enable
auditpol /set /subcategory:"File Share"                  /success:enable /failure:enable
auditpol /set /subcategory:"Registry"                    /success:enable
auditpol /set /subcategory:"File System"                 /success:enable
auditpol /set /subcategory:"Other Object Access Events"  /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events"         /success:enable /failure:enable
```

Registry keys for enhanced logging:
```
# Command line in process events (4688)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# PowerShell script block logging (4104)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# PowerShell module logging (4103)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f

# PowerShell transcription (write all PS sessions to disk)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\Program Files\DFI\data\ps_transcripts" /f
```

Event log size expansion:
```powershell
wevtutil sl Security /ms:536870912              # 512 MB
wevtutil sl System /ms:134217728                # 128 MB
wevtutil sl Application /ms:134217728           # 128 MB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /ms:67108864  # 64 MB
wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /ms:67108864
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456  # 256 MB (if Sysmon)
wevtutil sl "Microsoft-Windows-WMI-Activity/Operational" /ms:67108864
wevtutil sl "Microsoft-Windows-AppLocker/EXE and DLL" /ms:67108864
```
