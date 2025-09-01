# no-ghosts
A repo for baseline defense logic and queries for casp3r0x0 KeePassStealer.

## 📌 Context
Recently (as of 8/31/2025), a public proof-of-concept called **KeePassStealer** was released.  
It demonstrates a red-team technique where a malicious DLL is injected into `KeePass.exe` and hooks the Windows API **`advapi32!SystemFunction041`** (`RtlDecryptMemory`).  
When KeePass decrypts the master password, the hook copies it out to disk.  

⚠️ **Important:** This is not a break of KeePass encryption.  
It is a **post-compromise credential access technique** — attackers already need code execution on the target host.  

- MITRE ATT&CK:  
  - **T1055** – Process Injection  
  - **T1555.005** – Credentials from Password Managers  

This repo highlights detection content I’ve authored to defend against KeePass injection and similar API-hooking attempts.

---

## 🛡 Sigma Rules

### 1. Remote Thread Created in KeePass
```yaml
title: Remote Thread Created In KeePass
id: 9a6fa0d6-3c74-4fce-8f2c-rt-keest
status: experimental
description: Detect CreateRemoteThread into KeePass.exe
author: Daniel Conrad
date: 2025/08/31
logsource:
  product: windows
  category: create_remote_thread
detection:
  selection:
    TargetImage|endswith: '\KeePass.exe'
  condition: selection
fields:
  - Image
  - TargetImage
  - StartAddress
  - StartModule
level: high
tags:
  - attack.t1055
  - attack.credential_access
```

### 2. Suspicious Process Access to KeePass
```yaml
title: Suspicious ProcessAccess To KeePass
id: 0a2d54a1-6c7b-4989-9c3a-pa-keest
status: experimental
description: Detect access rights commonly used for injection into KeePass.exe
author: Daniel Conrad
date: 2025/08/31
logsource:
  product: windows
  category: process_access
detection:
  target:
    TargetImage|endswith: '\KeePass.exe'
  rights1:
    GrantedAccess|contains:
      - '0x1F0FFF'     # PROCESS_ALL_ACCESS
      - '0x0010'       # VM_READ
      - '0x0020'       # VM_WRITE
      - '0x0008'       # VM_OPERATION
  condition: target and rights1
fields:
  - SourceImage
  - TargetImage
  - GrantedAccess
  - CallTrace
level: high
tags:
  - attack.t1055
```

### 3. EasyHook Module Loaded in KeePass
```yaml
title: EasyHook Module Loaded In KeePass
id: 6c3a517b-2b7f-4b1a-bf6a-il-keest
status: experimental
description: Detect EasyHook DLLs inside KeePass.exe
author: Daniel Conrad
date: 2025/08/31
logsource:
  product: windows
  category: image_load
detection:
  selection:
    Image|endswith: '\KeePass.exe'
    ImageLoaded|contains:
      - '\EasyHook'
      - '\EasyLoad'
  condition: selection
fields:
  - Image
  - ImageLoaded
  - Signed
  - Signature
level: medium
tags:
  - attack.t1055
```

### 4. KeePass Writing Cleartext to Temp
```yaml
title: KeePass Writes Cleartext To Temp
id: 58f21c1c-5a29-40b0-9a6b-fc-keest
status: experimental
description: Detect KeePass.exe creating suspicious temp text files that may hold captured secrets
author: Daniel Conrad
date: 2025/08/31
logsource:
  product: windows
  category: file_create
detection:
  selection:
    Image|endswith: '\KeePass.exe'
    TargetFilename|contains:
      - '\AppData\Local\Temp\'
  filter_legit:
    TargetFilename|contains:
      - '\KeePass\'
      - '\Plugins\'
  condition: selection and not filter_legit
fields:
  - Image
  - TargetFilename
level: medium
tags:
  - attack.t1555.005
```

### 5. KeePass Spawning Unexpected Child Processes
```yaml
title: KeePass Spawns Child Process
id: 7f3a0c2f-9d64-4d1a-8f1a-cp-keest
status: experimental
description: KeePass rarely launches children. Alert and tune allowlist for known plugins.
author: Daniel Conrad
date: 2025/08/31
logsource:
  product: windows
  category: process_creation
detection:
  parent:
    ParentImage|endswith: '\KeePass.exe'
  condition: parent
fields:
  - Image
  - ParentImage
  - CommandLine
level: low
tags:
  - attack.defense_evasion
```

---

## 🔎 Splunk Hunts

### Remote thread into KeePass
```spl
index=sysmon EventCode=8 TargetImage="*\\KeePass.exe"
| stats values(Image) values(StartAddress) values(StartModule) by _time, Computer, TargetImage
```

### Suspicious access rights
```spl
index=sysmon EventCode=10 TargetImage="*\\KeePass.exe"
| search GrantedAccess="*0x1F0FFF*" OR GrantedAccess="*0x0020*" OR GrantedAccess="*0x0008*"
| stats values(SourceImage) values(GrantedAccess) by _time, Computer, TargetImage
```

### EasyHook DLL load
```spl
index=sysmon EventCode=7 Image="*\\KeePass.exe" ImageLoaded="*\\EasyHook*"
| table _time Computer Image ImageLoaded Signed Signature
```

### KeePass writing temp files
```spl
index=sysmon EventCode=11 Image="*\\KeePass.exe" TargetFilename="*\\AppData\\Local\\Temp\\*"
| stats values(TargetFilename) by _time, Computer
```

---

## 💻 Microsoft Defender AH (KQL)

### Remote thread or injection into KeePass
```kusto
DeviceEvents
| where ActionType in ("CreateRemoteThreadApiCall","RemoteThreadCreated","ProcessInjectionDetected")
| where AdditionalFields has_any ("KeePass.exe","\\KeePass.exe")
```

### EasyHook DLL load
```kusto
DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "KeePass.exe"
| where FileName startswith "EasyHook"
```

### KeePass creating temp files
```kusto
DeviceFileEvents
| where InitiatingProcessFileName =~ "KeePass.exe"
| where FolderPath has @"\AppData\Local\Temp\"
```
