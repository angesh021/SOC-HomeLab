# ✅ **04_fim_sensitive_folder.md**

### **Scenario 04 — File Integrity Monitoring (FIM) on Sensitive Folder**

---

# 📝 Overview

This simulates unauthorized modification of files within a folder monitored by Wazuh FIM.

---

# 🎯 Objective

* Detect file creation, deletion, or modification
* Validate FIM performance
* Link changes back to user/process
* MITRE: **T1565 – Data Manipulation**

---

# 📁 Folder Used

Create a sensitive folder:

```powershell
mkdir C:\SensitiveLab
```

Configure agent to monitor:

```
<directories realtime="yes">C:\SensitiveLab</directories>
```

---

# ⚔️ Attack Steps (Windows)

### File creation:

```powershell
echo secret123 > C:\SensitiveLab\creds.txt
```

### File modification:

```powershell
echo NEWLINE >> C:\SensitiveLab\creds.txt
```

### File deletion:

```powershell
del C:\SensitiveLab\creds.txt
```

---

# 🔍 Telemetry Collected

## **1. Wazuh FIM Alerts**

Sample:

```
File added: creds.txt
File modified: creds.txt
File deleted: creds.txt
```

## **2. Sysmon**

Event ID 11:

```
FileCreate
TargetFilename: C:\SensitiveLab\creds.txt
```

---

# 🧠 MITRE Mapping

* **T1565 — Data Manipulation**
* **T1070 — Indicator Removal**

---

# 📊 Outcome

Validates file integrity monitoring pipeline.

---