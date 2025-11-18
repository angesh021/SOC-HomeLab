# ✅ **05_privilege_escalation_detection.md**

### **Scenario 05 — Privilege Escalation via Local Admin Creation**

---

# 📝 Overview

This scenario simulates unauthorized **local administrator account creation**, a common lateral movement technique.

---

# 🎯 Objective

* Detect user creation
* Detect administrator group modification
* Validate Windows event collection
* MITRE: **T1078 — Valid Accounts**, **T1098 – Account Manipulation**

---

# ⚔️ Attack (Windows)

### Create user:

```powershell
net user pentestUser Pass123! /add
```

### Add to Administrators:

```powershell
net localgroup administrators pentestUser /add
```

---

# 🔍 Telemetry & Evidence

## **1. Event ID 4720 — User Created**

```
A user account was created.
NewAccountName: pentestUser
```

## **2. Event ID 4732 — Member Added to Admin Group**

```
A user was added to a privileged group.
```

---

# 🛡️ Wazuh Custom Rules

```xml
<rule id="400001" level="10">
  <field name="win.system.eventID">4720</field>
  <description>New Local User Created</description>
  <group>account,creation,privilege</group>
</rule>

<rule id="400002" level="12">
  <field name="win.system.eventID">4732</field>
  <description>User Added to Administrators Group</description>
  <group>privilege_escalation,account</group>
</rule>
```

---

# 🧠 MITRE Mapping

**T1098 – Account Manipulation**
**T1078 – Valid Accounts**

---

# 📊 Outcome

This scenario verifies:

* Lateral movement detection
* Privilege escalation monitoring
* Wazuh rule accuracy

---