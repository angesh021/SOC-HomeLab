# ✅ **02_bruteforce_wazuh_rule.md**

### **Scenario 02 — SMB Bruteforce Attack Detection (Hydra → Windows)**

---

# 📝 Overview

This scenario simulates a **password brute-force attack** against SMB/RDP using Hydra from the attacker machine.

Goal: test Wazuh correlation, Windows event logging, and Sysmon monitoring.

---

# 🎯 Objectives

* Detect multiple failed logons (Event ID 4625)
* Enrich with attacker IP information
* Trigger custom Wazuh brute-force rule
* Map to MITRE: **T1110 – Brute Force**

---

# ⚔️ Attack Steps (Kali Attacker)

### SMB brute-force:

```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://10.20.20.20
```

### RDP brute-force:

```bash
hydra -l administrator -P rockyou.txt rdp://10.20.20.20
```

---

# 🔍 Telemetry & Evidence

## **1. Windows Event Logs**

Event ID **4625** (Failed Logon)

Expected values:

* `LogonType: 3`
* `IpAddress: 10.20.20.10`
* `FailureReason: Unknown user name or bad password`

---

## **2. Sysmon**

Sysmon will record network connections from attacker to SMB ports:

```
EventID: 3
DestinationPort: 445
SourceIp: 10.20.20.10
```

---

## **3. Wazuh Agent**

Wazuh forwards all:

* Sysmon events
* Windows security logs

---

# 🛡️ Wazuh Detection Rule

Place in:

```
/var/ossec/etc/rules/local_rules.xml
```

### **Rule 100001 — Multiple Authentication Failures**

```xml
<group name="windows,authentication,bruteforce,local">
  <rule id="100001" level="10">
    <if_sid>18107</if_sid>
    <same_source_ip />
    <frequency>5</frequency>
    <timeframe>60</timeframe>
    <description>Bruteforce attack detected: repeated authentication failures from same IP</description>
  </rule>
</group>
```

---

# 🧠 MITRE Mapping

**T1110 — Brute Force**
Techniques:

* T1110.001 Password Guessing
* T1110.002 Password Cracking

---

# 📊 Outcome

This scenario validates:

* Authentication monitoring
* Correlation rule tuning
* Attack → detection → response pipeline

---