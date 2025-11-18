# ✅ **01_port_scan_recon.md**

### **Scenario 01 — Port Scan & Reconnaissance Detection (Nmap → Windows 10 Victim)**

---

# 📝 Overview

This scenario simulates external attacker reconnaissance using **Nmap** from Kali Linux against the Windows 10 victim host.
The purpose is to validate **network telemetry visibility**, **Sysmon logging**, **Wazuh correlation**, and **Zeek/Suricata IDS detection**.

---

# 🎯 Objectives

* Detect TCP SYN scan behavior
* Correlate attacker IP → victim IP
* Analyze artifacts using Sysmon, Zeek, Suricata, and Wazuh
* Map detection to MITRE ATT&CK Technique **T1046 – Network Service Scanning**

---

# ⚔️ Attack Steps (Kali Attacker)

### **Basic SYN scan:**

```bash
nmap -Pn -sS -T4 10.20.20.20
```

### **Full port range:**

```bash
nmap -p- -T4 10.20.20.20
```

### **OS fingerprinting:**

```bash
nmap -O 10.20.20.20
```

---

# 🔍 Evidence & Telemetry Collected

## **1. Sysmon (on Windows Victim)**

Sysmon Event **ID 3** (Network Connection)
Repeated inbound connections to many ports:

```
Source IP: 10.20.20.10
Destination IP: 10.20.20.20
Protocol: TCP
Destination Ports: 21,22,23,80,445,3389, ...
```

---

## **2. Zeek (on SOC VM)**

Check Zeek's conn.log:

```bash
cat /opt/zeek/logs/current/conn.log | grep 10.20.20.10
```

Expected behavior:

* Large number of connection attempts
* Short-duration connections
* No established sessions

---

## **3. Suricata IDS**

Fast.log entries (depending on signatures):

```
ET SCAN NMAP -sS window 1024
ET SCAN Nmap Scripting Engine User-Agent Detected
```

---

## **4. Wazuh Events**

Search Wazuh for network scanning:

### Query:

```
data.win.eventdata.DestinationPort: *
AND
data.win.eventdata.SourceIp: "10.20.20.10"
```

---

# 🛡️ Detection Logic (Wazuh Custom Rule)

Place inside `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="network_scan,windows,local">
  <rule id="100001" level="10">
    <if_sid>61603</if_sid>
    <description>Nmap Stealth Scan Detected</description>
    <group>attack,nmap,scan</group>
  </rule>
</group>
```

---

# 🧠 MITRE Mapping

**T1046 — Network Service Scanning**

---

# 📊 Outcome

This scenario validates:

* Network telemetry visibility
* IDS/EDR log forwarding
* Detection pipeline
* Correlation between hosts

---
