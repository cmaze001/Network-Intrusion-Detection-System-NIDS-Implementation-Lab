# Network Intrusion Detection System (NIDS) Implementation Lab

This repository contains the implementation of a **Network Intrusion Detection System (NIDS)** using **Snort**, **Wireshark**, **Scapy**, and **Metasploit**. The project demonstrates the setup, configuration, and testing of a custom NIDS to detect various types of network attacks, including port scans, Denial of Service (DoS) attacks, and SQL injection attacks.

## **Project Overview**

The goal of this project is to provide hands-on experience in designing, implementing, and testing an NIDS solution. The lab includes:

- **Setting up Snort** to monitor network traffic for intrusions.
- **Simulating network attacks** using tools like **Nmap**, **Metasploit**, and **Scapy**.
- **Traffic analysis** using **Wireshark** and **Scapy** for detecting malicious activities.
- **Creating custom Snort rules** to detect specific attacks.

This project is intended for cybersecurity professionals and enthusiasts who want to deepen their understanding of network security monitoring and incident response.

---

## **Lab Requirements**

### **Hardware/Software Requirements**
- **Operating System**: Ubuntu (or other Linux distributions).
- **Snort**: Open-source NIDS tool.
- **Wireshark**: Packet analysis tool.
- **Metasploit**: Framework for simulating real-world attacks.
- **Nmap**: Network scanning tool.
- **Scapy**: Python tool for interactive packet manipulation.

### **Network Configuration**
- Set up a local network environment with at least two machines: one for the **attacker** and one for the **target**.
- IP Configuration Example:
  - Attacker machine IP: `192.168.1.10`
  - Target machine IP: `192.168.1.20`

---

## **Setup and Installation**

### **1. Install Snort**
Install Snort on your monitoring machine (Ubuntu):

```bash
sudo apt update
sudo apt install snort
```

Configure Snort to monitor the correct network interface (e.g., `eth0`):

```bash
sudo snort -A console -c /etc/snort/snort.conf -i eth0
```

### **2. Install Wireshark**
Install Wireshark for packet capture and traffic analysis:

```bash
sudo apt install wireshark
```

### **3. Install Metasploit**
Metasploit is required for simulating attacks. To install Metasploit:

```bash
sudo apt install metasploit-framework
```

### **4. Install Nmap**
Install Nmap for network scanning:

```bash
sudo apt install nmap
```

### **5. Install Scapy**
Scapy is used for advanced traffic analysis and attack simulation. To install:

```bash
sudo apt install python3-scapy
```

---

## **Running the Lab**

### **1. Configure Snort**

Edit the Snort configuration file (`/etc/snort/snort.conf`) to define network variables:

```bash
var HOME_NET [192.168.1.0/24]
var EXTERNAL_NET any
```

Enable logging to a specific directory:

```bash
output log_tcpdump: /var/log/snort/alerts
```

### **2. Start Snort in IDS Mode**
Run Snort to start monitoring network traffic:

```bash
sudo snort -A console -c /etc/snort/snort.conf -i eth0
```

### **3. Simulate Attacks**

#### **Port Scan (Nmap)**

Run a port scan from the attacker machine:

```bash
nmap -sS -T4 192.168.1.20
```

Check Snort logs and Wireshark capture for **port scan** detection.

#### **Denial of Service (DoS) Attack (Metasploit)**

Start a **SYN flood** DoS attack from the attacker machine:

```bash
msfconsole
use auxiliary/dos/tcp/synflood
set RHOST 192.168.1.20
set RPORT 80
run
```

Monitor Snort alerts and Wireshark capture for **DoS** attack detection.

#### **SQL Injection Attack (Web Application)**

Set up a vulnerable web application (e.g., DVWA or Mutillidae). Simulate an SQL injection attack:

```bash
' OR '1'='1
```

Monitor Snort and Wireshark for **SQL injection** detection.

### **4. Analyze Alerts**

Snort logs alerts to `/var/log/snort/alerts`. You can view these logs with:

```bash
cat /var/log/snort/alerts
```

In **Wireshark**, you can filter packets based on attack types:
- **Port Scan**: `ip.src == 192.168.1.10 && ip.dst == 192.168.1.20 && tcp.flags.syn == 1`
- **DoS Attack**: `ip.src == 192.168.1.10 && ip.dst == 192.168.1.20 && tcp.flags.syn == 1`
- **SQL Injection**: `http contains "' OR '1'='1"`

---

## **Traffic Analysis and Response**

- **Blocking Malicious IPs**: Use `iptables` to block IPs identified as malicious by Snort:

```bash
sudo iptables -A INPUT -s 192.168.1.10 -j DROP
```

- **Custom Snort Rules**: Add custom rules to Snort to detect specific attack patterns, such as:

```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; flow:to_server,established; content:"' OR '1'='1"; sid:100001;)
```

---

## **Conclusion**

This lab demonstrates how to:
- Set up and configure a **Network Intrusion Detection System (NIDS)**.
- Simulate **real-world network attacks** such as port scans, DoS attacks, and SQL injections.
- Use tools like **Snort**, **Wireshark**, **Scapy**, and **Metasploit** for traffic analysis and attack detection.



---

## **Further Enhancements**
- **Extend Snort with Custom Rules**: Add advanced Snort rules to detect additional attacks.
- **Automate Incident Response**: Write Python scripts to automatically respond to detected intrusions.
- **Integrate Other IDS Tools**: Expand the lab to use **Suricata** or **Bro/Zeek** for additional network monitoring capabilities.

---
