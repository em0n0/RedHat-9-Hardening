# RHEL 9 Security Hardening -- Automated Setup Script

An automated, defensive shell script designed to streamline security baseline provisioning on **Red Hat Enterprise Linux (RHEL) 10**. 

This script consolidates infrastructure hardening, Multi-Factor Authentication (MFA), defensive deception (honeypot deployment), stateful firewall logic, and a lightweight Network Intrusion Detection System (NIDS) installation into a unified execution flow.

---

##  Security Architecture Overview

The script automates configuration across five major security vectors:

1. **OpenSSH Server Hardening**:
   * Transitions SSH to a non-standard port (Default: `2222`).
   * Enforces Public Key Authentication (`PubkeyAuthentication yes`) and disables password logins.
   * Disables root login, empty passwords, host-based auth, and TCP/X11 forwarding.
   * Registers custom system ports dynamically in **SELinux** (`ssh_port_t`).
   * Renders a dynamic legal warning banner embedding organizational employee tracking metrics.

2. **Multi-Factor Authentication (MFA/TOTP)**:
   * Provisions Google Authenticator PAM modules via EPEL.
   * Configures `/etc/pam.d/sshd` to require both an SSH public key *and* an interactive Time-based One-Time Password (`publickey,keyboard-interactive`).
   * Safely isolates password fallbacks.

3. **Cowrie Deployment**:
   * Installs an isolated, non-privileged system user (`cowrie`) to handle incoming reconnaissance threats.
   * Clones and builds Cowrie within a Python 3 virtual environment (`virtualenv`).
   * Binds to a dedicated honeypot port (Default: `2223`) mimicking a vulnerable system.
   * Sets up a custom authentication database (`userdb.txt`) that explicitly drops/logs all `root` attempts while permitting simulated credentials.

4. **Stateful `iptables` Firewall**:
   * Gracefully dismantles `firewalld` and migrates the system to native `iptables-services`.
   * Establishes a strict **Default DROP** policy on `INPUT` and `FORWARD` chains.
   * Implements granular system logging with distinctive kernel logging prefixes (`< SSH TRAFFIC >`, `<< HONEYPOT TRAFFIC >>`, `<<< BLOCKED TRAFFIC >>>`).

5. **Snort 3 Intrusion Detection System**:
   * Pulls dependencies via the CodeReady Builder (CRB) repository.
   * Compiles and instances `libdaq` and **Snort 3** from source.
   * Mounts custom security analytics definitions (`local.rules`) encompassing ICMP diagnostics, core web/database payloads (SQL injection validation), reconnaissance footprints (Nmap Christmas/Null/FIN scans), reverse shells (`netcat`), and DoS thresholding.

---

##  Prerequisites & Requirements

* **Operating System**: RHEL 9 (Registered with an active subscription or configured with working software repositories).
* **Privileges**: Root execution via `sudo`.
* **Network**: An active Internet connection during installation to fetch packages from DNF, EPEL, and GitHub.

---

##  Execution & Usage Guide

The script utilizes a design pattern where all configuration parameters are collected **interactively at runtime startup**. Once confirmed, the script processes all phases non-interactively.

### 1. Download and Prepare the Script
Move the script onto your RHEL 9 target, name it `rhel10_security_setup.sh`, and mark it as executable:
```bash
chmod +x rhel10_security_setup.sh

```

### 2. Run the Automated Suite

Execute the script as root:

```bash
sudo ./rhel10_security_setup.sh

```

### 3. Provide Interactive Parameters

The script will prompt you for the following inputs:

* **Employee ID** & **Full Name** (Used to dynamically label system warning banners and honeypot hostnames).
* **SSH Port** (Target port for real administrator access; default `2222`).
* **Cowrie Port** (Target port for baiting malicious traffic; default `2223`).
* **Cowrie Staff Password** (Simulated access pass inside the honeypot).
* **Network Interface** (Auto-detects active non-loopback interfaces like `ens3` or `eth0`).

---

##  Mandatory Manual Next Steps

Because the security pipeline enforces strict MFA and Public Key validation, **you must complete these manual tasks before closing your terminal window** to avoid losing access to the machine.

### Step 1: Copy Your SSH Public Key to the Server

From your **local machine (client)**, generate an modern keypair if you haven't already, and copy it to the server using the custom port you defined:

```bash
# On your local workstation:
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_rhel10
ssh-copy-id -i ~/.ssh/id_ed25519_rhel10.pub -p <YOUR_CUSTOM_SSH_PORT> <user>@<server_ip>

```

### Step 2: Enroll Your User Account in TOTP MFA

Log into your target RHEL 9 system, drop to the context of the regular user account authorized to connect via SSH, and run the authenticator initialization binary:

```bash
# On the RHEL 9 Server:
google-authenticator

```

* **Recommended answers**:
* Make tokens time-based? `y`
* Update your `~/.google_authenticator` file? `y`
* Disallow multiple uses of the same token? `y`
* Increase time-window tolerance? `n`
* Enable rate-limiting? `y`


* **Scan the generated QR Code** using your preferred authenticator application (Google Authenticator, Authy, Aegis, etc.).

### Step 3: Verify Connection Stability

**Do not close your active root session.** Open a brand new terminal instance on your local computer and test your login path:

```bash
ssh -i ~/.ssh/id_ed25519_rhel10 -p <YOUR_CUSTOM_SSH_PORT> <user>@<server_ip>

```

*You should see your custom employee banner appear, followed by a prompt asking for your Verification Code (TOTP token).*

---

## 🔍 Verification & Log Management

Verify system services are healthy and actively capturing telemetry with the following monitoring commands:

### Service Health Checks

```bash
systemctl status sshd
systemctl status cowrie
systemctl status snort
systemctl status iptables

```

### Operational Log Framework

| Threat Vector / Component | Target Destination Path |
| --- | --- |
| **System Auth & MFA Logs** | `/var/log/secure` |
| **Firewall (iptables Log Streams)** | `/var/log/messages` |
| **Cowrie Honeypot Sessions** | `/opt/cowrie/var/log/cowrie/cowrie.log` |
| **Snort 3 NIDS Alerts** | `/var/log/snort/alert_fast.txt` |

### Live Monitoring Snippets

Stream live firewall modifications and dropping events:

```bash
tail -f /var/log/messages | grep -E 'SSH TRAFFIC│HONEYPOT│BLOCKED'

```

Watch for Snort IDS signatures catching suspicious network operations (like ping sweeps or web directory probes):

```bash
tail -f /var/log/snort/alert_fast.txt

```

```

***# RHEL 9  Hardening -- Automated Setup Script

An automated, defensive shell script designed to streamline  baseline provisioning on **Red Hat Enterprise Linux (RHEL) 10**. 

This script consolidates infrastructure hardening, Multi-Factor Authentication (MFA), defensive deception (honeypot deployment), stateful firewall logic, and a lightweight Network Intrusion Detection System (NIDS) installation into a unified execution flow.

---

##   Architecture Overview

The script automates configuration across five major  vectors:

1. **OpenSSH Server Hardening**:
   * Transitions SSH to a non-standard port (Default: `2222`).
   * Enforces Public Key Authentication (`PubkeyAuthentication yes`) and disables password logins.
   * Disables root login, empty passwords, host-based auth, and TCP/X11 forwarding.
   * Registers custom system ports dynamically in **SELinux** (`ssh_port_t`).
   * Renders a dynamic legal warning banner embedding organizational employee tracking metrics.

2. **Multi-Factor Authentication (MFA/TOTP)**:
   * Provisions Google Authenticator PAM modules via EPEL.
   * Configures `/etc/pam.d/sshd` to require both an SSH public key *and* an interactive Time-based One-Time Password (`publickey,keyboard-interactive`).
   * Safely isolates password fallbacks.

3. **Cowrie Honeypot Deployment**:
   * Installs an isolated, non-privileged system user (`cowrie`) to handle incoming reconnaissance threats.
   * Clones and builds Cowrie within a Python 3 virtual environment (`virtualenv`).
   * Binds to a dedicated honeypot port (Default: `2223`) mimicking a vulnerable system.
   * Sets up a custom authentication database (`userdb.txt`) that explicitly drops/logs all `root` attempts while permitting simulated credentials.

4. **Stateful `iptables` Firewall**:
   * Gracefully dismantles `firewalld` and migrates the system to native `iptables-services`.
   * Establishes a strict **Default DROP** policy on `INPUT` and `FORWARD` chains.
   * Implements granular system logging with distinctive kernel logging prefixes (`< SSH TRAFFIC >`, `<< HONEYPOT TRAFFIC >>`, `<<< BLOCKED TRAFFIC >>>`).

5. **Snort 3 Intrusion Detection System**:
   * Pulls dependencies via the CodeReady Builder (CRB) repository.
   * Compiles and instances `libdaq` and **Snort 3** from source.
   * Mounts custom  analytics definitions (`local.rules`) encompassing ICMP diagnostics, core web/database payloads (SQL injection validation), reconnaissance footprints (Nmap Christmas/Null/FIN scans), reverse shells (`netcat`), and DoS thresholding.

---

##  Prerequisites & Requirements

* **Operating System**: RHEL 9 (Registered with an active subscription or configured with working software repositories).
* **Privileges**: Root execution via `sudo`.
* **Network**: An active Internet connection during installation to fetch packages from DNF, EPEL, and GitHub.

---

##  Execution & Usage Guide

The script utilizes a design pattern where all configuration parameters are collected **interactively at runtime startup**. Once confirmed, the script processes all phases non-interactively.

### 1. Download and Prepare the Script
Move the script onto your RHEL 9 target, name it `rhel10_security_setup.sh`, and mark it as executable:
```bash
chmod +x rhel10_security_setup.sh

```

### 2. Run the Automated Suite

Execute the script as root:

```bash
sudo ./rhel10_security_setup.sh

```

### 3. Provide Interactive Parameters

The script will prompt you for the following inputs:

* **Employee ID** & **Full Name** (Used to dynamically label system warning banners and honeypot hostnames).
* **SSH Port** (Target port for real administrator access; default `2222`).
* **Cowrie Port** (Target port for baiting malicious traffic; default `2223`).
* **Cowrie Staff Password** (Simulated access pass inside the honeypot).
* **Network Interface** (Auto-detects active non-loopback interfaces like `ens3` or `eth0`).

---

##  Mandatory Manual Next Steps

Because the  pipeline enforces strict MFA and Public Key validation, **you must complete these manual tasks before closing your terminal window** to avoid losing access to the machine.

### Step 1: Copy Your SSH Public Key to the Server

From your **local machine (client)**, generate an modern keypair if you haven't already, and copy it to the server using the custom port you defined:

```bash
# On your local workstation:
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_rhel10
ssh-copy-id -i ~/.ssh/id_ed25519_rhel10.pub -p <YOUR_CUSTOM_SSH_PORT> <user>@<server_ip>

```

### Step 2: Enroll Your User Account in TOTP MFA

Log into your target RHEL 9 system, drop to the context of the regular user account authorized to connect via SSH, and run the authenticator initialization binary:

```bash
# On the RHEL 9 Server:
google-authenticator

```

* **Recommended answers**:
* Make tokens time-based? `y`
* Update your `~/.google_authenticator` file? `y`
* Disallow multiple uses of the same token? `y`
* Increase time-window tolerance? `n`
* Enable rate-limiting? `y`


* **Scan the generated QR Code** using your preferred authenticator application (Google Authenticator, Authy, Aegis, etc.).

### Step 3: Verify Connection Stability

**Do not close your active root session.** Open a brand new terminal instance on your local computer and test your login path:

```bash
ssh -i ~/.ssh/id_ed25519_rhel10 -p <YOUR_CUSTOM_SSH_PORT> <user>@<server_ip>

```

*You should see your custom employee banner appear, followed by a prompt asking for your Verification Code (TOTP token).*

---

##  Verification & Log Management

Verify system services are healthy and actively capturing telemetry with the following monitoring commands:

### Service Health Checks

```bash
systemctl status sshd
systemctl status cowrie
systemctl status snort
systemctl status iptables

```

### Operational Log Framework

| Threat Vector / Component | Target Destination Path |
| --- | --- |
| **System Auth & MFA Logs** | `/var/log/secure` |
| **Firewall (iptables Log Streams)** | `/var/log/messages` |
| **Cowrie Honeypot Sessions** | `/opt/cowrie/var/log/cowrie/cowrie.log` |
| **Snort 3 NIDS Alerts** | `/var/log/snort/alert_fast.txt` |

### Live Monitoring Snippets

Stream live firewall modifications and dropping events:

```bash
tail -f /var/log/messages | grep -E 'SSH TRAFFIC│HONEYPOT│BLOCKED'

```

Watch for Snort IDS signatures catching suspicious network operations (like ping sweeps or web directory probes):

```bash
tail -f /var/log/snort/alert_fast.txt
