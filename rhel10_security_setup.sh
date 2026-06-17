#!/usr/bin/env bash
# =============================================================================
# Order   : Snort -> OpenSSH -> MFA -> Firewall -> Cowrie -> Snort Rules -> OpenSCAP
set -euo pipefail
IFS=$'\n\t'
# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  — edit these before running
# ─────────────────────────────────────────────────────────────────────────────
SSH_PORT=                         # Custom SSH (OpenSSH) port
COWRIE_PORT=                      # Port Cowrie honeypot listens on (default 22)
Employee_ID=                      # Your Employee
Employee_NAME=                    # Your full name

# Cowrie user passwords
ROOT_COWRIE_PASS=                 # Password for 'root' inside Cowrie
STAFF_COWRIE_PASS=                # Password for 'staff' inside Cowrie

# Public key for real OpenSSH key-based auth
SSH_PUBLIC_KEY=

# OpenSCAP profile  (CIS Level 2 for RHEL 10 — change if STIG is preferred)
OSCAP_PROFILE=
OSCAP_REPORT_DIR=

# Snort installation path (source-built binary location)
SNORT_BIN=
SNORT_CONF=
SNORT_RULES_DIR=
SNORT_LOG_DIR=

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()     { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[ERROR]${NC} $*" >&2; }
section() { echo -e "\n${CYAN}══════════════════════════════════════════════════════${NC}"; \
            echo -e "${CYAN}  $*${NC}"; \
            echo -e "${CYAN}══════════════════════════════════════════════════════${NC}\n"; }

require_root() {
    [[ $EUID -eq 0 ]] || { err "Run as root (sudo)."; exit 1; }
}

pkg_install() {
    log "Installing packages: $*"
    dnf install -y "$@" 2>&1 | grep -E '(Installed|Nothing|Error)' || true
}

backup_file() {
    local f="$1"
    [[ -f "$f" ]] && cp -p "$f" "${f}.bak.$(date +%Y%m%d%H%M%S)" && log "Backed up $f"
}

# ─────────────────────────────────────────────────────────────────────────────
# PRE-FLIGHT
# ─────────────────────────────────────────────────────────────────────────────
require_root

section "PRE-FLIGHT: System preparation"

log "Detecting primary network interface..."
NET_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
NET_IFACE="${NET_IFACE:-eth0}"
log "Using interface: ${NET_IFACE}"

log "Disabling SELinux temporarily (will be re-enabled after OpenSCAP remediation)..."
setenforce 0 || warn "Could not change SELinux mode (may already be permissive)"
sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config

log "Updating system packages..."
dnf update -y -q

# Install common build dependencies
pkg_install epel-release
pkg_install git curl wget gcc make cmake python3 python3-pip \
            python3-virtualenv authselect pam google-authenticator \
            libcap-ng libcap-ng-devel libpcap libpcap-devel pcre2 pcre2-devel \
            hwloc-devel luajit luajit-devel openssl-devel libdnet-devel \
            zlib-devel flex bison pkg-config iptables-services iptables \
            iptables-nft nftables jq net-tools

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1 — SNORT IDS INSTALLATION
# ═════════════════════════════════════════════════════════════════════════════
section "PHASE 1: Snort 3 Installation"

SNORT_VERSION="3.3.4.0"
SNORT_ARCHIVE="snort3-${SNORT_VERSION}.tar.gz"
SNORT_SRC_URL="https://github.com/snort3/snort3/archive/refs/tags/${SNORT_VERSION}.tar.gz"
BUILD_DIR="/tmp/snort_build"

install_snort_from_source() {
    log "Building Snort 3 from source (this takes ~10 minutes)..."
    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"

    # libdaq
    if [[ ! -f /usr/local/lib/libdaq.so ]]; then
        log "Building libdaq..."
        git clone --depth 1 https://github.com/snort3/libdaq.git libdaq
        cd libdaq
        ./bootstrap && ./configure && make -j"$(nproc)" && make install
        ldconfig
        cd "${BUILD_DIR}"
    fi

    # Snort 3 source
    if [[ ! -f "${SNORT_ARCHIVE}" ]]; then
        wget -q "${SNORT_SRC_URL}" -O "${SNORT_ARCHIVE}"
    fi
    tar -xzf "${SNORT_ARCHIVE}"
    cd "snort3-${SNORT_VERSION}"

    ./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc 2>&1 | tail -5
    cd build
    make -j"$(nproc)" 2>&1 | tail -5
    make install
    ldconfig
    log "Snort 3 installed: $("${SNORT_BIN}" -V 2>&1 | head -2)"
}

if command -v snort &>/dev/null || [[ -x "${SNORT_BIN}" ]]; then
    log "Snort already present, skipping build."
else
    install_snort_from_source
fi

# Directory skeleton
mkdir -p "${SNORT_RULES_DIR}" "${SNORT_LOG_DIR}" /usr/local/etc/snort

# Base snort.lua (minimal, rules are appended in Phase 6)
if [[ ! -f "${SNORT_CONF}" ]]; then
    log "Creating base snort.lua..."
    cat > "${SNORT_CONF}" <<'SNORT_LUA'
-- Snort 3 main configuration
-- Custom rules are in /usr/local/etc/snort/rules/local.rules

HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    enable_builtin_rules = true,
    rules = [[
        include /usr/local/etc/snort/rules/local.rules
    ]],
}

alert_fast = {
    file = true,
    packet = false,
    limit = 10,
}

-- Use unix socket for alert output
-- Output can also be piped to a SIEM
SNORT_LUA
fi

# Snort systemd service
cat > /etc/systemd/system/snort3.service <<SNORT_SVC
[Unit]
Description=Snort 3 Intrusion Detection System
After=network.target

[Service]
Type=simple
ExecStart=${SNORT_BIN} -c ${SNORT_CONF} -i ${NET_IFACE} -l ${SNORT_LOG_DIR} -D -q
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SNORT_SVC

systemctl daemon-reload
log "Snort service unit created (not started yet — rules configured in Phase 6)."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2 — OpenSSH SERVER
# ═════════════════════════════════════════════════════════════════════════════
section "PHASE 2: OpenSSH Configuration"

pkg_install openssh-server openssh-clients

SSHD_CONF="/etc/ssh/sshd_config"
backup_file "${SSHD_CONF}"

log "Writing hardened sshd_config on port ${SSH_PORT}..."
cat > "${SSHD_CONF}" <<SSHD_EOF
# ============================================================
# OpenSSH Server Configuration — Hardened Baseline
# Generated by rhel10_hardening.sh
# Author: ${Employee_ID} — ${Employee_NAME}
# ============================================================

Port ${SSH_PORT}
AddressFamily inet
ListenAddress 0.0.0.0:${SSH_PORT}

# ── Authentication ──────────────────────────────────────────
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication yes
UsePAM yes

# ── MFA (Google Authenticator) ──────────────────────────────
# AuthenticationMethods is set below; keep this section for PAM.
AuthenticationMethods publickey,keyboard-interactive

# ── Forwarding / Tunneling ──────────────────────────────────
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
PermitTunnel no
AllowAgentForwarding no

# ── Banner ──────────────────────────────────────────────────
Banner /etc/ssh/banner

# ── Session hardening ───────────────────────────────────────
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
StrictModes yes
IgnoreRhosts yes
LogLevel VERBOSE
SyslogFacility AUTH

# ── Allowed ciphers / MACs (RHEL 10 strong defaults) ────────
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521
SSHD_EOF

# Banner file
log "Creating SSH login banner..."
cat > /etc/ssh/banner <<BANNER_EOF
╔═══════════════════════════════════════════════════════════════╗
║           AUTHORIZED ACCESS ONLY                              ║
║                                                               ║
║  Employee ID  : ${Employee_ID}                                  ║
║  Name        : ${Employee_NAME}                                ║
║                                                               ║
║  All activities on this system are monitored and recorded.    ║
║  Unauthorized access is strictly prohibited and will be       ║
║  prosecuted under applicable law.                             ║
╚═══════════════════════════════════════════════════════════════╝
BANNER_EOF

# Install public key for current sudo user (or root if called directly)
REAL_USER="${SUDO_USER:-root}"
if [[ "${REAL_USER}" == "root" ]]; then
    AUTH_KEY_DIR="/root/.ssh"
else
    AUTH_KEY_DIR="/home/${REAL_USER}/.ssh"
fi
mkdir -p "${AUTH_KEY_DIR}"
chmod 700 "${AUTH_KEY_DIR}"

AUTH_KEY_FILE="${AUTH_KEY_DIR}/authorized_keys"
if ! grep -qF "${SSH_PUBLIC_KEY}" "${AUTH_KEY_FILE}" 2>/dev/null; then
    echo "${SSH_PUBLIC_KEY}" >> "${AUTH_KEY_FILE}"
    log "Public key added to ${AUTH_KEY_FILE}"
fi
chmod 600 "${AUTH_KEY_FILE}"
[[ "${REAL_USER}" != "root" ]] && chown -R "${REAL_USER}:${REAL_USER}" "${AUTH_KEY_DIR}"

# SELinux port label for custom SSH port
if command -v semanage &>/dev/null; then
    semanage port -a -t ssh_port_t -p tcp "${SSH_PORT}" 2>/dev/null \
        || semanage port -m -t ssh_port_t -p tcp "${SSH_PORT}" 2>/dev/null \
        || warn "semanage port adjustment failed — check SELinux manually"
fi

# Validate config before enabling
sshd -t && log "sshd_config syntax OK"

systemctl enable --now sshd
systemctl restart sshd
log "OpenSSH listening on port ${SSH_PORT}."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3 — MULTI-FACTOR AUTHENTICATION (Google Authenticator TOTP)
# ═════════════════════════════════════════════════════════════════════════════
section "PHASE 3: MFA via Google Authenticator (PAM TOTP)"

pkg_install google-authenticator qrencode

PAM_SSHD="/etc/pam.d/sshd"
backup_file "${PAM_SSHD}"

log "Configuring PAM for SSH with TOTP..."
# Insert google-authenticator PAM module at the top of sshd PAM stack.
# 'nullok' allows existing users without a .google_authenticator file to still
# log in (remove 'nullok' to enforce MFA for everyone).
PAM_LINE="auth required pam_google_authenticator.so nullok secret=\${HOME}/.ssh/.google_authenticator"
if ! grep -q "pam_google_authenticator" "${PAM_SSHD}"; then
    # Insert after the first auth line so password module still runs for
    # accounts that haven't set up MFA yet.
    sed -i "1s|^|${PAM_LINE}\n|" "${PAM_SSHD}"
fi

# Ensure system-auth doesn't short-circuit our MFA
if grep -q "^auth.*system-auth" "${PAM_SSHD}"; then
    # Keep it but ensure google-authenticator runs
    log "system-auth found in PAM, MFA line prepended — review manually if needed."
fi

log "MFA PAM configured."
log ""
log "  ┌─────────────────────────────────────────────────────────────────┐"
log "  │  IMPORTANT: Each user must run 'google-authenticator' manually  │"
log "  │  to generate their TOTP secret and QR code.                     │"
log "  │                                                                  │"
log "  │  Run as the target user:                                        │"
log "  │    google-authenticator -t -d -f -r 3 -R 30                    │"
log "  │        -s ~/.ssh/.google_authenticator                          │"
log "  │                                                                  │"
log "  │  Then scan the printed QR code with Google Authenticator app.   │"
log "  └─────────────────────────────────────────────────────────────────┘"
log ""

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4 — IPTABLES FIREWALL
# ═════════════════════════════════════════════════════════════════════════════
section "PHASE 4: iptables Firewall"

log "Disabling firewalld in favour of raw iptables..."
systemctl disable --now firewalld 2>/dev/null || true
systemctl enable --now iptables

log "Flushing existing rules..."
iptables -F
iptables -X
iptables -Z
ip6tables -F
ip6tables -X

# ── Default policies ──────────────────────────────────────────────────────
log "Setting default DROP policy on all chains..."
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

# ── Allow loopback ────────────────────────────────────────────────────────
iptables -A INPUT -i lo -j ACCEPT

# ── Allow established / related connections ───────────────────────────────
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ── LOG + ACCEPT OpenSSH traffic ─────────────────────────────────────────
log "Creating OpenSSH rules on port ${SSH_PORT}..."
iptables -A INPUT -p tcp --dport "${SSH_PORT}" \
    -m limit --limit 10/min --limit-burst 20 \
    -j LOG --log-prefix "< SSH TRAFFIC > " --log-level 4

iptables -A INPUT -p tcp --dport "${SSH_PORT}" \
    -m conntrack --ctstate NEW \
    -m recent --set --name SSH_BRUTE
iptables -A INPUT -p tcp --dport "${SSH_PORT}" \
    -m conntrack --ctstate NEW \
    -m recent --update --seconds 60 --hitcount 6 --name SSH_BRUTE \
    -j DROP
iptables -A INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT

# ── LOG + ACCEPT Cowrie (honeypot) traffic ────────────────────────────────
log "Creating Cowrie / honeypot rules on port ${COWRIE_PORT}..."
iptables -A INPUT -p tcp --dport "${COWRIE_PORT}" \
    -m limit --limit 30/min --limit-burst 50 \
    -j LOG --log-prefix "<< HONEYPOT TRAFFIC >> " --log-level 4

iptables -A INPUT -p tcp --dport "${COWRIE_PORT}" -j ACCEPT

# ── LOG blocked traffic ───────────────────────────────────────────────────
log "Adding catch-all blocked traffic logging rule..."
iptables -A INPUT \
    -m limit --limit 5/min --limit-burst 10 \
    -j LOG --log-prefix "<<< BLOCKED TRAFFIC >>> " --log-level 4

# (Default policy DROP handles the actual block; LOG rule above just records it)

# ── IPv6: block everything except loopback ────────────────────────────────
ip6tables -P INPUT   DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT  ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ── Persist rules ─────────────────────────────────────────────────────────
log "Saving iptables rules..."
iptables-save  > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
systemctl restart iptables
log "Firewall rules applied and saved."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5 — COWRIE HONEYPOT
# ═════════════════════════════════════════════════════════════════════════════
section "PHASE 5: Cowrie Honeypot"

COWRIE_HOME="/opt/cowrie"
COWRIE_USER="cowrie"
COWRIE_VENV="${COWRIE_HOME}/cowrie-env"

# Create dedicated system user
if ! id "${COWRIE_USER}" &>/dev/null; then
    useradd -r -s /sbin/nologin -d "${COWRIE_HOME}" "${COWRIE_USER}"
    log "System user '${COWRIE_USER}' created."
fi

# Clone Cowrie
if [[ ! -d "${COWRIE_HOME}/.git" ]]; then
    log "Cloning Cowrie repository..."
    git clone --depth 1 https://github.com/cowrie/cowrie.git "${COWRIE_HOME}"
fi
chown -R "${COWRIE_USER}:${COWRIE_USER}" "${COWRIE_HOME}"

# Virtual environment
if [[ ! -d "${COWRIE_VENV}" ]]; then
    log "Creating Python virtual environment..."
    python3 -m venv "${COWRIE_VENV}"
    sudo -u "${COWRIE_USER}" "${COWRIE_VENV}/bin/pip" install --quiet --upgrade pip
    sudo -u "${COWRIE_USER}" "${COWRIE_VENV}/bin/pip" install --quiet -r "${COWRIE_HOME}/requirements.txt"
fi

# ── Cowrie configuration ──────────────────────────────────────────────────
COWRIE_CFG="${COWRIE_HOME}/etc/cowrie.cfg"
[[ ! -f "${COWRIE_CFG}" ]] && cp "${COWRIE_HOME}/etc/cowrie.cfg.dist" "${COWRIE_CFG}"
backup_file "${COWRIE_CFG}"

log "Writing Cowrie configuration (hostname=${Employee_ID}, port=${COWRIE_PORT})..."

# Use Python's configparser-compatible sed replacements
# ── [honeypot] section ──
python3 - <<PYCONF
import configparser, os, re

cfg_path = '${COWRIE_CFG}'
with open(cfg_path, 'r') as f:
    content = f.read()

# Ensure sections exist
for section in ['honeypot', 'ssh']:
    if f'[{section}]' not in content:
        content += f'\n[{section}]\n'

with open(cfg_path, 'w') as f:
    f.write(content)

cfg = configparser.ConfigParser(strict=False, allow_no_value=True)
cfg.read(cfg_path)

# [honeypot]
if not cfg.has_section('honeypot'):
    cfg.add_section('honeypot')
cfg.set('honeypot', 'hostname', '${Employee_ID}')
cfg.set('honeypot', 'log_path', 'var/log/cowrie')
cfg.set('honeypot', 'download_path', 'var/lib/cowrie/downloads')
cfg.set('honeypot', 'share_path', 'share/cowrie')
cfg.set('honeypot', 'state_path', 'var/lib/cowrie')
cfg.set('honeypot', 'etc_path', 'honeyfs/etc')

# [ssh]
if not cfg.has_section('ssh'):
    cfg.add_section('ssh')
cfg.set('ssh', 'enabled', 'true')
cfg.set('ssh', 'listen_endpoints', 'tcp:${COWRIE_PORT}:interface=0.0.0.0')
cfg.set('ssh', 'version', 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6')

with open(cfg_path, 'w') as f:
    cfg.write(f)
print('Cowrie cfg updated via Python.')
PYCONF

# ── Cowrie userdb (allowed users) ──
USERDB="${COWRIE_HOME}/etc/userdb.txt"
log "Writing Cowrie userdb (root + staff only)..."
cat > "${USERDB}" <<USERDB_EOF
# Cowrie userdb — format: username:uid:password
# '!' prefix on password = hashed password required (use plain text here for cowrie)
# Use '*' to reject, '' to accept any password
root:0:${ROOT_COWRIE_PASS}
staff:1001:${STAFF_COWRIE_PASS}
USERDB_EOF
chown "${COWRIE_USER}:${COWRIE_USER}" "${USERDB}"
log "userdb written: root (custom pass), staff (custom pass)."

# ── Cowrie systemd service ─────────────────────────────────────────────────
cat > /etc/systemd/system/cowrie.service <<COWRIE_SVC
[Unit]
Description=Cowrie SSH Honeypot
After=network.target sshd.service

[Service]
Type=simple
User=${COWRIE_USER}
Group=${COWRIE_USER}
WorkingDirectory=${COWRIE_HOME}
ExecStart=${COWRIE_VENV}/bin/python3 ${COWRIE_HOME}/src/cowrie/core/main.py -n
ExecStop=/bin/kill -TERM \$MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
COWRIE_SVC

systemctl daemon-reload
systemctl enable cowrie
systemctl start cowrie || warn "Cowrie start failed — check logs: journalctl -u cowrie"
log "Cowrie started on port ${COWRIE_PORT}."

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 6 — SNORT RULES CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════
section "PHASE 6: Snort 3 Rules"

RULES_FILE="${SNORT_RULES_DIR}/local.rules"
log "Writing custom detection rules to ${RULES_FILE}..."

cat > "${RULES_FILE}" <<'SNORT_RULES'
# =============================================================================
# Snort 3 Local Rules — rhel10_hardening.sh
# =============================================================================

# ─── 1. ICMP Traffic (Diagnostics / Ping) ────────────────────────────────────
alert icmp any any -> $HOME_NET any (
    msg:"ICMP Ping Detected";
    itype:8;
    sid:1000001; rev:1;)

alert icmp any any -> $HOME_NET any (
    msg:"ICMP Echo Reply";
    itype:0;
    sid:1000002; rev:1;)

# ─── 2. TCP Traffic — Web ────────────────────────────────────────────────────
alert tcp any any -> $HOME_NET 80 (
    msg:"TCP HTTP Traffic Detected";
    flags:S;
    flow:to_server,established;
    sid:1000010; rev:1;)

alert tcp any any -> $HOME_NET 443 (
    msg:"TCP HTTPS Traffic Detected";
    flags:S;
    flow:to_server,established;
    sid:1000011; rev:1;)

# ─── 2. TCP Traffic — SSH ────────────────────────────────────────────────────
alert tcp any any -> $HOME_NET 22 (
    msg:"TCP SSH Traffic on Port 22 (Cowrie)";
    flags:S;
    sid:1000020; rev:1;)

alert tcp any any -> $HOME_NET ${SSH_PORT} (
    msg:"TCP SSH Traffic on Custom Port (OpenSSH)";
    flags:S;
    sid:1000021; rev:1;)

# ─── 2. TCP Traffic — Email ──────────────────────────────────────────────────
alert tcp any any -> $HOME_NET 25 (
    msg:"TCP SMTP Traffic Detected";
    flags:S;
    sid:1000030; rev:1;)

alert tcp any any -> $HOME_NET 587 (
    msg:"TCP SMTP Submission Traffic Detected";
    flags:S;
    sid:1000031; rev:1;)

alert tcp any any -> $HOME_NET 143 (
    msg:"TCP IMAP Traffic Detected";
    flags:S;
    sid:1000032; rev:1;)

alert tcp any any -> $HOME_NET 993 (
    msg:"TCP IMAPS Traffic Detected";
    flags:S;
    sid:1000033; rev:1;)

alert tcp any any -> $HOME_NET 110 (
    msg:"TCP POP3 Traffic Detected";
    flags:S;
    sid:1000034; rev:1;)

# ─── 3. UDP Traffic — DNS ────────────────────────────────────────────────────
alert udp any any -> $HOME_NET 53 (
    msg:"UDP DNS Query Detected";
    sid:1000040; rev:1;)

alert udp $HOME_NET any -> any 53 (
    msg:"UDP DNS Response Detected";
    sid:1000041; rev:1;)

# ─── 3. UDP Traffic — NTP ────────────────────────────────────────────────────
alert udp any any -> $HOME_NET 123 (
    msg:"UDP NTP Traffic Detected";
    sid:1000050; rev:1;)

# ─── 4. Web Attacks — SQL Injection ──────────────────────────────────────────
alert http any any -> $HOME_NET any (
    msg:"WEB ATTACK SQL Injection -- UNION SELECT";
    http_uri;
    content:"UNION";
    nocase;
    content:"SELECT";
    nocase;
    distance:0;
    sid:1000060; rev:2;)

alert http any any -> $HOME_NET any (
    msg:"WEB ATTACK SQL Injection -- OR 1=1";
    http_uri;
    content:"1=1";
    nocase;
    sid:1000061; rev:2;)

alert http any any -> $HOME_NET any (
    msg:"WEB ATTACK SQL Injection -- Single Quote";
    http_uri;
    content:"'";
    content:"SELECT";
    nocase;
    within:50;
    sid:1000062; rev:2;)

alert http any any -> $HOME_NET any (
    msg:"WEB ATTACK SQL Injection -- DROP TABLE";
    http_uri;
    content:"DROP";
    nocase;
    content:"TABLE";
    nocase;
    distance:1;
    within:20;
    sid:1000063; rev:2;)

alert http any any -> $HOME_NET any (
    msg:"WEB ATTACK SQL Injection -- Comment Evasion";
    http_uri;
    content:"--";
    content:"SELECT";
    nocase;
    within:100;
    sid:1000064; rev:2;)

# ─── 5. Inbound Reconnaissance — Nmap FIN Scan ───────────────────────────────
alert tcp any any -> $HOME_NET any (
    msg:"RECON Nmap FIN Scan Detected";
    flags:F;
    ack:0;
    sid:1000070; rev:2;)

alert tcp any any -> $HOME_NET any (
    msg:"RECON Nmap NULL Scan Detected";
    flags:0;
    sid:1000071; rev:2;)

alert tcp any any -> $HOME_NET any (
    msg:"RECON Nmap XMAS Scan Detected";
    flags:FPU;
    sid:1000072; rev:2;)

alert tcp any any -> $HOME_NET any (
    msg:"RECON Nmap SYN Stealth Scan Detected";
    flags:S;
    ack:0;
    sid:1000073; rev:2;)

# ─── 6. C2 / Reverse Shell — Netcat ─────────────────────────────────────────
alert tcp any any -> $HOME_NET any (
    msg:"C2 Netcat Reverse Shell Inbound";
    content:"cmd.exe";
    nocase;
    sid:1000080; rev:2;)

alert tcp any any -> $HOME_NET any (
    msg:"C2 Netcat -e /bin/bash Pattern";
    content:"/bin/bash";
    nocase;
    sid:1000081; rev:2;)

alert tcp any any -> $HOME_NET any (
    msg:"C2 Netcat -e /bin/sh Pattern";
    content:"/bin/sh";
    nocase;
    sid:1000082; rev:2;)

alert tcp $HOME_NET any -> any any (
    msg:"C2 Suspicious Outbound Netcat Reverse Shell";
    content:"/bin/sh";
    nocase;
    sid:1000083; rev:2;)

# ─── 7. DoS — ICMP Flood / Ping of Death ────────────────────────────────────
alert icmp any any -> $HOME_NET any (
    msg:"DOS ICMP Flood Attack Detected";
    itype:8;
    detection_filter:track by_src, count 100, seconds 5;
    sid:1000090; rev:2;)

alert icmp any any -> $HOME_NET any (
    msg:"DOS Ping of Death -- Oversized ICMP Packet";
    itype:8;
    dsize:>1024;
    sid:1000091; rev:2;)

alert icmp any any -> $HOME_NET any (
    msg:"DOS Fragmented ICMP (Possible PoD)";
    fragbits:M;
    itype:8;
    sid:1000092; rev:2;)

# =============================================================================
# End of local.rules
# =============================================================================
SNORT_RULES

log "Snort rules written ($(wc -l < "${RULES_FILE}") lines)."

# Validate config
if "${SNORT_BIN}" -c "${SNORT_CONF}" --plugin-path /usr/local/lib/snort/ --daq-dir /usr/local/lib/daq/ -T 2>&1 | grep -iq "snort successfully validated"; then
    log "Snort configuration validated successfully."
else
    warn "Snort validation returned warnings — check manually: ${SNORT_BIN} -c ${SNORT_CONF} -T"
fi

# Start / restart Snort
systemctl restart snort3 && log "Snort 3 service (re)started." \
    || warn "Snort service failed — check: journalctl -u snort3"

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 7 — OpenSCAP / COMPLIANCE AUDIT
# ═════════════════════════════════════════════════════════════════════════════
section "PHASE 7: OpenSCAP Compliance Audit & Remediation"

pkg_install openscap-scanner scap-security-guide openscap-utils

SCAP_DS="/usr/share/xml/scap/ssg/content/ssg-rhel10-ds.xml"
# Fallback to RHEL 9 content if RHEL 10 not yet available
[[ ! -f "${SCAP_DS}" ]] && SCAP_DS="/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
[[ ! -f "${SCAP_DS}" ]] && { err "No SCAP datastream found. Install scap-security-guide."; exit 1; }
log "Using SCAP datastream: ${SCAP_DS}"

# Verify profile exists
PROFILE_LIST=$(oscap info "${SCAP_DS}" 2>/dev/null | grep -A200 'Profiles:' | grep -oP 'xccdf_[^\s]+')
if echo "${PROFILE_LIST}" | grep -q "${OSCAP_PROFILE}"; then
    log "Profile '${OSCAP_PROFILE}' found."
else
    warn "Profile '${OSCAP_PROFILE}' not found. Listing available profiles:"
    echo "${PROFILE_LIST}" | head -20
    # Fall back to a safe default
    OSCAP_PROFILE=$(echo "${PROFILE_LIST}" | grep -i "cis" | head -1)
    [[ -z "${OSCAP_PROFILE}" ]] && OSCAP_PROFILE=$(echo "${PROFILE_LIST}" | head -1)
    warn "Falling back to: ${OSCAP_PROFILE}"
fi

mkdir -p "${OSCAP_REPORT_DIR}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OSCAP_RESULTS_XML="${OSCAP_REPORT_DIR}/results_${TIMESTAMP}.xml"
OSCAP_REPORT_HTML="${OSCAP_REPORT_DIR}/report_${TIMESTAMP}.html"
OSCAP_REMEDIATED_HTML="${OSCAP_REPORT_DIR}/report_post_remediation_${TIMESTAMP}.html"
OSCAP_REMEDIATED_XML="${OSCAP_REPORT_DIR}/results_post_remediation_${TIMESTAMP}.xml"

# ── Step 1: Initial scan ──────────────────────────────────────────────────
log "Running initial OpenSCAP scan (this may take 2–5 minutes)..."
oscap xccdf eval \
    --profile  "${OSCAP_PROFILE}" \
    --results  "${OSCAP_RESULTS_XML}" \
    --report   "${OSCAP_REPORT_HTML}" \
    --oval-results \
    "${SCAP_DS}" \
    || true   # oscap exits non-zero when rules fail — that's expected

log "Initial scan complete → ${OSCAP_REPORT_HTML}"

# Extract pass/fail summary from XML
PASS_COUNT=$(grep -c 'result>pass<' "${OSCAP_RESULTS_XML}" 2>/dev/null || echo "?")
FAIL_COUNT=$(grep -c 'result>fail<' "${OSCAP_RESULTS_XML}" 2>/dev/null || echo "?")
log "Initial scan results — Pass: ${PASS_COUNT} | Fail: ${FAIL_COUNT}"

# ── Step 2: Automated remediation ────────────────────────────────────────
log "Applying automated remediation (oscap xccdf remediate)..."
oscap xccdf remediate \
    --profile  "${OSCAP_PROFILE}" \
    --results  "${OSCAP_REMEDIATED_XML}" \
    --report   "${OSCAP_REMEDIATED_HTML}" \
    "${SCAP_DS}" \
    || true

log "Remediation complete → ${OSCAP_REMEDIATED_HTML}"

# ── Step 3: Post-remediation verification scan ────────────────────────────
OSCAP_FINAL_XML="${OSCAP_REPORT_DIR}/results_final_${TIMESTAMP}.xml"
OSCAP_FINAL_HTML="${OSCAP_REPORT_DIR}/report_final_${TIMESTAMP}.html"

log "Running post-remediation verification scan..."
oscap xccdf eval \
    --profile  "${OSCAP_PROFILE}" \
    --results  "${OSCAP_FINAL_XML}" \
    --report   "${OSCAP_FINAL_HTML}" \
    --oval-results \
    "${SCAP_DS}" \
    || true

FINAL_PASS=$(grep -c 'result>pass<' "${OSCAP_FINAL_XML}" 2>/dev/null || echo "?")
FINAL_FAIL=$(grep -c 'result>fail<' "${OSCAP_FINAL_XML}" 2>/dev/null || echo "?")
log "Final scan results — Pass: ${FINAL_PASS} | Fail: ${FINAL_FAIL}"

# ── Step 4: Compliance loop (verify → remediate → verify until clean) ────
log "Entering compliance verification loop (max 3 iterations)..."

MAX_ITER=3
ITER=0
while [[ ${ITER} -lt ${MAX_ITER} ]]; do
    ITER=$(( ITER + 1 ))
    LOOP_FAIL=$(grep -c 'result>fail<' "${OSCAP_FINAL_XML}" 2>/dev/null || echo 0)
    log "Iteration ${ITER}: ${LOOP_FAIL} failing rule(s)."

    [[ "${LOOP_FAIL}" -eq 0 ]] && { log "System is compliant — exiting loop."; break; }

    warn "Iteration ${ITER}: ${LOOP_FAIL} failing rules remain. Applying remediation..."

    LOOP_REM_XML="${OSCAP_REPORT_DIR}/results_loop${ITER}_${TIMESTAMP}.xml"
    LOOP_REM_HTML="${OSCAP_REPORT_DIR}/report_loop${ITER}_${TIMESTAMP}.html"

    oscap xccdf remediate \
        --profile  "${OSCAP_PROFILE}" \
        --results  "${LOOP_REM_XML}" \
        --report   "${LOOP_REM_HTML}" \
        "${SCAP_DS}" \
        || true

    # Re-scan after remediation
    OSCAP_FINAL_XML="${OSCAP_REPORT_DIR}/results_loop${ITER}_verify_${TIMESTAMP}.xml"
    OSCAP_FINAL_HTML="${OSCAP_REPORT_DIR}/report_loop${ITER}_verify_${TIMESTAMP}.html"

    oscap xccdf eval \
        --profile  "${OSCAP_PROFILE}" \
        --results  "${OSCAP_FINAL_XML}" \
        --report   "${OSCAP_FINAL_HTML}" \
        --oval-results \
        "${SCAP_DS}" \
        || true
done

REMAINING_FAIL=$(grep -c 'result>fail<' "${OSCAP_FINAL_XML}" 2>/dev/null || echo "?")
if [[ "${REMAINING_FAIL}" -eq 0 ]]; then
    log "Compliance loop complete — system FULLY COMPLIANT."
else
    warn "Compliance loop finished after ${MAX_ITER} iterations — ${REMAINING_FAIL} rule(s) still failing."
    warn "Manual remediation may be required for remaining failures."
fi

log "Final HTML compliance report → ${OSCAP_FINAL_HTML}"

# ── Re-enable SELinux enforcing after remediation ─────────────────────────
log "Re-enabling SELinux enforcing mode..."
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
setenforce 1 || warn "Could not set SELinux to enforcing; reboot may be required."

# ═════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═════════════════════════════════════════════════════════════════════════════
section "HARDENING COMPLETE — Summary"

echo -e "${GREEN}"
cat <<SUMMARY
  ┌──────────────────────────────────────────────────────────────────────┐
  │                 RHEL 10 Hardening Summary                            │
  ├──────────────────────────────────────────────────────────────────────┤
  │  Employee    : ${Employee_ID} — ${Employee_NAME}
  ├──────────────────────────────────────────────────────────────────────┤
  │  [Phase 1]  Snort 3 IDS installed & configured                       │
  │  [Phase 2]  OpenSSH hardened on port ${SSH_PORT}                           │
  │             → Password auth DISABLED                                 │
  │             → Key-based auth ENABLED                                 │
  │             → Root login DISABLED                                    │
  │             → TCP/X11 forwarding DISABLED                            │
  │             → Login banner set                                       │
  │  [Phase 3]  MFA (Google Authenticator TOTP) configured via PAM      │
  │             → Each user must run: google-authenticator               │
  │  [Phase 4]  iptables firewall enforced                               │
  │             → Only ports ${COWRIE_PORT} (Cowrie) and ${SSH_PORT} (SSH) ACCEPT        │
  │             → Log prefixes: < SSH TRAFFIC >                          │
  │                             << HONEYPOT TRAFFIC >>                   │
  │                             <<< BLOCKED TRAFFIC >>>                  │
  │  [Phase 5]  Cowrie honeypot running on port ${COWRIE_PORT}                  │
  │             → Hostname: ${Employee_ID}                                │
  │             → Users: root (custom pass), staff (custom pass)         │
  │  [Phase 6]  Snort local.rules written                                │
  │             → ICMP, TCP (Web/SSH/Email), UDP (DNS/NTP)               │
  │             → SQL Injection, Nmap FIN scan, Netcat C2                │
  │             → ICMP Flood / Ping of Death detection                   │
  │  [Phase 7]  OpenSCAP CIS L2 scan + auto-remediation loop            │
  │             → Reports: ${OSCAP_REPORT_DIR}/
  │             → Remaining failures: ${REMAINING_FAIL}
  ├──────────────────────────────────────────────────────────────────────┤
  │  NEXT STEPS:                                                         │
  │  1. Enroll MFA: sudo -u <user> google-authenticator                  │
  │     -t -d -f -r 3 -R 30 -s ~/.ssh/.google_authenticator             │
  │  2. Verify SSH: ssh -p ${SSH_PORT} -i ~/.ssh/id_ed25519 <user>@<host>      │
  │  3. Check Snort: journalctl -u snort3 -f                             │
  │  4. Check Cowrie: journalctl -u cowrie -f                            │
  │  5. Review SCAP report: ${OSCAP_REPORT_DIR}/                         │
  └──────────────────────────────────────────────────────────────────────┘
SUMMARY
echo -e "${NC}"
