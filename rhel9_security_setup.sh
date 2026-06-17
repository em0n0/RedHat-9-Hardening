#!/usr/bin/env bash
# ===================================================================================
#  RHEL 9 Server Hardening & Script
#  Order: Snort Install → OpenSSH → MFA → Firewall → Cowrie → Snort Rules → OpenSCAP
# This script is intended for an isolated lab / test VM. It opens a honeypot
# (Cowrie) and changes SSH, firewall and PAM configuration system-wide.
# Do not run on a production host without reviewing every step first.
# ===================================================================================

set -euo pipefail

# ─── Color codes ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ─── Logging helpers ─────────────────────────────────────────────────────────
LOG_FILE="/var/log/rhel10_hardening.log"
log()    { echo -e "${GREEN}[+]${RESET} $*" | tee -a "$LOG_FILE"; }
warn()   { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$LOG_FILE"; }
err()    { echo -e "${RED}[ERROR]${RESET} $*" | tee -a "$LOG_FILE"; exit 1; }
header() { echo -e "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; \
           echo -e "${BOLD}${CYAN}  $*${RESET}"; \
           echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"; }

# ─── Root check ──────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "This script must be run as root. Use: sudo $0"

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
log "Hardening script started at $(date)"

# =============================================================================
#  PHASE 0 — INTERACTIVE INPUT COLLECTION
# =============================================================================
header "PHASE 0 — Configuration Input"

echo -e "${BOLD}Please provide the following details. Press ENTER to accept defaults.${RESET}\n"

# --- User ID & Name ----------------------------------------------------------
read -rp "$(echo -e "${CYAN}Enter your User (anything) ID:${RESET} ")" USER_ID
[[ -z "$USER_ID" ]] && err "User ID cannot be empty."

read -rp "$(echo -e "${CYAN}Enter your Full Name:${RESET} ")" USER_NAME
[[ -z "$USER_NAME" ]] && err "Full Name cannot be empty."

# --- SSH Port ----------------------------------------------------------------
while true; do
    read -rp "$(echo -e "${CYAN}Enter SSH port [default: 2222]:${RESET} ")" SSH_PORT
    SSH_PORT=${SSH_PORT:-2222}
    if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1024 && SSH_PORT <= 65535 )); then
        break
    else
        warn "Port must be a number between 1024–65535. Try again."
    fi
done

# --- SSH Public Key ----------------------------------------------------------
echo -e "\n${CYAN}Paste your SSH public key (ed25519 or RSA recommended):${RESET}"
echo -e "${YELLOW}  Example: ssh-ed25519 AAAA... user@host${RESET}"
read -rp "> " SSH_PUBKEY
[[ -z "$SSH_PUBKEY" ]] && err "SSH public key cannot be empty."
# Basic format validation
if ! echo "$SSH_PUBKEY" | grep -qE '^(ssh-(rsa|ed25519|ecdsa)|ecdsa-sha2-nistp(256|384|521)) '; then
    err "Invalid SSH public key format."
fi

# --- Cowrie Port -------------------------------------------------------------
while true; do
    read -rp "$(echo -e "${CYAN}Enter Cowrie honeypot listen port [default: 2223]:${RESET} ")" COWRIE_PORT
    COWRIE_PORT=${COWRIE_PORT:-2223}
    if [[ "$COWRIE_PORT" =~ ^[0-9]+$ ]] && (( COWRIE_PORT >= 1024 && COWRIE_PORT <= 65535 )); then
        if [[ "$COWRIE_PORT" == "$SSH_PORT" ]]; then
            warn "Cowrie port cannot be the same as SSH port ($SSH_PORT). Try again."
        else
            break
        fi
    else
        warn "Port must be a number between 1024–65535. Try again."
    fi
done

# --- Cowrie: additional user prompt ------------------------------------------
COWRIE_USERS=()
COWRIE_PASSWORDS=()

echo ""
while true; do
    read -rp "$(echo -e "${CYAN}Do you want to create a fake Cowrie OS user? (yes/no) [default: no]:${RESET} ")" CREATE_COWRIE_USER
    CREATE_COWRIE_USER=${CREATE_COWRIE_USER:-no}
    case "${CREATE_COWRIE_USER,,}" in
        yes|y)
            read -rp "  $(echo -e "${CYAN}Enter fake username:${RESET} ")" C_USER
            [[ -z "$C_USER" ]] && warn "Username cannot be empty." && continue
            while true; do
                read -rsp "  $(echo -e "${CYAN}Enter password for '${C_USER}':${RESET} ")" C_PASS; echo
                read -rsp "  $(echo -e "${CYAN}Confirm password:${RESET} ")" C_PASS2; echo
                if [[ "$C_PASS" == "$C_PASS2" ]] && [[ -n "$C_PASS" ]]; then
                    COWRIE_USERS+=("$C_USER")
                    COWRIE_PASSWORDS+=("$C_PASS")
                    log "Cowrie fake user '$C_USER' queued."
                    break
                else
                    warn "Passwords do not match or are empty. Try again."
                fi
            done
            read -rp "$(echo -e "${CYAN}Create another Cowrie user? (yes/no) [default: no]:${RESET} ")" MORE_USERS
            [[ "${MORE_USERS,,}" != "yes" && "${MORE_USERS,,}" != "y" ]] && break
            ;;
        no|n|"")
            break
            ;;
        *)
            warn "Please enter 'yes' or 'no'."
            ;;
    esac
done

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}Configuration Summary:${RESET}"
echo -e "  ID/Name      : ${USER_ID} / ${USER_NAME}"
echo -e "  SSH Port     : ${SSH_PORT}"
echo -e "  Cowrie Port  : ${COWRIE_PORT}"
echo -e "  Cowrie Users : ${#COWRIE_USERS[@]}"
echo ""
read -rp "$(echo -e "${YELLOW}Proceed with hardening? (yes/no):${RESET} ")" CONFIRM
[[ "${CONFIRM,,}" != "yes" && "${CONFIRM,,}" != "y" ]] && echo "Aborted." && exit 0

# =============================================================================
#  PHASE 1 — INSTALL SNORT
# =============================================================================
header "PHASE 1 — Snort IDS Installation"

log "Updating system packages..."
dnf update -y >> "$LOG_FILE" 2>&1

log "Installing Snort and dependencies..."
dnf install -y epel-release >> "$LOG_FILE" 2>&1 || warn "EPEL may already be enabled."

# Install build dependencies + snort
dnf install -y \
    snort \
    pcre-devel \
    libpcap-devel \
    libdnet-devel \
    daq \
    daq-devel \
    zlib-devel \
    >> "$LOG_FILE" 2>&1 || {
        warn "Snort not in default repos. Attempting manual install..."
        # Fallback: build from source or use community repo
        dnf install -y gcc flex bison libpcap-devel libdnet-devel \
            pcre-devel zlib-devel luajit-devel openssl-devel \
            >> "$LOG_FILE" 2>&1

        SNORT_VER="2.9.20"
        SNORT_URL="https://www.snort.org/downloads/snort/snort-${SNORT_VER}.tar.gz"
        warn "Note: If Snort tarball download fails, manually download from snort.org"
        cd /tmp
        curl -sLO "$SNORT_URL" || warn "Could not auto-download Snort ${SNORT_VER}. Place tarball at /tmp/snort-${SNORT_VER}.tar.gz"
        if [[ -f "/tmp/snort-${SNORT_VER}.tar.gz" ]]; then
            tar xzf "snort-${SNORT_VER}.tar.gz"
            cd "snort-${SNORT_VER}"
            ./configure --enable-sourcefire >> "$LOG_FILE" 2>&1
            make -j"$(nproc)" >> "$LOG_FILE" 2>&1
            make install >> "$LOG_FILE" 2>&1
            ldconfig
            cd /
        fi
    }

# Create Snort directory structure
log "Creating Snort directory structure..."
mkdir -p /etc/snort/rules
mkdir -p /etc/snort/preproc_rules
mkdir -p /var/log/snort
mkdir -p /usr/local/lib/snort_dynamicrules

# Create base snort.conf (will be populated in Phase 6)
if [[ ! -f /etc/snort/snort.conf ]]; then
    touch /etc/snort/snort.conf
fi

touch /etc/snort/rules/local.rules
touch /etc/snort/rules/white_list.rules
touch /etc/snort/rules/black_list.rules
chown -R root:root /etc/snort
chmod -R 640 /etc/snort
chmod 755 /etc/snort /etc/snort/rules /var/log/snort

log "Snort installation complete."

# =============================================================================
#  PHASE 2 — OPENSSH SERVER HARDENING
# =============================================================================
header "PHASE 2 — OpenSSH Server Configuration"

log "Installing OpenSSH server..."
dnf install -y openssh-server openssh-clients >> "$LOG_FILE" 2>&1

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BACKUP="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"

log "Backing up existing sshd_config to $SSHD_BACKUP"
cp "$SSHD_CONFIG" "$SSHD_BACKUP"

# ─── Write hardened sshd_config ──────────────────────────────────────────────
log "Writing hardened sshd_config..."
cat > "$SSHD_CONFIG" <<SSHD_EOF
# =============================================================================
#  OpenSSH Server Configuration — Hardened Baseline
#  Generated by rhel10_hardening.sh for ${USER_ID} / ${USER_NAME}
#  Generated on: $(date)
# =============================================================================

# ─── Port & Address ──────────────────────────────────────────────────────────
Port ${SSH_PORT}
AddressFamily inet
ListenAddress 0.0.0.0:${SSH_PORT}

# ─── Authentication ──────────────────────────────────────────────────────────
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication yes
UsePAM yes
AuthenticationMethods publickey,keyboard-interactive

# ─── Security Hardening ──────────────────────────────────────────────────────
PermitRootLogin no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
AllowTCPForwarding no
GatewayPorts no
X11Forwarding no
PermitTunnel no
AllowStreamLocalForwarding no
AllowAgentForwarding no

# ─── Session & Login ─────────────────────────────────────────────────────────
Banner /etc/ssh/sshd_banner
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2

# ─── Cryptography (Strong Ciphers/MACs/KEX) ──────────────────────────────────
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# ─── Logging ─────────────────────────────────────────────────────────────────
SyslogFacility AUTHPRIV
LogLevel VERBOSE

# ─── Subsystem ───────────────────────────────────────────────────────────────
Subsystem sftp /usr/lib/openssh/sftp-server
SSHD_EOF

# ─── Login Banner ────────────────────────────────────────────────────────────
log "Creating SSH login banner..."
cat > /etc/ssh/sshd_banner <<BANNER_EOF
################################################################################
#                          AUTHORIZED ACCESS ONLY                              #
################################################################################
#                                                                              #
#  This system is the property of an authorized organization.                  #
#  Unauthorized access is strictly prohibited and may be subject to            #
#  criminal prosecution.                                                       #
#                                                                              #
#  By connecting to this system, you acknowledge that:                         #
#    - All activities are monitored and logged                                 #
#    - There is no expectation of privacy                                      #
#    - Unauthorized access will be prosecuted to the fullest extent of law     #
#                                                                              #
#  User ID : ${USER_ID}                                                        #
#  Responsible Party   : ${USER_NAME}                                          #
#                                                                              #
################################################################################
BANNER_EOF

chmod 644 /etc/ssh/sshd_banner

# ─── Deploy SSH Public Key for root (or specify a target user) ───────────────
TARGET_USER="${SUDO_USER:-root}"
if [[ "$TARGET_USER" == "root" ]]; then
    KEY_DIR="/root/.ssh"
else
    KEY_DIR="/home/${TARGET_USER}/.ssh"
fi

log "Deploying SSH public key for user: $TARGET_USER"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

AUTH_KEYS="${KEY_DIR}/authorized_keys"
# Avoid duplicate key entry
if ! grep -qF "$SSH_PUBKEY" "$AUTH_KEYS" 2>/dev/null; then
    echo "$SSH_PUBKEY" >> "$AUTH_KEYS"
fi
chmod 600 "$AUTH_KEYS"

if [[ "$TARGET_USER" != "root" ]]; then
    chown -R "${TARGET_USER}:${TARGET_USER}" "$KEY_DIR"
fi

# ─── Enable & start SSHD ─────────────────────────────────────────────────────
log "Enabling and starting sshd..."
systemctl enable --now sshd >> "$LOG_FILE" 2>&1
systemctl restart sshd >> "$LOG_FILE" 2>&1 || warn "sshd restart failed — check config with: sshd -t"

# SELinux port labeling
if command -v semanage &>/dev/null; then
    log "Configuring SELinux port label for SSH port $SSH_PORT..."
    semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" >> "$LOG_FILE" 2>&1 || \
    semanage port -m -t ssh_port_t -p tcp "$SSH_PORT" >> "$LOG_FILE" 2>&1 || \
    warn "SELinux port labeling failed — may already exist or SELinux is permissive."
fi

log "OpenSSH hardening complete."

# =============================================================================
#  PHASE 3 — MULTI-FACTOR AUTHENTICATION (TOTP via Google Authenticator PAM)
# =============================================================================
header "PHASE 3 — Multi-Factor Authentication (MFA)"

log "Installing Google Authenticator PAM module..."
dnf install -y google-authenticator pam >> "$LOG_FILE" 2>&1 || \
    dnf install -y libpam-google-authenticator >> "$LOG_FILE" 2>&1 || \
    warn "google-authenticator not found in repos. Trying EPEL..."

# Ensure EPEL and retry
dnf install -y epel-release >> "$LOG_FILE" 2>&1 || true
dnf install -y google-authenticator >> "$LOG_FILE" 2>&1 || \
    warn "google-authenticator could not be installed automatically. Install manually: dnf install google-authenticator"

# ─── Configure PAM for SSH MFA ───────────────────────────────────────────────
log "Configuring PAM for SSH keyboard-interactive MFA..."

PAM_SSHD="/etc/pam.d/sshd"
PAM_BACKUP="/etc/pam.d/sshd.bak.$(date +%Y%m%d%H%M%S)"
cp "$PAM_SSHD" "$PAM_BACKUP"

# Prepend TOTP auth to sshd PAM stack
# nullok allows users without .google_authenticator to still login during setup
if ! grep -q "pam_google_authenticator" "$PAM_SSHD"; then
    sed -i '1s/^/auth required pam_google_authenticator.so nullok\n/' "$PAM_SSHD"
    log "pam_google_authenticator added to /etc/pam.d/sshd"
else
    log "pam_google_authenticator already present in /etc/pam.d/sshd"
fi

# Ensure password-auth is not the only auth mechanism
# Keep 'include password-auth' but ensure it is after TOTP
if grep -q "^auth.*include.*password-auth" "$PAM_SSHD"; then
    log "password-auth include found in PAM sshd config."
fi

log "MFA (PAM TOTP) configured. Each user must run 'google-authenticator' to set up their TOTP secret."
log "  → Run as target user: google-authenticator -t -d -f -r 3 -R 30 -W"
log "  → Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.)"
log ""
log "MFA setup complete."

# =============================================================================
#  PHASE 4 — FIREWALL (iptables)
# =============================================================================
header "PHASE 4 — iptables Firewall Configuration"

log "Installing iptables services..."
dnf install -y iptables-services >> "$LOG_FILE" 2>&1
systemctl enable iptables >> "$LOG_FILE" 2>&1
systemctl stop firewalld >> "$LOG_FILE" 2>&1 || true
systemctl disable firewalld >> "$LOG_FILE" 2>&1 || true

log "Flushing existing rules..."
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t mangle -F

# ─── Default DENY policies ───────────────────────────────────────────────────
log "Setting default DROP policies..."
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

# ─── Allow loopback ──────────────────────────────────────────────────────────
iptables -A INPUT -i lo -j ACCEPT

# ─── Allow established/related connections ───────────────────────────────────
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ─── SSH Traffic — log and allow ─────────────────────────────────────────────
log "Adding SSH traffic rules on port $SSH_PORT..."
iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
    -m comment --comment "SSH_TRAFFIC" \
    -j LOG --log-prefix "< SSH TRAFFIC > " --log-level 4
iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -j ACCEPT

# ─── Cowrie Honeypot Traffic — log and allow ─────────────────────────────────
log "Adding Cowrie honeypot traffic rules on port $COWRIE_PORT..."
iptables -A INPUT -p tcp --dport "$COWRIE_PORT" -m conntrack --ctstate NEW \
    -m comment --comment "HONEYPOT_TRAFFIC" \
    -j LOG --log-prefix "<< HONEYPOT TRAFFIC >> " --log-level 4
iptables -A INPUT -p tcp --dport "$COWRIE_PORT" -m conntrack --ctstate NEW -j ACCEPT

# ─── Block and log everything else ───────────────────────────────────────────
log "Adding catch-all block/log rule..."
iptables -A INPUT \
    -m comment --comment "BLOCKED_TRAFFIC" \
    -j LOG --log-prefix "<<< BLOCKED TRAFFIC >>> " --log-level 4
iptables -A INPUT -j DROP

# ─── Save rules ──────────────────────────────────────────────────────────────
log "Saving iptables rules..."
service iptables save >> "$LOG_FILE" 2>&1 || \
    iptables-save > /etc/sysconfig/iptables

log "iptables firewall configured. Current ruleset:"
iptables -L -v -n | tee -a "$LOG_FILE"

# =============================================================================
#  PHASE 5 — COWRIE HONEYPOT
# =============================================================================
header "PHASE 5 — Cowrie Honeypot Installation & Configuration"

log "Installing Cowrie dependencies..."
dnf install -y python3 python3-pip python3-virtualenv git authbind >> "$LOG_FILE" 2>&1

# ─── Create cowrie system user ───────────────────────────────────────────────
if ! id cowrie &>/dev/null; then
    log "Creating cowrie system user..."
    useradd -r -s /bin/false -d /opt/cowrie -m cowrie
fi

# ─── Clone Cowrie ────────────────────────────────────────────────────────────
COWRIE_DIR="/opt/cowrie"
if [[ ! -d "${COWRIE_DIR}/.git" ]]; then
    log "Cloning Cowrie from GitHub..."
    git clone https://github.com/cowrie/cowrie.git "$COWRIE_DIR" >> "$LOG_FILE" 2>&1
    chown -R cowrie:cowrie "$COWRIE_DIR"
else
    log "Cowrie already cloned. Pulling latest..."
    cd "$COWRIE_DIR" && sudo -u cowrie git pull >> "$LOG_FILE" 2>&1
fi

cd "$COWRIE_DIR"

# ─── Set up Python virtual environment ───────────────────────────────────────
log "Setting up Cowrie Python virtual environment..."
sudo -u cowrie python3 -m venv "${COWRIE_DIR}/cowrie-env" >> "$LOG_FILE" 2>&1
sudo -u cowrie "${COWRIE_DIR}/cowrie-env/bin/pip" install --upgrade pip >> "$LOG_FILE" 2>&1
sudo -u cowrie "${COWRIE_DIR}/cowrie-env/bin/pip" install -r "${COWRIE_DIR}/requirements.txt" >> "$LOG_FILE" 2>&1

# ─── Configure Cowrie ────────────────────────────────────────────────────────
COWRIE_CFG="${COWRIE_DIR}/etc/cowrie.cfg"
log "Writing Cowrie configuration..."
cp "${COWRIE_DIR}/etc/cowrie.cfg.dist" "$COWRIE_CFG" 2>/dev/null || touch "$COWRIE_CFG"

# Apply configuration using sed/python inline replacement for reliability
python3 - <<PYEOF
import re, os

cfg_path = "${COWRIE_CFG}"
hostname = "${USER_ID}"
ssh_port = "${COWRIE_PORT}"

with open(cfg_path, 'r') as f:
    content = f.read()

# Hostname
content = re.sub(r'^hostname\s*=.*', f'hostname = {hostname}', content, flags=re.MULTILINE)
if 'hostname = ' not in content:
    content = content.replace('[honeypot]', f'[honeypot]\nhostname = {hostname}', 1)

# Listen port
content = re.sub(r'^listen_port\s*=.*', f'listen_port = {ssh_port}', content, flags=re.MULTILINE)
if 'listen_port = ' not in content:
    content = content.replace('[ssh]', f'[ssh]\nlisten_port = {ssh_port}', 1)

# Disable backend real auth (fake filesystem)
content = re.sub(r'^backend\s*=.*', 'backend = shell', content, flags=re.MULTILINE)

with open(cfg_path, 'w') as f:
    f.write(content)

print("Cowrie config written successfully.")
PYEOF

chown cowrie:cowrie "$COWRIE_CFG"

# ─── Add fake Cowrie users ────────────────────────────────────────────────────
USERDB="${COWRIE_DIR}/etc/userdb.txt"
if [[ ! -f "$USERDB" ]]; then
    cp "${COWRIE_DIR}/etc/userdb.example" "$USERDB" 2>/dev/null || touch "$USERDB"
fi

for i in "${!COWRIE_USERS[@]}"; do
    CUSER="${COWRIE_USERS[$i]}"
    CPASS="${COWRIE_PASSWORDS[$i]}"
    # Cowrie userdb format: username:uid:password
    if ! grep -q "^${CUSER}:" "$USERDB"; then
        echo "${CUSER}:0:${CPASS}" >> "$USERDB"
        log "Added Cowrie fake user: $CUSER"
    else
        warn "Cowrie user '$CUSER' already in userdb, skipping."
    fi
done
chown cowrie:cowrie "$USERDB"
chmod 640 "$USERDB"

# ─── Systemd service for Cowrie ──────────────────────────────────────────────
log "Creating Cowrie systemd service..."
cat > /etc/systemd/system/cowrie.service <<COWRIE_SVC
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=${COWRIE_DIR}
ExecStart=${COWRIE_DIR}/cowrie-env/bin/python ${COWRIE_DIR}/bin/cowrie start -n
ExecStop=${COWRIE_DIR}/cowrie-env/bin/python ${COWRIE_DIR}/bin/cowrie stop
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
COWRIE_SVC

systemctl daemon-reload
systemctl enable cowrie >> "$LOG_FILE" 2>&1
systemctl start cowrie >> "$LOG_FILE" 2>&1 || warn "Cowrie failed to start — check: journalctl -u cowrie"
log "Cowrie honeypot configured (hostname: ${USER_ID}, port: ${COWRIE_PORT})."

# =============================================================================
#  PHASE 6 — SNORT RULES CONFIGURATION
# =============================================================================
header "PHASE 6 — Snort IDS Rules Configuration"

log "Writing Snort main configuration file..."
# Detect primary network interface and IP
NET_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
HOME_NET=$(ip -4 addr show "$NET_IFACE" 2>/dev/null | awk '/inet / {print $2}' | head -1 || echo "192.168.1.0/24")

cat > /etc/snort/snort.conf <<SNORT_CONF
# =============================================================================
#  Snort IDS Configuration — Generated by rhel10_hardening.sh
#  ID: ${USER_ID} | Name: ${USER_NAME} | Date: $(date)
# =============================================================================

# ─── Network Variables ────────────────────────────────────────────────────────
var HOME_NET ${HOME_NET}
var EXTERNAL_NET !\$HOME_NET

var HTTP_SERVERS \$HOME_NET
var SMTP_SERVERS \$HOME_NET
var SQL_SERVERS  \$HOME_NET
var DNS_SERVERS  \$HOME_NET

# ─── Port Variables ──────────────────────────────────────────────────────────
var HTTP_PORTS  [80,443,8080,8443]
var ORACLE_PORTS 1521
var SSH_PORTS   ${SSH_PORT}
var FTP_PORTS   [21,2100,3535]
var SMTP_PORTS  25
var IMAP_PORTS  143
var POP3_PORTS  110
var DNS_PORTS   53
var NTP_PORTS   123

# ─── File/Path Variables ──────────────────────────────────────────────────────
var RULE_PATH     /etc/snort/rules
var LOG_PATH      /var/log/snort
var SO_RULE_PATH  /usr/local/lib/snort_dynamicrules
var PREPROC_RULE_PATH /etc/snort/preproc_rules

# ─── Output ──────────────────────────────────────────────────────────────────
output alert_fast: /var/log/snort/alert
output log_tcpdump: /var/log/snort/snort.log

# ─── Decoders & Preprocessors ────────────────────────────────────────────────
config logdir: /var/log/snort
config pcre_match_limit: 3500
config pcre_match_limit_recursion: 1500

preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows detect_anomalies overlap_limit 10 min_fragment_length 100 timeout 180

preprocessor stream5_global: track_tcp yes, track_udp yes, track_icmp no, max_tcp 262144, max_udp 131072, max_active_responses 2, min_response_seconds 5
preprocessor stream5_tcp: log_asymmetric_traffic no, policy windows, detect_anomalies, require_3whs 180, overlap_limit 10, small_segments 3 bytes 150, timeout 180, ports client \$HTTP_PORTS \$FTP_PORTS \$SSH_PORTS, prune_log_max 0
preprocessor stream5_udp: timeout 180

preprocessor http_inspect: global iis_unicode_map /etc/snort/rules/unicode.map 1252
preprocessor http_inspect_server: server default \
    http_methods { GET POST PUT HEAD DELETE TRACE OPTIONS } \
    profile all ports { \$HTTP_PORTS } oversize_dir_length 500 \
    inspect_uri_only no server_flow_depth 65535 client_flow_depth 65535

preprocessor sfportscan: proto  { all } memcap { 10000000 } sense_level { medium } logfile { /var/log/snort/portscan.log }

# ─── Rules ────────────────────────────────────────────────────────────────────
include \$RULE_PATH/local.rules
SNORT_CONF

# ─── Write local.rules ────────────────────────────────────────────────────────
log "Writing Snort detection rules to /etc/snort/rules/local.rules..."
cat > /etc/snort/rules/local.rules <<'RULES_EOF'
# =============================================================================
#  Snort Local Rules — RHEL 9 Hardening
#  Categories:
#    1. ICMP Traffic (Ping / Diagnostic)
#    2. TCP Traffic (Web, SSH, Email)
#    3. UDP Traffic (DNS, NTP)
#    4. Web Attacks (SQL Injection)
#    5. Inbound Reconnaissance (Nmap FIN Scan)
#    6. Command & Control / Reverse Shells (Netcat)
#    7. Denial of Service (ICMP Flood / Ping of Death)
# =============================================================================

# ─── 1. ICMP Traffic (Diagnostic / Ping) ─────────────────────────────────────
# Detect ICMP Echo Request (ping)
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ICMP Echo Request (Ping) Detected"; itype:8; icode:0; sid:1000001; rev:1; classtype:misc-activity;)

# Detect ICMP Echo Reply
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ICMP Echo Reply Detected"; itype:0; icode:0; sid:1000002; rev:1; classtype:misc-activity;)

# Detect ICMP Traceroute (TTL Exceeded)
alert icmp any any -> $HOME_NET any (msg:"ICMP TTL Exceeded (Traceroute)"; itype:11; sid:1000003; rev:1; classtype:misc-activity;)

# ─── 2. TCP Traffic ──────────────────────────────────────────────────────────
# HTTP Traffic
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"TCP HTTP Traffic Detected"; flow:to_server,established; sid:1000010; rev:1; classtype:misc-activity;)

# HTTPS Traffic
alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"TCP HTTPS Traffic Detected"; flow:to_server,established; sid:1000011; rev:1; classtype:misc-activity;)

# SSH Traffic (custom port)
alert tcp $EXTERNAL_NET any -> $HOME_NET $SSH_PORTS (msg:"TCP SSH Traffic Detected"; flow:to_server,established; flags:S; sid:1000012; rev:1; classtype:attempted-admin;)

# SMTP Email Traffic
alert tcp $EXTERNAL_NET any -> $HOME_NET 25 (msg:"TCP SMTP Traffic Detected"; flow:to_server,established; sid:1000013; rev:1; classtype:misc-activity;)

# IMAP Traffic
alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"TCP IMAP Traffic Detected"; flow:to_server,established; sid:1000014; rev:1; classtype:misc-activity;)

# POP3 Traffic
alert tcp $EXTERNAL_NET any -> $HOME_NET 110 (msg:"TCP POP3 Traffic Detected"; flow:to_server,established; sid:1000015; rev:1; classtype:misc-activity;)

# ─── 3. UDP Traffic ──────────────────────────────────────────────────────────
# DNS UDP
alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"UDP DNS Query Detected"; sid:1000020; rev:1; classtype:misc-activity;)

# DNS TCP (zone transfers / large responses)
alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"TCP DNS Query Detected (Possible Zone Transfer)"; flow:to_server,established; sid:1000021; rev:1; classtype:misc-activity;)

# NTP UDP
alert udp $EXTERNAL_NET any -> $HOME_NET 123 (msg:"UDP NTP Traffic Detected"; sid:1000022; rev:1; classtype:misc-activity;)

# NTP Amplification Attack
alert udp $EXTERNAL_NET any -> $HOME_NET 123 (msg:"UDP NTP Amplification Attempt (monlist)"; content:"|00 01 00 2a|"; depth:4; sid:1000023; rev:1; classtype:attempted-dos;)

# ─── 4. Web Attacks — SQL Injection ──────────────────────────────────────────
# Classic UNION-based SQLi
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"WEB ATTACK SQL Injection UNION SELECT"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; within:20; http_uri; sid:1000030; rev:1; classtype:web-application-attack;)

# OR 1=1 based SQLi
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"WEB ATTACK SQL Injection OR 1=1"; flow:to_server,established; content:"OR 1=1"; nocase; http_uri; sid:1000031; rev:1; classtype:web-application-attack;)

# Single quote injection attempt
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"WEB ATTACK SQL Injection Single Quote"; flow:to_server,established; content:"'"; content:"SELECT"; nocase; http_uri; sid:1000032; rev:1; classtype:web-application-attack;)

# DROP TABLE injection
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"WEB ATTACK SQL Injection DROP TABLE"; flow:to_server,established; content:"DROP"; nocase; content:"TABLE"; nocase; distance:0; within:10; http_uri; sid:1000033; rev:1; classtype:web-application-attack;)

# Blind SQLi via SLEEP/WAITFOR
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"WEB ATTACK SQL Injection Time-Based Blind (SLEEP)"; flow:to_server,established; content:"SLEEP("; nocase; http_uri; sid:1000034; rev:1; classtype:web-application-attack;)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"WEB ATTACK SQL Injection Time-Based Blind (WAITFOR)"; flow:to_server,established; content:"WAITFOR DELAY"; nocase; http_uri; sid:1000035; rev:1; classtype:web-application-attack;)

# ─── 5. Inbound Reconnaissance — Nmap FIN Scan ───────────────────────────────
# FIN scan: only FIN flag set, no ACK
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"RECON Nmap FIN Scan Detected"; flags:F,12; sid:1000040; rev:1; classtype:attempted-recon;)

# NULL scan: no flags set
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"RECON Nmap NULL Scan Detected"; flags:0; sid:1000041; rev:1; classtype:attempted-recon;)

# XMAS scan: FIN+PSH+URG
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"RECON Nmap XMAS Scan Detected"; flags:FPU,12; sid:1000042; rev:1; classtype:attempted-recon;)

# SYN scan on privileged ports (stealth scan)
alert tcp $EXTERNAL_NET any -> $HOME_NET 1:1024 (msg:"RECON Nmap SYN Stealth Scan on Privileged Ports"; flags:S,12; threshold:type threshold, track by_src, count 20, seconds 5; sid:1000043; rev:1; classtype:attempted-recon;)

# Port sweep detection
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"RECON Port Sweep Detected"; flags:S,12; threshold:type threshold, track by_src, count 30, seconds 10; sid:1000044; rev:1; classtype:attempted-recon;)

# ─── 6. Command & Control / Reverse Shells (Netcat) ─────────────────────────
# Netcat listener / reverse shell indicator in payload
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"C2 Netcat Reverse Shell Keyword (cmd.exe)"; flow:established; content:"cmd.exe"; nocase; sid:1000050; rev:1; classtype:trojan-activity;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"C2 Netcat Reverse Shell Keyword (/bin/sh)"; flow:established; content:"/bin/sh"; sid:1000051; rev:1; classtype:trojan-activity;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"C2 Netcat Reverse Shell Keyword (/bin/bash)"; flow:established; content:"/bin/bash"; sid:1000052; rev:1; classtype:trojan-activity;)

# Netcat with -e flag pipe (common in reverse shells)
alert tcp any any -> $HOME_NET any (msg:"C2 Possible Netcat Pipe Shell (-e flag pattern)"; flow:established; content:"-e"; content:"sh"; distance:1; within:5; sid:1000053; rev:1; classtype:trojan-activity;)

# Outbound shell on suspicious high port (beaconing)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 Outbound Reverse Shell Attempt (high port)"; flow:to_server,established; content:"/bin/bash"; sid:1000054; rev:1; classtype:trojan-activity;)

# ─── 7. Denial of Service — ICMP Flood / Ping of Death ───────────────────────
# ICMP Flood (rate-based threshold)
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"DOS ICMP Flood Detected"; itype:8; threshold:type both, track by_src, count 100, seconds 5; sid:1000060; rev:1; classtype:attempted-dos;)

# Ping of Death (oversized ICMP — length > 65535 bytes fragmented)
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"DOS Ping of Death Oversized ICMP Packet"; dsize:>1024; itype:8; sid:1000061; rev:1; classtype:attempted-dos;)

# ICMP Type 3 (Destination Unreachable) flood — can be used in amplification
alert icmp any any -> $HOME_NET any (msg:"DOS ICMP Destination Unreachable Flood"; itype:3; threshold:type both, track by_src, count 50, seconds 10; sid:1000062; rev:1; classtype:attempted-dos;)

# SYN Flood
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"DOS TCP SYN Flood Detected"; flags:S,12; threshold:type both, track by_src, count 200, seconds 5; sid:1000063; rev:1; classtype:attempted-dos;)

# UDP Flood
alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"DOS UDP Flood Detected"; threshold:type both, track by_src, count 500, seconds 5; sid:1000064; rev:1; classtype:attempted-dos;)

RULES_EOF

chmod 640 /etc/snort/rules/local.rules

# ─── Create Snort systemd service ────────────────────────────────────────────
log "Creating Snort systemd service..."
cat > /etc/systemd/system/snort.service <<SNORT_SVC
[Unit]
Description=Snort IDS
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i ${NET_IFACE} -l /var/log/snort
Restart=on-failure

[Install]
WantedBy=multi-user.target
SNORT_SVC

# Create snort user if not exists
id snort &>/dev/null || useradd -r -s /sbin/nologin -d /var/log/snort snort
chown -R snort:snort /var/log/snort

systemctl daemon-reload
systemctl enable snort >> "$LOG_FILE" 2>&1
systemctl start snort >> "$LOG_FILE" 2>&1 || warn "Snort failed to start — validate config with: snort -T -c /etc/snort/snort.conf"
log "Snort IDS rules configured and service started."

# =============================================================================
#  PHASE 7 — OpenSCAP / COMPLIANCE AUDIT
# =============================================================================
header "PHASE 7 — OpenSCAP Compliance Audit & Remediation"

log "Installing OpenSCAP tooling and SCAP Security Guide..."
dnf install -y openscap openscap-scanner scap-security-guide >> "$LOG_FILE" 2>&1 || \
    warn "OpenSCAP packages not available — attempting EPEL..."
dnf install -y --enablerepo=epel openscap openscap-scanner scap-security-guide >> "$LOG_FILE" 2>&1 || \
    warn "OpenSCAP install failed. Install manually: dnf install openscap openscap-scanner scap-security-guide"

SCAP_DIR="/usr/share/xml/scap/ssg/content"
SCAP_DATASTREAM=""
OSCAP_REPORT_DIR="/var/log/oscap"
mkdir -p "$OSCAP_REPORT_DIR"

# ─── Locate RHEL 9 / RHEL 9 SCAP datastream ─────────────────────────────────
for ds in \
    "${SCAP_DIR}/ssg-rhel10-ds.xml" \
    "${SCAP_DIR}/ssg-rhel9-ds.xml" \
    "${SCAP_DIR}/ssg-rhel8-ds.xml"; do
    if [[ -f "$ds" ]]; then
        SCAP_DATASTREAM="$ds"
        log "Found SCAP datastream: $ds"
        break
    fi
done

if [[ -z "$SCAP_DATASTREAM" ]]; then
    warn "No SCAP datastream found in $SCAP_DIR. OpenSCAP audit will be skipped."
    warn "Install scap-security-guide and re-run: dnf install scap-security-guide"
else
    # Determine available profiles
    log "Available SCAP profiles:"
    oscap info "$SCAP_DATASTREAM" 2>/dev/null | grep -i "Profile" | head -20 | tee -a "$LOG_FILE" || true

    # Choose profile: prefer STIG, fall back to CIS, then default
    SCAP_PROFILE=""
    for PROFILE_CANDIDATE in \
        "xccdf_org.ssgproject.content_profile_stig" \
        "xccdf_org.ssgproject.content_profile_cis" \
        "xccdf_org.ssgproject.content_profile_cis_server_l1" \
        "xccdf_org.ssgproject.content_profile_standard"; do
        if oscap info "$SCAP_DATASTREAM" 2>/dev/null | grep -q "$PROFILE_CANDIDATE"; then
            SCAP_PROFILE="$PROFILE_CANDIDATE"
            log "Selected SCAP profile: $SCAP_PROFILE"
            break
        fi
    done

    if [[ -z "$SCAP_PROFILE" ]]; then
        warn "Could not auto-detect SCAP profile. Listing available:"
        oscap info "$SCAP_DATASTREAM" 2>/dev/null | tee -a "$LOG_FILE"
        warn "Skipping automated scan. Run manually: oscap xccdf eval --profile <PROFILE> $SCAP_DATASTREAM"
    else
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        REPORT_HTML="${OSCAP_REPORT_DIR}/oscap_report_${TIMESTAMP}.html"
        RESULTS_XML="${OSCAP_REPORT_DIR}/oscap_results_${TIMESTAMP}.xml"
        REMEDIATION_SCRIPT="${OSCAP_REPORT_DIR}/oscap_remediation_${TIMESTAMP}.sh"

        # ── Step 1: Initial Scan ─────────────────────────────────────────────
        log "Running OpenSCAP initial compliance scan (this may take a few minutes)..."
        oscap xccdf eval \
            --profile "$SCAP_PROFILE" \
            --results "$RESULTS_XML" \
            --report "$REPORT_HTML" \
            --fetch-remote-resources \
            "$SCAP_DATASTREAM" >> "$LOG_FILE" 2>&1 || \
            warn "oscap scan completed with findings (non-zero exit is normal when issues are found)."

        log "Initial scan report: $REPORT_HTML"
        log "Initial scan XML results: $RESULTS_XML"

        # ── Step 2: Generate Remediation Script ──────────────────────────────
        log "Generating automated remediation bash script..."
        oscap xccdf generate fix \
            --profile "$SCAP_PROFILE" \
            --template urn:xccdf:fix:script:sh \
            --output "$REMEDIATION_SCRIPT" \
            "$SCAP_DATASTREAM" >> "$LOG_FILE" 2>&1 || \
            warn "Remediation script generation failed."

        if [[ -f "$REMEDIATION_SCRIPT" ]]; then
            chmod 700 "$REMEDIATION_SCRIPT"
            log "Remediation script saved: $REMEDIATION_SCRIPT"

            echo ""
            read -rp "$(echo -e "${YELLOW}Apply OpenSCAP automated remediation now? This will modify system settings. (yes/no):${RESET} ")" APPLY_REMEDIATION

            if [[ "${APPLY_REMEDIATION,,}" == "yes" || "${APPLY_REMEDIATION,,}" == "y" ]]; then
                log "Applying remediation script: $REMEDIATION_SCRIPT"
                bash "$REMEDIATION_SCRIPT" >> "$LOG_FILE" 2>&1 || \
                    warn "Remediation script completed with warnings (check log)."

                # ── Step 3: Post-remediation scan ────────────────────────────
                log "Running post-remediation compliance scan..."
                POST_REPORT="${OSCAP_REPORT_DIR}/oscap_post_remediation_${TIMESTAMP}.html"
                POST_RESULTS="${OSCAP_REPORT_DIR}/oscap_post_results_${TIMESTAMP}.xml"

                oscap xccdf eval \
                    --profile "$SCAP_PROFILE" \
                    --results "$POST_RESULTS" \
                    --report "$POST_REPORT" \
                    --fetch-remote-resources \
                    "$SCAP_DATASTREAM" >> "$LOG_FILE" 2>&1 || \
                    warn "Post-remediation scan completed with remaining findings."

                log "Post-remediation report: $POST_REPORT"
                log "Post-remediation XML:    $POST_RESULTS"
                echo -e "${GREEN}[+] Post-remediation scan complete. Review: ${POST_REPORT}${RESET}"
            else
                log "Remediation script generated but not applied. Run manually: bash $REMEDIATION_SCRIPT"
            fi
        fi
    fi
fi

# =============================================================================
#  PHASE 8 — VERIFICATION & SUMMARY
# =============================================================================
header "PHASE 8 — Verification & Summary"

echo -e "${BOLD}${GREEN}Service Status:${RESET}"
for SVC in sshd cowrie snort iptables; do
    STATUS=$(systemctl is-active "$SVC" 2>/dev/null || echo "inactive")
    if [[ "$STATUS" == "active" ]]; then
        echo -e "  ${GREEN}✔${RESET} ${SVC}: ${GREEN}active${RESET}"
    else
        echo -e "  ${RED}✘${RESET} ${SVC}: ${RED}${STATUS}${RESET}"
    fi
done

echo ""
echo -e "${BOLD}${CYAN}Configuration Summary:${RESET}"
echo -e "  ┌─────────────────────────────────────────────────────────"
echo -e "  │  ID / Name       : ${USER_ID} / ${USER_NAME}"
echo -e "  │  SSH Port        : ${SSH_PORT}"
echo -e "  │  Cowrie Port     : ${COWRIE_PORT}"
echo -e "  │  Cowrie Hostname : ${USER_ID}"
echo -e "  │  Snort Interface : ${NET_IFACE}"
echo -e "  │  Snort Rules     : /etc/snort/rules/local.rules"
echo -e "  │  OpenSCAP Report : ${OSCAP_REPORT_DIR}/"
echo -e "  │  Log File        : ${LOG_FILE}"
echo -e "  └─────────────────────────────────────────────────────────"

echo ""
echo -e "${BOLD}${YELLOW}Post-Install Reminders:${RESET}"
echo -e "  1. Each user must run ${BOLD}google-authenticator${RESET} to enroll their TOTP key:"
echo -e "     ${CYAN}google-authenticator -t -d -f -r 3 -R 30 -W${RESET}"
echo -e "  2. Test SSH login from another terminal before closing this session:"
echo -e "     ${CYAN}ssh -p ${SSH_PORT} -i <your_key> ${TARGET_USER:-root}@<server_ip>${RESET}"
echo -e "  3. Verify iptables rules: ${CYAN}iptables -L -v -n${RESET}"
echo -e "  4. Check Snort alerts:   ${CYAN}tail -f /var/log/snort/alert${RESET}"
echo -e "  5. Check Cowrie logs:    ${CYAN}tail -f /opt/cowrie/var/log/cowrie/cowrie.json${RESET}"
echo -e "  6. OpenSCAP HTML reports are in: ${CYAN}${OSCAP_REPORT_DIR}/${RESET}"
echo ""
log "Hardening script completed successfully at $(date)."
echo -e "${BOLD}${GREEN}All phases complete. System hardened and ready.${RESET}\n"
