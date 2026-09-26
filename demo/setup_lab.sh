#!/usr/bin/env bash
#
# setup_lab.sh — create a deliberately weak baseline for the hardenctl demo.
#
#   LAB VM ONLY. This intentionally weakens SSH, file permissions and kernel
#   settings. Never run it on a machine you care about, and never on anything
#   reachable from a network you do not control.
#
# Undo:  sudo ./setup_lab.sh --restore   (or roll back the VMware snapshot)

set -euo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; OFF=$'\e[0m'
say() { printf "%s[*]%s %s\n" "$DIM" "$OFF" "$1"; }
ok()  { printf "%s[+]%s %s\n" "$GRN" "$OFF" "$1"; }

[[ $EUID -eq 0 ]] || { echo "${RED}run with sudo${OFF}"; exit 1; }

# ---------------------------------------------------------------- restore ---
if [[ "${1:-}" == "--restore" ]]; then
    say "restoring pre-demo state"
    [[ -f /etc/ssh/sshd_config.lab-orig ]] && \
        cp /etc/ssh/sshd_config.lab-orig /etc/ssh/sshd_config && \
        chmod 600 /etc/ssh/sshd_config && ok "sshd_config restored"
    chmod 640 /etc/shadow 2>/dev/null && ok "/etc/shadow restored to 0640"
    sysctl -q -w kernel.randomize_va_space=2
    sysctl -q -w net.ipv4.tcp_syncookies=1
    sysctl -q -w net.ipv4.conf.all.accept_redirects=0
    ok "sysctls restored"
    exit 0
fi

# ------------------------------------------------------------- safety gate ---
printf "%s" "$YEL"
cat <<'BANNER'
+----------------------------------------------------------------+
|  This script deliberately WEAKENS this machine's security.     |
|  It is for an isolated lab VM only.                            |
|                                                                |
|  Before continuing:                                            |
|    1. Take a VMware snapshot  (VM > Snapshot > Take Snapshot)  |
|    2. Use the VMware CONSOLE, not an SSH session               |
+----------------------------------------------------------------+
BANNER
printf "%s" "$OFF"

read -rp "Snapshot taken, and this is a disposable lab VM? [yes/N] " ans
[[ "$ans" == "yes" ]] || { echo "aborted"; exit 1; }

# -------------------------------------------------------------- packages ---
say "installing packages that will show up in the scan"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssh-server redis-server nginx python3-pip >/dev/null
ok "openssh-server, redis-server, nginx installed"

# ------------------------------------------------------------------ sshd ---
say "weakening sshd_config"
[[ -f /etc/ssh/sshd_config.lab-orig ]] || \
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.lab-orig

cat > /etc/ssh/sshd_config <<'EOF'
# Demo baseline — deliberately weak
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding yes
MaxAuthTries 6
LoginGraceTime 120
ClientAliveInterval 0
UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
chmod 644 /etc/ssh/sshd_config      # loose on purpose
ok "sshd weakened (root login on, password auth on, mode 0644)"

# ----------------------------------------------------------------- redis ---
say "exposing redis on all interfaces"
if [[ -f /etc/redis/redis.conf ]]; then
    sed -i 's/^bind .*/bind 0.0.0.0/' /etc/redis/redis.conf
    sed -i 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf
    systemctl restart redis-server || true
    ok "redis bound to 0.0.0.0, protected-mode off"
fi

# ----------------------------------------------------------- permissions ---
say "loosening a sensitive file"
chmod 644 /etc/shadow
ok "/etc/shadow set to 0644"

# --------------------------------------------------------------- sysctls ---
say "weakening kernel settings"
sysctl -q -w kernel.randomize_va_space=0
sysctl -q -w net.ipv4.tcp_syncookies=0
sysctl -q -w net.ipv4.conf.all.accept_redirects=1
ok "ASLR off, syn cookies off, ICMP redirects accepted"

echo
printf "%sLab baseline ready.%s Run: %shardenctl scan%s\n" "$GRN" "$OFF" "$DIM" "$OFF"
