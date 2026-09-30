#!/usr/bin/env bash
#
# run_baselines.sh — CIS scoring and the baseline comparison, on the lab VM.
#
#   rules / llm   hardenctl plan -> apply -> score -> rollback -> score
#   openscap      oscap --remediate with the same CIS Level 1 Server profile
#   devsec        dev-sec ansible os_hardening + ssh_hardening
#
# Every phase changes the host. openscap and devsec have NO rollback, so each
# one starts from a fresh "weak-lab" snapshot and ends with you reverting it.
#
#   sudo eval/run_baselines.sh prep          # once: packages + SCAP content
#   sudo lab/setup_lab.sh                    # build the weak lab, then SNAPSHOT it: "weak-lab"
#   sudo eval/run_baselines.sh hardenctl     # rules (and llm if configured); rolls itself back
#   sudo eval/run_baselines.sh openscap      # then revert to "weak-lab"
#   sudo eval/run_baselines.sh devsec        # then revert to "weak-lab"
#   eval/run_baselines.sh summary            # no root: tables from results/baselines/
#
# Lab VM only. Never run it on a machine you care about.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/results/baselines"
CONTENT_DIR="$REPO/eval/content"
SSG_VER="0.1.82"
SSG_ZIP="scap-security-guide-$SSG_VER.zip"
SSG_URL="https://github.com/ComplianceAsCode/content/releases/download/v$SSG_VER"
DS="$CONTENT_DIR/ssg-ubuntu2404-ds.xml"
PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"
STAMP="$(date +%Y%m%d-%H%M%S)"

# Always run the repo's code, not whatever `hardenctl` is on root's PATH.
hctl() { env PYTHONPATH="$REPO" python3 -m hardenctl.cli "$@"; }

say() { printf '\e[2m[*]\e[0m %s\n' "$1"; }
die() { printf '\e[31m[!]\e[0m %s\n' "$1" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "run with sudo"; }

confirm_snapshot() {
    printf '\e[33m%s\e[0m\n' "This phase changes the host. Snapshot taken and this is the lab VM?"
    read -rp "type yes: " ans
    [[ "$ans" == "yes" ]] || die "aborted"
}

# ------------------------------------------------------------------ health ---
# Service preservation: which of the lab's services are up, and which ports
# listen. Recorded before and after every change.
UNITS=(ssh redis-server nginx openplc)
health() {  # $1 = output file
    {
        echo "{"
        echo "  \"units\": {"
        local first=1
        for u in "${UNITS[@]}"; do
            systemctl list-unit-files "$u.service" >/dev/null 2>&1 || continue
            systemctl cat "$u.service" >/dev/null 2>&1 || continue
            [[ $first -eq 1 ]] || echo ","
            first=0
            printf '    "%s": "%s"' "$u" "$(systemctl is-active "$u.service" 2>/dev/null || true)"
        done
        echo ""
        echo "  },"
        printf '  "listening": ['
        ss -ltnH | awk '{print $4}' | sed 's/.*://' | sort -un | paste -sd, - | tr -d '\n'
        echo "]"
        echo "}"
    } > "$1"
}

score() {  # $1 = label
    local base="$OUT/$STAMP-$1"
    say "oscap: scoring ($1)"
    # exit code 2 means "some rules failed", which is the normal case
    oscap xccdf eval --profile "$PROFILE" --results "$base.xml" \
        --report "$base.html" "$DS" >/dev/null 2>&1 || [[ $? -eq 2 ]]
    python3 "$REPO/eval/parse_xccdf.py" "$base.xml" > "$base.json"
    python3 - "$base.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"    score {d['score']:.2f}  pass {d['counts'].get('pass', 0)}  fail {d['counts'].get('fail', 0)}")
PY
}

lynis_index() {  # $1 = label
    command -v lynis >/dev/null || return 0
    lynis audit system --quick --no-colors >/dev/null 2>&1 || true
    local idx
    idx=$(grep -oP '^hardening_index=\K[0-9]+' /var/log/lynis-report.dat 2>/dev/null || echo "")
    echo "{\"lynis_hardening_index\": ${idx:-null}}" > "$OUT/$STAMP-$1-lynis.json"
    say "lynis hardening index ($1): ${idx:-n/a}"
}

snapshot_files() {  # $1 = output file: hashes + modes of files hardenctl touches
    {
        for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf /etc/shadow \
                 /etc/gshadow /etc/passwd /etc/group /etc/sysctl.d/99-hardenctl.conf; do
            [[ -e "$f" ]] || { echo "absent $f"; continue; }
            echo "$(sha256sum "$f" | cut -d' ' -f1) $(stat -c %a "$f") $f"
        done
        for k in kernel.randomize_va_space net.ipv4.tcp_syncookies \
                 net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects fs.suid_dumpable; do
            echo "sysctl $k=$(sysctl -n "$k")"
        done
    } > "$1"
}

# ------------------------------------------------------------------ phases ---
phase_prep() {
    need_root
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq openscap-scanner lynis ansible unzip curl >/dev/null
    mkdir -p "$CONTENT_DIR"
    if [[ ! -f "$DS" ]]; then
        say "downloading SCAP Security Guide $SSG_VER (Ubuntu's own package has no 24.04 content)"
        cd "$CONTENT_DIR"
        curl -fsSLO "$SSG_URL/$SSG_ZIP"
        curl -fsSLO "$SSG_URL/$SSG_ZIP.sha512"
        sha512sum -c "$SSG_ZIP.sha512" || die "SSG checksum mismatch"
        unzip -qjo "$SSG_ZIP" "scap-security-guide-$SSG_VER/ssg-ubuntu2404-ds.xml" -d "$CONTENT_DIR"
        rm -f "$SSG_ZIP"
    fi
    oscap info --profiles "$DS" | grep -q "$PROFILE" || die "profile $PROFILE not in $DS"
    sudo -u "${SUDO_USER:-root}" ansible-galaxy collection install devsec.hardening >/dev/null
    say "ready: $(oscap --version | head -1), SSG $SSG_VER, profile $PROFILE"
}

phase_hardenctl() {
    need_root; confirm_snapshot; mkdir -p "$OUT"
    health "$OUT/$STAMP-weak-health.json"
    snapshot_files "$OUT/$STAMP-weak-files.txt"
    score weak; lynis_index weak

    for proposer in rules llm; do
        if [[ $proposer == llm ]] && ! hctl configure --show 2>/dev/null | grep -q "key *: sk-\|provider : ollama"; then
            say "llm: no provider configured, skipped"; continue
        fi
        say "$proposer: plan"
        hctl plan --proposer "$proposer" --out "$OUT/$STAMP-$proposer-plan.json" \
            | tee "$OUT/$STAMP-$proposer-plan.txt"
        say "$proposer: apply"
        hctl apply "$OUT/$STAMP-$proposer-plan.json" --yes | tee "$OUT/$STAMP-$proposer-apply.txt" || true
        health "$OUT/$STAMP-$proposer-health.json"
        score "$proposer"; lynis_index "$proposer"
        say "$proposer: rollback"
        hctl rollback --last
        snapshot_files "$OUT/$STAMP-$proposer-rolledback-files.txt"
        if diff -q "$OUT/$STAMP-weak-files.txt" "$OUT/$STAMP-$proposer-rolledback-files.txt" >/dev/null; then
            say "$proposer: rollback restored every tracked file and sysctl exactly"
        else
            say "$proposer: ROLLBACK DIFFERS — see the two *-files.txt"
        fi
        score "$proposer-rolledback"
    done
}

phase_openscap() {
    need_root; confirm_snapshot; mkdir -p "$OUT"
    health "$OUT/$STAMP-weak-health.json"; score weak
    say "openscap: remediating with $PROFILE (no rollback — revert the snapshot after)"
    oscap xccdf eval --remediate --profile "$PROFILE" \
        --results "$OUT/$STAMP-openscap-remediation.xml" "$DS" >/dev/null 2>&1 || true
    health "$OUT/$STAMP-openscap-health.json"
    score openscap; lynis_index openscap
    printf '\e[33m%s\e[0m\n' "Done. Revert the VM to the weak-lab snapshot before the next phase."
}

phase_devsec() {
    need_root; confirm_snapshot; mkdir -p "$OUT"
    health "$OUT/$STAMP-weak-health.json"; score weak
    local pb="$OUT/$STAMP-devsec-playbook.yml"
    cat > "$pb" <<'YML'
- hosts: localhost
  connection: local
  become: true
  collections: [devsec.hardening]
  roles: [os_hardening, ssh_hardening]
YML
    say "devsec: os_hardening + ssh_hardening (no rollback — revert the snapshot after)"
    sudo -u "${SUDO_USER:-root}" ansible-galaxy collection list devsec.hardening \
        | tee "$OUT/$STAMP-devsec-version.txt" >/dev/null || true
    ANSIBLE_COLLECTIONS_PATH="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)/.ansible/collections" \
        ansible-playbook -i localhost, "$pb" > "$OUT/$STAMP-devsec-ansible.log" 2>&1 || true
    health "$OUT/$STAMP-devsec-health.json"
    score devsec; lynis_index devsec
    printf '\e[33m%s\e[0m\n' "Done. Revert the VM to the weak-lab snapshot."
}

phase_summary() {
    python3 "$REPO/eval/parse_xccdf.py" --summary "$OUT"
}

case "${1:-}" in
    prep) phase_prep ;;
    hardenctl) phase_hardenctl ;;
    openscap) phase_openscap ;;
    devsec) phase_devsec ;;
    summary) phase_summary ;;
    *) sed -n '3,20p' "$0"; exit 1 ;;
esac
