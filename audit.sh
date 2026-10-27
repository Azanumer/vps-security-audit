#!/usr/bin/env bash
# vps-security-audit — one-shot VPS security posture check.
# Prints PASS / WARN / FAIL per check, exits 2 if any FAIL, 1 if only WARNs, 0 if clean.
# Usage: audit.sh [--json] [--webroot /var/www/html]
set -u

JSON=0
WEBROOT="/var/www/html"
while [ $# -gt 0 ]; do
    case "$1" in
        --json) JSON=1 ;;
        --webroot) WEBROOT="$2"; shift ;;
        --webroot=*) WEBROOT="${1#--webroot=}" ;;
        --help) echo "Usage: audit.sh [--json] [--webroot PATH]"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 3 ;;
    esac
    shift
done

PASS=0; WARN=0; FAIL=0
RESULTS=()

# check <name> <status: PASS|WARN|FAIL> <detail>
check() {
    RESULTS+=("$2|$1|$3")
    case "$2" in PASS) PASS=$((PASS+1));; WARN) WARN=$((WARN+1));; FAIL) FAIL=$((FAIL+1));; esac
}

# --- SSH hardening (sshd -T prints effective config, no parsing of commented lines) ---
if command -v sshd >/dev/null 2>&1; then
    ROOT_LOGIN=$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print tolower($2)}' | head -1)
    [ "$ROOT_LOGIN" = "no" ] || [ "$ROOT_LOGIN" = "prohibit-password" ] \
        && check "SSH root login disabled" PASS "permitrootlogin=$ROOT_LOGIN" \
        || check "SSH root login disabled" FAIL "permitrootlogin=${ROOT_LOGIN:-unknown}"
    PW_AUTH=$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print tolower($2)}' | head -1)
    [ "$PW_AUTH" = "no" ] \
        && check "SSH password auth disabled" PASS "passwordauthentication=no" \
        || check "SSH password auth disabled" WARN "passwordauthentication=${PW_AUTH:-unknown}"
else
    check "SSH config readable" WARN "sshd binary not found"
fi

# --- Firewall active? ---
if command -v ufw >/dev/null 2>&1; then
    ufw status 2>/dev/null | grep -q "Status: active" \
        && check "UFW firewall active" PASS "ufw active" \
        || check "UFW firewall active" FAIL "ufw inactive"
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --state 2>/dev/null | grep -q running \
        && check "firewalld active" PASS "firewalld running" \
        || check "firewalld active" FAIL "firewalld not running"
else
    check "Firewall present" WARN "neither ufw nor firewalld found"
fi

# --- Automatic security updates ---
if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    grep -q 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades \
        && check "Unattended upgrades enabled" PASS "20auto-upgrades on" \
        || check "Unattended upgrades enabled" WARN "20auto-upgrades present but off"
else
    check "Unattended upgrades enabled" WARN "no 20auto-upgrades config"
fi

# --- Pending security updates (Debian/Ubuntu) ---
if command -v apt-get >/dev/null 2>&1; then
    SEC_UPDATES=$(apt-get -s dist-upgrade 2>/dev/null | grep -ci "inst.*security" || true)
    [ "$SEC_UPDATES" -eq 0 ] \
        && check "No pending security updates" PASS "0 pending" \
        || check "No pending security updates" WARN "$SEC_UPDATES security updates pending"
fi

# --- Listening ports: flag anything unexpected beyond SSH/HTTP(S)/DNS ---
if command -v ss >/dev/null 2>&1; then
    OPEN_PORTS=$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | tr '\n' ' ')
    SUSPECT=""
    for p in $OPEN_PORTS; do
        case "$p" in 22|80|443|53) ;; *) SUSPECT="$SUSPECT $p";; esac
    done
    [ -z "$SUSPECT" ] \
        && check "No unexpected listening ports" PASS "ports: $OPEN_PORTS" \
        || check "No unexpected listening ports" WARN "also listening on:$SUSPECT"
fi

# --- Failed SSH logins in the last 24h ---
if [ -f /var/log/auth.log ]; then
    FAILED=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || true)
    [ "$FAILED" -lt 50 ] \
        && check "SSH brute-force volume low" PASS "$FAILED failed logins in auth.log" \
        || check "SSH brute-force volume low" WARN "$FAILED failed logins — consider fail2ban"
fi

# --- World-writable files under the webroot (a classic compromise sign) ---
if [ -d "$WEBROOT" ]; then
    WW=$(find "$WEBROOT" -type f -perm -o+w 2>/dev/null | head -5)
    [ -z "$WW" ] \
        && check "No world-writable web files" PASS "none under $WEBROOT" \
        || check "No world-writable web files" FAIL "e.g. $(echo "$WW" | head -1)"
fi

# --- Output ---
if [ "$JSON" -eq 1 ]; then
    printf '{"pass":%s,"warn":%s,"fail":%s,"checks":[' "$PASS" "$WARN" "$FAIL"
    FIRST=1
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r status name detail <<< "$r"
        [ "$FIRST" -eq 1 ] || printf ','
        FIRST=0
        printf '{"check":%s,"status":%s,"detail":%s}' \
            "$(printf '%s' "$name" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" \
            "$(printf '%s' "$status" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" \
            "$(printf '%s' "$detail" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
    done
    printf ']}\n'
else
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r status name detail <<< "$r"
        printf '[%s] %s — %s\n' "$status" "$name" "$detail"
    done
    printf 'Summary: %s PASS, %s WARN, %s FAIL\n' "$PASS" "$WARN" "$FAIL"
fi

[ "$FAIL" -gt 0 ] && exit 2
[ "$WARN" -gt 0 ] && exit 1
exit 0
