#!/usr/bin/env bash
# Install the php2shell web protections: fail2ban jails that ban exploit/webshell scanners in
# iptables AND nginx, the Cloudflare real-IP config, and the "only index.php runs PHP" nginx snippet.
#
# Usage:
#   harden.sh                      plan: tests the filters against your logs, changes nothing (default)
#   harden.sh --apply              install
# Options:
#   --bantime T      fail2ban ban time (default 1w; -1 = permanent)
#   --mail-to ADDR   hourly email digest of bans (needs a working sendmail)
#   --cloudflare     force the Cloudflare real-IP config (auto-detected from the logs otherwise)
#   --no-webshell    do not enable the nginx-webshell jail (use for WordPress or sites with many .php files)
#   --ignore "IPs"   extra IPs/CIDRs never to ban (your office, monitoring...)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MODE=plan; BANTIME=1w; MAILTO=""; CF=auto; WEBSHELL=1; EXTRA_IGNORE=""
while [ $# -gt 0 ]; do case "$1" in
  --apply) MODE=apply; shift;; --bantime) BANTIME="$2"; shift 2;; --mail-to) MAILTO="$2"; shift 2;;
  --cloudflare) CF=yes; shift;; --no-webshell) WEBSHELL=0; shift;; --ignore) EXTRA_IGNORE="$2"; shift 2;;
  -h|--help) sed -n '2,15p' "$0"; exit 0;; *) echo "unknown option: $1" >&2; exit 2;; esac; done
say() { printf '\n>>> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (sudo)"
command -v nginx >/dev/null || die "nginx not found. These protections are for nginx (Apache: use mod_security instead)."
STAMP=$(date +%Y%m%d%H%M%S); BACKUP=/var/backups/php2shell-harden-$STAMP

# ---- access log and format
LOG=$(nginx -T 2>/dev/null | grep -oE '^\s*access_log\s+/[^ ;]+' | awk '{print $2}' | head -1 || true)
LOG=${LOG:-/var/log/nginx/access.log}
[ -r "$LOG" ] || die "cannot read access log $LOG"
FIRST=$(tail -n 1 "$LOG")
echo "$FIRST" | grep -qE '^[0-9a-fA-F:.]+ \S+ \S+ \[' || die "the access log does not start with the client IP (combined/main format). The filters would not match: $FIRST"
echo "access log: $LOG"

# ---- Cloudflare?
CFHITS=$(tail -n 20000 "$LOG" | awk '{print $1}' | grep -cE '^(104\.(1[6-9]|2[0-9]|3[01])|172\.(6[4-9]|7[01])|108\.162|162\.158|173\.245|188\.114|190\.93|197\.234|198\.41|141\.101|103\.(21|22|31))\.' || true)
HAS_REALIP=$(nginx -T 2>/dev/null | grep -c 'real_ip_header' || true)
[ $CF = auto ] && { [ "$CFHITS" -gt 100 ] && CF=yes || CF=no; }
echo "Cloudflare: $CF (hits in last 20000 lines: $CFHITS, real_ip already configured: $([ "$HAS_REALIP" -gt 0 ] && echo yes || echo no))"
[ $CF = yes ] && [ "$HAS_REALIP" = 0 ] && echo "   -> logs show Cloudflare IPs. Without the real-IP config, fail2ban would ban Cloudflare. It will be installed."

# ---- ignore list: localhost, this host's own addresses, Cloudflare (only matters if real IP is not restored)
SELF=$(hostname -I 2>/dev/null || true)
PUB=$(curl -fsS --max-time 3 http://checkip.amazonaws.com 2>/dev/null || true)
IGNORE="127.0.0.1/8 ::1 $SELF $PUB $EXTRA_IGNORE"
[ $CF = yes ] && IGNORE="$IGNORE $(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v4 2>/dev/null | tr '\n' ' ') $(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v6 2>/dev/null | tr '\n' ' ')"
IGNORE=$(echo $IGNORE)   # one line, single spaces
echo "never ban: $IGNORE"

# ---- vhosts that still run any .php
say "nginx sites that pass ANY .php file to PHP (uploaded scripts could run)"
nginx -T 2>/dev/null | awk '/^# configuration file/ {f=$4} /location[ \t]+~\*?[ \t]+\\\.php\$?[ \t]*\{/ {print "   " f}' | sort -u
echo "   Fix: in those server blocks use the snippet $HERE/nginx/php-front-controller-only.conf"
echo "   (installed as /etc/nginx/snippets/php-front-controller-only.conf; edit vhosts by hand, then nginx -t)."

# ---- dry-run the filters against real traffic
say "testing the filters against $LOG (who would be banned)"
if command -v fail2ban-regex >/dev/null; then
  for f in nginx-webshell nginx-upload-flood nginx-404-flood; do
    [ $f = nginx-webshell ] && [ $WEBSHELL = 0 ] && continue
    n=$(fail2ban-regex "$LOG" "$HERE/fail2ban/filter.d/$f.conf" 2>/dev/null | grep -oE '^Lines: .*' | head -1 || true)
    echo "   $f: $n"
  done
  echo "   top IPs matching nginx-webshell (check none of them is you or a legitimate user):"
  fail2ban-regex --print-all-matched "$LOG" "$HERE/fail2ban/filter.d/nginx-webshell.conf" 2>/dev/null \
     | grep -oE '^\|\s+[0-9a-fA-F:.]+' | awk '{print $2}' | sort | uniq -c | sort -rn | head -8 | sed 's/^/     /' || true
else
  echo "   fail2ban is not installed. Install it first:"
  echo "     Amazon Linux/RHEL: dnf install -y fail2ban (RHEL/Alma/Rocky need EPEL)  |  Debian/Ubuntu: apt-get install -y fail2ban"
  [ $MODE = apply ] && die "install fail2ban and run again"
fi

if [ $MODE = plan ]; then
  cat <<EOF

PLAN (nothing was changed). --apply will:
  - copy the snippet to /etc/nginx/snippets/php-front-controller-only.conf (not enabled by itself)
$( [ $CF = yes ] && echo "  - write /etc/nginx/conf.d/01-cloudflare-realip.conf from Cloudflare's current IP list (skipped if real_ip is set in another file)" )
  - create /etc/nginx/conf.d/00-blocklist-auto.conf (fail2ban adds 'deny <ip>;' lines there)
  - install fail2ban filters (nginx-webshell$( [ $WEBSHELL = 0 ] && echo ' [disabled]' ), nginx-upload-flood, nginx-404-flood) and actions
  - write /etc/fail2ban/jail.d/php2shell-web.local (bantime $BANTIME)
$( [ -n "$MAILTO" ] && echo "  - hourly ban digest to $MAILTO (/etc/php2shell/notify.conf, /etc/cron.d/php2shell-f2b-digest)" )
  - test nginx and fail2ban configs; on failure, everything is restored from the backup.
Backups go to $BACKUP.
EOF
  exit 0
fi

# ---- apply
mkdir -p "$BACKUP"
backup() { for f in "$@"; do [ -e "$f" ] && cp -a --parents "$f" "$BACKUP/"; done; return 0; }
FILES="/etc/nginx/snippets/php-front-controller-only.conf /etc/nginx/conf.d/01-cloudflare-realip.conf /etc/nginx/conf.d/00-blocklist-auto.conf
 /etc/fail2ban/filter.d/nginx-webshell.conf /etc/fail2ban/filter.d/nginx-upload-flood.conf /etc/fail2ban/filter.d/nginx-404-flood.conf
 /etc/fail2ban/action.d/nginx-deny.conf /etc/fail2ban/action.d/php2shell-notify.conf /etc/fail2ban/jail.d/php2shell-web.local"
backup $FILES
restore() {
  echo "restoring previous files from $BACKUP"
  for f in $FILES; do if [ -e "$BACKUP$f" ]; then cp -a "$BACKUP$f" "$f"; else rm -f "$f"; fi; done
  nginx -t -q && systemctl reload nginx || true
}

say "nginx"
mkdir -p /etc/nginx/snippets
install -m 644 "$HERE/nginx/php-front-controller-only.conf" /etc/nginx/snippets/
if [ $CF = yes ]; then
  if [ "$HAS_REALIP" = 0 ] || [ -f /etc/nginx/conf.d/01-cloudflare-realip.conf ]; then bash "$HERE/nginx/cloudflare-realip.sh" /etc/nginx/conf.d/01-cloudflare-realip.conf
  else echo "real_ip is already configured in another file; leaving it alone"; fi
fi
touch /etc/nginx/conf.d/00-blocklist-auto.conf
if ! nginx -t; then restore; die "nginx config test failed (maybe real_ip is already set elsewhere). Restored."; fi
systemctl reload nginx

say "fail2ban"
install -m 644 "$HERE"/fail2ban/filter.d/*.conf /etc/fail2ban/filter.d/
install -m 644 "$HERE/fail2ban/action.d/nginx-deny.conf" /etc/fail2ban/action.d/
NOTIFY=""
if [ -n "$MAILTO" ]; then
  install -m 644 "$HERE/fail2ban/action.d/php2shell-notify.conf" /etc/fail2ban/action.d/
  install -m 755 "$HERE"/fail2ban/notify/php2shell-f2b-* /usr/local/bin/
  mkdir -p /etc/php2shell
  [ -f /etc/php2shell/notify.conf ] || printf 'MAIL_TO=%s\n#MAIL_FROM=security@example.com\nACCESS_LOG=%s\n' "$MAILTO" "$LOG" > /etc/php2shell/notify.conf
  echo "17 * * * * root /usr/local/bin/php2shell-f2b-digest" > /etc/cron.d/php2shell-f2b-digest
  NOTIFY=php2shell-notify
  command -v sendmail >/dev/null || echo "WARNING: no sendmail found; digests will be queued and logged to /var/log/php2shell-f2b.log until one is installed"
fi
sed -e "s#@IGNOREIP@#$IGNORE#" -e "s#@BANTIME@#$BANTIME#" -e "s#@LOGPATH@#$LOG#" -e "s#@NOTIFY@#$NOTIFY#" \
    "$HERE/fail2ban/jail.d/php2shell-web.local" > /etc/fail2ban/jail.d/php2shell-web.local
[ $WEBSHELL = 0 ] && sed -i '/^\[nginx-webshell\]/,/^\[/ s/^enabled  = true/enabled  = false/' /etc/fail2ban/jail.d/php2shell-web.local
if ! fail2ban-client -t >/dev/null 2>&1; then fail2ban-client -t || true; restore; die "fail2ban config test failed. Restored."; fi
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban; sleep 2
fail2ban-client status | sed 's/^/   /'

say "done. Backups: $BACKUP"
echo "List bans:  fail2ban-client status nginx-webshell"
echo "Unban:      fail2ban-client set <jail> unbanip <ip>"
echo "Remember to add the front-controller snippet to the sites listed above."
