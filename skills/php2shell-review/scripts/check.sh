#!/usr/bin/env bash
# php2shell-review: read-only check for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).
# Changes nothing. Run as root or as a user with passwordless sudo for full results.
# Usage: bash check.sh [--days N] [--no-containers]
# The last block of the output ("SUMMARY") holds the verdict and the next steps.
set -u
DAYS=14; CONTAINERS=1
while [ $# -gt 0 ]; do case "$1" in
  --days) DAYS="$2"; shift 2;; --no-containers) CONTAINERS=0; shift;;
  -h|--help) sed -n '2,6p' "$0"; exit 0;; *) echo "unknown option $1"; exit 2;; esac; done

FIXED="8.5.12 8.4.27 8.3.36 8.2.35"
LIVEWIRE3_MIN="3.6.4"
WEB_USERS="nginx apache www-data nobody http"

if [ "$(id -u)" = 0 ]; then SUDO=""; elif sudo -n true 2>/dev/null; then SUDO="sudo -n"; else SUDO=""; NOROOT=1; fi
S() { $SUDO "$@"; }
h() { printf '\n==================== %s ====================\n' "$*"; }

# Findings collected for the SUMMARY: severity|text
FINDINGS=""
add() { FINDINGS="${FINDINGS}$1|$2"$'\n'; printf '!! [%s] %s\n' "$1" "$2"; }

vge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }   # $1 >= $2
php_status() {   # prints FIXED / VULNERABLE / UNKNOWN for a version like 8.4.10
  local v="$1" f
  for f in $FIXED; do
    if [ "${f%.*}" = "${v%.*}" ]; then vge "$v" "$f" && echo "FIXED" || echo "VULNERABLE"; return; fi
  done
  vge "$v" "8.6.0" && echo "UNKNOWN" || echo "VULNERABLE"
}
php_ver() { "$@" -n -v 2>/dev/null | grep -m1 -oE '^PHP [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2; }

h "HOST"
echo "host=$(hostname) date=$(date -u +%FT%TZ) user=$(id -un) root_access=$([ -n "${NOROOT:-}" ] && echo NO || echo yes)"
grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null
rpm -q system-release 2>/dev/null | grep -v 'not installed'
[ -n "${NOROOT:-}" ] && add INFO "No root/sudo: logs, other users' files and process binaries may be unreadable. Re-run with sudo for a complete result."

h "1. PHP THAT SERVES WEB TRAFFIC"
WEB_PHP=0; WEB_VULN=0
for p in $(pgrep -f 'php-fpm: master' 2>/dev/null); do
  WEB_PHP=1
  exe=$(S readlink -f /proc/$p/exe 2>/dev/null)
  ver=""; [ -n "$exe" ] && ver=$(php_ver S "$exe")
  st=$([ -n "$ver" ] && php_status "$ver" || echo UNKNOWN)
  echo "php-fpm pid=$p binary=${exe:-unreadable} version=${ver:-unknown} status=$st started=$(ps -o lstart= -p $p)"
  case $st in
    VULNERABLE) WEB_VULN=1; add HIGH "php-fpm (pid $p, $exe) runs PHP $ver, which is vulnerable. Fixed: $FIXED";;
    UNKNOWN) add INFO "Could not read the version of php-fpm pid $p (needs root)";;
  esac
  # Load ini files exactly like the running master does (same PHP_INI_SCAN_DIR), so stale ini lines are only reported if they really affect it
  scan=$(S cat /proc/$p/environ 2>/dev/null | tr '\0' '\n' | grep '^PHP_INI_SCAN_DIR=')
  [ -n "$exe" ] && S env ${scan:-PHP_INI_SCAN_DIR_UNSET=1} "$exe" -v 2>&1 | grep -oE "Unable to load dynamic library '[^']+'" | sort -u | sed "s/^/   ini loads a missing extension in $exe: /"
done
for a in httpd apache2; do
  command -v $a >/dev/null || continue
  if S $a -M 2>/dev/null | grep -qi php; then
    WEB_PHP=1; v=$(php_ver php); echo "apache $a loads mod_php (system php reports ${v:-unknown})"
    [ -n "$v" ] && [ "$(php_status "$v")" = VULNERABLE ] && { WEB_VULN=1; add HIGH "Apache mod_php uses PHP $v (vulnerable)"; }
  fi
done
pgrep -af 'php-cgi|frankenphp|rr serve|swoole|octane:start' 2>/dev/null | grep -v pgrep | sed 's/^/other PHP server: /'
[ $WEB_PHP = 0 ] && echo "No php-fpm or mod_php found on the host (see CONTAINERS)."

h "2. OTHER PHP ON DISK (not necessarily serving web)"
for b in $(ls /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm* /opt/*/bin/php /opt/*/sbin/php-fpm /opt/remi/*/root/usr/bin/php /opt/remi/*/root/usr/sbin/php-fpm 2>/dev/null | sort -u); do
  [ -x "$b" ] && [ -f "$b" ] || continue
  if head -c2 "$b" | grep -q '#!'; then echo "$b (script: $(grep -m1 -E '^exec' "$b"))"; continue; fi
  v=$(php_ver "$b"); [ -n "$v" ] && echo "$b $v $(php_status "$v")"
done
echo "-- systemd php units and drop-ins:"
for u in $(systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep -i php); do
  echo "$u ($(systemctl is-active "$u"))"; systemctl cat "$u" 2>/dev/null | grep -E '^# /|^ExecStart=.+' | sed 's/^/   /'
done
echo "-- packages:"
command -v rpm >/dev/null && rpm -qa 2>/dev/null | grep -iE '^php' | sort
command -v dpkg >/dev/null && dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /^(php|libapache2-mod-php)/ {print $2, $3}'
if command -v dnf >/dev/null; then
  echo "-- dnf updates for php* (cached metadata; 'nothing' does NOT prove you are patched):"; S dnf -q check-update 'php*' 2>/dev/null | tail -10
  S dnf -q check-release-update 2>/dev/null | head -5
elif command -v apt-get >/dev/null; then
  echo "-- apt upgradable php (as fresh as the last 'apt update'):"; apt list --upgradable 2>/dev/null | grep -i php
fi

h "3. WEB SERVER AND SITES"
NGX=""; command -v nginx >/dev/null && NGX=$(S nginx -T 2>/dev/null)
[ -z "$NGX" ] && NGX=$(S sh -c 'cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null')
APC=$(S sh -c 'cat /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf /etc/apache2/sites-enabled/* 2>/dev/null')
echo "$NGX" | grep -oE '^\s*(server_name|root)\s+[^;]+' | sed 's/^\s*//' | sort -u | head -60
echo "$APC" | grep -E '^\s*(ServerName|DocumentRoot)' | sed 's/^\s*//' | sort -u | head -40
DOCROOTS=$( { echo "$NGX" | grep -oE '^\s*root\s+/[^;]+' | awk '{print $2}'; echo "$APC" | grep -oE 'DocumentRoot\s+"?/[^" ]+' | awk '{print $2}' | tr -d '"'; } | sort -u)
APPS=$(for d in $DOCROOTS; do [ -d "$d" ] || continue; [ "$(basename "$d")" = public ] && dirname "$d" || echo "$d"; done | sort -u)
if [ -n "$NGX" ] && echo "$NGX" | grep -qE 'location\s+~\*?\s+\\\.php\$?\s*\{'; then
  add MEDIUM "nginx passes ANY *.php file to PHP. Uploaded scripts could run. Prefer allowing only the front controller (index.php)."
fi

h "4. ACCESS LOGS"
LOGS=$(S sh -c 'ls /var/log/nginx/*access*log* /var/log/httpd/*access*log* /var/log/apache2/*access*log* 2>/dev/null' | tr '\n' ' ')
CURLOGS=$(echo "$LOGS" | tr ' ' '\n' | grep -vE '\.gz$|[0-9]$' | grep . | head -3 | tr '\n' ' ')
if [ -z "${LOGS// /}" ] || ! S head -c1 ${LOGS%% *} >/dev/null 2>&1; then
  add INFO "Access logs not found or not readable: attack activity was NOT checked."
  LOGS=""
fi
ALL() { S sh -c "zcat -f $LOGS 2>/dev/null"; }
PROBES=0; EXEC200=0
if [ -n "$LOGS" ]; then
  echo "-- PHP2Shell indicators (user agent, upload-progress field, session include):"
  ALL | grep -iE 'php2shell|PHP_SESSION_UPLOAD_PROGRESS|upload_progress_|sess_[A-Za-z0-9]*exploit|[?&][a-z_]+=[^ ]*(/sess_|/var/lib/php/sess)' > /tmp/.p2s.$$ 2>/dev/null
  PROBES=$(wc -l < /tmp/.p2s.$$)
  tail -30 /tmp/.p2s.$$ | cut -c1-300
  echo "-- by IP and HTTP status:"; awk '{print $1, $9}' /tmp/.p2s.$$ | sort | uniq -c | sort -rn | head -15
  rm -f /tmp/.p2s.$$
  [ "$PROBES" -gt 0 ] && add INFO "$PROBES PHP2Shell probe requests in the logs (attempts, not proof of success)"
  echo "-- Livewire attack traffic (count ip method status path):"
  ALL | grep -E 'livewire/(update|upload-file|message)|livewire-tmp' | awk '{split($7,a,"?"); sub(/livewire-tmp\/.*/,"livewire-tmp/*",a[1]); print $1,$6,$9,a[1]}' | sort | uniq -c | sort -rn | awk '$1>50' | head -15
  echo "-- pearcmd / path traversal probes by status:"; ALL | grep -E 'pearcmd|\.\./\.\./' | awk '{print $9}' | sort | uniq -c | sort -rn | head
  echo "-- HTTP 200 on requests that try to RUN code (review each line):"
  ALL | grep -E '[?&](x|cmd|c|exec|command)=|/livewire-tmp/|\.(phtml|pht|phar|pgif)[? ]|/tmp/[^ ]*\.php' | awk '$9==200' > /tmp/.p2e.$$
  EXEC200=$(wc -l < /tmp/.p2e.$$); tail -20 /tmp/.p2e.$$ | cut -c1-300; rm -f /tmp/.p2e.$$
  [ "$EXEC200" -gt 0 ] && add MEDIUM "$EXEC200 code-execution attempts got HTTP 200. Check them: Laravel often answers 200 with its normal page, which is harmless."
  echo "-- top POST sources (current log):"
  S cat $CURLOGS 2>/dev/null | awk '$6 ~ /POST/ {print $1}' | sort | uniq -c | sort -rn | head -5
  CF=$(S tail -q -n 20000 $CURLOGS 2>/dev/null | awk '{print $1}' | grep -cE '^(104\.(1[6-9]|2[0-9]|3[01])|172\.(6[4-9]|7[01])|108\.162|162\.158|173\.245|188\.114|190\.93|197\.234|198\.41|141\.101|103\.(21|22|31))\.')
  if [ "${CF:-0}" -gt 100 ] && ! echo "$NGX$APC" | grep -qE 'real_ip_header|RemoteIPHeader'; then
    add INFO "Traffic comes through Cloudflare but the real client IP is not restored. Logs show Cloudflare IPs: do NOT ban those."
  fi
fi

h "5. SIGNS OF COMPROMISE"
COMPROMISE=0
hit() { COMPROMISE=$((COMPROMISE+1)); add CRITICAL "$1"; }
echo "-- session files containing PHP code:"
for d in /var/lib/php/session /var/lib/php/sessions /tmp/sessions /var/opt/remi/*/lib/php/session; do
  for f in $(S grep -lE '<\?php|<\?=' "$d" -r 2>/dev/null | head -10); do hit "Session file contains PHP code: $f"; done
done
echo "-- PHP files in /tmp, /var/tmp, /dev/shm (owner date path):"
S find /tmp /var/tmp /dev/shm -xdev \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.pht' \) -not -path '*/claude-*' -printf '%u %TY-%Tm-%Td %p\n' 2>/dev/null | head -30 > /tmp/.p2t.$$
cat /tmp/.p2t.$$
for u in $WEB_USERS; do awk -v u=$u '$1==u {print $3}' /tmp/.p2t.$$; done | while read -r f; do echo "$f"; done > /tmp/.p2w.$$
while read -r f; do [ -n "$f" ] && hit "PHP file in a temp dir written by the web server user: $f"; done < /tmp/.p2w.$$
rm -f /tmp/.p2t.$$ /tmp/.p2w.$$
for a in $APPS; do
  echo "-- site: $a"
  S find "$a" -xdev -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.pht' -o -name '.user.ini' -o -name '.htaccess' \) -mtime -"$DAYS" \
    -not -path '*/vendor/*' -not -path '*/node_modules/*' -not -path '*/storage/framework/*' -not -path '*/.git/*' -printf "   changed in last $DAYS days: %u %TY-%Tm-%Td %p\n" 2>/dev/null | head -20
  for f in $(S find "$a/public" "$a/storage/app" -xdev -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phar' -o -iname '*.pgif' \) -not -path "$a/public/index.php" -not -path '*/vendor/*' 2>/dev/null | head -20); do
    echo "   PHP file in public/ or uploads (check if it belongs to the app): $f"
  done
  for f in $(S grep -rlE --include='*.php' --include='*.phtml' --exclude-dir=vendor --exclude-dir=node_modules \
      'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(|eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|assert\s*\(\s*\$_(POST|GET|REQUEST)|(system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)' "$a" 2>/dev/null | head -10); do
    hit "Webshell pattern in $f"
  done
  for f in $(S grep -rl '<?php' "$a/storage/app/livewire-tmp" "$a/storage/app/private/livewire-tmp" "$a/public/uploads" "$a/storage/app/public" 2>/dev/null | head -10); do
    hit "Uploaded file contains PHP code: $f"
  done
done
echo "-- processes run by web users that are not the web server or php-fpm:"
ps -eo user=,pid=,lstart=,cmd= 2>/dev/null | while read -r u rest; do
  case " $WEB_USERS " in *" $u "*) ;; *) continue;; esac
  echo "$rest" | grep -qE 'php-fpm: |nginx: |/httpd|apache2 -k|/usr/sbin/apache2|php-fpm[0-9.]*: ' && continue
  echo "$u $rest"
done > /tmp/.p2r.$$
while read -r l; do hit "Unexpected process run by the web user: $l"; done < /tmp/.p2r.$$; rm -f /tmp/.p2r.$$
echo "-- crontabs of web users:"
for u in $WEB_USERS; do id "$u" >/dev/null 2>&1 || continue
  c=$(S crontab -u "$u" -l 2>/dev/null | grep -vE '^\s*(#|$)')
  [ -n "$c" ] && hit "Web user $u has a crontab: $(echo "$c" | head -3 | tr '\n' ';')"
done
echo "-- outbound connections from web processes (excluding ports 80/443/3306/5432/6379/53):"
S ss -tnp state established 2>/dev/null | grep -E 'php|nginx|httpd|apache' | awk '{print $4, $5, $6}' | grep -vE ':(80|443|3306|5432|6379|53|9000) ' | head -15
echo "-- authorized_keys changed in last $DAYS days:"
S find /root/.ssh /home/*/.ssh /var/www /var/lib/nginx -name 'authorized_keys*' -mtime -"$DAYS" 2>/dev/null

h "6. LARAVEL / LIVEWIRE APPS"
for lock in $(S find /opt /var/www /srv /home -maxdepth 4 -name composer.lock -not -path '*/vendor/*' 2>/dev/null); do
  d=$(dirname "$lock")
  lw=$(grep -A1 '"name": "livewire/livewire"' "$lock" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  lf=$(grep -A1 '"name": "laravel/framework"' "$lock" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  [ -z "$lw$lf" ] && continue
  served=no; echo "$APPS" | grep -qxF "$d" && served=yes
  echo "$d laravel=${lf:--} livewire=${lw:--} served_by_webserver=$served"
  case "$lw" in 3.*) vge "$lw" "$LIVEWIRE3_MIN" || {
    [ $served = yes ] && add HIGH "Livewire $lw in $d (served) is vulnerable to CVE-2025-54068. Update to >= $LIVEWIRE3_MIN" \
                      || add LOW "Livewire $lw in $d is vulnerable but the site does not seem to be served"; };;
  esac
done

if [ $CONTAINERS = 1 ]; then
  h "7. CONTAINERS"
  for rt in docker podman; do command -v $rt >/dev/null || continue
    for c in $(S $rt ps -q 2>/dev/null); do
      v=$(S $rt exec "$c" sh -c 'php -v 2>/dev/null || php-fpm -v 2>/dev/null' 2>/dev/null | grep -m1 -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2)
      [ -z "$v" ] && continue
      st=$(php_status "$v"); echo "$rt container $c image=$(S $rt inspect -f '{{.Config.Image}}' "$c") PHP $v $st"
      [ "$st" = VULNERABLE ] && { WEB_PHP=1; WEB_VULN=1; add HIGH "Container $c runs PHP $v (vulnerable)"; }
    done
  done
fi

# ---------------------------------------------------------------- summary
if [ $COMPROMISE -gt 0 ]; then VERDICT="COMPROMISED / SUSPECTED"
elif [ $WEB_PHP = 0 ]; then VERDICT="INCONCLUSIVE - no PHP serving web traffic was found"
elif [ $WEB_VULN = 1 ]; then VERDICT="VULNERABLE - no evidence of exploitation found"
elif [ -n "${NOROOT:-}" ] || [ -z "$LOGS" ]; then VERDICT="NOT VULNERABLE (partial check: run again with sudo)"
else VERDICT="NOT VULNERABLE"; fi

h "SUMMARY"
echo "VERDICT: $VERDICT"
echo "host: $(hostname)   checked: $(date -u +%FT%TZ)"
echo "php2shell_probes_in_logs: $PROBES   exec_attempts_with_200: $EXEC200   compromise_indicators: $COMPROMISE"
echo
echo "FINDINGS (most severe first):"
for s in CRITICAL HIGH MEDIUM LOW INFO; do printf '%s' "$FINDINGS" | awk -F'|' -v s=$s '$1==s {print "- [" $1 "] " $2}'; done
[ -z "$FINDINGS" ] && echo "- none"
echo
echo "NEXT STEPS:"
case "$VERDICT" in
  COMPROMISED*) echo "1. Do NOT delete anything. Keep the evidence."
                echo "2. Isolate the server (block inbound traffic or take it out of the load balancer) and snapshot the disk."
                echo "3. Start incident response: rotate passwords, keys and .env secrets. Rebuild from a clean image.";;
  VULNERABLE*)  echo "1. Upgrade PHP to a fixed version ($FIXED) and reload php-fpm."
                echo "2. If you can't upgrade today, set session.upload_progress.enabled=0 as a PARTIAL workaround."
                echo "3. Run this check again and confirm the php-fpm line says FIXED.";;
  INCONCLUSIVE*) echo "1. Find out how PHP is served here (container, another host, panel) and check that.";;
  *)            echo "1. Keep the fixed PHP. Make sure a package update or a removed systemd drop-in can't bring back an old binary.";;
esac
grep -q 'HIGH|Livewire' <<<"$FINDINGS" && echo "- Update Livewire: cd <app> && composer update livewire/livewire, then reload php-fpm."
echo "Lines marked !! above were found by automatic checks. Check them before acting."
