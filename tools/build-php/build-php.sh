#!/usr/bin/env bash
# Build a fixed PHP from the official php.net source into its own prefix, without touching
# the distro packages, then (optionally) switch php-fpm to it with automatic rollback.
# Use it when your distro has no fixed package yet.
#
# Usage:
#   build-php.sh                 plan only: shows what it would do (default, changes nothing)
#   build-php.sh --apply         install build deps, download + verify, build, install to /opt/php-<ver>
#   build-php.sh --switch        point the running php-fpm service to the new build (restart, ~1 s)
#   build-php.sh --rollback      remove the php2shell drop-in and go back to the distro php-fpm
# Options:
#   --version X.Y.Z   default: newest release of the branch php-fpm runs now
#   --prefix DIR      default: /opt/php-<version>
#   --sha256 HASH     default: taken from php.net's release data
#   --wrappers        with --switch: also make /usr/local/bin/php and composer use the new build
#   --force           with --switch: switch even if some PHP modules are missing in the new build
set -euo pipefail

MODE=plan; VERSION=""; PREFIX=""; SHA=""; WRAPPERS=0; FORCE=0
while [ $# -gt 0 ]; do case "$1" in
  --apply) MODE=apply; shift;; --switch) MODE=switch; shift;; --rollback) MODE=rollback; shift;;
  --version) VERSION="$2"; shift 2;; --prefix) PREFIX="$2"; shift 2;; --sha256) SHA="$2"; shift 2;;
  --wrappers) WRAPPERS=1; shift;; --force) FORCE=1; shift;;
  -h|--help) sed -n '2,18p' "$0"; exit 0;; *) echo "unknown option: $1" >&2; exit 2;; esac; done

say() { printf '\n>>> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (sudo)"
fetch() { curl -fsSL --max-time 300 "$1" 2>/dev/null || wget -qO- --timeout=300 "$1"; }
DROPIN_NAME=php2shell-php.conf

# ---- what runs now
MASTER=$(pgrep -f 'php-fpm: master' | head -1 || true)
OLD_EXE=""; UNIT=""; FPM_CONF=""; PHP_INI=""; OLD_VER=""
if [ -n "$MASTER" ]; then
  OLD_EXE=$(readlink -f /proc/$MASTER/exe)
  UNIT=$(ps -o unit= -p "$MASTER" 2>/dev/null | tr -d ' ' || true)
  FPM_CONF=$(tr '\0' ' ' < /proc/$MASTER/cmdline | grep -oE '\(/[^)]+\)' | tr -d '()' || true)
  OLD_VER=$("$OLD_EXE" -n -v 2>/dev/null | grep -m1 -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
  OLD_SCAN=$(tr '\0' '\n' < /proc/$MASTER/environ | grep '^PHP_INI_SCAN_DIR=' | cut -d= -f2- || true)
  PHP_INI=$(env ${OLD_SCAN:+PHP_INI_SCAN_DIR=$OLD_SCAN} "$OLD_EXE" -i 2>/dev/null | awk -F'=> ' '/^Loaded Configuration File/ {print $2}' | tr -d ' ')
  [ "$PHP_INI" = "(none)" ] && PHP_INI=""
fi

if [ $MODE = rollback ]; then
  [ -n "$UNIT" ] || die "no running php-fpm systemd unit found"
  D=/etc/systemd/system/$UNIT.d/$DROPIN_NAME
  [ -f "$D" ] || die "no $D: nothing to roll back"
  mv "$D" "$D.disabled-$(date +%s)"; systemctl daemon-reload; systemctl restart "$UNIT"
  sleep 2; NEW=$(readlink -f /proc/$(systemctl show -p MainPID --value "$UNIT")/exe)
  say "rolled back: $UNIT now runs $NEW ($($NEW -n -v | head -1))"
  exit 0
fi

# ---- target version
if [ -z "$VERSION" ]; then
  BR=${OLD_VER%.*}; [ -n "$BR" ] || die "no running php-fpm; pass --version X.Y.Z"
  VERSION=$(fetch "https://www.php.net/releases/index.php?json&max=1&version=$BR" | grep -oE "\"$BR\.[0-9]+\"" | head -1 | tr -d '"' || true)
  [ -n "$VERSION" ] || die "could not get the latest $BR release from php.net (branch may be end-of-life: upgrade to a supported branch)"
fi
case "${VERSION%.*}" in 8.2|8.3|8.4|8.5) ;; *) echo "WARNING: PHP ${VERSION%.*} is end-of-life. There is no official fixed release for it; move the app to PHP 8.2 or newer.";; esac
PREFIX=${PREFIX:-/opt/php-$VERSION}
NEW_FPM=$PREFIX/sbin/php-fpm; NEW_PHP=$PREFIX/bin/php; SCAN=$PREFIX/etc/conf.d

echo "running php-fpm : ${OLD_EXE:-none} ${OLD_VER:-} (unit ${UNIT:-?}, conf ${FPM_CONF:-?}, ini ${PHP_INI:-?})"
echo "target          : PHP $VERSION in $PREFIX (ini scan dir $SCAN)"

# ---- build deps
if command -v dnf >/dev/null || command -v yum >/dev/null; then
  PM=$(command -v dnf || command -v yum)
  DEPS="gcc gcc-c++ make autoconf bison re2c pkgconf-pkg-config libxml2-devel sqlite-devel openssl-devel libcurl-devel oniguruma-devel libzip-devel zlib-devel bzip2-devel libpng-devel libjpeg-turbo-devel libwebp-devel freetype-devel libicu-devel libsodium-devel readline-devel libxslt-devel systemd-devel libacl-devel gettext-devel tar xz"
elif command -v apt-get >/dev/null; then
  PM=apt-get
  DEPS="build-essential autoconf bison re2c pkg-config libxml2-dev libsqlite3-dev libssl-dev libcurl4-openssl-dev libonig-dev libzip-dev zlib1g-dev libbz2-dev libpng-dev libjpeg-dev libwebp-dev libfreetype6-dev libicu-dev libsodium-dev libreadline-dev libxslt1-dev libsystemd-dev libacl1-dev xz-utils"
else die "unsupported package manager (need dnf, yum or apt-get)"; fi

CONFIGURE="--prefix=$PREFIX --with-config-file-path=$PREFIX/etc --with-config-file-scan-dir=$SCAN
 --enable-fpm --with-fpm-systemd --with-fpm-acl
 --enable-bcmath --with-bz2 --with-curl --enable-calendar --enable-exif --enable-gd --with-freetype --with-jpeg --with-webp
 --with-gettext --enable-intl --enable-mbstring --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd --with-pdo-sqlite --with-sqlite3
 --with-openssl --with-readline --enable-soap --with-sodium --enable-sockets --enable-pcntl --enable-shmop
 --enable-sysvmsg --enable-sysvsem --enable-sysvshm --with-xsl --with-zip --with-zlib ${EXTRA_CONFIGURE:-}"

if [ $MODE = plan ]; then
  cat <<EOF

PLAN (nothing was changed). Steps for --apply:
  1. $PM install: $DEPS
  2. download https://www.php.net/distributions/php-$VERSION.tar.xz and check its SHA-256 against php.net
  3. ./configure $(echo $CONFIGURE)
  4. make -j$(nproc) && make install   (into $PREFIX only)
  5. create $SCAN with only opcache settings (old /etc ini dirs are NOT loaded)
  6. php-fpm -t with your current pool config, and compare PHP modules with the running version
Then run --switch to move $UNIT to the new build (with automatic rollback if it fails).
Extra configure flags: EXTRA_CONFIGURE="--with-pgsql --with-ldap" $0 --apply
EOF
  exit 0
fi

compare_modules() {   # prints modules the old php-fpm has and the new one lacks
  [ -n "$OLD_EXE" ] || return 0
  diff <(env ${OLD_SCAN:+PHP_INI_SCAN_DIR=$OLD_SCAN} "$OLD_EXE" ${PHP_INI:+-c "$PHP_INI"} -m 2>/dev/null | grep -vE '^\[|^$' | tr A-Z a-z | sort -u) \
       <(PHP_INI_SCAN_DIR=$SCAN "$NEW_FPM" ${PHP_INI:+-c "$PHP_INI"} -m 2>/dev/null | grep -vE '^\[|^$' | tr A-Z a-z | sort -u) | sed -n 's/^< //p' || true
}

if [ $MODE = apply ]; then
  say "installing build dependencies"
  if [ $PM = apt-get ]; then apt-get update -qq; apt-get install -y $DEPS; else $PM install -y $DEPS || die "some packages failed. On RHEL/Alma/Rocky enable CRB + EPEL for oniguruma-devel and libzip-devel"; fi

  WORK=$(mktemp -d /usr/local/src/php2shell-build.XXXX); cd "$WORK"
  say "downloading PHP $VERSION"
  fetch "https://www.php.net/distributions/php-$VERSION.tar.xz" > php.tar.xz || die "download failed"
  if [ -z "$SHA" ]; then
    SHA=$(fetch "https://www.php.net/releases/index.php?json&version=$VERSION" | tr '{}' '\n\n' | grep "php-$VERSION.tar.xz" | grep -oE '[0-9a-f]{64}' | head -1 || true)
  fi
  [ -n "$SHA" ] || die "no SHA-256 for php-$VERSION.tar.xz; pass --sha256 from https://www.php.net/downloads"
  echo "$SHA  php.tar.xz" | sha256sum -c - || die "SHA-256 mismatch: do not use this file"
  tar xf php.tar.xz; cd "php-$VERSION"

  say "configure"; ./configure $CONFIGURE > "$WORK/configure.log" 2>&1 || { tail -30 "$WORK/configure.log"; die "configure failed (full log: $WORK/configure.log). Usually a missing -devel package."; }
  say "make (this takes a while)"; make -j"$(nproc)" > "$WORK/make.log" 2>&1 || { tail -30 "$WORK/make.log"; die "make failed (log: $WORK/make.log)"; }
  say "make install into $PREFIX"; make install > "$WORK/install.log" 2>&1 || { tail -20 "$WORK/install.log"; die "make install failed"; }

  mkdir -p "$SCAN"
  if ! "$NEW_PHP" -n -m | grep -qi 'zend opcache' && ls "$("$NEW_PHP" -n -r 'echo ini_get("extension_dir");')"/opcache.so >/dev/null 2>&1; then
    { echo "; written by php2shell build-php"; echo "zend_extension=opcache"
      OLD_SCAN_DIR=$(env ${OLD_SCAN:+PHP_INI_SCAN_DIR=$OLD_SCAN} "$OLD_EXE" -i 2>/dev/null | awk -F'=> ' '/^Scan this dir/ {print $2}' | tr -d ' ')
      [ -d "${OLD_SCAN_DIR:-/nonexistent}" ] && grep -hE '^\s*opcache\.' "$OLD_SCAN_DIR"/*.ini 2>/dev/null || true
    } > "$SCAN/10-opcache.ini"
  fi
  say "installed: $("$NEW_PHP" -n -v | head -1)"
fi

# ---- validate (apply and switch)
[ -x "$NEW_FPM" ] || die "$NEW_FPM not found: run --apply first"
say "testing php-fpm config with the new build"
PHP_INI_SCAN_DIR=$SCAN "$NEW_FPM" -t ${FPM_CONF:+-y "$FPM_CONF"} ${PHP_INI:+-c "$PHP_INI"} || die "php-fpm -t failed. If it mentions listen.acl_users, the build lacks --with-fpm-acl"
MISSING=$(compare_modules)
if [ -n "$MISSING" ]; then
  echo "Modules in the running PHP that the new build lacks:"; echo "$MISSING" | sed 's/^/   - /'
  echo "Add them with EXTRA_CONFIGURE=... and --apply again, or build the PECL ones (imagick, redis...) with $PREFIX/bin/phpize"
  echo "and add an ini file for them to $SCAN."
fi
[ $MODE = apply ] && { say "build ready. Next: $0 --switch${MISSING:+ (or --switch --force to ignore missing modules)}"; exit 0; }

# ---- switch
[ -n "$MISSING" ] && [ $FORCE = 0 ] && die "refusing to switch while modules are missing (use --force if they are not needed)"
[ -n "$UNIT" ] && command -v systemctl >/dev/null || die "php-fpm is not a systemd service here; switch manually: start $NEW_FPM -y $FPM_CONF -c $PHP_INI with PHP_INI_SCAN_DIR=$SCAN"
D=/etc/systemd/system/$UNIT.d; mkdir -p "$D"
OTHER=$(ls "$D"/*.conf 2>/dev/null | grep -v "/$DROPIN_NAME$" || true)
[ -n "$OTHER" ] && { echo "NOTE: other drop-ins exist for $UNIT (php2shell's file sorts last and wins for ExecStart):"; echo "$OTHER" | sed 's/^/   /'; }
cat > "$D/$DROPIN_NAME" <<EOF
# Written by php2shell build-php on $(date -u +%F). Remove this file (or run build-php.sh --rollback) to go back.
[Service]
Environment=PHP_INI_SCAN_DIR=$SCAN
ExecStart=
ExecStart=$NEW_FPM --nodaemonize${FPM_CONF:+ -y $FPM_CONF}${PHP_INI:+ -c $PHP_INI}
EOF
echo "drop-in:"; cat "$D/$DROPIN_NAME"
systemctl daemon-reload
say "restarting $UNIT"
ok=1; systemctl restart "$UNIT" || ok=0; sleep 3
PID=$(systemctl show -p MainPID --value "$UNIT"); RUN=$(readlink -f /proc/$PID/exe 2>/dev/null || true)
[ "$RUN" = "$(readlink -f "$NEW_FPM")" ] || ok=0
if [ $ok = 0 ]; then
  echo "switch FAILED (running: ${RUN:-nothing}). Rolling back."; journalctl -u "$UNIT" -n 20 --no-pager || true
  mv "$D/$DROPIN_NAME" "$D/$DROPIN_NAME.failed-$(date +%s)"; systemctl daemon-reload; systemctl restart "$UNIT"
  die "rolled back to $OLD_EXE"
fi
say "php-fpm now runs $RUN ($("$NEW_FPM" -n -v | head -1))"

if [ $WRAPPERS = 1 ]; then
  for w in php composer; do
    T=/usr/local/bin/$w
    if [ -e "$T" ] && ! grep -q php2shell "$T" 2>/dev/null; then echo "skipping $T: exists and was not written by php2shell"; continue; fi
    if [ $w = php ]; then TARGET="$NEW_PHP${PHP_INI:+ -c $PHP_INI}"; else C=$(command -v composer || true); [ -n "$C" ] || continue; TARGET="$NEW_PHP${PHP_INI:+ -c $PHP_INI} $C"; fi
    printf '#!/bin/sh\n# php2shell wrapper\nexport PHP_INI_SCAN_DIR=%s\nexec %s "$@"\n' "$SCAN" "$TARGET" > "$T.php2shell-new"; chmod 755 "$T.php2shell-new"; mv "$T.php2shell-new" "$T"
    echo "wrapper: $T -> $TARGET"
  done
fi
echo
echo "Other services still running the old PHP CLI (queue workers, schedulers) need their own drop-in:"
for u in $(systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'); do
  systemctl show -p ExecStart --value "$u" 2>/dev/null | grep -qE "path=(/usr/bin/php|$OLD_EXE)" && echo "   $u"
done
echo "Check your sites now. To undo: $0 --rollback"
