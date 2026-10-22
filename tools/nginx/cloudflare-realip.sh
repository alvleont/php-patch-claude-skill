#!/usr/bin/env bash
# Writes an nginx config that restores the real visitor IP behind Cloudflare.
# Without it, nginx logs (and fail2ban bans) Cloudflare's IPs instead of the attacker's.
# Usage: cloudflare-realip.sh [output-file]   (default: print to stdout)
# Trusts CF-Connecting-IP only from Cloudflare's published ranges.
set -eu
OUT="${1:-/dev/stdout}"
fetch() { curl -fsS --max-time 20 "$1" 2>/dev/null || wget -qO- --timeout=20 "$1"; }

V4=$(fetch https://www.cloudflare.com/ips-v4) || { echo "could not download Cloudflare IPv4 list" >&2; exit 1; }
V6=$(fetch https://www.cloudflare.com/ips-v6) || { echo "could not download Cloudflare IPv6 list" >&2; exit 1; }
# Sanity check: every line must look like a CIDR, and there must be a reasonable number of them
ALL=$(printf '%s\n%s\n' "$V4" "$V6" | grep -E '^[0-9a-fA-F:.]+/[0-9]+$')
[ "$(echo "$ALL" | wc -l)" -ge 10 ] || { echo "Cloudflare list looks wrong; not writing" >&2; exit 1; }

{
  echo "# Real visitor IP behind Cloudflare. Generated $(date -u +%F) from cloudflare.com/ips-v4 and /ips-v6."
  echo "$ALL" | sed 's/^/set_real_ip_from /; s/$/;/'
  echo "real_ip_header CF-Connecting-IP;"
} > "$OUT"
