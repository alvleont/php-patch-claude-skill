# Web stack review, October 2026

PHP2Shell was not the only problem in October 2026. Attackers who scan for it also hit the rest of a typical PHP web stack. This page lists the advisories that matter for **nginx + PHP-FPM + Laravel + Livewire + Filament** servers. For each one it explains how to check if your server is exposed, how to tell if it was exploited, and how to patch it safely.

It is based on a real review of a production server (Amazon Linux 2023, nginx, PHP-FPM, several Laravel apps, behind Cloudflare) on October 24, 2026. Check the linked advisories before acting: versions keep moving.

> Defensive only. Every command below reads versions, configuration or logs. None of them sends attack traffic.

## Summary

| Component | Advisories | Fixed in | Priority |
|---|---|---|---|
| PHP | PHP2Shell, CVE-2026-109618 / CVE-2026-109619 | 8.5.12, 8.4.27, 8.3.36, 8.2.35 | Critical. See the [README](../README.md) |
| nginx | 26 advisories in 2026, including "NGINX Rift" (CVE-2026-42945), which is exploited in the wild | **1.30.6** (stable) or 1.31.7 (mainline). The 1.28 branch is not fixed | Critical: it faces the internet |
| OpenSSL | Old builds (3.2.x from 2024) miss two years of fixes | Your distro's latest package | High: nginx and PHP use it for TLS |
| Laravel | CVE-2026-114509 (TokenGuard auth bypass), CVE-2026-114508 (relationship inclusion) | 12.68.0 / 13.29.0 and newer | High, if you use the affected feature |
| Livewire | GHSA-mhf7-xp6r-6qrc (`#[Authorize]` bypass), CVE-2026-81887 (XSS), CVE-2025-54068 (RCE, v3) | 4.4.8 / 3.8.3 / 3.6.4 | High |
| Filament | Five advisories from October 2026 (MFA bypass, tenant scope, three XSS) | 5.10.2, 4.15.2, 3.3.57 | Medium |
| Alpine.js | No 2026 advisory found. It ships inside Livewire | Comes with your Livewire update | — |
| Node.js | October 21, 2026 release, 10 CVEs (Brotli RCE, TLS/DNS) | 26.12.1, 24.22.1, 22.23.4 | Low if Node does not listen on a port. Update it in a maintenance window |

## nginx

**Why it matters.** nginx is the first program that touches every request, and Cloudflare does not protect it if your origin IP is public. Version **1.28.0 is affected by 22 of the 26 advisories** published in 2026. The 1.28 branch only got fixes for some of them (1.28.2 / 1.28.3). The lowest stable release that fixes all of them is **1.30.6**.

**Check the version and which risky features you use:**

```bash
nginx -v
sudo nginx -T 2>/dev/null | grep -vE '^\s*#' \
  | grep -oE '^\s*(rewrite|if|set|return|break|map|alias|ssi|slice|dav_methods|mp4|aio|ssl_session_tickets|proxy_pass|grpc_pass|scgi_pass|uwsgi_pass|charset)\b' \
  | sed 's/^\s*//' | sort | uniq -c
sudo nginx -T 2>/dev/null | grep -E 'listen .*quic|http3'           # HTTP/3
sudo nginx -T 2>/dev/null | grep -E 'ssl_session_tickets'            # "off" avoids CVE-2026-97629
```

- **Rewrite module** (`rewrite`, `if`, `set`, `return`, `break`): nearly every config uses `return` or `if`. That is where NGINX Rift (CVE-2026-42945) and CVE-2026-9256 live, so assume you are exposed.
- **`map` with a regex** (`~` inside a `map` block): CVE-2026-42533, rated *major*.
- **`alias` together with `rewrite`**: CVE-2026-15176.
- **HTTP/3, TLS session tickets, SSI, slice, DAV, mp4, AIO**: each has its own advisory. If you don't enable them, those advisories don't apply.

**Signs of exploitation.** These are heap overflows. With ASLR on, a failed attempt usually crashes a worker process:

```bash
sudo zgrep -hE 'exited on signal|segfault|core dumped' /var/log/nginx/error.log*
coredumpctl list nginx 2>/dev/null
sudo journalctl -k | grep -i 'nginx.*segfault'
```

If you find no crashes, there is no sign of exploitation. That is not proof, but it is the best signal the logs give you.

**Patch.** Use your distro package if it carries a fixed version. If it doesn't, use the nginx.org repository.

- **Amazon Linux 2023 is pinned to a release.** Plain `dnf check-update` only shows updates for that release, so an old server can say "nothing to do" while newer packages exist. Look at the latest release:

  ```bash
  dnf check-release-update
  sudo dnf --releasever=latest list --available nginx openssl-libs
  sudo dnf --releasever=latest upgrade nginx --assumeno   # dry run: see what it pulls in
  ```

  At the time of writing, the latest release offered nginx **1.30.5**. It fixes Rift and most other advisories, but not the five fixed in 1.30.6 (CVE-2026-15176, -93479, -95101, -97629, -97205). One of them, CVE-2026-93479, only exists in the 1.30 branch, so check that one against your config. The nginx package also pulls in **OpenSSL 3.5**, so plan both together (see below).

- **After the upgrade, restart nginx.** A reload is not enough, because the binary changed. Run `sudo nginx -t && sudo systemctl restart nginx`.

## OpenSSL

nginx, PHP and sshd load the system `libssl`. On a server pinned to an old Amazon Linux release, OpenSSL can be from 2024 (3.2.2). Within 3.x the ABI is stable, so programs built against 3.2 (including a PHP you built with `build-php`) keep working with 3.5. Even so, it is the riskiest package on the box, because a broken `sshd` locks you out. Follow the safe procedure below.

## Laravel

```bash
composer audit --no-dev                          # in every app
grep -nE "'driver'\s*=>\s*'token'" config/auth.php   # CVE-2026-114509 needs the token guard
grep -rlE 'JsonApiResource' app                  # CVE-2026-114508 needs relationship inclusion
```

- **CVE-2026-114509 (TokenGuard auth bypass, critical):** affects the built-in `token` guard on some MySQL/MariaDB setups. Fixed in 12.68.0 and 13.29.0. Sanctum and session auth don't use that guard.
- **CVE-2026-114508 (data destruction through relationship inclusion, medium):** affects 12.45.0–12.68.0 and 13.x before 13.27.0. It only matters if you expose relationship inclusion (`?include=`) on API resources.
- **Signs of exploitation:** look for `?include=` requests to your API that got HTTP 200. Generic LFI probes like `/view.php?include=/etc/passwd` that got 404 are noise.

Updating inside the same major version (`composer update laravel/framework --with-dependencies`) is low risk. Laravel 12 is fixed in 12.68.0, so you don't need to move to 13 for these advisories.

## Livewire (and Alpine.js)

```bash
grep -A1 '"name": "livewire/livewire"' composer.lock | grep version
grep -rlE '#\[(Authorize|Json)\b' app            # GHSA-mhf7-xp6r-6qrc needs these attributes
```

- **GHSA-mhf7-xp6r-6qrc** (published October 23, 2026, medium): authorization bypass in `#[Authorize]` through reordered parameter keys and the `#[Json]` execution order. It affects 4.3.0 up to, but not including, 4.4.8. It only matters if your components use those attributes.
- **CVE-2026-81887** (XSS during client-side state handling): affects v3 ≤ 3.8.2 and v4 ≤ 4.3.3.
- **CVE-2025-54068** (pre-auth RCE, v3 < 3.6.4): still mass-scanned (`/livewire/update`, `/livewire/upload-file`). `php2shell check` already reports it.
- **Alpine.js** is bundled with Livewire. No 2026 advisory was found for it. Updating Livewire updates Alpine too.

## Filament

```bash
grep -A1 '"name": "filament/filament"' composer.lock | grep version
grep -rnE 'multiFactorAuthentication|EmailAuthentication' app/Providers/Filament/
```

| Advisory | Issue | Fixed in |
|---|---|---|
| GHSA-jpwg-8rw9-v3jj | Email MFA can be bypassed in multi-panel apps with colliding user IDs | 4.15.0, 5.10.0 |
| GHSA-6p72-cx74-63f5 | Resource pages keep access to records after they leave the tenant scope | 4.15.0, 5.10.0 |
| GHSA-q2ph-j76w-c7qx | XSS through client-controlled FileUpload extensions | 3.3.56, 4.15.0, 5.10.0 |
| GHSA-9g92-9qj5-cqjc | XSS in imported RichEditor custom block previews | 4.15.0, 5.10.0 |
| GHSA-9f9v-vm6w-3wx6 | XSS in tenant name tooltips | 3.3.57, 4.15.2, 5.10.2 |

All of them need a logged-in user, so they are less urgent than nginx or PHP. The MFA bypass only applies when Filament's own MFA is enabled in a panel provider. After `composer update 'filament/*'`, run `php artisan filament:upgrade` to republish the assets.

## Node.js

The October 21, 2026 release fixes 10 CVEs. Four are rated high, including a Brotli decoder RCE (CVE-2026-111497). The fixed versions are 26.12.1, 24.22.1 and 22.23.4. Node 20 and older get no fix. Most details so far come from secondary sources, so check nodejs.org.

On a typical Laravel server, Node is only used to build assets or to run headless Chrome (Browsershot, Puppeteer), and it doesn't listen on any port. Check with `sudo ss -tlnp | grep node`. If nothing shows up, update Node in a normal maintenance window.

## Safe procedure for OS package upgrades

Upgrading nginx and OpenSSL on a live server is the riskiest step in this review. Do it like this:

1. **Take a snapshot first.** On EC2 that is an AMI or EBS snapshot. On Lightsail, use the console (instance → *Snapshots* → *Create snapshot*). The Lightsail instance role usually cannot create snapshots itself. To recover, you create a new instance from the snapshot and attach the static IP to it.
2. **Back up the configuration and record the package versions:**
   ```bash
   sudo cp -a /etc/nginx /root/backup-$(date +%Y%m%d)-nginx/
   rpm -qa | grep -E '^(nginx|openssl)' | sort > /root/backup-$(date +%Y%m%d)-nginx/rpm-before.txt
   ```
3. **Take an HTTP baseline** for every site (status code and size), so you can compare afterwards:
   ```bash
   curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' --resolve example.com:443:127.0.0.1 https://example.com/
   ```
4. **Keep your current SSH session open.** After the upgrade, open a *second* SSH session before you close the first one. On Lightsail, the browser-based SSH console is another way back in.
5. Run the upgrade, then `sudo nginx -t`, then `sudo systemctl restart nginx`, then repeat the HTTP baseline.
6. **Rollback:** `sudo dnf history undo last`, restore `/etc/nginx`, restart nginx.
7. **Don't reboot as part of this.** A new kernel waits until the next reboot, which you can do in a maintenance window with the snapshot ready.

## Pitfalls seen while updating Laravel apps

- **A paid dev-only package blocks `composer update`.** If `composer.json` lists a private repository (for example `packages.filamentphp.com` for `filament/blueprint`) and the server has no credentials, every `composer update` fails, even for unrelated packages. Either put the credentials in an `auth.json` outside the repository, or remove the dev-only package and its repository entry when production doesn't need them.
- **`post-update-cmd` calls dev-only packages.** With `--no-dev`, a script like `artisan boost:update` fails. Run `composer update --no-dev --no-scripts`, then run what you need by hand: `composer dump-autoload --optimize`, `php artisan filament:upgrade`, `php artisan view:clear`.
- **`vendor/` can be behind `composer.lock`.** One app had older packages installed than its lock file said. `composer install --dry-run` shows the difference.
- **Reload PHP-FPM after updating** (`sudo systemctl reload php-fpm`), so OPcache serves the new code. Then compare the HTTP baseline and check `storage/logs/` for new errors.
- **`filament:upgrade` resets file modes on published assets** (755 → 644). That fills `git diff` with mode-only changes. Restore them before you commit:
  ```bash
  git diff --summary | awk '/mode change 100755 => 100644/{print $NF}' | xargs -r chmod 755
  ```
- **Static analysis noise.** IDE helper files left in `vendor/` (for example `vendor/_laravel_ide/`) declare model methods as `static`. They can make Mago or PHPStan report thousands of false errors. Leave them out when you compare analysis results before and after an update.

## Known gaps in `php2shell check`

Found during this review. These are planned fixes:

- **The extension warning never shows.** Line 54 of `check.sh` builds a `sed "s/^/…$exe…/"` expression. The binary path contains `/`, so `sed` fails with `unknown option to 's'`, and the "ini loads a missing extension" warning never appears. A different delimiter fixes it.
- **The Cloudflare IP ranges are wrong.** The regex `104\.(1[6-9]|2[0-9]|3[01])` also matches 104.28–104.31, which belong to Cloudflare WARP clients, not proxy edges. It also misses `162.159.0.0/16`. Use the published ranges (`104.16.0.0/13`, `104.24.0.0/14`, `162.158.0.0/15`, …).
- **No Filament check.** Section 6 only checks Livewire. It should also flag Filament 3 < 3.3.57, 4 < 4.15.2 and 5 < 5.10.2.
- **False positives on "HTTP 200 on code-execution attempts".** For pearcmd `config-create` probes, the script could read the target file (for example `/tmp/index1.php`) and check that it exists, or compare the response size with the home page. If the file doesn't exist, the finding should be INFO, not MEDIUM.
- **Stale PHP CLIs.** A vulnerable PHP CLI left on disk (for example the distro `/usr/bin/php` after switching php-fpm to a built PHP) is listed but not flagged. A LOW finding when cron or systemd units still call it would help.
- **No checks for the rest of the stack.** nginx, OpenSSL and Node versions aren't checked yet. A read-only section listing the versions, the risky nginx directives above, and worker crashes in `error.log` would cover this page.

## References

- nginx: [security advisories](https://nginx.org/en/security_advisories.html) · [Beazley on NGINX Rift](https://beazley.security/alerts-advisories/critical-18-year-old-rce-vulnerability-in-nginx-aka-nginx-rift-cve-2026-42945) · [FINRA alert](https://www.finra.org/rules-guidance/guidance/cybersecurity-alert-nginx-critical-vulnerability) · [CSA Singapore AL-2026-150](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-150/) · [Orca on CVE-2026-42533](https://orca.security/resources/blog/cve-2026-42533-nginx-heap-buffer-overflow/)
- PHP2Shell: [Rapid7](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/) · [Unit 42](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/) · [Sansec](https://sansec.io/research/php2shell) · [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- Laravel: [CVE-2026-114509](https://advisories.gitlab.com/composer/laravel/framework/CVE-2026-114509/) · [CVE-2026-114508](https://advisories.gitlab.com/composer/laravel/framework/CVE-2026-114508/)
- Livewire: [GHSA-mhf7-xp6r-6qrc](https://github.com/advisories/GHSA-mhf7-xp6r-6qrc) · [CVE-2026-81887](https://advisories.gitlab.com/composer/livewire/livewire/CVE-2026-81887/) · [Imperva on CVE-2025-54068](https://www.imperva.com/blog/cve-2025-54068-laravel-livewire-credential-theft-campaign-6000-applications-compromised/)
- Filament: [security advisories](https://github.com/filamentphp/filament/security/advisories)
- Alpine.js: [Snyk](https://security.snyk.io/package/npm/alpinejs)
- Node.js: [Astra summary of the October 2026 release](https://www.getastra.com/blog/security-advisory/nodejs-october-2026-security-patches/)
