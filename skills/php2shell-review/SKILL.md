---
name: php2shell-review
description: Check a Linux web server for PHP2Shell (CVE-2026-109618, CVE-2026-109619), look for signs of compromise, and help patch it. Use when asked to check a server for PHP2Shell, audit PHP/php-fpm after the October 2026 PHP advisories, or investigate a suspected PHP attack. Defensive only.
---

# PHP2Shell review

Follow the steps in order. Do not skip step 1.

## Rules

- **Defensive only.** Never write, send or test exploit payloads, not even against localhost.
- **Read-only until the user says yes.** Steps 1 to 3 change nothing. Before any change in step 4, show the command and wait for the user's OK.
- **If you find signs of compromise, stop.** Do not delete files. Tell the user to isolate the server and keep the evidence.

## Facts

- **Every PHP version is affected** except these fixed releases (Oct 21 2026): **8.5.12, 8.4.27, 8.3.36, 8.2.35** and newer.
- PHP 8.1 and older (including 7.x and 5.x) are affected and get **no official fix**. Move those apps to PHP 8.2+.
- **No configuration change fully protects you.** `session.upload_progress.enabled = 0` is only a partial workaround.
- Many distros (Amazon Linux included) shipped no fixed package yet. `dnf`/`apt` saying "nothing to do" does NOT mean patched.
- Attackers also try Livewire RCE (`/livewire/update`, `/livewire/upload-file`). Livewire 3 below **3.6.4** is vulnerable (CVE-2025-54068).

## Step 1: run the check

The tools live in the repository that contains this skill. `REPO` is two folders up from this SKILL.md file (`skills/php2shell-review/` → repo root). If you only have this folder, `scripts/check.sh` is next to this file.

```bash
sudo bash "$REPO/php2shell" check        # or: sudo bash scripts/check.sh
```

It prints a **SUMMARY** block: `VERDICT`, `FINDINGS` and `NEXT STEPS`. Read it.

## Step 2: understand the verdict

| VERDICT | Meaning | What to do |
|---|---|---|
| NOT VULNERABLE | php-fpm runs a fixed PHP and nothing suspicious was found | Step 4 is optional (hardening) |
| NOT VULNERABLE (partial check) | Same, but run without root | Run again with sudo |
| VULNERABLE - no evidence of exploitation found | Web PHP is old, no traces of attack success | Patch now (step 4) |
| COMPROMISED / SUSPECTED | Webshell, PHP code in session/upload files, odd processes run by the web user | **Stop.** Report it. No cleanup |
| INCONCLUSIVE | No PHP serving web was found | Ask the user how PHP runs (container, other host) |

## Step 3: check the findings

The full report has a line starting with `!!` for each finding. For each one:

- **[CRITICAL]**: open the file it names, then show the user its owner, date and the first lines. Never run it.
- **[HIGH] php-fpm ... vulnerable**: this is the PHP that serves the sites. Patch it.
- **[MEDIUM] code-execution attempts got HTTP 200**: look at those log lines. Laravel often answers 200 with its normal page, which is harmless. It is only bad if a file the attack dropped exists or a process started.
- **[INFO] Cloudflare**: do not ban IPs until the real client IP is restored (`harden` does it).

Important: the PHP that matters is the **php-fpm line** (taken from `/proc`). `php -v` on the command line can be a different PHP.

## Step 4: fix (ask the user before each command)

1. **Patch PHP.** First try the distro packages (`dnf update 'php*'` / `apt-get install --only-upgrade 'php*'`). If no fixed version is offered:
   ```bash
   sudo bash "$REPO/php2shell" build-php            # plan, changes nothing
   sudo bash "$REPO/php2shell" build-php --apply    # build into /opt/php-<version>
   sudo bash "$REPO/php2shell" build-php --switch   # move php-fpm to it (auto-rollback on failure)
   ```
   Do NOT remove the distro php-fpm package. It owns the systemd unit.
2. **Update Livewire** in every Laravel app the check lists as vulnerable:
   `cp composer.lock composer.lock.bak && composer update livewire/livewire`, then `sudo systemctl reload php-fpm`, then check that the site opens.
3. **Harden nginx + fail2ban:**
   ```bash
   sudo bash "$REPO/php2shell" harden            # plan: shows who would be banned
   sudo bash "$REPO/php2shell" harden --apply
   ```
   Use `--no-webshell` for WordPress sites.
4. Run step 1 again and confirm the php-fpm line says **FIXED**.

## Step 5: report

Fill in `report-template.md` (next to this file). Start with the VERDICT line from the check.
List every change you made and how to undo it.
