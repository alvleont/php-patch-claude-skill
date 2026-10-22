# php2shell: check and patch servers for PHP2Shell

Tools to check Linux web servers for **PHP2Shell** (CVE-2026-109618, CVE-2026-109619), look for signs of compromise, and fix them. You can use them in three ways:

| You have | Use |
|---|---|
| No AI, or an old server | `sudo ./php2shell check`: plain bash, no Python needed |
| An AI agent (Claude Code, Codex, Gemini CLI, Cursor, Copilot...) | The skill in `skills/php2shell-review/`, or `AGENTS.md` |
| A chat-only or free AI model | `PROMPT.md`: paste a short summary, get the steps |

> **Defensive tool.** It never sends exploit traffic. `check` is read-only. Commands that change the system show a plan first and only act with `--apply` / `--switch`. Read the plan before you run them.

## What you need to know

- **Every PHP version is affected** except the fixed releases from October 21, 2026: **8.5.12, 8.4.27, 8.3.36, 8.2.35** (and newer).
- **PHP 8.1 and older** (7.x, 5.x) are affected and get **no official release**. Move those apps to PHP 8.2+.
- **No configuration change fully protects you.** Disabling `session.upload_progress` is only partial.
- **Your distro may not have a fixed package yet.** Amazon Linux 2023, for example, still offered only 8.4.10/8.4.14 when this was written. `dnf`/`apt` saying "nothing to do" does not mean you are patched. `build-php` covers that gap.
- **Check the PHP that php-fpm actually runs**, not `php -v`. They can be different binaries, and `check` reads the real one from `/proc`.

## Quick start (no AI)

```bash
git clone https://github.com/alvleont/php-patch-claude-skill.git
cd php-patch-claude-skill
sudo ./php2shell check
```

No git on the server? Download the tarball instead:

```bash
curl -fsSL https://github.com/alvleont/php-patch-claude-skill/archive/refs/heads/main.tar.gz | tar xz
cd php-patch-claude-skill-main && sudo ./php2shell check
```

`check` prints a short **SUMMARY** with a verdict and the next steps, and saves the full report in `/var/log/php2shell/`.

| VERDICT | Meaning |
|---|---|
| `NOT VULNERABLE` | php-fpm runs a fixed PHP, nothing suspicious found |
| `VULNERABLE - no evidence of exploitation found` | Patch now (see below) |
| `COMPROMISED / SUSPECTED` | Webshell or similar found. **Do not delete anything.** Isolate the server and start incident response |
| `INCONCLUSIVE` | No PHP serving web was found on this host (container? another server?) |

### Patch PHP when your distro has no fix

```bash
sudo ./php2shell build-php            # plan only: shows versions, packages, configure flags
sudo ./php2shell build-php --apply    # build the official php.net source (SHA-256 checked) into /opt/php-<version>
sudo ./php2shell build-php --switch   # move php-fpm to the new build, with automatic rollback if it fails
sudo ./php2shell build-php --rollback # go back to the distro php-fpm
```

What `build-php` does for you, based on what went wrong the first time:

- **Leaves the distro packages installed.** Removing the distro php-fpm package would also remove the systemd unit. `build-php` switches with a systemd drop-in instead.
- **Gives the new PHP its own ini scan dir**, so it never loads the old `/etc/php.d` extension files. Those files cause "Unable to load dynamic library" warnings and crashes.
- **Builds with `--with-fpm-acl`**, which pools using `listen.acl_users` need, and **`--with-zlib`**, which Composer needs.
- **Compares PHP modules** between the old and new build, and refuses to switch if any are missing (unless `--force`).
- **Lists other services** (queue workers, schedulers) that still run the old PHP CLI. `--wrappers` also points `/usr/local/bin/php` and `composer` to the new build.

Extra extensions: `EXTRA_CONFIGURE="--with-pgsql --with-ldap" sudo ./php2shell build-php --apply`. PECL extensions (imagick, redis...) need `/opt/php-<version>/bin/phpize`.

### Harden nginx + fail2ban

```bash
sudo ./php2shell harden                                   # plan: tests the filters on your real logs and shows who WOULD be banned
sudo ./php2shell harden --apply --mail-to you@example.com # install (hourly email digest is optional)
```

- **fail2ban jails:**
  - `nginx-webshell`: webshell runs, `?x=id`-style probes, Livewire attack paths, `.env`/`.git` scans.
  - `nginx-upload-flood`: Livewire upload floods.
  - `nginx-404-flood`: path scanners.
- **Bans in iptables and nginx.** Banned IPs are written to `00-blocklist-auto.conf`, so the ban also works for visitors coming through Cloudflare.
- **Cloudflare real IP:** auto-detected. Without it, nginx logs Cloudflare's IPs and you would ban Cloudflare.
- **`php-front-controller-only.conf`:** an nginx snippet that lets only `index.php` run PHP, so uploaded scripts never execute. This is what stopped every webshell attempt in the original incident. Add it to your server blocks by hand; `harden` lists the sites that still pass any `.php` to PHP.
- **WordPress or any site with many `.php` files:** use `--no-webshell`.
- **Default ban time is 1 week.** Use `--bantime -1` for permanent bans.

### Update Livewire (Laravel apps)

Attackers going after PHP2Shell also mass-POST `/livewire/update` and `/livewire/upload-file`. `check` lists every app and its Livewire version. Livewire 3 below 3.6.4 is vulnerable (CVE-2025-54068).

```bash
cd /path/to/app && cp composer.lock composer.lock.bak
composer update livewire/livewire --dry-run   # usually updates only livewire
composer update livewire/livewire && php artisan optimize:clear
sudo systemctl reload php-fpm                 # so opcache serves the new code
```

## With an AI agent

**Claude Code** (plugin):

```
/plugin marketplace add alvleont/php-patch-claude-skill
/plugin install php2shell-review@php2shell
```

Then ask: *"check this server for PHP2Shell"*.

**Other agents** (Codex, Gemini CLI, Cursor, Copilot, OpenCode...):

- Clone the repo on the server and open the agent in it. `AGENTS.md` tells it what to do.
- Or copy `skills/php2shell-review/` into your agent's skills folder, if it supports the `SKILL.md` format.

The skill is written in short, numbered steps, so small and free models can follow it. The script does the hard work and computes the verdict itself.

**Chat-only / free models:** see [PROMPT.md](PROMPT.md).

## What `check` looks at

- **PHP versions:**
  - the php-fpm binary actually running (from `/proc`), mod_php, containers
  - every PHP on disk and the distro packages
  - systemd drop-ins that decide which binary runs
- **Access logs**, including rotated ones:
  - PHP2Shell user agents and upload-progress / session-include requests
  - Livewire attack traffic and pearcmd / path traversal probes
  - code-execution attempts that got HTTP 200
  - top POST sources
- **Signs of compromise:**
  - session files containing PHP code
  - PHP files in `/tmp` written by the web user
  - webshell patterns in the sites
  - PHP code inside uploaded files
  - unexpected processes run by the web user
  - web user crontabs, outbound connections, new `authorized_keys`
- **Configuration:** nginx sites that run any `.php`, missing Cloudflare real-IP, Laravel/Livewire versions.

## Tested on

Amazon Linux 2023 (nginx + php-fpm, Laravel/Filament/Livewire, behind Cloudflare). The scripts also support Debian/Ubuntu (apt) and RHEL-family (dnf/yum), but **they have not been tested there yet**. Please open an issue with the output if something fails.

## Repository layout

```
php2shell                         entry point (check | harden | build-php | help)
skills/php2shell-review/          Agent Skill: SKILL.md, scripts/check.sh, report-template.md
tools/build-php/build-php.sh      build and switch to a fixed PHP from php.net source
tools/harden.sh                   install fail2ban + nginx protections
tools/fail2ban/                   filters, actions, jail template, email digest
tools/nginx/                      front-controller-only snippet, Cloudflare real-IP generator
AGENTS.md / PROMPT.md             instructions for AI agents / chat-only models
.claude-plugin/                   Claude Code plugin + marketplace manifest
```

## References

- [Tenable: php2shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [watchTowr: PHP2Shell FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [JFrog: PHP2Shell, all you need to know](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/)
- Official versions and checksums: https://www.php.net/downloads

## Disclaimer

MIT licensed (see [LICENSE](LICENSE)). Provided as is, without warranty. Run the plan (no `--apply`) first, keep backups, and test on a staging server when you can.
