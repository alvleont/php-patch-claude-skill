# Instructions for AI agents

This repository checks Linux web servers for PHP2Shell (CVE-2026-109618, CVE-2026-109619) and helps patch them.

When the user asks you to check or patch a server, follow **`skills/php2shell-review/SKILL.md`** step by step.

In short:

1. Run `sudo bash ./php2shell check` and read the SUMMARY block it prints.
2. Explain the VERDICT and each finding to the user.
3. Before any change (`build-php --apply/--switch`, `harden --apply`, `composer update`), show the command and wait for the user's OK.
4. Defensive only: never write or send exploit payloads.
5. If the verdict is COMPROMISED / SUSPECTED, stop. Do not delete anything. Tell the user to isolate the server.

For the rest of the web stack (nginx, OpenSSL, Laravel, Livewire, Filament, Node.js), use `docs/stack-review-2026-10.md`. Its commands are read-only too. Package upgrades still need the user's OK, and a snapshot comes first.

When you change anything in this repository:

- Never commit to `main`. It is protected and a direct push is rejected. Create a branch from `origin/main` and open a pull request.
- Keep them plain bash with standard GNU tools (no Python, no jq). They must run on old servers.
- `check.sh` must stay read-only.
- Any script that changes the system must default to a plan or dry run, back files up, and roll back on failure.
- Test with `bash -n` and run the read-only commands (`php2shell check`, `harden` without `--apply`, `build-php` without options) on a real server.
