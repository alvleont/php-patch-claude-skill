# Prompt for chat-only and free AI models

Use this when your AI can't run commands on the server (ChatGPT, Gemini, Claude.ai, Copilot chat, free tiers, or small local models).

1. On the server, run:
   ```bash
   sudo ./php2shell check
   ```
2. Copy **only the SUMMARY block** it prints, from `==== SUMMARY ====` to the end. It is short, so free models can handle it.
   Before pasting, remove anything you consider private, such as hostnames or IPs.
3. Paste it into the chat after this prompt:

---

```text
You are helping me secure a Linux web server against PHP2Shell (CVE-2026-109618, CVE-2026-109619).
Facts:
- Fixed PHP versions: 8.5.12, 8.4.27, 8.3.36, 8.2.35 (and newer). Every older PHP is affected, including 8.1, 7.x and 5.x, which have no official fix.
- No configuration change fully protects. session.upload_progress.enabled=0 is only a partial workaround.
- The PHP that matters is the one php-fpm runs (the php-fpm line), not "php -v".
- If the verdict is COMPROMISED / SUSPECTED: tell me to isolate the server and keep the evidence. Do not tell me to delete files.
- The tool has these commands: "php2shell build-php" (plan), "--apply" (build a fixed PHP), "--switch" (move php-fpm to it), "--rollback";
  "php2shell harden" (plan) and "--apply" (fail2ban + nginx protections; add --no-webshell for WordPress).
- Only suggest defensive steps. Never write exploit code.

Below is the SUMMARY of the check. Explain in simple words:
1. Is my server vulnerable or compromised?
2. What should I do first, second and third? Give me the exact commands.
3. What should I check after each step?

SUMMARY:
<paste here>
```

---

If the model asks about a finding, open the full report (the path is printed at the end of the check) and paste only the lines starting with `!!`.
