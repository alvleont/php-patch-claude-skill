# PHP2Shell review – <hostname>

- **Date (UTC):** <yyyy-mm-dd hh:mm>
- **Reviewed by:** <agent / person>
- **VERDICT:** <copy the VERDICT line from the check>
- **Full report:** <path printed by "php2shell check">

## 1. PHP that serves the websites

| Process | Binary (from /proc) | Version | FIXED / VULNERABLE |
|---|---|---|---|
| php-fpm | | | |

Other PHP on the server (CLI, distro packages):

Could the old PHP come back? (distro package still installed, systemd drop-ins):

## 2. Attacks seen in the logs

| Source IP | Requests | Technique (PHP2Shell, Livewire, pearcmd...) | Succeeded? |
|---|---|---|---|

PHP2Shell probes before the server was patched (IP, time, status):

## 3. Signs of compromise

| Check | Result |
|---|---|
| Webshell patterns in the sites | |
| PHP code in session or upload files | |
| Unexpected processes run by the web user | |
| Crontab for the web user | |

## 4. Laravel / Livewire apps

| App | Livewire | Status |
|---|---|---|

## 5. Recommendations (most urgent first)

1.

## 6. Changes made (only the ones the user approved)

| Change | How to undo it |
|---|---|
