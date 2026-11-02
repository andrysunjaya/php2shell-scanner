# php2shell-scanner

A single read-only bash script that checks a Linux server for **PHP2Shell**
(CVE-2026-109618 / CVE-2026-109619, unauthenticated RCE in PHP). It then prints a
**remediation plan for that machine**: the upgrade command for its package manager, the
services to restart, a multipart block for its web server (with exceptions if the site
uses uploads), the php.ini or pool files to change, and what to do if it finds signs of
compromise.

```bash
curl -fsSLO https://raw.githubusercontent.com/andrysunjaya/php2shell-scanner/main/check-php2shell.sh
less check-php2shell.sh               # read it first; it runs as root
sudo bash check-php2shell.sh          # report + remediation plan
sudo bash check-php2shell.sh -o plan.md   # also save the plan as Markdown
sudo bash check-php2shell.sh -q       # summary line only (for cron / fleets)
```

Exit code: `0` not affected, `1` affected or restart needed, `2` could not decide.

Requires bash 4.2+, coreutils, grep, awk and sed. curl and ss are used if present.
Tested on CentOS 7, Rocky 9, Debian 10–13, Ubuntu 24.04 and the official Docker `php`
images, with mod_php, PHP-FPM, nginx and Apache 2.4.

## What it checks

| Section | What it tells you |
|---|---|
| PHP binaries | Every PHP binary on the machine (packages, Remi SCL, cPanel EA, Plesk, CloudLinux alt-php, custom builds, running processes), compared to the fixed release, or to a distro **backport** (both CVE ids in the package changelog) |
| Running PHP processes | php-fpm / mod_php workers still running a replaced binary, which need a restart |
| Stopgap mitigations | `session.upload_progress.enabled`, `fatal_error_backtraces` (8.5), any multipart rule in nginx/Apache, and `php_value` / pool / `.htaccess` lines that switch upload_progress back on |
| Upload usage in web roots | Whether the sites use uploads (multipart forms, `$_FILES` handlers, JS `FormData`), so you know what a multipart block would break |
| Live multipart block test | For each vhost: one tiny normal POST and one tiny multipart POST to a path that doesn't exist. Blocked means only the multipart one gets 403 |
| Indicators of compromise | Shells or downloaders under the web stack, `.htaccess` files that make images/JS run as PHP, image files containing PHP code, memory-limit fatal bursts, FPM worker crashes |
| Remediation plan | Markdown steps built from the findings above (see below) |

### Safety

- It changes nothing. The only file it writes is the one you pass to `-o`.
- The live test sends two POSTs per vhost, with the body `x=1`, to
  `/php2shell-check-<pid>.php` on `127.0.0.1`. That's no exploit traffic, and the requests
  show up in your access log as 404s, or 403s once the block is on.
- It reads web roots, but only to look for upload code and backdoors. It skips `vendor/`,
  `node_modules/`, `.git/` and cache folders.

## The remediation plan

The plan only contains steps that apply to the machine it ran on. For example:

- **Upgrade:** `dnf upgrade 'php*'`, `yum update 'php82-php*'` (Remi SCL), `apt install
  --only-upgrade 'php8.3*'`, `/scripts/upcp` (cPanel), or "rebuild on `php:8.3.36-fpm`" for a
  Docker image. It also prints the changelog command that confirms a backport. Webtatic
  (`php7xw`) and other branches that get no fix are flagged as needing a migration.
- **Restart:** a full `systemctl restart httpd|apache2` for mod_php (a graceful reload keeps
  the old library loaded), each running php-fpm unit, and `kill <pid>` for CLI daemons
  started from cron. Inside a container, it says to restart the container instead.
- **Multipart block:** the nginx snippet and the files it goes in. For Apache 2.4 it gives a
  `conf.d` file, and for Apache 2.2 per-vhost RewriteRules. If the site uses uploads, it
  lists the upload handlers it found and gives a template that keeps those URLs open
  (behind Basic Auth on Apache). Both templates were tested: the upload URL gets through,
  and everything else, including look-alike paths, gets 403.
- **PHP settings:** the exact php.ini / drop-in / pool files with `sed` lines, and any
  overrides to remove.
- **Compromise:** what it found, and the order to handle it in (evidence, logs, removal,
  secrets, persistence, rebuild).
- **Verify:** re-run the script, plus a curl line per vhost.

Read every command before you run it. The plan is a starting point written by a script,
not a change ticket.

## PHP2Shell in short

| Branch | Fixed in |
|---|---|
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** (security support ends 2026-12-31) |
| 7.4, 8.0, 8.1 | no upstream release. php.net published source-only backports. Packaged fixes exist from some vendors, e.g. Remi's EL9 7.4 module, RHEL/Rocky 9 AppStream 8.0.30, AlmaLinux and TuxCare |
| 7.3 and older (incl. Webtatic `php72w`) | **no fix**: upgrade, or use the stopgap |

A distro package can keep an old version string and still include the fix. The script
recognizes this from the package changelog.

- **Attack:** a crafted `multipart/form-data` request that hits a memory limit, against
  **any** PHP script. PHP parses the body before your code runs, so a site with no upload
  feature is still vulnerable. CVE-2026-109619 can also be reached without multipart,
  through the application's own `session_start()` / `unserialize()`.
- **Stopgap (partial):**
  - Block multipart requests at the web server.
  - Set `session.upload_progress.enabled = 0` in php.ini, an FPM pool or the Apache config
    (`ini_set()` and `.user.ini` are too late).
  - On PHP 8.5, also set `fatal_error_backtraces = Off`.
  - Optionally set `pm.max_requests = 1`.
  - Some advisories also suggest `memory_limit = -1`, but then one request can use all the
    RAM.
- **The block only covers traffic that goes through the web server.** php-fpm on a public
  TCP port, a backend container reachable from a compromised neighbour, or a vhost
  without the rule all go around it. The script flags php-fpm listening on the network.
- One report (Abstract Security, 2026-10-22) claims RCE on a patched 8.2.35. It was
  unconfirmed when this was written. Re-check the advisories before you remove the stopgap.

## Notes from real cleanups

- **Old webshells move with the site.** When a site is copied to a new server, backdoors
  from years ago come along. A common kit uses an `.htaccess` such as
  `<Files "white.jpg"> AddType application/x-httpd-php .jpg </Files>`, which makes one
  "image" run as PHP. It also fakes the file's mtime to match the files next to it. Check
  the **ctime** (`stat`): it can't be faked without root, and it shows when the file really
  arrived.
- If you find one, run the script on **every server copied from the same source**. The same
  files tend to turn up across them.
- Root cron jobs that run PHP files owned by the web user let the web user become root.
  Give that code to root.

## Sources

- php.net advisory: https://www.php.net/archive/2026.php#2026-10-21-5
- watchTowr FAQ: https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
- Sansec: https://sansec.io/research/php2shell
- PatchMon: https://patchmon.net/blog/php2shell-cve-2026-109618-cve-2026-109619-php-rce-patch
- SecurityWeek: https://www.securityweek.com/php2shell-mass-exploitation-looms-for-leaked-critical-php-flaws/

MIT License (see `LICENSE`). No warranty. Run it on machines you're responsible for.
