#!/usr/bin/env bash
# check-php2shell.sh - check this machine for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
# and print a remediation plan built from what it found.
#
# Read-only and passive. It sends no exploit traffic and changes nothing. It checks:
#   1. every PHP binary it can find, and its version against the fixed releases
#   2. distro backports (package changelog mentions both CVE ids)
#   3. running php-fpm / mod_php processes still holding the old binary (need restart)
#   4. the stopgap mitigations (upload_progress, fatal_error_backtraces, multipart block),
#      whether the web roots use uploads, and a live test that the block works
#   5. a few cheap indicators of compromise
# Then it prints a remediation plan (Markdown) for the issues it found.
#
# Usage:   sudo ./check-php2shell.sh [-q] [-o FILE]
#            -q       summary only (no report, no plan on screen)
#            -o FILE  also write the remediation plan to FILE
# Exit:    0 = not affected (or no PHP), 1 = affected / restart needed, 2 = could not decide
#
# Fixed upstream (php.net, 2026-10-21): 8.5.12, 8.4.27, 8.3.36, 8.2.35.
# 8.1 and older get no upstream release; only a distro/vendor backport fixes them.

FIXED_85="8.5.12"
FIXED_84="8.4.27"
FIXED_83="8.3.36"
FIXED_82="8.2.35"
CVE_RE='CVE-2026-10961[89]'

QUIET=0; OUT=""
while getopts "qo:h" opt; do
    case "$opt" in
        q) QUIET=1 ;;
        o) OUT=$OPTARG ;;
        *) echo "usage: $0 [-q] [-o FILE]"; exit 3 ;;
    esac
done

if [ -t 1 ]; then
    RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLD=$'\e[1m'; RST=$'\e[0m'
else
    RED=""; GRN=""; YLW=""; BLD=""; RST=""
fi

VULN=0      # count of vulnerable binaries / stale processes
UNKNOWN=0   # count of things we could not decide
FOUND=0     # count of PHP binaries found
IOC=0       # count of indicator-of-compromise findings

# findings the remediation plan is built from
VULN_BINS=()     # "bin|version|branch|pkg|fixed"
STALE=()         # "pid|name|systemd unit"
OPEN_URLS=()     # vhosts where the live test got through
UPLOAD_CODE=""   # files handling $_FILES
UP_ON=()         # PHP binaries with upload_progress on
FEB_ON=()        # PHP 8.5 binaries with fatal_error_backtraces on
OVERRIDES=""     # php_value / pool lines turning upload_progress back on
IOC_LINES=()
MODPHP=0; APACHE_SVC=""
RULE_PRESENT=0; LOCAL_EXEMPT=0

say()  { [ "$QUIET" -eq 0 ] && echo "$@"; }
hdr()  { say ""; say "${BLD}== $* ==${RST}"; }
ok()   { say "  ${GRN}[OK]${RST}   $*"; }
bad()  { echo "  ${RED}[VULN]${RST} $*"; }
warn() { say "  ${YLW}[WARN]${RST} $*"; }
info() { say "  [..]   $*"; }

# ver_ge A B -> true if A >= B
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]; }

[ "$(id -u)" -ne 0 ] && warn "not running as root; process and config checks may be incomplete"

# OS and environment, used for the commands in the plan
ID=""; ID_LIKE=""; VERSION_ID=""
[ -r /etc/os-release ] && . <(grep -E '^(ID|ID_LIKE|VERSION_ID)=' /etc/os-release)
IN_CONTAINER=0
{ [ -f /.dockerenv ] || [ -f /run/.containerenv ] || grep -qE 'docker|kubepods|libpod' /proc/1/cgroup 2>/dev/null; } && IN_CONTAINER=1
if   command -v dnf >/dev/null 2>&1; then PM=dnf
elif command -v yum >/dev/null 2>&1; then PM=yum
elif command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v apk >/dev/null 2>&1; then PM=apk
else PM=""
fi

echo "${BLD}PHP2Shell check on $(hostname) - $(date '+%F %T')${RST}"

# ---------------------------------------------------------------- 1. find PHP
hdr "PHP binaries"

declare -A SEEN
BINS=()
add_bin() {
    local b real
    for b in "$@"; do
        [ -x "$b" ] && [ -f "$b" ] || continue
        real=$(readlink -f "$b")
        [ -n "${SEEN[$real]}" ] && continue
        SEEN[$real]=1
        BINS+=("$real")
    done
}

add_bin $(command -v php php-cgi php-fpm 2>/dev/null)
add_bin /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm* \
        /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
        /opt/rh/*php*/root/usr/bin/php /opt/rh/*php*/root/usr/sbin/php-fpm \
        /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
        /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm \
        /opt/alt/php*/usr/bin/php /usr/local/php*/bin/php /usr/local/php*/sbin/php-fpm
# binaries of running processes too (catches custom builds in odd places)
for exe in /proc/[0-9]*/exe; do
    t=$(readlink "$exe" 2>/dev/null) || continue
    case "$t" in *php*) add_bin "${t% (deleted)}" ;; esac
done

# only keep real PHP executables (skip phpize, php-config, phpdbg wrappers etc.)
PHP_BINS=()
for b in "${BINS[@]}"; do
    case "$(basename "$b")" in
        phpize*|php-config*|phar*|phpdbg*) continue ;;   # phpdbg -v opens an interactive prompt
    esac
    "$b" -v </dev/null 2>/dev/null | grep -q '^PHP [0-9]' && PHP_BINS+=("$b")
done

if [ "${#PHP_BINS[@]}" -eq 0 ]; then
    ok "no PHP binary found on this machine"
fi

# owning package of a file -> "pkgname" ("" if none)
owner_pkg() {
    if command -v rpm >/dev/null 2>&1 && rpm -qf "$1" >/dev/null 2>&1; then
        rpm -qf --qf '%{NAME}\n' "$1" | head -n1
    elif command -v dpkg >/dev/null 2>&1; then
        dpkg -S "$1" 2>/dev/null | head -n1 | cut -d: -f1
    elif command -v apk >/dev/null 2>&1; then
        apk info -W "$1" 2>/dev/null | awk '{print $NF}' | head -n1
    fi
}

# does the package changelog list both CVE ids? (distro backport)
has_backport() {
    local pkg=$1 log=""
    [ -z "$pkg" ] && return 1
    if command -v rpm >/dev/null 2>&1 && rpm -q "$pkg" >/dev/null 2>&1; then
        log=$(rpm -q --changelog "$pkg" 2>/dev/null)
    elif command -v dpkg >/dev/null 2>&1; then
        local f
        for f in /usr/share/doc/"$pkg"/changelog.Debian.gz /usr/share/doc/"${pkg%%-*}"*/changelog.Debian.gz; do
            [ -f "$f" ] && log+=$(zcat "$f" 2>/dev/null)
        done
    fi
    [ "$(grep -oE "$CVE_RE" <<<"$log" | sort -u | wc -l)" -ge 2 ]
}

for b in "${PHP_BINS[@]}"; do
    FOUND=$((FOUND + 1))
    ver=$("$b" -v </dev/null 2>/dev/null | sed -nE '1s/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
    branch=${ver%.*}
    pkg=$(owner_pkg "$b")
    label="$b (PHP $ver${pkg:+, pkg $pkg})"

    case "$branch" in
        8.5) fixed=$FIXED_85 ;;
        8.4) fixed=$FIXED_84 ;;
        8.3) fixed=$FIXED_83 ;;
        8.2) fixed=$FIXED_82 ;;
        "")  warn "$b: could not read version"; UNKNOWN=$((UNKNOWN + 1)); continue ;;
        *)   fixed="" ;;
    esac

    if [ -n "$fixed" ] && ver_ge "$ver" "$fixed"; then
        ok "$label >= $fixed"
    elif has_backport "$pkg"; then
        ok "$label: below upstream fix, but package changelog lists both CVEs (backport)"
    elif [ -n "$fixed" ]; then
        bad "$label: fixed in $fixed"
        VULN=$((VULN + 1)); VULN_BINS+=("$b|$ver|$branch|$pkg|$fixed")
    elif ver_ge "$ver" "5.4.0"; then
        bad "$label: branch $branch has no upstream fix; needs vendor backport or upgrade to >= 8.2"
        VULN=$((VULN + 1)); VULN_BINS+=("$b|$ver|$branch|$pkg|")
    else
        warn "$label: older than 5.4.0 (reported range starts at 5.4.0) - but EOL, upgrade anyway"
        UNKNOWN=$((UNKNOWN + 1))
    fi
done

# --------------------------------------------- 2. running processes (restart)
hdr "Running PHP processes (old code still loaded?)"

unit_of() { sed -nE 's#.*/([^/]+\.service).*#\1#p' "/proc/$1/cgroup" 2>/dev/null | head -n1; }

stale=0; running=0
for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    name=$(basename "${exe% (deleted)}")
    case "$name" in
        php*)
            running=$((running + 1))
            if [[ "$exe" == *"(deleted)" ]]; then
                bad "pid $pid ($name) runs a binary replaced on disk - restart the service"
                stale=$((stale + 1)); STALE+=("$pid|$name|$(unit_of "$pid")")
            fi ;;
        httpd|apache2)
            # mod_php: look for a replaced libphp in the process maps
            if grep -qE 'libphp[^ ]*\.so' "$p/maps" 2>/dev/null; then
                running=$((running + 1)); MODPHP=1; APACHE_SVC=$name
                if grep -E 'libphp[^ ]*\.so' "$p/maps" | grep -q '(deleted)'; then
                    bad "pid $pid ($name) has a replaced libphp loaded - restart the service"
                    stale=$((stale + 1)); STALE+=("$pid|$name|$(unit_of "$pid")")
                fi
            fi ;;
    esac
done
if [ "$running" -eq 0 ]; then
    info "no running php-fpm / php-cgi / mod_php processes"
elif [ "$stale" -eq 0 ]; then
    ok "$running PHP process(es) running, none on a replaced binary"
fi
VULN=$((VULN + stale))

FPM_UNITS=$(systemctl list-units --type=service --state=running --plain --no-legend 2>/dev/null \
            | awk '{print $1}' | grep -iE 'php.*fpm|fpm.*php')
# php-fpm reachable over the network bypasses any web server block
FPM_TCP=$(ss -ltnp 2>/dev/null | awk '/php-fpm/ && $4 !~ /^(127\.|\[::1\]|\[::ffff:127\.)/ {print $4}' | sort -u)

# effective web server config: used for vhost names, web roots and the plan
webconf() {
    if command -v nginx >/dev/null 2>&1 && nginx -T >/dev/null 2>&1; then
        nginx -T 2>/dev/null
    else
        cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null
    fi
    cat /etc/httpd/conf/*.conf /etc/httpd/conf.d/*.conf /etc/httpd/conf.modules.d/*.conf \
        /etc/apache2/apache2.conf /etc/apache2/sites-enabled/* /etc/apache2/mods-enabled/*.load \
        /usr/local/apache/conf/httpd.conf /usr/local/apache/conf/extra/*.conf 2>/dev/null
}
WEBCONF=$(webconf)
NAMES=$(sed -nE 's/^[[:space:]]*(server_name|ServerName|ServerAlias)[[:space:]]+([^;#]+).*/\2/Ip' <<<"$WEBCONF" \
        | tr ' \t' '\n\n' | sed 's/:.*//' | grep -vE '^$|^_$|[*~$]' | sort -u)
# root/DocumentRoot, Apache "Alias /url /dir" and nginx "alias /dir;"
ROOTS=$(sed -nE -e 's/^[[:space:]]*(root|DocumentRoot)[[:space:]]+"?([^";# ]+).*/\2/Ip' \
                -e 's/^[[:space:]]*Alias[[:space:]]+[^[:space:]]+[[:space:]]+"?([^";# ]+).*/\1/p' \
                -e 's/^[[:space:]]*alias[[:space:]]+"?([^";# ]+);.*/\1/p' <<<"$WEBCONF" \
        | grep -v '\$' | sed 's:/*$::' | grep -vE '^/usr/share/(httpd|apache2)/(icons|error)')
# web roots to scan, skipping a root nested in one already listed (sort puts parents first)
SCAN_ROOTS=""
for r in $( { echo "$ROOTS"; ls -d /var/www /usr/share/nginx/html /home/*/public_html 2>/dev/null; } | sort -u); do
    [ -d "$r" ] || continue
    nested=0
    for s in $SCAN_ROOTS; do case "$r/" in "$s"/*) nested=1 ;; esac; done
    [ "$nested" -eq 0 ] && SCAN_ROOTS+=" $r"
done
grep -qiE '^[[:space:]]*LoadModule[[:space:]]+php' <<<"$WEBCONF" && MODPHP=1
if [ -z "$APACHE_SVC" ]; then
    if   command -v httpd >/dev/null 2>&1 || [ -d /etc/httpd ]; then APACHE_SVC=httpd
    elif command -v apache2 >/dev/null 2>&1 || [ -d /etc/apache2 ]; then APACHE_SVC=apache2
    fi
fi
HAS_NGINX=0; { command -v nginx >/dev/null 2>&1 || pgrep -x nginx >/dev/null; } && HAS_NGINX=1
HAS_APACHE=0
{ command -v httpd >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1 || pgrep -x 'httpd|apache2' >/dev/null; } && HAS_APACHE=1
# nginx config files that hand requests to PHP or a backend
NGINX_FILES=$(nginx -T 2>/dev/null | awk '/^# configuration file /{f=$4; sub(/:$/,"",f); next}
              { sub(/#.*/, "") } /(^|[;{[:space:]])(fastcgi_pass|proxy_pass)[[:space:]]/{print f}' | sort -u)

# ------------------------------------------------------------ 3. mitigations
hdr "Stopgap mitigations (do not replace patching)"

for b in "${PHP_BINS[@]}"; do
    case "$(basename "$b")" in php-fpm*|php-cgi*) continue ;; esac   # read ini via the CLI binary
    vals=$("$b" -r 'echo ini_get("session.upload_progress.enabled"),"|",ini_get("memory_limit"),"|",var_export(ini_get("fatal_error_backtraces"),true);' </dev/null 2>/dev/null) || continue
    up=${vals%%|*}; rest=${vals#*|}; ml=${rest%%|*}; feb=${rest#*|}
    if [ -z "$up" ] || [ "$up" = "0" ] || [ "$up" = "Off" ]; then
        ok "$b: session.upload_progress.enabled is off"
    else
        info "$b: session.upload_progress.enabled is on (CLI ini; FPM pools and mod_php may differ)"
        UP_ON+=("$b")
    fi
    [ "$ml" = "-1" ] && info "$b: memory_limit = -1"
    # fatal_error_backtraces exists from PHP 8.5; false = setting unknown
    case "$feb" in
        false|"'0'"|"''"|"'Off'"|"'off'") ;;
        *) info "$b: fatal_error_backtraces is on (only matters while unpatched)"; FEB_ON+=("$b") ;;
    esac
done

pools=$(grep -rlE 'upload_progress\.enabled\]?\s*=\s*(0|off)' /etc/php* /etc/opt/remi /opt/remi/*/root/etc \
        /opt/cpanel/ea-php*/root/etc /usr/local/etc 2>/dev/null | head -n5)
[ -n "$pools" ] && ok "upload_progress disabled in: $(tr '\n' ' ' <<<"$pools")"

# settings that turn upload_progress back on (Apache php_value/php_flag, .htaccess, FPM pools)
OVERRIDES=$( {
    grep -rniE '^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]+session\.upload_progress\.enabled[[:space:]]+(1|on)' \
        /etc/httpd /etc/apache2 /usr/local/apache/conf 2>/dev/null
    grep -rniE '^[[:space:]]*php_(admin_)?(value|flag)\[session\.upload_progress\.enabled\][[:space:]]*=[[:space:]]*(1|on)' \
        /etc/php* /etc/opt/remi /opt/remi/*/root/etc /usr/local/etc 2>/dev/null
    for r in $SCAN_ROOTS; do
        find "$r" -name .htaccess -exec grep -HniE '^[[:space:]]*php_(value|flag)[[:space:]]+session\.upload_progress\.enabled[[:space:]]+(1|on)' {} + 2>/dev/null
    done; } | head -n10)
if [ -n "$OVERRIDES" ]; then
    warn "upload_progress is switched back on here (these win over php.ini):"
    say "$(sed 's/^/           /' <<<"$OVERRIDES")"
fi

# block rule in web server config (commented-out lines ignored)
rules=$(grep -rniE 'multipart' /etc/nginx /etc/httpd /etc/apache2 /usr/local/apache/conf 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#')
if [ -n "$rules" ]; then
    RULE_PRESENT=1
    grep -qE '127\.0\.0\.1|::1|-R ' <<<"$rules" && LOCAL_EXEMPT=1
    ok "multipart rule(s) in web server config (live test below confirms):"
    say "$(head -n10 <<<"$rules" | sed 's/^/           /')"
else
    info "no multipart block rule found in nginx/apache config"
fi

# ------------------------------------------- 3b. does the site use uploads?
hdr "Upload usage in web roots (would a multipart block break anything?)"

FORM_RE='enctype[[:space:]]*=[[:space:]]*.?multipart/form-data|type[[:space:]]*=[[:space:]]*.?file\b'
CODE_RE='\$_FILES|move_uploaded_file|is_uploaded_file|getUploadedFiles|getClientOriginalName'
JS_RE='new FormData\('
INC=(--include='*.php' --include='*.phtml' --include='*.inc' --include='*.html' --include='*.htm'
     --include='*.tpl' --include='*.twig' --include='*.js' --include='*.vue' --include='*.jsx' --include='*.tsx')
EXCL=(--exclude-dir=vendor --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=cache)

# list up to 3 matching files, indented
show() { [ -n "$1" ] && say "$(head -n3 <<<"$1" | sed 's/^/             /')"; }

uploads=0
for r in $SCAN_ROOTS; do
    forms=$(grep -rIliE "$FORM_RE" "${INC[@]}" "${EXCL[@]}" "$r" 2>/dev/null)
    code=$(grep -rIlE "$CODE_RE" "${INC[@]}" "${EXCL[@]}" "$r" 2>/dev/null)
    js=$(grep -rIlE "$JS_RE" "${INC[@]}" "${EXCL[@]}" "$r" 2>/dev/null)
    nf=$(grep -c . <<<"$forms"); nc=$(grep -c . <<<"$code"); nj=$(grep -c . <<<"$js")

    if [ $((nf + nc + nj)) -eq 0 ]; then
        ok "$r: no upload forms, upload handlers or FormData posts"
        continue
    fi
    uploads=$((uploads + 1))
    [ -n "$code" ] && UPLOAD_CODE+="$code"$'\n'
    warn "$r: uses uploads - a multipart block will break these"
    [ "$nf" -gt 0 ] && { say "           $nf file(s) with multipart/file-input forms:"; show "$forms"; }
    [ "$nc" -gt 0 ] && { say "           $nc PHP file(s) handling \$_FILES:"; show "$code"; }
    [ "$nj" -gt 0 ] && { say "           $nj JS file(s) posting FormData (sent as multipart):"; show "$js"; }
done
if [ -z "$SCAN_ROOTS" ]; then
    info "no web roots found"
elif [ "$uploads" -eq 0 ]; then
    ok "no upload usage found - blocking multipart/form-data should be safe (still test the site)"
fi

# --------------------------------------------- 3c. is the block really on?
hdr "Live multipart block test (harmless POST to this machine)"

# Sends a tiny form (x=1) twice per vhost to a non-existent path: once as a
# normal POST, once as multipart. Blocked = multipart gets 403, normal does not.
tested=0
if ! command -v curl >/dev/null 2>&1; then
    info "curl not found - skipped"
else
    ports=$(ss -ltnp 2>/dev/null | awk '/nginx|httpd|apache2|litespeed|lsws/ {n=split($4,a,":"); print a[n]}' | sort -un)
    [ -z "$ports" ] && pgrep -x 'nginx|httpd|apache2' >/dev/null && ports="80 443"
    if [ -z "$ports" ]; then
        info "no web server listening - skipped"
    else
        for host in localhost $NAMES; do
            for port in $ports; do
                for scheme in https http; do
                    url="$scheme://$host:$port/php2shell-check-$$.php"
                    c=(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 --resolve "$host:$port:127.0.0.1")
                    plain=$("${c[@]}" -d x=1 "$url")
                    [ "$plain" = "000" ] && continue      # wrong scheme for this port
                    multi=$("${c[@]}" -F x=1 "$url")
                    tested=$((tested + 1))
                    if [ "$multi" = "403" ] && [ "$plain" != "403" ]; then
                        ok "$scheme://$host:$port blocked (multipart 403, normal POST $plain)"
                    elif [ "$multi" = "$plain" ] && [ "$plain" = "403" ]; then
                        info "$scheme://$host:$port returns 403 for every POST - can't tell"
                    elif [ "$multi" = "$plain" ] && [[ "$plain" == 30? ]]; then
                        info "$scheme://$host:$port redirects every POST ($plain) - PHP not reached here"
                    elif [ "$VULN" -eq 0 ]; then
                        info "$scheme://$host:$port not blocked (fine: PHP here is patched)"
                    else
                        warn "$scheme://$host:$port NOT blocked (multipart $multi, normal POST $plain)"
                        OPEN_URLS+=("$scheme://$host:$port")
                    fi
                    break
                done
            done
        done
        [ "$tested" -eq 0 ] && info "web server on port(s) $(echo $ports) did not answer - skipped"
        [ "$tested" -gt 0 ] && [ "${#OPEN_URLS[@]}" -eq 0 ] && ok "multipart is blocked on all $tested tested vhost/port(s)"
        [ "${#OPEN_URLS[@]}" -gt 0 ] && [ "$LOCAL_EXEMPT" -eq 1 ] && \
            info "your rule seems to exempt localhost, and this test comes from 127.0.0.1 - test from outside too"
    fi
fi
[ -n "$FPM_TCP" ] && warn "php-fpm listens on the network ($(echo $FPM_TCP)) - a web server block does not cover that"

# ------------------------------------------------------ 4. indicators (cheap)
hdr "Indicators of compromise (basic)"

# shells / downloaders spawned by the web stack
WEB_PARENTS='php-fpm|php-cgi|php|httpd|apache2|nginx|lsphp'
SUSP_CHILD='sh|bash|dash|zsh|python[0-9.]*|perl|nc|ncat|socat|curl|wget|whoami|id'
hits=$(ps -eo pid=,ppid=,user=,comm= 2>/dev/null | awk -v P="^($WEB_PARENTS)" -v C="^($SUSP_CHILD)$" '
    { comm[$1]=$4; line[$1]=$0; ppid[$1]=$2 }
    END { for (p in ppid) if (comm[p] ~ C && comm[ppid[p]] ~ P) print "    " line[p] "  <- parent " comm[ppid[p]] }')
if [ -n "$hits" ]; then
    warn "shell/downloader running under the web stack (check these):"
    echo "$hits"
    IOC=$((IOC + 1)); IOC_LINES+=("shell/downloader running under the web stack:"$'\n'"$hits")
else
    ok "no shells or downloaders running under php/web server processes"
fi

# PHP hidden in images, and .htaccess files that make non-PHP files run as PHP
for r in $SCAN_ROOTS; do
    ht=$(find "$r" -name .htaccess -exec grep -HniE '(AddType|AddHandler)[^#]*(php|x-httpd)' {} + 2>/dev/null \
         | grep -iE '\.(png|jpe?g|gif|ico|bmp|webp|svg|txt|css|js|html?)([[:space:]]|$)')
    img=$(grep -rlE --include='*.png' --include='*.jpg' --include='*.jpeg' --include='*.gif' \
               --include='*.ico' --include='*.bmp' --include='*.webp' '<\?php|eval\(|base64_decode\(' "$r" 2>/dev/null)
    if [ -n "$ht" ]; then
        warn "$r: .htaccess makes non-PHP files run as PHP (classic backdoor trick):"
        say "$(head -n5 <<<"$ht" | sed 's/^/           /')"
        IOC=$((IOC + 1)); IOC_LINES+=(".htaccess running non-PHP files as PHP:"$'\n'"$ht")
    fi
    if [ -n "$img" ]; then
        warn "$r: image file(s) containing PHP code:"
        say "$(head -n5 <<<"$img" | sed 's/^/           /')"
        IOC=$((IOC + 1)); IOC_LINES+=("image files containing PHP code:"$'\n'"$img")
    fi
done
[ -n "$SCAN_ROOTS" ] && [ "$IOC" -eq 0 ] && ok "no PHP hidden in images and no .htaccess running images as PHP"

# memory-limit fatals in PHP/web error logs over the last 3 days
logs=$(find /var/log /var/opt/remi /opt/remi/*/root/var/log /usr/local/apache/logs \
       -type f \( -name '*error*log*' -o -name '*php*fpm*log*' -o -name 'www-error.log*' \) \
       -mtime -3 2>/dev/null | grep -v '\.gz$')
if [ -n "$logs" ]; then
    n=$(grep -h 'Allowed memory size of' $logs 2>/dev/null | wc -l)
    if [ "$n" -gt 20 ]; then
        warn "$n 'Allowed memory size' fatals in error logs (last 3 days) - look for multipart POST bursts"
        IOC=$((IOC + 1)); IOC_LINES+=("$n 'Allowed memory size' fatals in the last 3 days (look for multipart POST bursts)")
    else
        ok "$n 'Allowed memory size' fatals in error logs (last 3 days)"
    fi
    n=$(grep -hE 'child [0-9]+ exited on signal (11|6)' $logs 2>/dev/null | wc -l)
    if [ "$n" -gt 0 ]; then
        warn "$n php-fpm child segfault/abort lines (worker churn) in the last 3 days"
        IOC=$((IOC + 1)); IOC_LINES+=("$n php-fpm child segfault/abort lines in the last 3 days")
    fi
else
    info "no recent PHP/web error logs found"
fi

# ------------------------------------------------------ 5. remediation plan

# update command for one package
update_cmd() {
    local pkg=$1 branch=$2 up=update
    [ "$PM" = dnf ] && up=upgrade
    case "$PM" in
        dnf|yum)
            case "$pkg" in
                php[0-9][0-9]-php*) echo "$PM $up '${pkg%%-*}-php*'      # Remi SCL" ;;
                ea-php*)            echo "/scripts/upcp      # cPanel; or: yum update '${pkg%%-*}*'" ;;
                alt-php*)           echo "yum update '${pkg%%-*}*'      # CloudLinux" ;;
                *)                  echo "$PM clean metadata && $PM $up 'php*'" ;;
            esac
            echo "rpm -q --changelog $pkg | grep -E '$CVE_RE'      # a backport lists both CVEs" ;;
        apt)
            echo "apt update && apt install --only-upgrade 'php$branch*'"
            echo "apt changelog $pkg | grep -E '$CVE_RE'      # a backport lists both CVEs" ;;
        apk)
            echo "apk update && apk upgrade 'php*'" ;;
    esac
}

plan() {
    local n=0 e b ver branch pkg fixed cmds="" nofix=0
    step() { n=$((n + 1)); echo; echo "## $n. $*"; echo; }

    echo "# PHP2Shell remediation plan for $(hostname)"
    echo
    echo "Generated $(date '+%F %T') by check-php2shell.sh from this machine's scan."
    echo "OS: ${ID:-unknown} ${VERSION_ID}. Read every command before you run it, and test the sites afterwards."
    if [ "$IN_CONTAINER" -eq 1 ]; then
        echo
        echo "> **This scan ran inside a container.** Changes made inside it are lost when the container is"
        echo "> recreated. Put package updates and php.ini changes into the image (or a mounted file), and put"
        echo "> the multipart block in the host's reverse proxy if there is one."
    fi

    if [ "${#VULN_BINS[@]}" -gt 0 ]; then
        step "Upgrade PHP (the only real fix)"
        # one bullet per package/version (php and php-cgi usually share one)
        local -A grp=(); local order=() key
        for e in "${VULN_BINS[@]}"; do
            IFS='|' read -r b ver branch pkg fixed <<<"$e"
            key="$ver|$branch|$pkg|$fixed"
            [ -z "${grp[$key]}" ] && order+=("$key")
            grp[$key]+="\`$b\`, "
        done
        for key in "${order[@]}"; do
            IFS='|' read -r ver branch pkg fixed <<<"$key"
            b=${grp[$key]%%\`,*}; b=${b#\`}      # first binary of the group
            echo "- ${grp[$key]%, }: PHP $ver${pkg:+ (package \`$pkg\`)}"
            case "$pkg" in
                php[0-9]*w|php[0-9]*w-*)
                    echo "  - Webtatic package: that repo is dead and gets no fixes. Move to a supported PHP (8.2.35+)"
                    echo "    from another repo or a newer OS. Until then, use the stopgap below."
                    nofix=1; continue ;;
            esac
            if [ -z "$pkg" ]; then
                if [ "$IN_CONTAINER" -eq 1 ] && [[ "$b" == /usr/local/* ]]; then
                    local variant=fpm; [ "$MODPHP" -eq 1 ] && variant=apache
                    echo "  - Not from a package; looks like an official Docker \`php\` image. Rebuild on a fixed tag"
                    echo "    (e.g. \`php:${fixed:-$FIXED_83}-$variant\`) and recreate the container. A restart is not enough."
                else
                    echo "  - Not from a package (custom build). Rebuild from source: ${fixed:-8.2.35}+."
                fi
                [ -z "$fixed" ] && nofix=1
                continue
            fi
            if [ -n "$fixed" ]; then
                echo "  - Update to $fixed or newer, or a distro build whose changelog lists both CVEs."
            else
                nofix=1
                case "$branch" in
                    7.4|8.0|8.1)
                        echo "  - No upstream release for $branch. php.net published source-only backports; packaged fixes"
                        echo "    exist only from some vendors (AlmaLinux, TuxCare, Ubuntu Pro, Debian LTS...). Try the update"
                        echo "    below in case your distro shipped one; otherwise upgrade to 8.2.35+." ;;
                    *)
                        echo "  - No fix exists for $branch. Upgrade to 8.2.35+ (or a vendor-supported build)."
                        echo "    Until then, use the stopgap below." ;;
                esac
            fi
            cmds+=$(update_cmd "$pkg" "$branch")$'\n'
        done
        if [ -n "$cmds" ]; then
            echo
            echo '```bash'
            awk '!seen[$0]++' <<<"${cmds%$'\n'}"
            echo '```'
        fi
        echo
        echo "PHP 8.2 security support ends 2026-12-31; plan the move to 8.3+ anyway."
    fi

    if [ "${#VULN_BINS[@]}" -gt 0 ] || [ "${#STALE[@]}" -gt 0 ]; then
        step "Restart everything that runs PHP"
        echo "Old workers keep running the vulnerable code until they restart."
        echo
        if [ "$IN_CONTAINER" -eq 1 ] && [ ! -d /run/systemd/system ]; then
            echo "No systemd in this container: restart the container from the host"
            echo "(\`podman restart <name>\` / \`docker restart <name>\`), or recreate it after an image rebuild."
        else
        echo '```bash'
        [ "$MODPHP" -eq 1 ] && [ -n "$APACHE_SVC" ] && \
            echo "systemctl restart $APACHE_SVC      # mod_php: full restart; a graceful reload keeps the old libphp loaded"
        for e in $FPM_UNITS; do echo "systemctl restart $e"; done
        local s_pid s_name s_unit
        for e in "${STALE[@]}"; do
            IFS='|' read -r s_pid s_name s_unit <<<"$e"
            if [ -n "$s_unit" ]; then
                grep -qx "$s_unit" <<<"$FPM_UNITS" || [ "$s_unit" = "$APACHE_SVC.service" ] || echo "systemctl restart $s_unit"
            else
                echo "kill $s_pid      # $s_name, not a service (cron/CLI job?); whatever starts it will start the new binary"
            fi
        done
        echo '```'
        fi
    fi

    if [ "${#VULN_BINS[@]}" -gt 0 ]; then
        if [ "$nofix" -eq 1 ]; then
            step "Stopgap until PHP is upgraded (needed: no fix is available for at least one binary)"
        else
            step "Stopgap, only if you can't upgrade right away"
        fi
        echo "These close the main attack path, not all of it: CVE-2026-109619 can also be reached without"
        echo "multipart, through the app's own \`session_start()\`/\`unserialize()\`. Only upgrading fixes that."

        echo
        echo "### a. Block multipart requests at the web server"
        echo
        echo "A site with no upload feature is still vulnerable (PHP parses the body before your code runs),"
        echo "but it loses nothing from this block."
        if [ "$RULE_PRESENT" -eq 1 ]; then
            echo
            echo "**A multipart rule is already configured** (listed under \"Stopgap mitigations\" in the report)."
            echo "Keep it if it covers every vhost; the templates below are for comparison, not to add twice."
        fi
        if [ "$uploads" -gt 0 ]; then
            echo
            echo "**This machine uses uploads.** A full block breaks them. Find the URL(s) these handlers are"
            echo "served at, and put those in place of \`UPLOAD/URL\` below so they stay open (behind a password):"
            echo
            awk 'NF && !seen[$0]++' <<<"$UPLOAD_CODE" | head -n15 | sed 's/^/    /'
        fi
        local up_re="UPLOAD/URL|OTHER/UPLOAD"
        if [ "$HAS_NGINX" -eq 1 ]; then
            echo
            if [ -n "$NGINX_FILES" ]; then
                echo "**nginx**, in the \`server {}\` blocks that pass requests to PHP or a backend, in:"
                echo
                sed 's/^/- /' <<<"$NGINX_FILES"
            else
                echo "**nginx**, in every \`server {}\` block that passes requests to PHP or a backend:"
            fi
            echo
            if [ "$uploads" -eq 0 ]; then
                echo '```nginx'
                echo '    # PHP2Shell stopgap (CVE-2026-109618/109619) - remove after the PHP upgrade'
                echo '    if ($content_type ~* multipart) { return 403; }'
                echo '```'
            else
                echo "In \`/etc/nginx/conf.d/php2shell-map.conf\` (http level; the first matching line wins):"
                echo
                echo '```nginx'
                echo 'map "$content_type|$uri" $php2shell_block {'
                echo '    default 0;'
                echo "    \"~*^multipart/.*\\|/($up_re)\$\" 0;      # upload URLs stay open"
                echo '    "~*^multipart/" 1;'
                echo '}'
                echo '```'
                echo
                echo "and in each \`server {}\` block above:"
                echo
                echo '```nginx'
                echo '    if ($php2shell_block) { return 403; }'
                echo '```'
                echo
                echo "If you can, also require a password on those upload locations (\`auth_basic\`)."
            fi
            echo
            echo '```bash'
            echo 'nginx -t && nginx -s reload'
            echo '```'
        fi
        if [ "$HAS_APACHE" -eq 1 ] && [ -n "$APACHE_SVC" ]; then
            local aver conf auth
            aver=$( { apachectl -v || apache2ctl -v || $APACHE_SVC -v; } 2>/dev/null | sed -nE 's#.*Apache/([0-9]+\.[0-9]+).*#\1#p' | head -n1)
            if [ -d /etc/httpd/conf.d ]; then conf=/etc/httpd/conf.d/00-php2shell-block.conf; auth=/etc/httpd/.htpasswd-upload
            else conf=/etc/apache2/conf-available/php2shell-block.conf; auth=/etc/apache2/.htpasswd-upload; fi
            echo
            [ "$HAS_NGINX" -eq 1 ] && echo "**Apache** (if nginx forwards to it, the nginx block is enough; add this as well if Apache is reachable directly):" \
                                   || echo "**Apache**"
            echo
            if [ -n "$aver" ] && ! ver_ge "$aver" "2.4"; then
                echo "Apache $aver has no \`<If>\`. Add this to **every** vhost:"
                echo
                echo '```apache'
                echo 'RewriteEngine On'
                echo 'RewriteCond %{HTTP:Content-Type} multipart [NC]'
                [ "$uploads" -gt 0 ] && echo "RewriteCond %{REQUEST_URI} !^/($up_re)"
                echo 'RewriteRule .* - [F]'
                echo '```'
            else
                echo "In its own file, \`$conf\` (server level, so it covers every vhost):"
                echo
                echo '```apache'
                echo '# PHP2Shell stopgap (CVE-2026-109618/109619) - remove after the PHP upgrade'
                if [ "$uploads" -eq 0 ]; then
                    echo '<If "%{HTTP:Content-Type} =~ /multipart/i">'
                    echo '    Require all denied'
                    echo '</If>'
                else
                    echo "<If \"%{HTTP:Content-Type} =~ /multipart/i && %{THE_REQUEST} !~ m#^POST /($up_re)[ ?/]#\">"
                    echo '    Require all denied'
                    echo '</If>'
                    echo "<If \"%{HTTP:Content-Type} =~ /multipart/i && %{THE_REQUEST} =~ m#^POST /($up_re)[ ?/]#\">"
                    echo '    AuthType Basic'
                    echo '    AuthName "Upload"'
                    echo "    AuthUserFile $auth"
                    echo '    Require valid-user'
                    echo '</If>'
                fi
                echo '```'
                echo
                echo "Don't write \`\\/\` in the regex: Apache 2.4.6 fails with \"Failed to compile regular expression\"."
            fi
            echo
            echo '```bash'
            [ "$uploads" -gt 0 ] && echo "htpasswd -c $auth uploader      # give this login to the people who upload"
            [ "${conf#/etc/apache2}" != "$conf" ] && echo "a2enconf php2shell-block"
            [ "$APACHE_SVC" = httpd ] && echo "apachectl -t && systemctl reload httpd" || echo "apache2ctl -t && systemctl reload apache2"
            echo '```'
        fi
        if [ -n "$FPM_TCP" ]; then
            echo
            echo "**php-fpm listens on the network ($(echo $FPM_TCP)).** Requests sent to it directly skip any web"
            echo "server block. Make it listen on a socket or 127.0.0.1, or firewall the port."
        fi
        if [ "${#OPEN_URLS[@]}" -gt 0 ] && [ "$RULE_PRESENT" -eq 1 ]; then
            echo
            echo "A multipart rule exists, but the live test still got through on: ${OPEN_URLS[*]}"
            [ "$LOCAL_EXEMPT" -eq 1 ] && echo "(the rule exempts localhost, so test those from outside before changing anything)"
        fi

        echo
        echo "### b. PHP settings"
        echo
        echo "Set these in a file PHP reads at startup: php.ini, an FPM pool file, or the Apache config."
        echo "\`ini_set()\` and \`.user.ini\` are too late and don't count."
        echo
        local inis="" scandirs="" pools
        for b in "${PHP_BINS[@]}"; do
            case "$(basename "$b")" in php-fpm*|php-cgi*) continue ;; esac
            inis+=$("$b" --ini 2>/dev/null | sed -nE 's/^Loaded Configuration File:[[:space:]]*(\/.*)/\1/p')$'\n'
            scandirs+=$("$b" --ini 2>/dev/null | sed -nE 's/^Scan for additional .ini files in:[[:space:]]*(\/.*)/\1/p')$'\n'
        done
        scandirs=$(tr ':' '\n' <<<"$scandirs" | awk 'NF && !seen[$0]++')
        inis+=$(ls /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini 2>/dev/null)
        inis=$(awk 'NF && !seen[$0]++' <<<"$inis")
        pools=$(ls /etc/php-fpm.d/*.conf /etc/php/*/fpm/pool.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf \
                   /opt/remi/php*/root/etc/php-fpm.d/*.conf /usr/local/etc/php-fpm.d/*.conf \
                   /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf 2>/dev/null | grep -v 'docker\|zz-')
        if [ -n "$inis" ]; then
            echo '```bash'
            for e in $inis; do
                echo "cp -p $e $e.bak-$(date +%Y%m%d)"
                echo "sed -i -E 's/^;?[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=.*/session.upload_progress.enabled = 0/' $e"
                echo "grep -q '^session.upload_progress.enabled' $e || echo 'session.upload_progress.enabled = 0' >> $e"
            done
            echo '```'
        elif [ -n "$scandirs" ]; then
            echo "No php.ini is loaded; add a drop-in file instead:"
            echo
            echo '```bash'
            for e in $scandirs; do
                echo "echo 'session.upload_progress.enabled = 0' > $e/zz-php2shell.ini"
                [ "${#FEB_ON[@]}" -gt 0 ] && echo "echo 'fatal_error_backtraces = Off' >> $e/zz-php2shell.ini"
            done
            echo '```'
        else
            echo "Could not find the php.ini PHP loads; set \`session.upload_progress.enabled = 0\` there."
        fi
        if [ -n "$pools" ]; then
            echo
            echo "PHP-FPM pools can override php.ini. Add to each pool file:"
            echo
            sed 's/^/- /' <<<"$pools"
            echo
            echo '```ini'
            echo 'php_admin_flag[session.upload_progress.enabled] = off'
            [ "${#FEB_ON[@]}" -gt 0 ] && echo 'php_admin_flag[fatal_error_backtraces] = off'
            echo '```'
        fi
        if [ "${#FEB_ON[@]}" -gt 0 ]; then
            echo
            echo "PHP 8.5 (${FEB_ON[*]}): also set \`fatal_error_backtraces = Off\` in the same php.ini file(s)."
        fi
        if [ -n "$OVERRIDES" ]; then
            echo
            echo "These lines switch upload_progress back on and win over php.ini. Change them to 0/off:"
            echo
            sed 's/^/    /' <<<"$OVERRIDES"
        fi
        echo
        echo "Then restart PHP (step 2 commands; for mod_php a full \`systemctl restart\`, not reload)."
        echo "Optional: \`pm.max_requests = 1\` in FPM pools shortens the life of a corrupted worker, at a CPU cost."
    elif [ "$RULE_PRESENT" -eq 1 ]; then
        step "Remove the stopgap"
        echo "PHP here is patched. The multipart block found in the web server config is no longer needed:"
        echo
        head -n5 <<<"$rules" | sed 's/^/    /'
        echo
        echo "Remove it (and any upload password file made for it), restore \`session.upload_progress\` if"
        echo "you need it, reload the web server and re-run this script."
    fi

    if [ "$IOC" -gt 0 ]; then
        step "Possible compromise: check before anything else"
        for e in "${IOC_LINES[@]}"; do
            echo "- ${e%%$'\n'*}"
            [ "$e" != "${e#*$'\n'}" ] && sed 's/^/      /' <<<"${e#*$'\n'}" | head -n10
        done
        echo
        echo "1. Keep evidence first: copy the files with timestamps (\`tar -cpzf\`), save the web and PHP logs."
        echo "2. Find who used them: search the access logs for the file names; note the client IPs and dates."
        echo "3. Remove the files and the \`.htaccess\` lines, and stop PHP running in upload/image folders."
        echo "4. Rotate every secret the web user could read: DB passwords, API keys, \`.env\`, mail logins."
        echo "5. Look for persistence: cron jobs, SSH keys, users, files owned by the web user that root runs."
        echo "6. If in doubt, rebuild from a known-clean source. Check where the site was copied from, too."
    fi

    step "Verify"
    echo '```bash'
    echo "sudo ./check-php2shell.sh      # every PHP OK, no stale processes, every vhost 'blocked' or patched"
    for e in $(head -n3 <<<"$NAMES"); do
        echo "curl -sk -o /dev/null -w '%{http_code}\\n' -F x=1 https://$e/      # expect 403 while the block is on"
    done
    echo '```'
}

NEED_PLAN=0
{ [ "$VULN" -gt 0 ] || [ "$IOC" -gt 0 ] || { [ "$FOUND" -gt 0 ] && [ "$RULE_PRESENT" -eq 1 ]; }; } && NEED_PLAN=1
if [ "$NEED_PLAN" -eq 1 ]; then
    PLAN=$(plan)
    if [ "$QUIET" -eq 0 ]; then
        hdr "Remediation plan"
        echo
        echo "$PLAN"
    fi
    if [ -n "$OUT" ]; then
        if printf '%s\n' "$PLAN" > "$OUT"; then echo "plan written to $OUT"; else echo "could not write $OUT"; fi
    fi
elif [ -n "$OUT" ]; then
    echo "nothing to fix - no plan written"
fi

# ---------------------------------------------------------------- summary
echo ""
if [ "$FOUND" -eq 0 ]; then
    echo "${GRN}${BLD}RESULT: no PHP found - not affected${RST}"
    exit 0
elif [ "$VULN" -gt 0 ]; then
    echo "${RED}${BLD}RESULT: AFFECTED - $VULN issue(s). Follow the remediation plan${OUT:+ ($OUT)}${RST}"
    exit 1
elif [ "$UNKNOWN" -gt 0 ]; then
    echo "${YLW}${BLD}RESULT: could not decide for $UNKNOWN binary(ies) - check manually${RST}"
    exit 2
else
    echo "${GRN}${BLD}RESULT: not affected ($FOUND PHP binary(ies) patched, no stale processes)${RST}"
    [ "$IOC" -gt 0 ] && echo "${YLW}but $IOC indicator(s) of compromise - see the plan${RST}"
    exit 0
fi
