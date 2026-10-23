# filescan

Scan the current directory recursively with **YARA-X (`yr`)**, list suspicious
files with Linux birth timestamps, and correlate their URL paths with current
and rotated Nginx/Apache access logs. Site files and logs are read only. PHP,
JavaScript and other site code are never executed.

## Install and run

`filescan` is included alongside `wpreset` and `dbscan` in every platform release.
Install [YARA-X](https://virustotal.github.io/yara-x/docs/intro/getting-started/)
separately so `yr` is on `PATH`, or supply `--yr /path/to/yr`.
YARA-X 1.22.0 is tested in CI; newer compatible versions can be used. The legacy
`yara` executable is not a substitute. The Go binary itself has no Go module or
CGo runtime dependencies. Linux birth-time collection also needs GNU `stat`
(normally provided by coreutils).

```sh
cd /var/www/example.com
filescan

# Select a site and its own access logs, including .1 and .gz rotations.
filescan --path /var/www/example.com \
  --logs '/var/log/nginx/example.com.access.log*'

# Combine copied Nginx and Apache log archives.
filescan --logs '/evidence/nginx/access.log*' \
  --logs '/evidence/apache2/*access.log*'

# WordPress is mounted at https://example.com/blog/.
filescan --path /var/www/example.com/blog --url-prefix /blog \
  --logs '/var/log/apache2/example.access.log*'

# Include every matching request, or save a machine-readable report.
filescan --max-accesses 0
filescan --format json > /private/evidence/filescan-report.json

# Use your own YARA file/directory, or scan without access logs.
filescan --rules /opt/site-rules
filescan --no-logs
filescan --rules-info
```

Run from the HTTP document root, or set `--path` and `--url-prefix` to describe
the same directory's URL mount point. Quote log globs so filescan expands them.
Use an account that can read the site and logs. A permission failure makes the
report incomplete; it never silently becomes a clean scan.
Write redirected reports outside the scanned directory so the output file does
not become a scan target.

## Reading the report

The following is illustrative; rule matches and attribution come from YARA-X:

```text
FILESCAN  |  COMPLETE  |  all times UTC
Root: "/var/www/example.com"
Rules: "Neo23x0/signature-base @ 3ce6640c26046da8e6d8094af3eaaee3ee84e648"
Files submitted: 4912  |  Suspicious files: 1  |  Links/special files skipped: 0
Access logs: 3  |  Lines read: 81924

1. "wp-content/uploads/cache.php"
   Born: 2026-10-22 03:14:20 UTC  |  Unix: 1792638860
   URL:  "/wp-content/uploads/cache.php"
   Rule: "WEBSHELL_PHP_Gzinflated"  |  score "75"
         "PHP webshell which directly eval()s obfuscated string"
         Author: "Arnim Rupp (https://github.com/ruppde)"
   HTTP: 2 requests  |  status counts: 200=1, 404=1
   First: 2026-10-22 03:15:02 UTC
   Last:  2026-10-23 08:40:11 UTC

   Request timeline (2 of 2 rows, earliest first):
   TIME (UTC)           STATUS  METHOD  CLIENT / REQUEST
   2026-10-22 03:15:02  200     "POST"  "192.0.2.10"  "/wp-content/uploads/cache.php"
      "/var/log/nginx/access.log.2.gz":418
   2026-10-23 08:40:11  404     "GET"   "192.0.2.11"  "/wp-content/uploads/cache.php?x=1"
      "/var/log/nginx/access.log.1":710
```

Each file gets one block, ordered by relative pathname. Requests are sorted by
time across rotations, with source log and line number for investigation.
The default timeline shows the earliest **20** requests per file; totals,
status counts and first/last times always include every matching entry read.
Increase `--max-accesses` or set it to `0` to display all requests. Unlimited
timelines require memory proportional to the number of matching log entries.
All timestamps are converted to UTC, regardless of the log's original offset.
Filenames, request fields and metadata are quoted to escape terminal controls.
Request targets longer than 180 characters are shortened in the readable
timeline; the JSON report retains the complete target.

**Born** is the filesystem's birth/creation time, shown as UTC and integer Unix
seconds. On Linux, filescan obtains it from GNU `stat --format=%W`, which uses
kernel/filesystem birth-time support. If unavailable, the report says so:
**ctime and mtime are never substituted**. Non-Linux builds report Linux birth
time as unavailable. Birth time is the current inode's creation time, which may
reflect a restore or replacement rather than the arrival of malware. Requests
before the current birth time are counted and called out explicitly.

**HTTP** entries record requests, including unsuccessful statuses. A request
does not prove the file existed then or that its code executed. No matching
requests means none were found in the available, successfully read logs.
Internal PHP includes, cron execution and unlogged requests will not appear.

## Rules and coverage

The default is a pinned, embedded selection of seven files (809 rules including
private rules) from [Neo23x0 Signature-Base](https://github.com/Neo23x0/signature-base).
It covers generic PHP webshells, obfuscated payloads, known webshell families
and WordPress-specific infections. Some rules also detect other web languages.
This is a practical incident-response default, not a benchmark claim that one
ruleset is universally best. Broad source-code vulnerability checks are not
mixed into malware findings.

The exact revision, upstream filenames, attribution, license and byte hashes
are recorded in [the bundled rule notice](cmd/filescan/rules/README.md) and
`SHA256SUMS`. `--rules-info` prints the notice and license. Bundled rules work
offline and are not automatically downloaded or changed between scans.
`--rules` replaces the bundled selection with a trusted local file/directory;
custom rules must compile without scanner-specific external variables.
Matching rule metadata and author attribution are retained in JSON reports,
with descriptions, authors and scores included in the readable report.
Scores are upstream rule metadata, not a calibrated probability of compromise.

Every regular file is submitted, regardless of extension. Filescan does not
unpack archives, decrypt content or deobfuscate arbitrary payloads. Child
symlinks and special files are skipped and counted; directory links are never
traversed. The selected root itself is resolved before traversal. Scanning a
live directory is not a filesystem snapshot; use a preserved copy for stable
evidence. Temporary rule copies, the file inventory and YARA-X output are kept
in a private OS temporary directory and removed after scanning.

## Access-log support

With no `--logs` arguments, filescan discovers files whose names contain
`access.log` or `access_log` directly inside `/var/log/nginx` and
`/var/log/apache2`. This includes normal numbered and date-based rotations,
site-specific access logs and `.gz` archives. Use repeated `--logs` options for
other locations. Plain text and gzip are supported; other compression formats,
corrupt gzip, read failures and overlong lines are reported as incomplete.

Parses the standard **common/combined** access format and Apache's
`vhost_combined` variant. Custom JSON/escaped formats may need conversion first.
Non-empty unparseable lines are counted and make correlation incomplete.
The parser limits each line to 4 MiB. Logs are streamed once and matched
against all findings. Repeating the same resolved log path does not double
count it; separate copies or overlapping rotations are counted independently.

Matching uses the request URL path, percent-decoded once, with the query
excluded. Absolute-form requests are also accepted. A slash suffix is allowed
for PHP `PATH_INFO` (`/shell.php/extra`). Different directories, filenames such
as `shell.php.bak`, query references and referrer headers do not match.
URLs in the timeline retain their original query strings.

The default assumes `--path` is served at `/`. Files under different virtual
hosts can share the same URL path: select that site's own logs when possible.
Apache virtual-host prefixes are displayed when present. Shared logs without
host information cannot establish which site a request reached. Server aliases,
rewrites, front controllers and unusual URI escaping require contextual review;
filescan does not read web-server configuration or infer those mappings.

Missing default log directories or no discovered logs produce a clear
"history unavailable" warning. An explicitly requested log that cannot be
found/read makes the run incomplete. `--no-logs` explicitly disables correlation.

## Exit codes, build and CI

- `0`: file scan completed with no rule matches.
- `2`: file scan completed with suspicious files.
- `1`: usage error, interrupted/failed YARA-X scan, incomplete file coverage,
  or an error while reading/parsing requested or discovered access logs.

An unavailable birth timestamp alone does not fail the scan. YARA-X diagnostics
are checked even when `yr` exits with status zero, since it can otherwise hide
individual unreadable files. `--timeout` bounds the YARA-X process (default 15m).
Partial findings remain visible when possible and the report says INCOMPLETE.

```sh
go build -trimpath -o filescan ./cmd/filescan
go test ./...
go vet ./...

# Use a specific yr for the real-rule integration test.
FILESCAN_TEST_YR=/opt/yara-x/yr go test -count=1 -v ./cmd/filescan
```

The existing main-branch/pull-request CI installs checksum-pinned YARA-X 1.22.0,
tests real rule detection and correlation on Linux and Windows, then builds and
smoke-tests all three tools. The existing tagged-release workflow runs the same
integration tests and adds `filescan`, this guide and rule license/provenance
notices to each of the five platform archives. Users install `yr` separately.
