# wpreset

A standalone Go command for replacing compromised WordPress files. No PHP,
WP-CLI, database connection, Go modules, or external commands are needed at runtime.
Linux is the primary platform; macOS and Windows binaries are also built.

## Install and run

Download your platform's archive and `SHA256SUMS` from
[Releases](https://github.com/negrusti/wpreset/releases). On Linux, for example:

```sh
sha256sum --ignore-missing --check SHA256SUMS
tar -xzf wpreset_v0.1.0_linux_amd64.tar.gz
sudo install -m 0755 wpreset /usr/local/bin/wpreset
```

Use the archive name for the release you downloaded. Run as the site owner when
possible so replacement files have the correct ownership. The account needs write
access to the site **and its parent directory**, where private staging and recovery
directories are created on the same filesystem.

Stop the web server/PHP workers, cron jobs, deployment tools, and other processes
that write to the site before applying changes. A lock prevents simultaneous
wpreset runs; it cannot stop WordPress, an attacker process, or another tool.

From the WordPress installation directory (the directory containing `wp-admin`,
`wp-includes`, and `wp-content`):

```sh
# Preview: downloads and checks packages, but changes no site files.
wpreset

# Replace files, keeping installed versions when downloadable.
wpreset --apply

# Prefer current releases; write a machine-readable report outside the site.
wpreset --latest --apply --report ../cleanup-report.json

# Preserve specific plugin directories, even if their slug is downloadable.
wpreset --preserve my-custom-plugin,premium-plugin --apply

# Work from another directory, or override a damaged core version/locale.
wpreset --path /var/www/example --core-version 6.8.3 --locale en_US --apply
```

`--latest` updates both core and downloadable plugins. `--core-version` overrides
that choice for core. Without `--latest`, core uses the literal version read from
`wp-includes/version.php`, and plugins first try their installed version. If a
plugin's version is missing or its versioned ZIP returns 404/410, wpreset tries the
current unversioned ZIP. Reinstalling an old release can retain a vulnerability;
use `--latest` when compatible with the site.

No local PHP is executed, including `wp-config.php`. This tool supports conventional
WordPress directory layouts. Relocated content, custom plugin/upload locations,
and Composer-managed deployments need a separate procedure. Core locale is read
from `$wp_local_package` in `version.php`, otherwise `en_US`; use `--locale` to
override it. Older `WPLANG` settings are not evaluated.

## What changes

* **Core:** `wp-admin` and `wp-includes` are replaced as entire directories. Core
  root files and the `wp-content/index.php` and `wp-content/plugins/index.php`
  placeholders are replaced. Other root PHP-like files
  are removed, including obsolete scripts and root webshells. This also removes
  custom root PHP scripts: move anything required out before applying.
* **Plugins:** each immediate directory name under `wp-content/plugins` is its
  slug. wpreset directly requests official ZIPs by that slug. A downloadable
  package replaces the **entire** plugin directory, removing injected files,
  obsolete assets, local modifications, and plugin-owned runtime data inside it.
  There is no Plugin Name, Plugin URI, author, or Update URI identity check.
* **Unavailable plugins:** a slug whose ZIP returns 404/410 is preserved and listed
  with its reason. These entries may be commercial, custom, closed, renamed, or
  unknown; availability alone cannot distinguish them. An explicit `--preserve`
  entry always wins. A custom/commercial directory sharing a public slug will be
  replaced unless explicitly preserved.
* **Loose plugin files:** their basename is the slug, with `hello.php` mapped to
  `hello-dolly`. A compatible single-script package replaces the original script
  without changing its activation path. Packages requiring a directory are listed
  for manual reinstall instead. Unrecognized files are preserved and listed.
* **Uploads:** recursively removes PHP-like files, case-insensitively: `.php`,
  `.php3`/`.php5`/other numeric variants, `.phtml`, `.pht`, and `.phar`, including
  double extensions such as `image.php.jpg`. Media files stay intact.

`wp-config.php`, themes, the database, unavailable/preserved plugins, MU plugins,
drop-ins, caches, `.htaccess`, `.user.ini`, and other application files remain
untouched. The report lists additional paths for manual review. No default plugins
or themes from the core archive are installed. Existing activation settings in the
database are unchanged; updating versions may require normal WordPress upgrade steps.

Filesystem links are not traversed. Linked plugin entries are preserved and listed;
a PHP-named upload link is removed without touching its target. Other upload links
are listed for review because their targets may still contain PHP. Links in managed
parent paths cause the run to abort. Filenames alone cannot detect every executable
upload or server handler configuration.

## Downloads and recovery

All selected packages are downloaded and validated **before any site file changes**.
Only HTTPS and explicitly allowed official WordPress hosts are used, including on
redirects. There is no insecure TLS option. Core files being installed must match
the official checksum manifest. Plugin checksums are verified when published;
missing plugin checksum manifests (404/410) leave HTTPS as the source assurance.
Malformed ZIPs, checksum mismatches, timeouts, and server errors abort preparation.
Only definitive missing-package responses are treated as unavailable plugins.

ZIP extraction rejects traversal, links, special files, duplicate paths, and Windows
reserved names. Limits per archive: 512 MiB download, 2 GiB expanded data, 256 MiB
per file, and 100,000 entries. Large packages exceeding those limits are rejected.
Downloads have a configurable per-request `--timeout` (default `2m`).

Applying changes moves originals into a private `.wpreset-recovery-*` directory
beside the site, then renames staged replacements into place. Original files do
not remain in the active core or replaced plugin directories. Recovery copies are
retained outside the site and may contain malware: keep them offline and delete
them after you no longer need evidence or rollback. The parent must be outside
any served document root. Budget space for downloads, expanded packages, and originals.

Ordinary errors and Ctrl+C trigger rollback. After a process kill or interruption:

```sh
wpreset --recover /var/www/.wpreset-recovery-EXAMPLE --apply
```

This also reverses a completed cleanup. Recovery **restores potentially compromised
originals**, including deleted upload scripts. It is not a backup of the database
or preserved content. Recovery should happen before reopening the site to writers:
changes made to replaced paths after cleanup would be lost.

If a process was killed, its `.wpreset-lock-*` file beside the site may remain.
Confirm no cleanup is running before removing the exact stale lock named in the
error, then run recovery. Never remove the lock of a live process. Recovery uses
durable operation markers and is repeatable. On Linux, journal files and rename
parent directories are synced. Windows has weaker directory-sync guarantees;
power-loss behavior still depends on the filesystem and hardware.

`--report` creates a new private JSON file outside the site and refuses to overwrite
an existing file. Reports include replacements, preserve reasons, upload removals,
manual-review paths, and the recovery directory. Exit status is 0 for a completed
preview, cleanup, or recovery; errors return 1. Preserved plugins do not cause a
nonzero exit. Success describes the requested file operation, not a malware-free site.

## Build and test

Use a supported Go toolchain:

```sh
go build -trimpath -o wpreset .
go test ./...
go vet ./...

# Static Linux binary, including when cross-compiling.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o wpreset .
```

Tests use synthetic compromised sites and an in-memory HTTP transport. They verify
preview immutability, complete directory replacement, preserved paths, upload
cleanup, failed-install rollback, journal recovery, archive defenses, and links
(when the host permits creating them).

GitHub Actions tests Linux and Windows on pushes and pull requests, including a
Linux smoke test using real official packages on a disposable site. Pushing a
version tag publishes compressed static binaries for Linux amd64/arm64, macOS
amd64/arm64, and Windows amd64, plus `SHA256SUMS`:

```sh
git tag v0.1.0
git push origin v0.1.0
```

## Suggested next features

1. **Persistence audit:** inspect preserved config, server rules, MU plugins,
   drop-ins, scheduled tasks, and unexpected executable files without executing PHP.
2. **Database audit:** report unknown administrators, injected options/posts,
   suspicious cron events, and changed site URLs using explicit database access.
3. **Credential and session rotation:** reset WordPress salts/sessions and guide
   rotation of hosting, SSH, database, and administrator credentials.
4. **Upload execution hardening:** generate reviewable Apache/Nginx rules disabling
   script execution in uploads, including server-specific handler variants.
5. **Private package manifests:** accept operator-supplied premium/custom ZIPs with
   pinned SHA-256 hashes so those plugins can be replaced without public downloads.
6. **Baseline and repeat scans:** compare a known-clean inventory and hashes, and
   report new files, modified files, and the probable reinfection entry point.

File replacement alone does not address compromised themes, configuration,
database content, stolen credentials, or a still-running attacker process. Those
preserved surfaces need investigation before returning the site to service.
