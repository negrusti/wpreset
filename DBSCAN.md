# dbscan

A standalone Go command that scans MySQL/MariaDB **table dumps** for suspicious
stored PHP and JavaScript. It reads the dump locally, never connects to a database,
and never executes SQL, PHP, JavaScript, or PHP deserialization hooks. It uses only
the Go standard library and builds alongside `wpreset`.

## Build and run

Download the `wpreset` release archive for your platform from
[Releases](https://github.com/negrusti/wpreset/releases). Each archive includes
`wpreset`, `dbscan` and [filescan](FILESCAN.md), plus their documentation. Verify the archive against
the published `SHA256SUMS` before extracting. Windows executables have `.exe`.

To build from source instead:

```sh
go build -trimpath -o dbscan ./cmd/dbscan
./dbscan /private/backups/wordpress.sql
./dbscan --format=jsonl /private/backups/wordpress.sql.gz > findings.jsonl
./dbscan --min-severity=low /private/backups/wordpress.sql
```

On Windows, build with `-o bin/dbscan.exe`. A single `-` reads standard input.
Gzip is recognized by its header for both files and standard input. Options must
precede the input filename. Summary and warnings go to standard error; findings go
to standard output. JSONL writes one JSON object per finding and can be processed
as a stream without loading the whole report.

Exit status:

* **0:** parsing completed and no configured detection rules matched.
* **2:** parsing completed and at least one finding was reported.
* **1:** invalid arguments, I/O failure, resource limit, malformed SQL, or an
  unsupported SQL construct. Findings already emitted are **partial** results.

Neither status 0 nor status 2 certifies that a database is malware-free. Pay
attention to warnings about skipped objects and decoding limits.

## Prepare a dump

Run this from a private directory outside every served document root. Substitute
the actual database name and username. `-p` prompts for the password.

```sh
mysqldump -u wp_user -p --single-transaction --quick --skip-lock-tables --skip-triggers --hex-blob --result-file=wordpress.sql wordpress_db
```

Use the matching `mariadb-dump` client for MariaDB. `--single-transaction` provides
a consistent snapshot for InnoDB, not MyISAM or MEMORY; avoid concurrent schema
changes during the export. The dump still reads the database once. Subsequent
scans and detection passes run locally.

Keep **schema and data**: CREATE TABLE definitions supply column order and keys.
The scanner supports default multi-row INSERTs, so neither
`--skip-extended-insert` nor `--complete-insert` is necessary. Both options are
also supported if a more verbose, manually readable export is desired.

`--hex-blob` is supported: hex SQL literals are decoded before scanning. SQL
escaping, quoted identifiers, NULL, numeric/bit literals, character set
introducers, REPLACE, qualified table names, USE statements, and ordinary
mysqldump SQL mode save/restore comments are supported. Dumps with explicit
INSERT column lists can also be scanned without schema, with a warning that
primary/unique keys are unavailable.

Table exports are the supported input format. Custom DELIMITER directives,
INSERT SELECT, computed INSERT values, UPDATE/DELETE data scripts, and schema
alterations other than ENABLE/DISABLE KEYS cause an explicit error. Export
triggers, routines and events separately for manual review; they are outside
this tool's audit. Views and other non-table CREATE statements produce warnings.

## Finding exact database rows

Each finding includes the table and database (when present), affected column,
rule, heuristic severity, decoding path, and a bounded excerpt. Useful WordPress
context such as `option_name`, `meta_key` and `post_title` is included when present.

For example, a finding in `wp_options` can identify:

```text
Table:       wp_options
Row:         option_id = 1842 (primary_key)
Column:      option_value
Context:     option_name = widget_custom_html
Rule:        obfuscated-execution
Lookup SQL:  SELECT * FROM `wp_options` WHERE `option_id` = 1842;
```

Identifiers come from the dump, not the file position. Composite keys include
every component. If the primary key is missing from a partial INSERT, an
available UNIQUE key is used instead. A UNIQUE key containing NULL, a prefix
index, or an expression index is conservatively excluded from row identification.

When neither key is usable, the finding has `row.kind=non_unique_values` and
`row.ambiguous=true`. Up to four short values form a candidate lookup that may
match multiple rows. If no short identifying values exist, the lookup is omitted.
No dump row number is claimed to be a unique database identifier. `dump_row` is
only a supplemental ordinal across all INSERT/REPLACE rows in the input.

Lookup queries only SELECT data. String/binary key values use hex SQL literals
to avoid unsafe quote interpolation. JSONL includes the directly usable `query`
string; text output quotes it and other untrusted content to escape terminal
control characters. Reports can contain private site data; keep them private.
The dump represents a snapshot, so verify the current row before editing it.

## Detection and bounds

Rules flag PHP tags, dynamic execution, PHP/JavaScript decoders, remote PHP
includes, process execution, script elements, HTML event handlers, JavaScript
URLs and browser redirects. Dynamic
execution combined with a decoder in the same value produces a high-severity
finding. Iframes are low-severity and require `--min-severity=low` to report.

These are **review candidates**, not automatic malware verdicts. Analytics,
embeds, code examples, legitimate redirects and snippet plugins can match.
Encoded code is inspected using bounded layers of HTML entity, percent, string
escape, Base64, hex, gzip, zlib and raw DEFLATE decoding. JSON and PHP serialized
containers are searched as stored text; findings identify the containing column,
not an internal JSON or serialized path. No code or objects are evaluated.
Split strings, arbitrary packers, encryption, whitespace-obfuscated encodings,
and attacker-specific behavior can evade detection. Inspect files and the
compromise entry point as part of a full site review.

The parser reads one row at a time, keeping schema metadata in memory, rather
than buffering the dump or a whole multi-row INSERT. Findings are written as
they are found. A row and its individual values are bounded:

| Option | Default | Behavior |
|---|---|---|
| `--max-value-bytes` | 16 MiB | Abort if an individual SQL value/token exceeds this size |
| `--max-row-bytes` | 64 MiB | Abort if combined SQL-decoded values exceed this size |
| `--max-decoded-bytes` | 4 MiB | Additional cumulative decoding budget per value; warn if exhausted |
| `--decode-depth` | 3 | Maximum transformation layers; 0 disables them, maximum 8 |
| `--min-severity` | medium | Report low, medium, or high and above |

There are at most 64 candidates per encoding type per layer. Decoding limits are
summarized as warnings. SQL decoding itself is always performed, even with
`--decode-depth=0`. Raise value/row limits explicitly if a legitimate large
page-builder value exceeds them.

## Verify

```sh
go test ./...
go vet ./...
go test ./cmd/dbscan -run '^$' -bench BenchmarkStreamingDump -benchmem
```

`cmd/dbscan/testdata/example.sql` is a synthetic dump with safe and suspicious
content, an encoded payload, and a plugin table without a key:

```sh
./dbscan cmd/dbscan/testdata/example.sql
```

That example intentionally exits with status 2 because it contains findings.
