# Bundled filescan rules

Source: https://github.com/Neo23x0/signature-base
Immutable revision: 3ce6640c26046da8e6d8094af3eaaee3ee84e648
Retrieved: 2026-10-24

Seven upstream files are embedded unchanged (809 rules, including private rules):

- yara/gen_webshells.yar
- yara/gen_cn_webshells.yar
- yara/thor-webshells.yar
- yara/apt_laudanum_webshells.yar
- yara/apt_webshell_chinachopper.yar
- yara/cn_pentestset_webshells.yar
- yara/vul_php_zlib_backdoor.yar

These cover PHP webshells, obfuscation, known webshell families, WordPress
infections (including SoakSoak and wp-config prepend webshells), and some other
web technologies. This is a focused subset of Signature-Base, not its complete
malware feed. Rules requiring scanner-specific external variables are excluded.
No external variables are fabricated and no failed rules are silently skipped.
The complete subset is compile-tested and scan-tested with YARA-X 1.22.0.

Upstream license: Detection Rule License (DRL) 1.1, reproduced in LICENSE.
Rule authors, references and individual license metadata remain in the source.
Reports preserve supplied author attribution for each matching rule. Some rules
link directly to the SigmaHQ Detection Rule License; their metadata is retained.

SHA256SUMS records exact upstream bytes, including LICENSE. Tests verify these
hashes. To update: choose an immutable upstream commit, download the same seven
files and LICENSE from that revision, review upstream changes/licenses, update
rulesCommit in scan.go and this notice, regenerate SHA256SUMS, and run the full
test suite with yr installed. Do not merely change the commit label or hashes
without reviewing and validating the replacement rules.

Use --rules to replace this subset with your own compatible rules, and
--rules-info to view this notice and the license without extracting the binary.
