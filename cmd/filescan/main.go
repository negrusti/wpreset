// filescan scans a directory with YARA-X and correlates matches with HTTP logs.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var version = "dev"

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ", ") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

type options struct {
	root, yr, rules, format, prefix string
	logs                            stringsFlag
	noLogs                          bool
	maxAccesses                     int
	timeout                         time.Duration
}

type rule struct {
	Identifier string                 `json:"identifier"`
	Meta       map[string]interface{} `json:"meta,omitempty"`
}

type finding struct {
	Path      string        `json:"path"`
	URLPath   string        `json:"url_path"`
	BirthUnix *int64        `json:"birth_unix"`
	BirthUTC  string        `json:"birth_utc,omitempty"`
	BirthNote string        `json:"birth_note,omitempty"`
	Rules     []rule        `json:"rules"`
	Accesses  accessSummary `json:"access"`
}

type report struct {
	Root       string      `json:"root"`
	Ruleset    string      `json:"ruleset"`
	Files      int         `json:"files_submitted"`
	Skipped    int         `json:"links_and_special_files_skipped"`
	Logs       []string    `json:"logs"`
	LogLines   int64       `json:"log_lines"`
	Unparsed   int64       `json:"unparsed_log_lines"`
	Incomplete bool        `json:"incomplete"`
	Warnings   []string    `json:"warnings"`
	Findings   []*finding  `json:"findings"`
	Summary    scanSummary `json:"summary"`
	clientIPs  map[string]bool
}

type scanSummary struct {
	Requests          int64      `json:"requests"`
	ClientIPs         []string   `json:"client_ips"`
	EarliestRequest   *time.Time `json:"earliest_request_utc"`
	EarliestBirthUnix *int64     `json:"earliest_birth_unix"`
	EarliestBirthUTC  string     `json:"earliest_birth_utc,omitempty"`
}

func (r *report) summarize() {
	s := scanSummary{ClientIPs: make([]string, 0, len(r.clientIPs))}
	for ip := range r.clientIPs {
		s.ClientIPs = append(s.ClientIPs, ip)
	}
	sort.Strings(s.ClientIPs)
	for _, finding := range r.Findings {
		a := finding.Accesses
		s.Requests += a.Count
		if a.First != nil && (s.EarliestRequest == nil || a.First.Before(*s.EarliestRequest)) {
			s.EarliestRequest = a.First
		}
		if finding.BirthUnix != nil && (s.EarliestBirthUnix == nil || *finding.BirthUnix < *s.EarliestBirthUnix) {
			s.EarliestBirthUnix = finding.BirthUnix
		}
	}
	if s.EarliestBirthUnix != nil {
		s.EarliestBirthUTC = time.Unix(*s.EarliestBirthUnix, 0).UTC().Format(time.RFC3339)
	}
	r.Summary = s
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(cli(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func cli(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var o options
	var showVersion, rulesInfo bool
	f := flag.NewFlagSet("filescan", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.StringVar(&o.root, "path", ".", "directory to scan recursively (also the HTTP document root)")
	f.StringVar(&o.yr, "yr", "yr", "YARA-X executable, version 1.22.0 or later recommended")
	f.StringVar(&o.rules, "rules", "", "custom YARA file/directory instead of the bundled Neo rules")
	f.StringVar(&o.format, "format", "text", "report format: text or json")
	f.Var(&o.logs, "logs", "access log file or glob; repeat to combine sources (default: Nginx and Apache2 logs)")
	f.BoolVar(&o.noLogs, "no-logs", false, "skip access-log correlation")
	f.StringVar(&o.prefix, "url-prefix", "/", "URL mount point for this directory, e.g. /blog")
	f.IntVar(&o.maxAccesses, "max-accesses", 20, "earliest request rows shown per file; 0 shows all (counts/first/last always cover all)")
	f.DurationVar(&o.timeout, "timeout", 15*time.Minute, "maximum time for YARA-X scanning")
	f.BoolVar(&showVersion, "version", false, "print build version")
	f.BoolVar(&rulesInfo, "rules-info", false, "print bundled rule provenance and license")
	f.Usage = func() {
		fmt.Fprintln(stderr, "filescan: find suspicious files and their recorded HTTP requests.\nUsage: filescan [options]\n\nRequires YARA-X (yr). Reads site files and logs; never executes site code.\nExit status: 0 no findings, 2 findings, 1 incomplete scan or usage error.")
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if showVersion {
		fmt.Fprintln(stdout, "filescan", version)
		return 0
	}
	if rulesInfo {
		for _, name := range []string{"rules/README.md", "rules/LICENSE"} {
			data, _ := bundledRules.ReadFile(name)
			if _, err := stdout.Write(data); err != nil {
				return 1
			}
		}
		return 0
	}
	if f.NArg() != 0 || (o.format != "text" && o.format != "json") || o.maxAccesses < 0 || o.timeout <= 0 || (o.noLogs && len(o.logs) > 0) {
		fmt.Fprintln(stderr, "filescan: invalid arguments, format, limits, or conflicting log options")
		return 1
	}
	prefix, err := urlPrefix(o.prefix)
	if err != nil {
		fmt.Fprintln(stderr, "filescan:", err)
		return 1
	}
	o.prefix = prefix
	root, err := filepath.Abs(o.root)
	if err == nil {
		root, err = filepath.EvalSymlinks(root)
	}
	if err != nil {
		fmt.Fprintf(stderr, "filescan: directory: %q\n", err.Error())
		return 1
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		fmt.Fprintln(stderr, "filescan: --path must be a readable directory")
		return 1
	}
	o.root = root
	r := report{Root: root, Ruleset: "Neo23x0/signature-base @ " + rulesCommit, Logs: []string{}, Warnings: []string{}, Findings: []*finding{}}
	if o.rules != "" {
		r.Ruleset = "Custom rules: " + o.rules
	}
	fmt.Fprintf(stderr, "Ruleset: %q\n", r.Ruleset)
	fmt.Fprintf(stderr, "Scanning %q with YARA-X...\n", root)
	if err := scanFiles(ctx, o, &r); err != nil {
		r.warn("YARA-X scan: "+err.Error(), true)
	}
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].Path < r.Findings[j].Path })
	for _, finding := range r.Findings {
		if ctx.Err() != nil {
			r.warn("Scan interrupted", true)
			break
		}
		birth, note := birthTime(ctx, filepath.Join(root, filepath.FromSlash(finding.Path)))
		finding.BirthUnix, finding.BirthNote = birth, note
		if birth != nil {
			finding.BirthUTC = time.Unix(*birth, 0).UTC().Format(time.RFC3339)
		}
	}
	if o.noLogs {
		r.warn("Access-log correlation disabled", false)
	} else {
		correlate(ctx, o, &r)
	}
	if ctx.Err() != nil {
		r.warn("Scan interrupted", true)
	}
	r.summarize()
	if o.format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(r)
	} else {
		err = writeReport(stdout, &r)
	}
	if err != nil {
		fmt.Fprintf(stderr, "filescan: write report: %q\n", err.Error())
		return 1
	}
	if r.Incomplete {
		return 1
	}
	if len(r.Findings) > 0 {
		return 2
	}
	return 0
}

func (r *report) warn(message string, incomplete bool) {
	r.Warnings = append(r.Warnings, message)
	r.Incomplete = r.Incomplete || incomplete
}
