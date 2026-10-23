// dbscan audits MySQL table dumps without executing SQL, PHP, or JavaScript.
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var version = "dev"

type options struct {
	format, minSeverity                 string
	maxValue, maxRow, maxDecoded, depth int
}

type finding struct {
	Table    string            `json:"table"`
	Database string            `json:"database,omitempty"`
	Row      identity          `json:"row"`
	Column   string            `json:"column"`
	Context  map[string]string `json:"context,omitempty"`
	DumpRow  int64             `json:"dump_row"`
	Query    string            `json:"query,omitempty"`
	hit
}

type stats struct{ rows, values, findings, ambiguous, decodeLimited, warnings int64 }

func main() { os.Exit(cli(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func cli(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var o options
	var showVersion bool
	f := flag.NewFlagSet("dbscan", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.StringVar(&o.format, "format", "text", "output format: text or jsonl (one finding per line)")
	f.StringVar(&o.minSeverity, "min-severity", "medium", "minimum heuristic severity: low, medium, high")
	f.IntVar(&o.maxValue, "max-value-bytes", 16*1024*1024, "maximum SQL value/token size; exceeding it aborts the scan")
	f.IntVar(&o.maxRow, "max-row-bytes", 64*1024*1024, "maximum decoded SQL row size; exceeding it aborts the scan")
	f.IntVar(&o.maxDecoded, "max-decoded-bytes", 4*1024*1024, "cumulative additional decoding budget per value")
	f.IntVar(&o.depth, "decode-depth", 3, "maximum decoding layers, 0 to 8")
	f.BoolVar(&showVersion, "version", false, "print build version")
	f.Usage = func() {
		fmt.Fprintln(stderr, "dbscan: scan a MySQL table dump for suspicious stored PHP/JavaScript.\nUsage: dbscan [options] dump.sql[.gz]\n       dbscan [options] -\n\nReads only; never connects to MySQL or executes SQL or stored code.\nExit status: 0 no findings, 2 findings, 1 incomplete scan or usage error.")
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if showVersion {
		fmt.Fprintln(stdout, "dbscan", version)
		return 0
	}
	if f.NArg() != 1 {
		f.Usage()
		return 1
	}
	if (o.format != "text" && o.format != "jsonl") || severity(o.minSeverity) == 0 || o.maxValue <= 0 || o.maxRow <= 0 || o.maxDecoded <= 0 || o.depth < 0 || o.depth > 8 {
		fmt.Fprintln(stderr, "dbscan: invalid format, severity, or resource limit")
		return 1
	}
	var input io.Reader = stdin
	if f.Arg(0) != "-" {
		file, err := os.Open(f.Arg(0))
		if err != nil {
			fmt.Fprintf(stderr, "dbscan: %q\n", err.Error())
			return 1
		}
		defer file.Close()
		input = file
	}
	s, err := scanDump(input, o, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "dbscan: INCOMPLETE scan: %q\n", err.Error())
		return 1
	}
	fmt.Fprintf(stderr, "Scanned %d rows, %d string values; %d findings (%d with ambiguous row identity).\n", s.rows, s.values, s.findings, s.ambiguous)
	if s.decodeLimited > 0 {
		fmt.Fprintf(stderr, "Warning: decoding budget/candidate limit reached in %d values; some encoded content was not inspected.\n", s.decodeLimited)
	}
	if s.rows == 0 {
		fmt.Fprintln(stderr, "Warning: no INSERT/REPLACE data rows were scanned.")
	}
	if s.findings > 0 {
		return 2
	}
	return 0
}

func scanDump(input io.Reader, o options, out, log io.Writer) (stats, error) {
	var s stats
	r := bufio.NewReaderSize(input, 128*1024)
	magic, _ := r.Peek(2)
	var source io.Reader = r
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		z, err := gzip.NewReader(r)
		if err != nil {
			return s, err
		}
		defer z.Close()
		source = z
	}
	d := detector{o.depth, o.maxDecoded, severity(o.minSeverity)}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	warnings := make(map[string]bool)
	p := &parser{l: newLexer(source, o.maxValue), maxRow: o.maxRow}
	p.warn = func(message string) {
		if warnings[message] {
			return
		}
		warnings[message] = true
		s.warnings++
		fmt.Fprintln(log, "Warning:", message)
	}
	p.onRow = func(r row) error {
		s.rows++
		var id identity
		query := ""
		identified := false
		for i, v := range r.values {
			if v.kind != 's' {
				continue
			}
			s.values++
			hits, limited := d.scan(v.text)
			if limited {
				s.decodeLimited++
			}
			if len(hits) == 0 {
				continue
			}
			if !identified {
				id, query = identify(r)
				identified = true
			}
			ctx := make(map[string]string)
			for _, name := range []string{"option_name", "meta_key", "post_title", "post_type", "user_login", "comment_post_ID"} {
				j := columnIndex(r.columns, name)
				if j >= 0 && (r.values[j].kind == 's' || r.values[j].kind == 'n') {
					ctx[r.columns[j]] = excerpt(r.values[j].text, 0, 0)
				}
			}
			for _, h := range hits {
				f := finding{r.table.Name, r.table.DB, id, r.columns[i], ctx, r.number, query, h}
				var err error
				if o.format == "jsonl" {
					err = enc.Encode(f)
				} else {
					err = writeText(out, f)
				}
				if err != nil {
					return fmt.Errorf("write report: %w", err)
				}
				s.findings++
				if id.Ambiguous {
					s.ambiguous++
				}
			}
		}
		return nil
	}
	err := p.parse()
	return s, err
}

func writeText(w io.Writer, f finding) error {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s: table=%q column=%q", strings.ToUpper(f.Severity), f.Rule, f.Table, f.Column)
	if f.Database != "" {
		fmt.Fprintf(&b, " database=%q", f.Database)
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "  Row (%s):", f.Row.Kind)
	for _, field := range f.Row.Fields {
		fmt.Fprintf(&b, " %s=%s", strconv.Quote(field.Column), strconv.Quote(field.Value))
	}
	b.WriteByte('\n')
	if f.Row.Ambiguous {
		if len(f.Row.Fields) == 0 {
			b.WriteString("  Warning: no primary/unique key or short identifying values; no row lookup available.\n")
		} else {
			b.WriteString("  Warning: selector may match multiple rows; verify before changing anything.\n")
		}
	}
	for _, name := range []string{"option_name", "meta_key", "post_title", "post_type", "user_login", "comment_post_ID"} {
		if v, ok := f.Context[name]; ok {
			fmt.Fprintf(&b, "  %s: %q\n", name, v)
		}
	}
	fmt.Fprintf(&b, "  Reason: %s\n  Decoding: %s\n  Excerpt: %q\n", f.Reason, f.Encoding, f.Excerpt)
	if f.Query != "" {
		fmt.Fprintf(&b, "  Lookup SQL (quoted): %q\n", f.Query)
	}
	b.WriteByte('\n')
	_, err := io.WriteString(w, b.String())
	return err
}
