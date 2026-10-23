package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const rulesCommit = "3ce6640c26046da8e6d8094af3eaaee3ee84e648"

//go:embed rules/*
var bundledRules embed.FS

// The ndjson format in yr 1.22 represents metadata as [key,value] pairs,
// preserving repeated keys. Also accept object metadata used by other output
// versions, and normalize repeated keys to arrays in our own JSON report.
func (r *rule) UnmarshalJSON(data []byte) error {
	var wire struct {
		Identifier string          `json:"identifier"`
		Meta       json.RawMessage `json:"meta"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	r.Identifier = wire.Identifier
	r.Meta = nil
	raw := bytes.TrimSpace(wire.Meta)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	if raw[0] == '{' {
		return json.Unmarshal(raw, &r.Meta)
	}
	var pairs [][]json.RawMessage
	if err := json.Unmarshal(raw, &pairs); err != nil {
		return err
	}
	grouped := make(map[string][]interface{})
	for _, pair := range pairs {
		if len(pair) != 2 {
			return fmt.Errorf("invalid yr metadata pair")
		}
		var key string
		var value interface{}
		if err := json.Unmarshal(pair[0], &key); err != nil {
			return err
		}
		if err := json.Unmarshal(pair[1], &value); err != nil {
			return err
		}
		grouped[key] = append(grouped[key], value)
	}
	r.Meta = make(map[string]interface{}, len(grouped))
	for key, values := range grouped {
		if len(values) == 1 {
			r.Meta[key] = values[0]
		} else {
			r.Meta[key] = values
		}
	}
	return nil
}

// yr logs some per-file errors without failing the process. Capture stderr even
// when exit status is zero, but bound memory if a large tree is unreadable.
type diagnostics struct{ bytes.Buffer }

func (d *diagnostics) Write(p []byte) (int, error) {
	n := len(p)
	if left := 65536 - d.Len(); left > 0 {
		if len(p) > left {
			p = p[:left]
		}
		_, _ = d.Buffer.Write(p)
	}
	return n, nil
}

func scanFiles(ctx context.Context, o options, r *report) error {
	yr, err := exec.LookPath(o.yr)
	if err != nil {
		return fmt.Errorf("cannot find yr; install YARA-X or pass --yr: %w", err)
	}
	work, err := os.MkdirTemp("", "filescan-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	work, err = filepath.Abs(work)
	if err == nil {
		work, err = filepath.EvalSymlinks(work)
	}
	if err != nil {
		return err
	}
	rulesPath := o.rules
	if rulesPath == "" {
		rulesPath = filepath.Join(work, "rules")
		if err := os.Mkdir(rulesPath, 0700); err != nil {
			return err
		}
		entries, _ := bundledRules.ReadDir("rules")
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".yar") {
				continue
			}
			data, err := bundledRules.ReadFile("rules/" + entry.Name())
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(rulesPath, entry.Name()), data, 0600); err != nil {
				return err
			}
		}
	} else {
		rulesPath, err = filepath.Abs(rulesPath)
		if err != nil {
			return err
		}
	}
	listPath := filepath.Join(work, "files.txt")
	list, err := os.OpenFile(listPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(list)
	err = filepath.WalkDir(o.root, func(path string, entry fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			r.warn(fmt.Sprintf("Cannot inventory %q: %v", path, err), true)
			return nil
		}
		// Temporary rule/output files must not become scan targets if TMPDIR is
		// inside the selected root. WalkDir never follows directory symlinks.
		if path == work {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			r.warn(fmt.Sprintf("Cannot stat %q: %v", path, err), true)
			return nil
		}
		if !info.Mode().IsRegular() {
			r.Skipped++
			return nil
		}
		if strings.ContainsAny(path, "\r\n") {
			r.warn(fmt.Sprintf("Cannot submit filename with newline to yr: %q", path), true)
			return nil
		}
		if _, err := fmt.Fprintln(w, path); err != nil {
			return err
		}
		r.Files++
		return nil
	})
	flushErr := w.Flush()
	closeErr := list.Close()
	if err != nil {
		return err
	}
	if flushErr != nil {
		return flushErr
	}
	if closeErr != nil {
		return closeErr
	}
	output, err := os.OpenFile(filepath.Join(work, "matches.ndjson"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer output.Close()
	scanCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	cmd := exec.CommandContext(scanCtx, yr, "scan", "--output-format=ndjson", "--print-meta", "--disable-warnings", "--disable-console-logs", "--scan-list", "--", rulesPath, listPath)
	var diag diagnostics
	cmd.Stdout, cmd.Stderr = output, &diag
	runErr := cmd.Run()
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return err
	}
	parseErr := parseMatches(output, o, r)
	if diag.Len() > 0 {
		r.warn("YARA-X diagnostics (up to 64 KiB): "+strings.TrimSpace(diag.String()), true)
	}
	if scanCtx.Err() != nil {
		return fmt.Errorf("scan interrupted or timed out: %w", scanCtx.Err())
	}
	if runErr != nil {
		return runErr
	}
	return parseErr
}

func parseMatches(input io.Reader, o options, r *report) error {
	dec := json.NewDecoder(input)
	seen := make(map[string]*finding)
	for {
		var match struct {
			Path  string `json:"path"`
			Rules []rule `json:"rules"`
		}
		if err := dec.Decode(&match); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("invalid yr NDJSON output: %w", err)
		}
		if match.Path == "" || len(match.Rules) == 0 {
			return fmt.Errorf("unexpected yr NDJSON record (expected path and rules)")
		}
		path, err := filepath.Abs(match.Path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(o.root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("yr returned path outside scan root: %q", path)
		}
		rel = filepath.ToSlash(rel)
		for _, rule := range match.Rules {
			if rule.Identifier == "" {
				return fmt.Errorf("yr returned rule without identifier")
			}
		}
		if prev := seen[rel]; prev != nil {
			prev.Rules = append(prev.Rules, match.Rules...)
			continue
		}
		sort.Slice(match.Rules, func(i, j int) bool { return match.Rules[i].Identifier < match.Rules[j].Identifier })
		f := &finding{Path: rel, URLPath: o.prefix + rel, Rules: match.Rules, Accesses: accessSummary{Statuses: map[string]int64{}, Events: []accessEvent{}}}
		r.Findings = append(r.Findings, f)
		seen[rel] = f
	}
}
