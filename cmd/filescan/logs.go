package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type accessEvent struct {
	Time   time.Time `json:"time"`
	Client string    `json:"client"`
	VHost  string    `json:"vhost,omitempty"`
	Method string    `json:"method"`
	Target string    `json:"target"`
	Status int       `json:"status"`
	Log    string    `json:"log"`
	Line   int64     `json:"line"`
}

type accessSummary struct {
	Count       int64            `json:"count"`
	BeforeBirth int64            `json:"requests_before_birth"`
	First       *time.Time       `json:"first_utc,omitempty"`
	Last        *time.Time       `json:"last_utc,omitempty"`
	Statuses    map[string]int64 `json:"statuses"`
	Events      []accessEvent    `json:"events"`
}

func urlPrefix(prefix string) (string, error) {
	if !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "?#\\\r\n") {
		return "", fmt.Errorf("--url-prefix must be an absolute URL path without query or fragment")
	}
	return strings.TrimSuffix(path.Clean(prefix), "/") + "/", nil
}

// Common/combined Nginx and Apache logs, including Apache vhost_combined.
// Do not search the entire line for filenames: referrers and queries would
// falsely identify access to a different file.
var logRecord = regexp.MustCompile(`^(.+?) \[([^\]]+)\] "((?:\\.|[^"\\])*)" ([0-9]{3})(?:\s|$)`)

func parseAccess(line string) (accessEvent, string, bool) {
	m := logRecord.FindStringSubmatch(line)
	if m == nil {
		return accessEvent{}, "", false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		return accessEvent{}, "", false
	}
	fields := strings.Fields(m[1])
	request := strings.Fields(m[3])
	// A standard access record with "-" as the request has no URI (for
	// example a rejected TLS handshake on an HTTP port), so cannot match.
	if len(fields) >= 3 && m[3] == "-" {
		return accessEvent{}, "", true
	}
	if len(fields) < 3 || len(request) != 3 || !strings.HasPrefix(request[2], "HTTP/") {
		return accessEvent{}, "", false
	}
	status, _ := strconv.Atoi(m[4])
	event := accessEvent{Time: t.UTC(), Client: fields[len(fields)-3], Method: request[0], Target: request[1], Status: status}
	if len(fields) > 3 {
		event.VHost = strings.Join(fields[:len(fields)-3], " ")
	}
	// URL.Path decodes percent escapes once and does not turn '+' into a space.
	u, err := url.ParseRequestURI(request[1])
	if err != nil || !strings.HasPrefix(u.Path, "/") {
		return event, "", true
	}
	return event, u.Path, true
}

func eventLess(a, b accessEvent) bool {
	if !a.Time.Equal(b.Time) {
		return a.Time.Before(b.Time)
	}
	if a.Log != b.Log {
		return a.Log < b.Log
	}
	return a.Line < b.Line
}

func (f *finding) record(e accessEvent, max int) {
	a := &f.Accesses
	a.Count++
	a.Statuses[strconv.Itoa(e.Status)]++
	if a.First == nil || e.Time.Before(*a.First) {
		t := e.Time
		a.First = &t
	}
	if a.Last == nil || e.Time.After(*a.Last) {
		t := e.Time
		a.Last = &t
	}
	if f.BirthUnix != nil && e.Time.Unix() < *f.BirthUnix {
		a.BeforeBirth++
	}
	if max == 0 {
		a.Events = append(a.Events, e)
		return
	}
	// Keep the earliest N requests regardless of rotated-log traversal order.
	i := sort.Search(len(a.Events), func(i int) bool { return eventLess(e, a.Events[i]) })
	if len(a.Events) == max && i == max {
		return
	}
	a.Events = append(a.Events, accessEvent{})
	copy(a.Events[i+1:], a.Events[i:])
	a.Events[i] = e
	if len(a.Events) > max {
		a.Events = a.Events[:max]
	}
}

func discoverLogs(o options, r *report) []string {
	var candidates []string
	if len(o.logs) == 0 {
		for _, dir := range []string{"/var/log/nginx", "/var/log/apache2"} {
			entries, err := os.ReadDir(dir)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				r.warn(fmt.Sprintf("Cannot list logs in %q: %v", dir, err), true)
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() && (strings.Contains(entry.Name(), "access.log") || strings.Contains(entry.Name(), "access_log")) {
					candidates = append(candidates, filepath.Join(dir, entry.Name()))
				}
			}
		}
	} else {
		for _, pattern := range o.logs {
			// Literal filenames containing glob metacharacters still work.
			if _, err := os.Lstat(pattern); err == nil {
				candidates = append(candidates, pattern)
				continue
			}
			matches, err := filepath.Glob(pattern)
			if err != nil || len(matches) == 0 {
				r.warn(fmt.Sprintf("Log pattern %q did not resolve to readable files", pattern), true)
				continue
			}
			candidates = append(candidates, matches...)
		}
	}
	sort.Strings(candidates)
	seen := map[string]bool{}
	var logs []string
	for _, name := range candidates {
		canonical, err := filepath.Abs(name)
		if err == nil {
			canonical, err = filepath.EvalSymlinks(canonical)
		}
		if err != nil {
			r.warn(fmt.Sprintf("Cannot resolve log %q: %v", name, err), true)
			continue
		}
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		info, err := os.Stat(canonical)
		if err != nil || !info.Mode().IsRegular() {
			r.warn(fmt.Sprintf("Cannot read log %q as a regular file", name), true)
			continue
		}
		logs = append(logs, canonical)
	}
	return logs
}

func correlate(ctx context.Context, o options, r *report) {
	logs := discoverLogs(o, r)
	if len(logs) == 0 {
		r.warn("No access logs found; request history is unavailable. Use --logs with a file or quoted glob.", false)
		return
	}
	index := map[string]*finding{}
	for _, finding := range r.Findings {
		index[finding.URLPath] = finding
	}
	for _, name := range logs {
		if ctx.Err() != nil {
			return
		}
		r.Logs = append(r.Logs, name)
		if err := readLog(ctx, name, o.maxAccesses, index, r); err != nil {
			r.warn(fmt.Sprintf("Log %q: %v", name, err), true)
		}
	}
	if r.Unparsed > 0 {
		r.warn(fmt.Sprintf("%d non-empty log lines could not be parsed as common/combined access logs; correlation is incomplete", r.Unparsed), true)
	}
	for _, finding := range r.Findings {
		sort.Slice(finding.Accesses.Events, func(i, j int) bool { return eventLess(finding.Accesses.Events[i], finding.Accesses.Events[j]) })
	}
}

func readLog(ctx context.Context, name string, max int, index map[string]*finding, r *report) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	b := bufio.NewReader(f)
	magic, _ := b.Peek(2)
	var input io.Reader = b
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		z, err := gzip.NewReader(b)
		if err != nil {
			return err
		}
		defer z.Close()
		input = z
	} else if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".xz") || strings.HasSuffix(name, ".bz2") || strings.HasSuffix(name, ".zst") {
		return fmt.Errorf("unsupported or invalid compression (plain text and gzip supported)")
	}
	s := bufio.NewScanner(input)
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var line int64
	for s.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line++
		r.LogLines++
		text := s.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		e, requestPath, ok := parseAccess(text)
		if !ok {
			r.Unparsed++
			continue
		}
		e.Log, e.Line = name, line
		// Exact path, or a slash boundary for PATH_INFO such as shell.php/x.
		// A query, referrer, basename or prefix like shell.php.bak never matches.
		for candidate := requestPath; candidate != ""; {
			if finding := index[candidate]; finding != nil {
				finding.record(e, max)
				break
			}
			i := strings.LastIndexByte(candidate, '/')
			if i <= 0 {
				break
			}
			candidate = candidate[:i]
		}
	}
	return s.Err()
}
