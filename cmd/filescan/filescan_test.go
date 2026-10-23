package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Exercise the actual process boundary without requiring a shell or installed
// YARA-X for unit tests. Integration tests below also use the real yr binary.
func TestMain(m *testing.M) {
	if os.Getenv("FILESCAN_HELPER") == "1" {
		args := os.Args[1:]
		if len(args) == 0 || args[0] != "scan" {
			os.Exit(91)
		}
		list, err := os.ReadFile(args[len(args)-1])
		if err != nil || strings.Contains(string(list), "linked.php") {
			os.Exit(92)
		}
		if !strings.Contains(strings.Join(args, " "), "--print-meta") {
			os.Exit(93)
		}
		if diag := os.Getenv("FILESCAN_HELPER_DIAGNOSTIC"); diag != "" {
			fmt.Fprintln(os.Stderr, diag)
		}
		fmt.Print(os.Getenv("FILESCAN_HELPER_OUTPUT"))
		if os.Getenv("FILESCAN_HELPER_FAIL") == "1" {
			os.Exit(7)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func logLine(stamp, target, status string) string {
	return fmt.Sprintf("192.0.2.5 - - [%s] \"GET %s HTTP/1.1\" %s 12 \"-\" \"Agent\"\n", stamp, target, status)
}

func put(t *testing.T, name, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestParseAccess(t *testing.T) {
	for _, test := range []struct{ input, path, client, host string }{
		{logLine("24/Oct/2026:12:05:09 +0700", "/wp-content/a%20b.php?x=1", "200"), "/wp-content/a b.php", "192.0.2.5", ""},
		{"example.com:80 2001:db8::1 - - [24/Oct/2026:05:05:09 +0000] \"POST /a+b.php HTTP/2.0\" 403 0", "/a+b.php", "2001:db8::1", "example.com:80"},
		{logLine("24/Oct/2026:05:05:09 +0000", "https://example.com/shell.php", "404"), "/shell.php", "192.0.2.5", ""},
	} {
		e, path, ok := parseAccess(test.input)
		if !ok || path != test.path || e.Client != test.client || e.VHost != test.host || e.Time.Format(time.RFC3339) != "2026-10-24T05:05:09Z" {
			t.Fatalf("parseAccess: %+v %q %v", e, path, ok)
		}
	}
	for _, text := range []string{"malformed", logLine("bad-date", "/a.php", "200")} {
		if _, _, ok := parseAccess(text); ok {
			t.Fatalf("accepted %q", text)
		}
	}
}

func TestCorrelationRotatedLogsAndBoundedTimeline(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "access.log")
	rotated := filepath.Join(dir, "access.log.2.gz")
	put(t, current, logLine("24/Oct/2026:08:00:00 +0000", "/blog/uploads/a%20b.php?secret=1", "200")+
		logLine("24/Oct/2026:09:00:00 +0000", "/blog/uploads/a%20b.php/path-info", "403")+
		logLine("24/Oct/2026:10:00:00 +0000", "/index.php?file=/blog/uploads/a%20b.php", "200")+
		logLine("24/Oct/2026:10:00:00 +0000", "/elsewhere/a%20b.php", "200")+
		logLine("24/Oct/2026:10:00:00 +0000", "/blog/uploads/a%20b.php.bak", "200")+
		"192.0.2.1 - - [24/Oct/2026:10:00:00 +0000] \"GET /index.php HTTP/1.1\" 200 4 \"https://example.com/blog/uploads/a%20b.php\" \"Agent\"\n")
	f, err := os.Create(rotated)
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	_, _ = io.WriteString(z, logLine("23/Oct/2026:11:00:00 +0700", "/blog/uploads/a%20b.php", "404"))
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	birth := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC).Unix()
	found := &finding{URLPath: "/blog/uploads/a b.php", BirthUnix: &birth, Accesses: accessSummary{Statuses: map[string]int64{}}}
	r := report{Findings: []*finding{found}}
	o := options{logs: stringsFlag{filepath.Join(dir, "access.log*"), current}, maxAccesses: 1}
	correlate(context.Background(), o, &r)
	a := found.Accesses
	if r.Incomplete || r.Unparsed != 0 || len(r.Logs) != 2 || a.Count != 3 || len(a.Events) != 1 || a.Events[0].Status != 404 || a.BeforeBirth != 1 || a.Last.Hour() != 9 {
		t.Fatalf("report=%+v access=%+v", r, a)
	}
	if a.First.Format(time.RFC3339) != "2026-10-23T04:00:00Z" {
		t.Fatal(a.First)
	}
}

func TestIncompleteLogs(t *testing.T) {
	for _, kind := range []string{"malformed", "bad-gzip", "missing", "oversized", "truncated-gzip"} {
		t.Run(kind, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "access.log")
			switch kind {
			case "malformed":
				put(t, name, "not combined log data\n")
			case "bad-gzip":
				name += ".gz"
				put(t, name, "not gzip")
			case "oversized":
				put(t, name, strings.Repeat("x", 4*1024*1024+1))
			case "truncated-gzip":
				var b bytes.Buffer
				z := gzip.NewWriter(&b)
				io.WriteString(z, logLine("24/Oct/2026:12:00:00 +0000", "/a.php", "200"))
				z.Close()
				if err := os.WriteFile(name, b.Bytes()[:b.Len()-4], 0600); err != nil {
					t.Fatal(err)
				}
			}
			r := report{}
			correlate(context.Background(), options{logs: stringsFlag{name}}, &r)
			if !r.Incomplete {
				t.Fatalf("expected incomplete: %+v", r)
			}
		})
	}
}

func TestRequestSummaryAcrossFiles(t *testing.T) {
	name := filepath.Join(t.TempDir(), "access.log")
	withClient := func(stamp, target, client string) string {
		return strings.Replace(logLine(stamp, target, "200"), "192.0.2.5", client, 1)
	}
	put(t, name,
		withClient("24/Oct/2026:12:00:00 +0000", "/uploads/shell-a.php?x=1", "192.0.2.9")+
			withClient("23/Oct/2026:04:00:00 +0000", "/shell-b.php", "2001:0db8:0:0:0:0:0:1")+
			withClient("24/Oct/2026:03:00:00 +0000", "/uploads/shell-a.php", "192.0.2.5")+
			withClient("24/Oct/2026:04:00:00 +0000", "/uploads/shell-a.php/extra", "192.0.2.10")+
			withClient("24/Oct/2026:04:00:00 +0000", "/shell-b.php", "2001:db8::1")+
			withClient("24/Oct/2026:06:00:00 +0000", "/shell-b.php", "client.example")+
			withClient("22/Oct/2026:00:00:00 +0000", "/unrelated.php", "192.0.2.99"))
	aBirth := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC).Unix()
	bBirth := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC).Unix()
	a := &finding{Path: "uploads/shell-a.php", URLPath: "/uploads/shell-a.php", BirthUnix: &aBirth, Accesses: accessSummary{Statuses: map[string]int64{}}}
	b := &finding{Path: "shell-b.php", URLPath: "/shell-b.php", BirthUnix: &bBirth, Accesses: accessSummary{Statuses: map[string]int64{}}}
	r := report{Findings: []*finding{a, b}}
	correlate(context.Background(), options{logs: stringsFlag{name}, maxAccesses: 1}, &r)
	var out bytes.Buffer
	if err := writeReport(&out, &r); err != nil {
		t.Fatal(err)
	}
	s := r.Summary
	if s.Requests != 6 || strings.Join(s.ClientIPs, ",") != "192.0.2.10,192.0.2.5,192.0.2.9,2001:db8::1" || s.EarliestRequest.Format(time.RFC3339) != "2026-10-23T04:00:00Z" || *s.EarliestBirthUnix != bBirth {
		t.Fatalf("bad summary: %+v", s)
	}
	if len(a.Accesses.Events) != 1 || len(b.Accesses.Events) != 1 {
		t.Fatal("test must exercise truncated timelines")
	}
	text := out.String()
	if strings.Count(text, "shell-a.php") != 2 || strings.Count(text, "shell-b.php") != 2 || strings.Contains(text, name) {
		t.Fatalf("request rows repeat file paths: %s", text)
	}
	for _, want := range []string{"CLIENT IP", "Matching requests: 6", "Earliest request: 2026-10-23 04:00:00 UTC", "Earliest known file birth: 2026-10-22 03:00:00 UTC", "Unique client IPs: 4"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	if !strings.HasSuffix(text, "      2001:db8::1\n") {
		t.Fatal("summary must be at the end")
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"client_ips":["192.0.2.10","192.0.2.5","192.0.2.9","2001:db8::1"]`) || !strings.Contains(string(encoded), `"target":"/uploads/shell-a.php"`) || !strings.Contains(string(encoded), `"log":`) {
		t.Fatalf("JSON lost summary or source detail: %s", encoded)
	}
}

func TestCLISubprocessAndReadableReport(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "suspicious file.php")
	put(t, name, "synthetic content")
	put(t, filepath.Join(root, "nested", "clean.php"), "clean")
	_ = os.Symlink(name, filepath.Join(root, "linked.php"))
	exe, _ := os.Executable()
	payload, _ := json.Marshal(map[string]interface{}{"path": name, "rules": []rule{{Identifier: "SyntheticRule", Meta: map[string]interface{}{"author": "Test Author", "description": "Test reason", "score": 75}}}})
	t.Setenv("FILESCAN_HELPER", "1")
	t.Setenv("FILESCAN_HELPER_OUTPUT", string(payload)+"\n")
	var out, stderr bytes.Buffer
	args := []string{"--yr", exe, "--path", root, "--no-logs"}
	if code := cli(context.Background(), args, &out, &stderr); code != 2 {
		t.Fatalf("exit=%d out=%s stderr=%s", code, out.String(), stderr.String())
	}
	for _, want := range []string{"Suspicious files: 1", `"suspicious file.php"`, "Born:", "Author: \"Test Author\"", "request history unavailable"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
	out.Reset()
	if code := cli(context.Background(), append(args, "--format=json"), &out, &stderr); code != 2 {
		t.Fatal(code)
	}
	var r report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Files != 2 || len(r.Findings) != 1 || len(r.Findings[0].Rules) != 1 {
		t.Fatalf("report=%+v", r)
	}
	// A zero exit from yr with diagnostics must still fail as incomplete.
	t.Setenv("FILESCAN_HELPER_DIAGNOSTIC", "error: scanning unreadable.php: denied")
	out.Reset()
	if code := cli(context.Background(), args, &out, &stderr); code != 1 || !strings.Contains(out.String(), "INCOMPLETE") {
		t.Fatalf("exit=%d %s", code, out.String())
	}
	t.Setenv("FILESCAN_HELPER_DIAGNOSTIC", "")
	t.Setenv("FILESCAN_HELPER_OUTPUT", "not JSON")
	if code := cli(context.Background(), args, io.Discard, &stderr); code != 1 {
		t.Fatal(code)
	}
	t.Setenv("FILESCAN_HELPER_OUTPUT", "")
	t.Setenv("FILESCAN_HELPER_FAIL", "1")
	if code := cli(context.Background(), args, io.Discard, &stderr); code != 1 {
		t.Fatal(code)
	}
	t.Setenv("FILESCAN_HELPER_FAIL", "")
	if code := cli(context.Background(), args, io.Discard, &stderr); code != 0 {
		t.Fatal(code)
	}
}

func TestParseMatchesAndOutputSafety(t *testing.T) {
	root := t.TempDir()
	o := options{root: root, prefix: "/"}
	for _, payload := range []string{`{}`, `{"path":"x","rules":[]}`, `{"path":"x","rules":[{}]}`} {
		if err := parseMatches(strings.NewReader(payload), o, &report{}); err == nil {
			t.Errorf("accepted %q", payload)
		}
	}
	outside, _ := json.Marshal(map[string]interface{}{"path": filepath.Join(root, "..", "outside.php"), "rules": []rule{{Identifier: "r"}}})
	if err := parseMatches(bytes.NewReader(outside), o, &report{}); err == nil {
		t.Fatal("accepted path outside root")
	}
	r := report{Root: "root\x1b[31m", Findings: []*finding{{Path: "evil\nfile.php", Rules: []rule{{Identifier: "r", Meta: map[string]interface{}{"author": "author\x1b[31m"}}}}}}
	var out bytes.Buffer
	if err := writeReport(&out, &r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "evil\nfile") {
		t.Fatal("unescaped terminal control characters")
	}
}

func TestBundledRulesManifest(t *testing.T) {
	data, err := bundledRules.ReadFile("rules/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := bundledRules.ReadDir("rules")
	var count int
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yar") && entry.Name() != "LICENSE" {
			continue
		}
		dataFile, _ := bundledRules.ReadFile("rules/" + entry.Name())
		hash := sha256.Sum256(dataFile)
		if !strings.Contains(string(data), hex.EncodeToString(hash[:])+"  "+entry.Name()+"\n") {
			t.Errorf("manifest mismatch: %s", entry.Name())
		}
		count++
	}
	if count != 8 {
		t.Fatalf("expected seven rule files and license, got %d", count)
	}
}

func TestRealYaraX(t *testing.T) {
	yr := os.Getenv("FILESCAN_TEST_YR")
	if yr == "" {
		var err error
		yr, err = exec.LookPath("yr")
		if err != nil {
			if os.Getenv("FILESCAN_REQUIRE_YR") == "1" {
				t.Fatal("CI requires yr on PATH: ", err)
			}
			t.Skip("install yr or set FILESCAN_TEST_YR for integration test")
		}
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// An inert textual marker: the scanner never runs PHP, and the decoded
	// string contains no code. Exercise a genuine upstream detection rule.
	put(t, filepath.Join(root, "wp-content", "uploads", "example.php"), "<?php eval(base64_decode('RklMRVNDQU5fVEVTVA=='));\n")
	put(t, filepath.Join(root, "clean.php"), "<?php echo 'Hello';\n")
	log := filepath.Join(t.TempDir(), "access.log")
	put(t, log, logLine("24/Oct/2026:12:00:00 +0700", "/wp-content/uploads/example.php?x=1", "200"))
	var out, stderr bytes.Buffer
	if code := cli(context.Background(), []string{"--yr", yr, "--path", root, "--logs", log, "--format=json"}, &out, &stderr); code != 2 {
		t.Fatalf("exit=%d stderr=%s out=%s", code, stderr.String(), out.String())
	}
	var r report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Incomplete || r.Files != 2 || len(r.Findings) != 1 || r.Findings[0].Accesses.Count != 1 {
		t.Fatalf("bad integration report: %s", out.String())
	}
	if r.Summary.Requests != 1 || len(r.Summary.ClientIPs) != 1 || r.Summary.ClientIPs[0] != "192.0.2.5" || r.Summary.EarliestRequest == nil {
		t.Fatalf("missing CLI summary: %+v", r.Summary)
	}
	matched := false
	for _, rule := range r.Findings[0].Rules {
		if rule.Identifier == "WEBSHELL_PHP_Gzinflated" {
			matched = true
		}
		if metaText(rule, "author") == "" {
			t.Fatal("lost rule attribution")
		}
	}
	if !matched {
		t.Fatalf("expected upstream generic PHP detection: %s", out.String())
	}
	if runtime.GOOS == "linux" {
		birth := r.Findings[0].BirthUnix
		if birth == nil {
			t.Log("filesystem does not expose birth time")
		} else if delta := time.Now().Unix() - *birth; delta < 0 || delta > 120 {
			t.Fatalf("unexpected birth: %d", *birth)
		}
	}
	// Confirm the same rule subset accepts a clean tree without detections.
	if err := os.Remove(filepath.Join(root, "wp-content", "uploads", "example.php")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := cli(context.Background(), []string{"--yr", yr, "--path", root, "--no-logs"}, &out, &stderr); code != 0 {
		t.Fatalf("clean scan exit=%d: %s", code, out.String())
	}
	// A custom rule replaces the defaults and scans files without PHP extensions.
	custom := filepath.Join(t.TempDir(), "custom.yar")
	put(t, custom, `rule CustomMarker { strings: $s = "FILESCAN_MARKER" condition: $s }`)
	put(t, filepath.Join(root, "marker.bin"), "FILESCAN_MARKER")
	out.Reset()
	if code := cli(context.Background(), []string{"--yr", yr, "--path", root, "--rules", custom, "--no-logs"}, &out, &stderr); code != 2 || !strings.Contains(out.String(), "CustomMarker") {
		t.Fatalf("custom scan exit=%d: %s", code, out.String())
	}
}
