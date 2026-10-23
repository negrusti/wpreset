package main

import (
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type rule struct {
	id, severity, reason string
	pattern              *regexp.Regexp
}

var rules = []rule{
	{"php-tag", "medium", "PHP opening tag in stored data", regexp.MustCompile(`(?i)<\?(?:php\b|=)`)},
	{"dynamic-execution", "medium", "Dynamic code execution function", regexp.MustCompile(`(?i)\b(?:eval|assert|Function)\s*\(`)},
	{"php-decoder", "medium", "PHP decoding or decompression function", regexp.MustCompile(`(?i)\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(`)},
	{"remote-php-include", "high", "PHP include/require using a remote or executable stream", regexp.MustCompile(`(?i)\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?['"](?:https?|ftp|data|php)://`)},
	{"process-execution", "high", "Process execution function; verify owning plugin and intent", regexp.MustCompile(`(?i)\b(?:shell_exec|passthru|system|proc_open|popen)\s*\(`)},
	{"script-element", "medium", "Stored HTML script element", regexp.MustCompile(`(?i)<\s*script\b`)},
	{"iframe-element", "low", "Stored iframe; often a legitimate embed", regexp.MustCompile(`(?i)<\s*iframe\b`)},
	{"html-event-handler", "medium", "Executable HTML event attribute", regexp.MustCompile(`(?i)\bon(?:error|load|click|mouseover|focus|animationstart|pointerenter)\s*=`)},
	{"javascript-url", "medium", "JavaScript URL scheme", regexp.MustCompile(`(?i)javascript[\x00-\x20]*:`)},
	{"javascript-decoder", "medium", "JavaScript decoder or character-code construction", regexp.MustCompile(`(?i)\b(?:atob|unescape|fromCharCode)\s*\(`)},
	{"browser-redirect", "medium", "Browser navigation code; verify destination", regexp.MustCompile(`(?i)\b(?:(?:window|document|top|self)\s*\.\s*)?location\s*(?:\.\s*(?:href\s*=|(?:replace|assign)\s*\()|=)`)},
}

var dynamicCode = regexp.MustCompile(`(?i)\b(?:eval|assert|Function)\s*\(`)
var decoderCode = regexp.MustCompile(`(?i)\b(?:base64_decode|gzinflate|gzuncompress|atob|fromCharCode)\s*\(`)
var base64Blocks = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
var hexBlocks = regexp.MustCompile(`(?i)\b(?:0x)?[0-9a-f]{24,}\b`)
var escapedText = regexp.MustCompile(`\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[\\/"'])`)

type hit struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
	Encoding string `json:"encoding"`
	Excerpt  string `json:"excerpt"`
}

type detector struct{ depth, maxDecoded, minSeverity int }
type layer struct {
	text, path string
	depth      int
}

// Literal prefilters avoid running every regexp over the many ordinary settings,
// IDs and short text fields found in a WordPress dump.
func couldMatch(id, lower string) bool {
	switch id {
	case "php-tag":
		return strings.Contains(lower, "<?")
	case "dynamic-execution":
		return strings.Contains(lower, "eval") || strings.Contains(lower, "assert") || strings.Contains(lower, "function")
	case "php-decoder":
		return strings.Contains(lower, "base64_decode") || strings.Contains(lower, "gzinflate") || strings.Contains(lower, "gzuncompress") || strings.Contains(lower, "gzdecode") || strings.Contains(lower, "str_rot13")
	case "remote-php-include":
		return strings.Contains(lower, "include") || strings.Contains(lower, "require")
	case "process-execution":
		return strings.Contains(lower, "shell_exec") || strings.Contains(lower, "passthru") || strings.Contains(lower, "system") || strings.Contains(lower, "proc_open") || strings.Contains(lower, "popen")
	case "script-element":
		return strings.Contains(lower, "script")
	case "iframe-element":
		return strings.Contains(lower, "iframe")
	case "html-event-handler":
		for _, name := range []string{"onerror", "onload", "onclick", "onmouseover", "onfocus", "onanimationstart", "onpointerenter"} {
			if strings.Contains(lower, name) {
				return true
			}
		}
		return false
	case "javascript-url":
		return strings.Contains(lower, "javascript")
	case "javascript-decoder":
		return strings.Contains(lower, "atob") || strings.Contains(lower, "unescape") || strings.Contains(lower, "fromcharcode")
	case "browser-redirect":
		return strings.Contains(lower, "location")
	}
	return true
}

func severity(s string) int {
	switch s {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	}
	return 0
}

func excerpt(s string, start, end int) string {
	if start > 80 {
		start -= 80
	} else {
		start = 0
	}
	if end > start+320 {
		end = start + 320
	}
	if end+120 < len(s) {
		end += 120
	} else {
		end = len(s)
	}
	for start > 0 && !utf8.RuneStart(s[start]) {
		start--
	}
	for end < len(s) && !utf8.RuneStart(s[end]) {
		end++
	}
	return strings.ToValidUTF8(s[start:end], "\uFFFD")
}

func (d detector) scan(s string) ([]hit, bool) {
	queue := []layer{{s, "sql", 0}}
	seen := map[string]bool{s: true}
	matched := make(map[string]bool)
	var hits []hit
	remaining := d.maxDecoded
	limited := false
	add := func(v, path string, depth int) {
		if v == "" || seen[v] {
			return
		}
		if len(v) > remaining {
			limited = true
			return
		}
		remaining -= len(v)
		seen[v] = true
		queue = append(queue, layer{v, path, depth})
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		lower := strings.ToLower(current.text)
		for _, r := range rules {
			if matched[r.id] || severity(r.severity) < d.minSeverity || !couldMatch(r.id, lower) {
				continue
			}
			if loc := r.pattern.FindStringIndex(current.text); loc != nil {
				matched[r.id] = true
				hits = append(hits, hit{r.id, r.severity, r.reason, current.path, excerpt(current.text, loc[0], loc[1])})
			}
		}
		if !matched["obfuscated-execution"] && couldMatch("dynamic-execution", lower) && dynamicCode.MatchString(current.text) {
			if loc := decoderCode.FindStringIndex(current.text); loc != nil {
				matched["obfuscated-execution"] = true
				hits = append(hits, hit{"obfuscated-execution", "high", "Dynamic execution combined with a decoder in the same value", current.path, excerpt(current.text, loc[0], loc[1])})
			}
		}
		if current.depth >= d.depth {
			continue
		}
		nextDepth := current.depth + 1
		path := current.path + " -> "
		if strings.Contains(current.text, "&") {
			add(html.UnescapeString(current.text), path+"html", nextDepth)
		}
		if strings.Contains(current.text, "%") {
			if v, err := url.PathUnescape(current.text); err == nil {
				add(v, path+"percent", nextDepth)
			}
		}
		if strings.Contains(current.text, "\\") {
			v := escapedText.ReplaceAllStringFunc(current.text, func(m string) string {
				if len(m) == 2 {
					return m[1:]
				}
				n, err := strconv.ParseUint(m[2:], 16, 32)
				if err != nil {
					return m
				}
				if m[1] == 'x' {
					return string([]byte{byte(n)})
				}
				if n >= 0xd800 && n <= 0xdfff {
					return m
				}
				return string(rune(n))
			})
			add(v, path+"string-escapes", nextDepth)
		}
		// Decode candidates incrementally. Both count and cumulative output
		// limits keep adversarial encoded data from expanding without bound.
		for _, block := range []struct {
			re   *regexp.Regexp
			kind string
		}{{base64Blocks, "base64"}, {hexBlocks, "hex"}} {
			if len(current.text) < 16 {
				continue
			}
			locs := block.re.FindAllStringIndex(current.text, 65)
			if len(locs) > 64 {
				limited = true
				locs = locs[:64]
			}
			for _, loc := range locs {
				candidate := current.text[loc[0]:loc[1]]
				if len(candidate) > 2*remaining+4 {
					limited = true
					continue
				}
				var b []byte
				var err error
				if block.kind == "hex" {
					b, err = hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(candidate, "0x"), "0X"))
				} else {
					candidate = strings.TrimRight(candidate, "=")
					b, err = base64.RawStdEncoding.DecodeString(candidate)
					if err != nil {
						b, err = base64.RawURLEncoding.DecodeString(candidate)
					}
				}
				if err == nil {
					add(string(b), path+block.kind, nextDepth)
				}
			}
		}
		// gzip/zlib have recognizable headers. Raw DEFLATE is attempted only
		// on decoded candidates, never on every ordinary text value.
		var reader io.ReadCloser
		var err error
		kind := ""
		if strings.HasPrefix(current.text, "\x1f\x8b") {
			kind = "gzip"
			reader, err = gzip.NewReader(strings.NewReader(current.text))
		} else if len(current.text) >= 2 && current.text[0]&15 == 8 && (int(current.text[0])*256+int(current.text[1]))%31 == 0 {
			kind = "zlib"
			reader, err = zlib.NewReader(strings.NewReader(current.text))
		} else if strings.HasSuffix(current.path, "base64") || strings.HasSuffix(current.path, "hex") {
			kind = "deflate"
			reader = flate.NewReader(strings.NewReader(current.text))
		}
		if reader != nil && err == nil {
			b, readErr := io.ReadAll(io.LimitReader(reader, int64(remaining)+1))
			reader.Close()
			if len(b) > remaining {
				limited = true
			} else if readErr == nil {
				add(string(b), path+kind, nextDepth)
			}
		}
	}
	return hits, limited
}

type keyField struct {
	Column string `json:"column"`
	Value  string `json:"value"`
	Type   string `json:"type"`
}

type identity struct {
	Kind      string     `json:"kind"`
	Fields    []keyField `json:"fields"`
	Ambiguous bool       `json:"ambiguous"`
}

func identify(r row) (identity, string) {
	var candidates [][]string
	if r.schema != nil {
		if len(r.schema.primary) > 0 {
			candidates = append(candidates, r.schema.primary)
		}
		candidates = append(candidates, r.schema.unique...)
	}
	for _, columns := range candidates {
		id := identity{Kind: "unique_key"}
		if r.schema != nil && len(r.schema.primary) > 0 && equalColumns(columns, r.schema.primary) {
			id.Kind = "primary_key"
		}
		for _, c := range columns {
			i := columnIndex(r.columns, c)
			if i < 0 || (r.values[i].kind != 's' && r.values[i].kind != 'n') {
				id.Fields = nil
				break
			}
			id.Fields = append(id.Fields, field(r.columns[i], r.values[i]))
		}
		if len(id.Fields) == len(columns) {
			return id, selection(r.table, id)
		}
	}
	// A nullable UNIQUE key is unsuitable when any component is NULL.
	// For keyless tables, offer a small candidate selector explicitly marked
	// ambiguous. A dump row ordinal cannot identify a row in the live DB.
	id := identity{Kind: "non_unique_values", Ambiguous: true, Fields: []keyField{}}
	for i, c := range r.columns {
		v := r.values[i]
		if (v.kind == 's' || v.kind == 'n') && len(v.text) <= 256 {
			id.Fields = append(id.Fields, field(c, v))
			if len(id.Fields) == 4 {
				break
			}
		}
	}
	return id, selection(r.table, id)
}

func equalColumns(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func field(c string, v value) keyField {
	t := "bytes"
	if v.kind == 'n' {
		t = "number"
	}
	return keyField{c, v.text, t}
}

func selection(table tableName, id identity) string {
	if len(id.Fields) == 0 {
		return ""
	}
	var parts []string
	for _, f := range id.Fields {
		literal := "X'" + hex.EncodeToString([]byte(f.Value)) + "'"
		if f.Type == "number" {
			literal = f.Value
		}
		parts = append(parts, quoteID(f.Column)+" = "+literal)
	}
	return fmt.Sprintf("SELECT * FROM %s WHERE %s;", table.sql(), strings.Join(parts, " AND "))
}
