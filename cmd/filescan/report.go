package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

func utc(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") }

func quotedRequest(target string) string {
	chars := []rune(target)
	if len(chars) <= 180 {
		return strconv.Quote(target)
	}
	return fmt.Sprintf("%s ... (%d more characters; full request in JSON)", strconv.Quote(string(chars[:180])), len(chars)-180)
}

func metaText(r rule, key string) string {
	v := r.Meta[key]
	if v == nil {
		return ""
	}
	// YARA-X represents duplicate metadata keys as an array.
	if list, ok := v.([]interface{}); ok {
		var values []string
		for _, item := range list {
			values = append(values, fmt.Sprint(item))
		}
		return strings.Join(values, "; ")
	}
	return fmt.Sprint(v)
}

func writeReport(w io.Writer, r *report) error {
	var b strings.Builder
	state := "COMPLETE"
	if r.Incomplete {
		state = "INCOMPLETE"
	}
	fmt.Fprintf(&b, "FILESCAN  |  %s  |  all times UTC\nRoot: %q\nRules: %q\n", state, r.Root, r.Ruleset)
	fmt.Fprintf(&b, "Files submitted: %d  |  Suspicious files: %d  |  Links/special files skipped: %d\n", r.Files, len(r.Findings), r.Skipped)
	fmt.Fprintf(&b, "Access logs: %d  |  Lines read: %d\n", len(r.Logs), r.LogLines)
	for _, warning := range r.Warnings {
		fmt.Fprintf(&b, "Warning: %q\n", warning)
	}
	b.WriteString("\n")
	if len(r.Findings) == 0 {
		if r.Incomplete {
			b.WriteString("No findings reported so far; scan coverage is incomplete.\n")
		} else {
			b.WriteString("No suspicious files matched the selected rules.\n")
		}
	}
	for i, f := range r.Findings {
		fmt.Fprintf(&b, "%d. %q\n", i+1, f.Path)
		if f.BirthUnix == nil {
			fmt.Fprintf(&b, "   Born: unavailable - %s\n", f.BirthNote)
		} else {
			fmt.Fprintf(&b, "   Born: %s UTC  |  Unix: %d\n", utc(time.Unix(*f.BirthUnix, 0)), *f.BirthUnix)
		}
		fmt.Fprintf(&b, "   URL:  %q\n", f.URLPath)
		for _, rule := range f.Rules {
			fmt.Fprintf(&b, "   Rule: %q", rule.Identifier)
			if score := metaText(rule, "score"); score != "" {
				fmt.Fprintf(&b, "  |  score %q", score)
			}
			b.WriteByte('\n')
			if desc := metaText(rule, "description"); desc != "" {
				fmt.Fprintf(&b, "         %q\n", desc)
			}
			if author := metaText(rule, "author"); author != "" {
				fmt.Fprintf(&b, "         Author: %q\n", author)
			}
		}
		a := f.Accesses
		if len(r.Logs) == 0 {
			b.WriteString("   HTTP: request history unavailable\n\n")
			continue
		}
		if a.Count == 0 {
			b.WriteString("   HTTP: no matching requests in the logs read\n\n")
			continue
		}
		var statuses []string
		for status, count := range a.Statuses {
			statuses = append(statuses, status+"="+strconv.FormatInt(count, 10))
		}
		sort.Strings(statuses)
		fmt.Fprintf(&b, "   HTTP: %d requests  |  status counts: %s\n", a.Count, strings.Join(statuses, ", "))
		fmt.Fprintf(&b, "   First: %s UTC\n   Last:  %s UTC\n", utc(*a.First), utc(*a.Last))
		if a.BeforeBirth > 0 {
			fmt.Fprintf(&b, "   Note: %d requests predate the current file's birth (e.g. replaced file, prior path, or clock differences).\n", a.BeforeBirth)
		}
		fmt.Fprintf(&b, "\n   Request timeline (%d of %d rows, earliest first):\n", len(a.Events), a.Count)
		b.WriteString("   TIME (UTC)           STATUS  METHOD  CLIENT / REQUEST\n")
		for _, event := range a.Events {
			fmt.Fprintf(&b, "   %s  %3d     %-7s %s  %s\n", utc(event.Time), event.Status, strconv.Quote(event.Method), strconv.Quote(event.Client), quotedRequest(event.Target))
			fmt.Fprintf(&b, "      %q:%d", event.Log, event.Line)
			if event.VHost != "" {
				fmt.Fprintf(&b, "  vhost=%q", event.VHost)
			}
			b.WriteByte('\n')
		}
		if int64(len(a.Events)) < a.Count {
			b.WriteString("   More requests omitted from timeline; increase --max-accesses or use 0 for all.\n")
		}
		b.WriteByte('\n')
	}
	b.WriteString("Matches need review. HTTP entries are requests, including errors; they do not prove execution.\nCorrelation uses URL paths relative to --path/--url-prefix. Shared-host logs, rewrites and aliases need context.\n")
	_, err := io.WriteString(w, b.String())
	return err
}
