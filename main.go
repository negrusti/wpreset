package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

var version = "dev"

type options struct {
	path, coreVersion, locale, preserve, report, recover string
	apply, latest                                        bool
	timeout                                              time.Duration
}

type report struct {
	Root          string      `json:"root"`
	Status        string      `json:"status"`
	CoreInstalled string      `json:"core_installed"`
	CoreTarget    string      `json:"core_target"`
	Locale        string      `json:"locale"`
	Plugins       []*plugin   `json:"plugins"`
	Uploads       []string    `json:"uploads_php"`
	Changes       []operation `json:"changes"`
	Review        []string    `json:"manual_review"`
	Recovery      string      `json:"recovery_directory,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := cli(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "wpreset:", err)
		os.Exit(1)
	}
}

func cli(ctx context.Context, args []string, out io.Writer) error {
	var o options
	var showVersion bool
	f := flag.NewFlagSet("wpreset", flag.ContinueOnError)
	f.SetOutput(out)
	f.BoolVar(&showVersion, "version", false, "print build version")
	f.StringVar(&o.path, "path", ".", "WordPress site directory")
	f.BoolVar(&o.apply, "apply", false, "apply the cleanup (default: preview only)")
	f.BoolVar(&o.latest, "latest", false, "use latest core and public plugin releases instead of installed versions")
	f.StringVar(&o.coreVersion, "core-version", "", "explicit WordPress release (overrides --latest for core)")
	f.StringVar(&o.locale, "locale", "", "core locale (default: detected, otherwise en_US)")
	f.StringVar(&o.preserve, "preserve", "", "comma-separated plugin directory/file names to leave intact")
	f.StringVar(&o.report, "report", "", "write JSON report outside the site directory")
	f.StringVar(&o.recover, "recover", "", "restore originals from a recovery directory; requires --apply")
	f.DurationVar(&o.timeout, "timeout", 2*time.Minute, "timeout per HTTP request")
	f.Usage = func() {
		fmt.Fprintln(out, "wpreset: replace WordPress core/public plugins and remove PHP from uploads.\n\nRun while the web server, PHP workers, cron and other site writers are stopped.\nPreview downloads and validates packages but does not change site files.\nUsage: wpreset [options]")
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", f.Arg(0))
	}
	if showVersion {
		fmt.Fprintln(out, "wpreset", version)
		return nil
	}
	if o.timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	if o.recover != "" {
		if !o.apply {
			return fmt.Errorf("--recover requires --apply")
		}
		return recoverRun(o.recover, out)
	}
	return run(ctx, o, out)
}

func run(ctx context.Context, o options, out io.Writer) error {
	root, err := filepath.Abs(o.path)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	if err = validateSite(root); err != nil {
		return err
	}
	if o.report != "" {
		o.report, err = filepath.Abs(o.report)
		if err != nil {
			return err
		}
		parent, e := filepath.EvalSymlinks(filepath.Dir(o.report))
		if e != nil {
			return e
		}
		o.report = filepath.Join(parent, filepath.Base(o.report))
		if within(root, o.report) {
			return fmt.Errorf("--report must be outside the site")
		}
		if _, e = os.Lstat(o.report); !os.IsNotExist(e) {
			return fmt.Errorf("report destination must not already exist")
		}
	}
	var lock string
	if o.apply {
		lock, err = acquireLock(root)
		if err != nil {
			return err
		}
		defer os.Remove(lock)
	}
	work, err := os.MkdirTemp(filepath.Dir(root), ".wpreset-recovery-")
	if err != nil {
		return fmt.Errorf("create private staging directory beside site: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			os.RemoveAll(work)
		}
	}()
	r := report{Root: root, Status: "preview", Locale: o.locale}
	installed, locale, err := coreDetails(filepath.Join(root, "wp-includes", "version.php"))
	if err != nil && o.coreVersion == "" && !o.latest {
		return fmt.Errorf("read core version: %w (use --core-version or --latest)", err)
	}
	r.CoreInstalled = installed
	if r.Locale == "" {
		r.Locale = locale
	}
	if r.Locale == "" {
		r.Locale = "en_US"
	}
	if !localePattern.MatchString(r.Locale) {
		return fmt.Errorf("invalid locale %q", r.Locale)
	}
	r.CoreTarget = installed
	if o.coreVersion != "" {
		r.CoreTarget = o.coreVersion
	}
	api := newOfficial(o.timeout)
	if o.latest && o.coreVersion == "" {
		r.CoreTarget, err = api.latestCore(ctx, r.Locale)
		if err != nil {
			return err
		}
	}
	if !versionPattern.MatchString(r.CoreTarget) {
		return fmt.Errorf("invalid core version %q", r.CoreTarget)
	}
	fmt.Fprintf(out, "Site: %s\nPreparing WordPress %s (%s)...\n", root, r.CoreTarget, r.Locale)
	core, err := api.prepareCore(ctx, work, r.CoreTarget, r.Locale)
	if err != nil {
		return err
	}
	r.Plugins, err = inventoryPlugins(root)
	if err != nil {
		return err
	}
	preserved := map[string]bool{}
	for _, name := range strings.Split(o.preserve, ",") {
		if name = strings.TrimSpace(name); name != "" {
			preserved[name] = true
		}
	}
	for i, p := range r.Plugins {
		if err := ctx.Err(); err != nil {
			return err
		}
		fmt.Fprintf(out, "Checking plugin %s...\n", p.Path)
		if preserved[p.Entry] {
			p.Reason = "explicitly preserved"
			continue
		}
		if p.Reason != "" {
			continue
		}
		if err = api.preparePlugin(ctx, work, i, p, o.latest); err != nil {
			return fmt.Errorf("plugin %s: %w; no site files changed", p.Path, err)
		}
	}
	for name := range preserved {
		found := false
		for _, p := range r.Plugins {
			if p.Entry == name {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("--preserve entry %q does not exist in plugin inventory", name)
		}
	}
	r.Uploads, r.Review, err = inventoryReview(root)
	if err != nil {
		return err
	}
	r.Changes, err = planOperations(root, work, core, r.Plugins, r.Uploads)
	if err != nil {
		return err
	}
	printReport(out, &r)
	if o.apply {
		if err = ctx.Err(); err != nil {
			return err
		}
		j := journal{Root: root, State: "prepared", Operations: r.Changes}
		if err = saveJournal(work, &j); err != nil {
			return err
		}
		keep = true
		r.Recovery = work
		fmt.Fprintf(out, "Recovery directory: %s\n", work)
		if err = applyOperations(ctx, work, &j); err != nil {
			r.Status = "failed"
			undoErr := rollback(work, &j)
			if undoErr != nil {
				err = fmt.Errorf("%v; recovery also failed: %v; run --recover %q --apply", err, undoErr, work)
			} else {
				err = fmt.Errorf("%v; originals restored", err)
			}
			if o.report != "" {
				if e := writeReport(o.report, &r); e != nil {
					err = fmt.Errorf("%v; report: %v", err, e)
				}
			}
			return err
		}
		r.Status = "applied"
		fmt.Fprintln(out, "Cleanup applied. Recovery copies contain compromised files; keep them offline.")
	} else {
		fmt.Fprintln(out, "Preview only. Run with --apply to perform these changes.")
	}
	if o.report != "" {
		if err = writeReport(o.report, &r); err != nil {
			return err
		}
	}
	return nil
}

func printReport(out io.Writer, r *report) {
	fmt.Fprintf(out, "\nCore: %s -> %s (%s)\n", r.CoreInstalled, r.CoreTarget, r.Locale)
	for _, p := range r.Plugins {
		if p.Stage != "" {
			fmt.Fprintf(out, "REPLACE  %s  %s -> %s (%s)\n", p.Path, p.Version, p.Target, p.Checksums)
		} else {
			fmt.Fprintf(out, "PRESERVE %s  %s\n", p.Path, p.Reason)
		}
	}
	fmt.Fprintf(out, "PHP files to remove from uploads: %d\n", len(r.Uploads))
	for _, p := range r.Uploads {
		fmt.Fprintln(out, "REMOVE  ", p)
	}
	for _, op := range r.Changes {
		if !strings.HasPrefix(op.Path, "wp-content/") {
			fmt.Fprintln(out, "CORE    ", op.Path)
		}
	}
	for _, p := range r.Review {
		fmt.Fprintln(out, "REVIEW  ", p)
	}
	fmt.Fprintln(out, "Themes, wp-config.php, database, MU plugins and drop-ins are preserved and need separate review.")
}

func writeReport(path string, r *report) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	err = e.Encode(r)
	if ce := f.Close(); err == nil {
		err = ce
	}
	return err
}
