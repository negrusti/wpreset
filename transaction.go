package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type operation struct {
	Path        string `json:"path"`
	Source      string `json:"source,omitempty"`
	HadOriginal bool   `json:"had_original"`
	Started     bool   `json:"started"`
}

type journal struct {
	Root       string      `json:"root"`
	State      string      `json:"state"`
	Operations []operation `json:"operations"`
}

func isCoreRootName(name string) bool {
	return name != "wp-config.php" && (phpPattern.MatchString(name) || name == "readme.html" || name == "license.txt")
}

func planOperations(root, work, core string, plugins []*plugin, uploads []string) ([]operation, error) {
	var ops []operation
	add := func(rel, source string) error {
		if !allowedOperation(rel) {
			return fmt.Errorf("refusing protected or unexpected path: %s", rel)
		}
		parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(rel)))
		if parent != "." {
			if err := noLinks(root, parent); err != nil {
				return err
			}
		}
		_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		op := operation{Path: rel, HadOriginal: err == nil}
		if source != "" {
			s, e := filepath.Rel(work, source)
			if e != nil {
				return e
			}
			op.Source = filepath.ToSlash(s)
		}
		ops = append(ops, op)
		return nil
	}
	entries, err := os.ReadDir(core)
	if err != nil {
		return nil, err
	}
	newRoot := map[string]bool{}
	for _, entry := range entries {
		n := entry.Name()
		if n == "wp-content" {
			continue
		}
		if n == "wp-config.php" || (entry.IsDir() && n != "wp-admin" && n != "wp-includes") {
			return nil, fmt.Errorf("unexpected core package entry: %s", n)
		}
		newRoot[n] = true
		if err = add(n, filepath.Join(core, n)); err != nil {
			return nil, err
		}
	}
	// Restore core placeholders without touching themes or bundled plugins.
	for _, rel := range []string{"wp-content/index.php", "wp-content/plugins/index.php"} {
		if _, e := os.Stat(filepath.Join(root, filepath.Dir(filepath.FromSlash(rel)))); os.IsNotExist(e) {
			continue
		}
		if _, err = os.Stat(filepath.Join(core, filepath.FromSlash(rel))); err == nil {
			if err = add(rel, filepath.Join(core, filepath.FromSlash(rel))); err != nil {
				return nil, err
			}
		}
	}
	oldRoot, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range oldRoot {
		n := entry.Name()
		if !entry.IsDir() && n != "wp-config.php" && phpPattern.MatchString(n) && !newRoot[n] {
			if err = add(n, ""); err != nil {
				return nil, err
			}
		}
	}
	for _, p := range plugins {
		if p.Stage != "" {
			if err = add(p.Path, p.Stage); err != nil {
				return nil, err
			}
		}
	}
	for _, p := range uploads {
		if err = add(p, ""); err != nil {
			return nil, err
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].Path < ops[j].Path })
	return ops, nil
}

func allowedOperation(rel string) bool {
	if !safeRelative(rel) {
		return false
	}
	if rel == "wp-admin" || rel == "wp-includes" || rel == "wp-content/index.php" {
		return true
	}
	if !strings.Contains(rel, "/") {
		return isCoreRootName(rel)
	}
	if strings.HasPrefix(rel, "wp-content/plugins/") {
		return !strings.Contains(strings.TrimPrefix(rel, "wp-content/plugins/"), "/")
	}
	return strings.HasPrefix(rel, "wp-content/uploads/") && phpPattern.MatchString(filepath.Base(rel))
}

func lockPath(root string) string {
	h := sha256.Sum256([]byte(strings.ToLower(root)))
	return filepath.Join(filepath.Dir(root), ".wpreset-lock-"+hex.EncodeToString(h[:8]))
}

func acquireLock(root string) (string, error) {
	path := lockPath(root)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("cannot lock site; another run or interrupted run may exist (%s): %w", path, err)
	}
	_, err = fmt.Fprintf(f, "pid=%d\nsite=%s\n", os.Getpid(), root)
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func saveJournal(work string, j *journal) error {
	// Immutable durable snapshots also work on Windows without replacing an
	// existing file. A sequence number selects the most recent complete snapshot.
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(work, "journal-*.json")
	if err != nil {
		return err
	}
	name := f.Name()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		os.Remove(name)
		return err
	}
	// Partial temporary files without a sequence are ignored during recovery.
	entries, err := os.ReadDir(work)
	if err != nil {
		return err
	}
	next := 1
	for _, e := range entries {
		var n int
		if _, e := fmt.Sscanf(e.Name(), "state-%09d.json", &n); e == nil && n >= next {
			next = n + 1
		}
	}
	if err = os.Rename(name, filepath.Join(work, fmt.Sprintf("state-%09d.json", next))); err != nil {
		return err
	}
	return syncDirectory(work)
}

func validateJournal(work string, j *journal) error {
	root, err := filepath.Abs(j.Root)
	if err != nil || root != j.Root {
		return fmt.Errorf("invalid recovery site path")
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || canonical != root {
		return fmt.Errorf("site root changed or is a link")
	}
	if within(root, work) || within(work, root) {
		return fmt.Errorf("recovery directory must be outside site")
	}
	seen := map[string]bool{}
	for _, op := range j.Operations {
		if !allowedOperation(op.Path) || seen[op.Path] {
			return fmt.Errorf("unsafe/duplicate journal operation: %s", op.Path)
		}
		seen[op.Path] = true
		if op.Source != "" && (!safeRelative(op.Source) || !(strings.HasPrefix(op.Source, "core/") || strings.HasPrefix(op.Source, "plugin-"))) {
			return fmt.Errorf("unsafe journal source")
		}
		parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(op.Path)))
		if parent != "." {
			if err := noLinks(root, parent); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyOperations(ctx context.Context, work string, j *journal) error {
	if err := validateJournal(work, j); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(work, "originals"), 0700); err != nil {
		return err
	}
	j.State = "applying"
	if err := saveJournal(work, j); err != nil {
		return err
	}
	for i := range j.Operations {
		if err := ctx.Err(); err != nil {
			return err
		}
		op := &j.Operations[i]
		dest := filepath.Join(j.Root, filepath.FromSlash(op.Path))
		parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(op.Path)))
		if parent != "." {
			if err := noLinks(j.Root, parent); err != nil {
				return err
			}
		}
		_, e := os.Lstat(dest)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if (e == nil) != op.HadOriginal {
			return fmt.Errorf("site changed after planning: %s", op.Path)
		}
		op.Started = true
		if err := markStarted(work, i); err != nil {
			return err
		}
		if op.HadOriginal {
			if err := durableRename(dest, filepath.Join(work, "originals", fmt.Sprint(i))); err != nil {
				return fmt.Errorf("save original %s: %w", op.Path, err)
			}
		}
		if op.Source != "" {
			if err := durableRename(filepath.Join(work, filepath.FromSlash(op.Source)), dest); err != nil {
				return fmt.Errorf("install %s: %w", op.Path, err)
			}
		}
	}
	j.State = "complete"
	return saveJournal(work, j)
}

func rollback(work string, j *journal) error {
	if j.State == "rolled_back" {
		return nil
	}
	if err := validateJournal(work, j); err != nil {
		return err
	}
	if err := noLinks(work, "originals"); err != nil {
		return err
	}
	for i := len(j.Operations) - 1; i >= 0; i-- {
		op := &j.Operations[i]
		if !op.Started {
			continue
		}
		dest := filepath.Join(j.Root, filepath.FromSlash(op.Path))
		backup := filepath.Join(work, "originals", fmt.Sprint(i))
		if op.HadOriginal {
			if _, err := os.Lstat(backup); os.IsNotExist(err) {
				continue
			} else if err != nil {
				return err
			}
			// RemoveAll does not traverse a symlink at its final component.
			if err := os.RemoveAll(dest); err != nil {
				return err
			}
			if err := durableRename(backup, dest); err != nil {
				return err
			}
		} else if op.Source != "" {
			if err := os.RemoveAll(dest); err != nil {
				return err
			}
		}
	}
	j.State = "rolled_back"
	return saveJournal(work, j)
}

func loadJournal(work string) (*journal, error) {
	entries, err := os.ReadDir(work)
	if err != nil {
		return nil, err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		name := entries[i].Name()
		if !strings.HasPrefix(name, "state-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		if err := noLinks(work, name); err != nil {
			return nil, err
		}
		b, e := os.ReadFile(filepath.Join(work, name))
		if e != nil {
			return nil, e
		}
		var j journal
		if e = json.Unmarshal(b, &j); e != nil {
			return nil, fmt.Errorf("invalid recovery journal %s: %w", name, e)
		}
		for i := range j.Operations {
			marker := fmt.Sprintf("op-%09d.started", i)
			if err := noLinks(work, marker); err != nil {
				return nil, err
			}
			if st, err := os.Stat(filepath.Join(work, marker)); err == nil {
				if !st.Mode().IsRegular() {
					return nil, fmt.Errorf("invalid operation marker")
				}
				j.Operations[i].Started = true
			} else if !os.IsNotExist(err) {
				return nil, err
			}
		}
		return &j, nil
	}
	return nil, fmt.Errorf("no recovery journal found in %s", work)
}

func markStarted(work string, index int) error {
	f, err := os.OpenFile(filepath.Join(work, fmt.Sprintf("op-%09d.started", index)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = f.Sync()
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	return syncDirectory(work)
}

func recoverRun(work string, out io.Writer) error {
	work, err := filepath.Abs(work)
	if err != nil {
		return err
	}
	work, err = filepath.EvalSymlinks(work)
	if err != nil {
		return err
	}
	j, err := loadJournal(work)
	if err != nil {
		return err
	}
	if err = validateJournal(work, j); err != nil {
		return err
	}
	// Never steal a lock automatically: a live cleanup may still own it.
	lock, err := acquireLock(j.Root)
	if err != nil {
		return fmt.Errorf("%w; stop any running cleanup, then remove that stale lock before recovery", err)
	}
	defer os.Remove(lock)
	if err = rollback(work, j); err != nil {
		return err
	}
	fmt.Fprintln(out, "Original files restored. These files may be compromised; recovery reverses cleanup.")
	return nil
}

func durableRename(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(from)); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(to))
}
