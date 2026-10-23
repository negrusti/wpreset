package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func safeRelative(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\:\x00") || path.IsAbs(name) || path.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") {
		return false
	}
	for _, p := range strings.Split(name, "/") {
		if strings.TrimRight(p, ". ") != p || strings.ContainsAny(p, "<>\"|?*") {
			return false
		}
		base := strings.ToUpper(strings.SplitN(p, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9') {
			return false
		}
	}
	return true
}

func extractZIP(src, dest, prefix string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	if len(r.File) > 100000 {
		return fmt.Errorf("too many ZIP entries")
	}
	if err = os.Mkdir(dest, 0755); err != nil {
		return err
	}
	var total uint64
	seen := map[string]bool{}
	canonical := map[string]string{}
	for _, f := range r.File {
		name := strings.TrimSuffix(f.Name, "/")
		if !safeRelative(name) {
			return fmt.Errorf("unsafe ZIP path %q", f.Name)
		}
		if name == prefix && f.FileInfo().IsDir() {
			continue
		}
		if !strings.HasPrefix(name, prefix+"/") {
			return fmt.Errorf("unexpected ZIP package root %q", f.Name)
		}
		rel := strings.TrimPrefix(name, prefix+"/")
		parts := strings.Split(rel, "/")
		for i := range parts {
			component := strings.Join(parts[:i+1], "/")
			key := strings.ToLower(component)
			if previous, ok := canonical[key]; ok && previous != component {
				return fmt.Errorf("case-colliding ZIP paths: %s and %s", previous, component)
			}
			canonical[key] = component
		}
		key := strings.ToLower(rel)
		if seen[key] {
			return fmt.Errorf("duplicate ZIP path: %s", name)
		}
		seen[key] = true
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 || (!mode.IsRegular() && !mode.IsDir()) {
			return fmt.Errorf("special file in ZIP: %s", name)
		}
		if f.UncompressedSize64 > 256<<20 {
			return fmt.Errorf("ZIP file exceeds 256 MiB")
		}
		total += f.UncompressedSize64
		if total > 2<<30 {
			return fmt.Errorf("ZIP expands beyond 2 GiB")
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if !within(dest, target) {
			return fmt.Errorf("ZIP path escaped staging directory")
		}
		if mode.IsDir() {
			if err = os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		input, e := f.Open()
		if e != nil {
			return e
		}
		output, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if e != nil {
			input.Close()
			return e
		}
		n, e := io.Copy(output, io.LimitReader(input, int64(f.UncompressedSize64)+1))
		ic, oc := input.Close(), output.Close()
		if e != nil {
			return e
		}
		if ic != nil {
			return ic
		}
		if oc != nil {
			return oc
		}
		if uint64(n) != f.UncompressedSize64 {
			return fmt.Errorf("invalid ZIP size: %s", name)
		}
	}
	return nil
}
