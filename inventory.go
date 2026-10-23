package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var versionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}(?:[-a-zA-Z0-9.]*)$`)
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var localePattern = regexp.MustCompile(`^[a-z]{2,3}(?:_[A-Z]{2})?(?:_[a-z0-9]+)?$`)
var phpPattern = regexp.MustCompile(`(?i)\.(?:php[0-9]*|phtml|pht|phar)(?:\.|$)`)

type plugin struct {
	Path      string            `json:"path"`
	Entry     string            `json:"entry"`
	Slug      string            `json:"slug"`
	Name      string            `json:"name,omitempty"`
	Version   string            `json:"installed_version,omitempty"`
	Target    string            `json:"target_version,omitempty"`
	Reason    string            `json:"preserve_reason,omitempty"`
	Main      string            `json:"main_file,omitempty"`
	Stage     string            `json:"-"`
	Header    map[string]string `json:"-"`
	Single    bool              `json:"single_file"`
	Checksums string            `json:"checksums,omitempty"`
}

func within(root, path string) bool {
	r, err := filepath.Rel(root, path)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) && !filepath.IsAbs(r)
}

// Reject links on every existing component; never follow a site-controlled link.
func noLinks(root, rel string) error {
	if !safeRelative(filepath.ToSlash(rel)) {
		return fmt.Errorf("unsafe relative path %q", rel)
	}
	p := root
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		p = filepath.Join(p, part)
		st, err := os.Lstat(p)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symbolic link: %s", p)
		}
	}
	return nil
}

func validateSite(root string) error {
	for _, rel := range []string{"wp-admin", "wp-includes", "wp-content"} {
		if err := noLinks(root, rel); err != nil {
			return err
		}
		s, err := os.Stat(filepath.Join(root, rel))
		if err != nil || !s.IsDir() {
			return fmt.Errorf("%s must be a real directory", filepath.Join(root, rel))
		}
	}
	for _, rel := range []string{"wp-config.php", "wp-content/plugins", "wp-content/uploads", "wp-includes/version.php"} {
		if err := noLinks(root, rel); err != nil {
			return err
		}
	}
	return nil
}

func readPrefix(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !s.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	return io.ReadAll(io.LimitReader(f, 8192))
}

func headers(path string) (map[string]string, error) {
	b, err := readPrefix(path)
	if err != nil {
		return nil, err
	}
	h := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r", "\n"), "\n") {
		line = strings.TrimLeft(line, " \t/*#\xEF\xBB\xBF")
		pair := strings.SplitN(line, ":", 2)
		if len(pair) == 2 {
			key := strings.ToLower(strings.TrimSpace(pair[0]))
			if _, exists := h[key]; !exists {
				h[key] = strings.TrimSpace(strings.SplitN(pair[1], "*/", 2)[0])
			}
		}
	}
	return h, nil
}

func coreDetails(path string) (string, string, error) {
	b, err := readPrefix(path)
	if err != nil {
		return "", "", err
	}
	value := func(name string) string {
		re := regexp.MustCompile(`(?m)^\s*\$` + name + `\s*=\s*['"]([^'"\r\n]+)['"]\s*;`)
		m := re.FindSubmatch(b)
		if m == nil {
			return ""
		}
		return string(m[1])
	}
	v, l := value("wp_version"), value("wp_local_package")
	if !versionPattern.MatchString(v) {
		return "", l, fmt.Errorf("no valid literal $wp_version found")
	}
	return v, l, nil
}

func inventoryPlugins(root string) ([]*plugin, error) {
	dir := filepath.Join(root, "wp-content", "plugins")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var plugins []*plugin
	for _, entry := range entries {
		name := entry.Name()
		// This WordPress-owned placeholder is restored with core, not by slug.
		if name == "index.php" {
			continue
		}
		p := &plugin{Entry: name, Path: "wp-content/plugins/" + name, Slug: name}
		plugins = append(plugins, p)
		if entry.Type()&os.ModeSymlink != 0 {
			p.Reason = "symbolic link; manual review required"
			continue
		}
		var candidates []string
		if entry.IsDir() {
			files, e := os.ReadDir(filepath.Join(dir, name))
			if e != nil {
				return nil, e
			}
			for _, file := range files {
				if file.Type().IsRegular() && strings.EqualFold(filepath.Ext(file.Name()), ".php") {
					candidates = append(candidates, file.Name())
				}
			}
		} else if entry.Type().IsRegular() && strings.EqualFold(filepath.Ext(name), ".php") {
			p.Single = true
			p.Slug = strings.TrimSuffix(name, filepath.Ext(name))
			candidates = []string{name}
		} else {
			p.Reason = "unrecognized file; manual review required"
			continue
		}
		for _, candidate := range candidates {
			path := filepath.Join(dir, name, candidate)
			if p.Single {
				path = filepath.Join(dir, candidate)
			}
			h, e := headers(path)
			if e != nil {
				return nil, e
			}
			if h["plugin name"] != "" {
				if p.Main != "" {
					continue
				}
				p.Main, p.Header, p.Name, p.Version = candidate, h, h["plugin name"], h["version"]
			}
		}
		if !slugPattern.MatchString(p.Slug) {
			p.Reason = "nonstandard plugin slug; manual review required"
		}
		if p.Single && name == "hello.php" {
			p.Slug = "hello-dolly"
		}
	}
	return plugins, nil
}

func inventoryReview(root string) ([]string, []string, error) {
	var uploads, review []string
	base := filepath.Join(root, "wp-content", "uploads")
	if _, err := os.Lstat(base); err == nil {
		err = filepath.WalkDir(base, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(root, path)
			if e != nil {
				return e
			}
			rel = filepath.ToSlash(rel)
			if d.Type()&os.ModeSymlink != 0 {
				if phpPattern.MatchString(d.Name()) {
					uploads = append(uploads, rel)
				} else {
					review = append(review, rel+" (symbolic link; target not traversed)")
				}
				return nil
			}
			if !d.IsDir() && phpPattern.MatchString(d.Name()) {
				if !d.Type().IsRegular() {
					return fmt.Errorf("unsupported special upload file: %s", rel)
				}
				uploads = append(uploads, rel)
			}
			if !d.IsDir() && (d.Name() == ".htaccess" || d.Name() == ".user.ini") {
				review = append(review, rel+" (may enable PHP execution)")
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	for _, dir := range []string{"", "wp-content"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			return nil, nil, err
		}
		for _, e := range entries {
			n := e.Name()
			rel := filepath.ToSlash(filepath.Join(dir, n))
			if dir == "wp-content" && (n == "plugins" || n == "themes" || n == "uploads") {
				continue
			}
			if dir == "" && (n == "wp-admin" || n == "wp-includes" || n == "wp-content" || isCoreRootName(n)) {
				continue
			}
			review = append(review, rel)
		}
	}
	sort.Strings(uploads)
	sort.Strings(review)
	return uploads, review, nil
}
