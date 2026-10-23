package main

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxDownload = 512 << 20

type official struct{ client *http.Client }
type unavailable struct{ status int }

func (e unavailable) Error() string { return fmt.Sprintf("HTTP %d", e.status) }

func trustedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return fmt.Errorf("untrusted download URL: %s", raw)
	}
	switch u.Host {
	case "api.wordpress.org", "downloads.wordpress.org", "wordpress.org", "downloads.w.org":
		return nil
	}
	return fmt.Errorf("untrusted download host: %s", u.Host)
}

func newOfficial(timeout time.Duration) *official {
	return &official{client: &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return trustedURL(req.URL.String())
	}}}
}

func (a *official) get(ctx context.Context, raw string) (*http.Response, error) {
	if err := trustedURL(raw); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wpreset/1.0 (WordPress file recovery)")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, unavailable{resp.StatusCode}
	}
	return resp, nil
}

func (a *official) json(ctx context.Context, raw string, dst interface{}) error {
	r, err := a.get(ctx, raw)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, (32<<20)+1))
	if err != nil {
		return err
	}
	if len(b) > 32<<20 {
		return fmt.Errorf("API response too large")
	}
	return json.Unmarshal(b, dst)
}

func (a *official) download(ctx context.Context, raw, dest string) error {
	r, err := a.get(ctx, raw)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.ContentLength > maxDownload {
		return fmt.Errorf("download exceeds 512 MiB")
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r.Body, maxDownload+1))
	if ce := f.Close(); err == nil {
		err = ce
	}
	if n > maxDownload {
		return fmt.Errorf("download exceeds 512 MiB")
	}
	return err
}

func (a *official) latestCore(ctx context.Context, locale string) (string, error) {
	var data struct {
		Offers []struct{ Response, Version, Locale string }
	}
	if err := a.json(ctx, "https://api.wordpress.org/core/version-check/1.7/?locale="+url.QueryEscape(locale), &data); err != nil {
		return "", err
	}
	for _, o := range data.Offers {
		if o.Response == "upgrade" && o.Locale == locale && versionPattern.MatchString(o.Version) {
			return o.Version, nil
		}
	}
	return "", fmt.Errorf("no latest core release available for locale %s", locale)
}

func (a *official) prepareCore(ctx context.Context, work, version, locale string) (string, error) {
	var sums struct {
		Checksums map[string]string `json:"checksums"`
	}
	if err := a.json(ctx, "https://api.wordpress.org/core/checksums/1.0/?version="+url.QueryEscape(version)+"&locale="+url.QueryEscape(locale), &sums); err != nil {
		return "", fmt.Errorf("core checksums: %w", err)
	}
	if len(sums.Checksums) < 10 {
		return "", fmt.Errorf("missing core checksums for %s/%s", version, locale)
	}
	base := "https://downloads.wordpress.org/release/"
	if locale != "en_US" {
		base += locale + "/"
	}
	zipPath := filepath.Join(work, "core.zip")
	if err := a.download(ctx, base+"wordpress-"+version+".zip", zipPath); err != nil {
		return "", fmt.Errorf("core download: %w", err)
	}
	dir := filepath.Join(work, "core")
	if err := extractZIP(zipPath, dir, "wordpress"); err != nil {
		return "", err
	}
	// Only these areas are installed; bundled themes and plugins are ignored.
	err := verifyTree(dir, func(rel string, data []byte) error {
		if strings.HasPrefix(rel, "wp-content/") && rel != "wp-content/index.php" && rel != "wp-content/plugins/index.php" {
			return nil
		}
		expected, ok := sums.Checksums[rel]
		if !ok || digest(data, "md5") != expected {
			return fmt.Errorf("core checksum mismatch or unlisted file: %s", rel)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	for rel := range sums.Checksums {
		if strings.HasPrefix(rel, "wp-content/") && rel != "wp-content/index.php" && rel != "wp-content/plugins/index.php" {
			continue
		}
		if !safeRelative(rel) {
			return "", fmt.Errorf("unsafe core checksum path")
		}
		if st, e := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); e != nil || !st.Mode().IsRegular() {
			return "", fmt.Errorf("core package missing %s", rel)
		}
	}
	v, _, err := coreDetails(filepath.Join(dir, "wp-includes", "version.php"))
	if err != nil || v != version {
		return "", fmt.Errorf("core package version does not match requested release")
	}
	return dir, nil
}

func missing(err error) bool {
	e, ok := err.(unavailable)
	return ok && (e.status == 404 || e.status == 410)
}

func (a *official) preparePlugin(ctx context.Context, work string, index int, p *plugin, latest bool) error {
	// Slug availability alone determines eligibility. Local headers are only
	// version hints, never an identity check or reason to exclude a directory.
	base := "https://downloads.wordpress.org/plugin/" + p.Slug
	download := base + ".zip"
	if !latest && versionPattern.MatchString(p.Version) {
		download = base + "." + p.Version + ".zip"
	}
	zipPath := filepath.Join(work, fmt.Sprintf("plugin-%d.zip", index))
	err := a.download(ctx, download, zipPath)
	if missing(err) && download != base+".zip" {
		err = a.download(ctx, base+".zip", zipPath)
	}
	if missing(err) {
		p.Reason = "WordPress.org package is not directly downloadable"
		return nil
	} else if err != nil {
		return err
	}
	dir := filepath.Join(work, fmt.Sprintf("plugin-%d", index))
	if err = extractZIP(zipPath, dir, p.Slug); err != nil {
		return err
	}
	p.Target = "latest"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("empty plugin package")
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.EqualFold(filepath.Ext(entry.Name()), ".php") {
			continue
		}
		h, e := headers(filepath.Join(dir, entry.Name()))
		if e != nil {
			return e
		}
		if h["plugin name"] != "" && versionPattern.MatchString(h["version"]) {
			p.Target = h["version"]
			break
		}
	}
	// WordPress.org does not publish checksums for every historical package.
	// Verify them when available; TLS and constrained official hosts are always required.
	var sums struct {
		Files map[string]map[string]json.RawMessage `json:"files"`
	}
	err = a.json(ctx, "https://downloads.wordpress.org/plugin-checksums/"+p.Slug+"/"+p.Target+".json", &sums)
	p.Checksums = "not published; HTTPS only"
	if err != nil && !missing(err) {
		return fmt.Errorf("plugin checksums: %w", err)
	}
	if err == nil {
		p.Checksums = "verified against WordPress.org manifest"
		if len(sums.Files) == 0 {
			return fmt.Errorf("empty plugin checksum manifest")
		}
		if err = verifyTree(dir, func(rel string, data []byte) error {
			hashes, ok := sums.Files[rel]
			if !ok {
				return fmt.Errorf("unlisted plugin package file: %s", rel)
			}
			algorithm := "sha256"
			raw := hashes[algorithm]
			if len(raw) == 0 {
				algorithm = "md5"
				raw = hashes[algorithm]
			}
			var values []string
			var single string
			if e := json.Unmarshal(raw, &single); e == nil {
				values = []string{single}
			} else if e := json.Unmarshal(raw, &values); e != nil {
				return fmt.Errorf("invalid checksum for %s", rel)
			}
			actual := digest(data, algorithm)
			for _, expected := range values {
				if actual == expected {
					return nil
				}
			}
			return fmt.Errorf("plugin checksum mismatch: %s", rel)
		}); err != nil {
			return err
		}
		for rel := range sums.Files {
			if !safeRelative(rel) {
				return fmt.Errorf("unsafe checksum path")
			}
			if st, e := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); e != nil || !st.Mode().IsRegular() {
				return fmt.Errorf("plugin package missing %s", rel)
			}
		}
	}
	if p.Single {
		main := p.Entry
		// A loose-file plugin can only be restored without changing its activation
		// path when the package is itself a single script plus documentation.
		entries, e := os.ReadDir(dir)
		if e != nil {
			return e
		}
		found := false
		for _, f := range entries {
			if f.Name() == main && !f.IsDir() {
				found = true
				continue
			}
			n := strings.ToLower(f.Name())
			if f.IsDir() || !(n == "readme.txt" || n == "readme.md" || n == "license.txt" || n == "license") {
				p.Reason = "download requires a directory; loose-file installation needs manual reinstall"
				return nil
			}
		}
		if !found {
			p.Reason = "download cannot preserve loose-file activation path"
			return nil
		}
		p.Stage = filepath.Join(dir, main)
	} else {
		p.Stage = dir
	}
	return nil
}

func digest(data []byte, algorithm string) string {
	if algorithm == "sha256" {
		s := sha256.Sum256(data)
		return hex.EncodeToString(s[:])
	}
	s := md5.Sum(data)
	return hex.EncodeToString(s[:])
}

func verifyTree(dir string, check func(string, []byte) error) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return check(filepath.ToSlash(rel), b)
	})
}
