package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func zipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, content := range files {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = io.WriteString(w, content); e != nil {
			t.Fatal(e)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type roundTrip func(*http.Request) (*http.Response, error)

func (r roundTrip) RoundTrip(q *http.Request) (*http.Response, error) { return r(q) }

func mockOfficial(t *testing.T) {
	t.Helper()
	core := map[string]string{
		"index.php": "clean index", "wp-load.php": "clean loader", "wp-settings.php": "clean settings",
		"wp-login.php": "clean login", "wp-cron.php": "clean cron", "xmlrpc.php": "clean rpc",
		"wp-config-sample.php": "sample", "readme.html": "readme", "license.txt": "license",
		"wp-admin/admin.php": "clean admin", "wp-includes/version.php": "<?php\n$wp_version = '6.8.3';\n",
		"wp-content/index.php": "clean content index", "wp-content/themes/default/index.php": "NEVER INSTALL",
		"wp-content/plugins/index.php":         "clean plugin placeholder",
		"wp-content/plugins/bundled/index.php": "NEVER INSTALL",
	}
	archive := map[string]string{}
	sums := map[string]string{}
	for name, content := range core {
		archive["wordpress/"+name] = content
		sums[name] = digest([]byte(content), "md5")
	}
	coreZIP := zipBytes(t, archive)
	checksums, _ := json.Marshal(map[string]interface{}{"checksums": sums})
	pluginZIP := zipBytes(t, map[string]string{"public/public.php": "<?php\n/*\nPlugin Name: Different official name\nVersion: 2.0\n*/\n", "public/clean.txt": "clean plugin asset"})
	oldTransport := http.DefaultTransport
	http.DefaultTransport = roundTrip(func(q *http.Request) (*http.Response, error) {
		status := 200
		var data []byte
		switch q.URL.Path {
		case "/core/checksums/1.0/":
			data = checksums
		case "/release/wordpress-6.8.3.zip":
			data = coreZIP
		case "/plugin/public.1.0.zip":
			status = 404 // exercise latest fallback
		case "/plugin/public.zip":
			data = pluginZIP
		default:
			status = 404
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(data)), Header: http.Header{}, Request: q}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = oldTransport })
}

func fixture(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "site")
	for path, content := range map[string]string{
		"wp-includes/version.php":  "<?php\n$wp_version = '6.8.3';\n",
		"wp-includes/injected.php": "malware", "wp-admin/injected.php": "malware",
		"index.php": "infected", "webshell.php": "malware", "wp-config.php": "keep config",
		"wp-content/index.php": "infected", "wp-content/themes/custom/functions.php": "keep theme",
		"wp-content/plugins/index.php":           "infected placeholder",
		"wp-content/plugins/public/public.php":   "<?php\n/*\nPlugin Name: Local custom name\nVersion: 1.0\nUpdate URI: https://commercial.example\n*/",
		"wp-content/plugins/public/backdoor.php": "malware", "wp-content/plugins/public/stale.txt": "stale",
		"wp-content/plugins/commercial/commercial.php": "<?php\n/* Plugin Name: Premium */",
		"wp-content/plugins/no-header/data.txt":        "custom",
		"wp-content/uploads/a.PhP":                     "malware", "wp-content/uploads/2026/picture.php.jpg": "malware",
		"wp-content/uploads/2026/backdoor.phtml": "malware", "wp-content/uploads/2026/payload.phar": "malware",
		"wp-content/uploads/photo.jpg": "keep image", "wp-content/mu-plugins/custom.php": "keep mu",
		"wp-content/object-cache.php": "keep drop-in", ".htaccess": "keep server config",
	} {
		put(t, filepath.Join(root, filepath.FromSlash(path)), content)
	}
	// Match the CLI's canonical path handling, including Windows 8.3 aliases
	// used by hosted runners' TEMP directories.
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestCleanupPreviewApplyAndRecovery(t *testing.T) {
	mockOfficial(t)
	root := fixture(t)
	before := tree(t, root)
	var out bytes.Buffer
	if err := cli(context.Background(), []string{"--path", root}, &out); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(before) != fmt.Sprint(tree(t, root)) {
		t.Fatal("preview modified the site")
	}
	reportPath := filepath.Join(filepath.Dir(root), "report.json")
	if err := cli(context.Background(), []string{"--path", root, "--apply", "--report", reportPath}, &out); err != nil {
		t.Fatal(err)
	}
	after := tree(t, root)
	for _, path := range []string{"wp-includes/injected.php", "wp-admin/injected.php", "webshell.php", "wp-content/plugins/public/backdoor.php", "wp-content/plugins/public/stale.txt", "wp-content/uploads/a.PhP", "wp-content/uploads/2026/picture.php.jpg", "wp-content/uploads/2026/backdoor.phtml", "wp-content/uploads/2026/payload.phar"} {
		if _, exists := after[path]; exists {
			t.Errorf("old file survived: %s", path)
		}
	}
	for _, path := range []string{"wp-config.php", ".htaccess", "wp-content/themes/custom/functions.php", "wp-content/plugins/commercial/commercial.php", "wp-content/plugins/no-header/data.txt", "wp-content/mu-plugins/custom.php", "wp-content/object-cache.php", "wp-content/uploads/photo.jpg"} {
		if after[path] != before[path] {
			t.Errorf("preserved file changed: %s", path)
		}
	}
	if after["index.php"] != "clean index" || after["wp-content/index.php"] != "clean content index" || after["wp-content/plugins/index.php"] != "clean plugin placeholder" || after["wp-content/plugins/public/clean.txt"] != "clean plugin asset" {
		t.Fatal("clean files not installed")
	}
	if _, ok := after["wp-content/themes/default/index.php"]; ok {
		t.Fatal("bundled theme installed")
	}
	b, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var r report
	if err = json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.Status != "applied" || r.Recovery == "" || len(r.Uploads) != 4 {
		t.Fatalf("bad report: %+v", r)
	}
	if err = cli(context.Background(), []string{"--recover", r.Recovery, "--apply"}, &out); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(before) != fmt.Sprint(tree(t, root)) {
		t.Fatal("recovery did not restore original tree")
	}
	if err = cli(context.Background(), []string{"--recover", r.Recovery, "--apply"}, &out); err != nil {
		t.Fatal("recovery not idempotent:", err)
	}
}

func TestExplicitPreserveOverridesAvailableSlug(t *testing.T) {
	mockOfficial(t)
	root := fixture(t)
	before := tree(t, root)
	var out bytes.Buffer
	if err := cli(context.Background(), []string{"--path", root, "--apply", "--preserve", "public"}, &out); err != nil {
		t.Fatal(err)
	}
	for path, data := range tree(t, root) {
		if strings.HasPrefix(path, "wp-content/plugins/public/") && data != before[path] {
			t.Fatal("explicitly preserved plugin changed")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "wp-content", "plugins", "public", "backdoor.php")); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackOnFailedInstallation(t *testing.T) {
	root := fixture(t)
	work := filepath.Join(filepath.Dir(root), "work")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(work, "core", "index.php"), "new index")
	j := journal{Root: root, State: "prepared", Operations: []operation{
		{Path: "index.php", Source: "core/index.php", HadOriginal: true},
		{Path: "new.php", Source: "core/missing.php"},
	}}
	if err := applyOperations(context.Background(), work, &j); err == nil {
		t.Fatal("expected installation failure")
	}
	loaded, err := loadJournal(work)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Operations[0].Started || !loaded.Operations[1].Started {
		t.Fatal("durable progress markers missing")
	}
	if err = rollback(work, loaded); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "index.php"))
	if string(b) != "infected" {
		t.Fatal("original not restored")
	}
	if _, err = os.Lstat(filepath.Join(root, "new.php")); !os.IsNotExist(err) {
		t.Fatal("new file survived rollback")
	}
}

func TestZIPRejectsTraversalLinksDuplicatesAndLimits(t *testing.T) {
	for _, name := range []string{"../escape.php", "public/../../escape.php", "public/C:/bad", "public/evil\\path", "public/NUL.php", "public/trailing. "} {
		t.Run(name, func(t *testing.T) {
			work := t.TempDir()
			src := filepath.Join(work, "bad.zip")
			put(t, src, string(zipBytes(t, map[string]string{name: "bad"})))
			if err := extractZIP(src, filepath.Join(work, "out"), "public"); err == nil {
				t.Fatal("accepted unsafe archive")
			}
		})
	}
	for _, mode := range []string{"symlink", "duplicate", "case", "huge"} {
		t.Run(mode, func(t *testing.T) {
			var b bytes.Buffer
			z := zip.NewWriter(&b)
			h := &zip.FileHeader{Name: "public/test.php", Method: zip.Store}
			if mode == "symlink" {
				h.SetMode(os.ModeSymlink | 0777)
			}
			w, _ := z.CreateHeader(h)
			io.WriteString(w, "x")
			if mode == "duplicate" {
				z.Create("public/test.php")
			}
			if mode == "case" {
				z.Create("public/TEST.php")
			}
			z.Close()
			if mode == "huge" {
				// Patch uncompressed size in the central-directory header.
				data := b.Bytes()
				offset := bytes.Index(data, []byte{'P', 'K', 1, 2})
				data[offset+24] = 0xff
				data[offset+25] = 0xff
				data[offset+26] = 0xff
				data[offset+27] = 0x7f
			}
			work := t.TempDir()
			src := filepath.Join(work, "bad.zip")
			put(t, src, b.String())
			if err := extractZIP(src, filepath.Join(work, "out"), "public"); err == nil {
				t.Fatal("accepted unsafe archive")
			}
		})
	}
}

func TestSymlinkUploadDoesNotTouchTarget(t *testing.T) {
	root := fixture(t)
	outside := filepath.Join(filepath.Dir(root), "outside.php")
	put(t, outside, "untouched")
	link := filepath.Join(root, "wp-content", "uploads", "link.php")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	uploads, _, err := inventoryReview(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rel := range uploads {
		if strings.HasSuffix(rel, "link.php") {
			found = true
		}
	}
	if !found {
		t.Fatal("PHP symlink not scheduled")
	}
	work := filepath.Join(filepath.Dir(root), "work")
	os.Mkdir(work, 0700)
	j := journal{Root: root, Operations: []operation{{Path: "wp-content/uploads/link.php", HadOriginal: true}}}
	if err := applyOperations(context.Background(), work, &j); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(outside)
	if string(b) != "untouched" {
		t.Fatal("followed symlink")
	}
	if err := rollback(work, &j); err != nil {
		t.Fatal(err)
	}
	if st, e := os.Lstat(link); e != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link not restored")
	}
}

func TestProtectedPathsAndHTTPHosts(t *testing.T) {
	for _, path := range []string{"wp-config.php", "wp-content/themes/custom", "wp-content/mu-plugins/a.php", "../index.php", "wp-content/plugins/../themes", "wp-content/uploads/photo.jpg", "wp-content/plugins/a/b"} {
		if allowedOperation(path) {
			t.Errorf("allowed protected path %s", path)
		}
	}
	for _, u := range []string{"http://wordpress.org/file.zip", "https://wordpress.org.evil.test/file.zip", "https://wordpress.org@evil.test/file.zip", "https://downloads.wordpress.org:444/file.zip"} {
		if trustedURL(u) == nil {
			t.Errorf("allowed untrusted URL %s", u)
		}
	}
}

func TestCorruptPackageDoesNotMutateSite(t *testing.T) {
	mockOfficial(t)
	original := http.DefaultTransport
	http.DefaultTransport = roundTrip(func(q *http.Request) (*http.Response, error) {
		if strings.HasSuffix(q.URL.Path, ".zip") {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("corrupt")), Header: http.Header{}}, nil
		}
		return original.RoundTrip(q)
	})
	root := fixture(t)
	before := tree(t, root)
	var out bytes.Buffer
	if err := cli(context.Background(), []string{"--path", root, "--apply"}, &out); err == nil {
		t.Fatal("expected bad package error")
	}
	if fmt.Sprint(before) != fmt.Sprint(tree(t, root)) {
		t.Fatal("site mutated after failed preparation")
	}
}

func TestPublishedPluginChecksums(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprint("corrupt=", corrupt), func(t *testing.T) {
			mockOfficial(t)
			original := http.DefaultTransport
			mainHash := digest([]byte("<?php\n/*\nPlugin Name: Different official name\nVersion: 2.0\n*/\n"), "sha256")
			if corrupt {
				mainHash = strings.Repeat("0", 64)
			}
			manifest, _ := json.Marshal(map[string]interface{}{"files": map[string]interface{}{
				"public.php": map[string]interface{}{"sha256": []string{mainHash, "another-historical-hash"}},
				"clean.txt":  map[string]interface{}{"md5": digest([]byte("clean plugin asset"), "md5")},
			}})
			http.DefaultTransport = roundTrip(func(q *http.Request) (*http.Response, error) {
				if q.URL.Path == "/plugin-checksums/public/2.0.json" {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(manifest)), Header: http.Header{}}, nil
				}
				return original.RoundTrip(q)
			})
			root := fixture(t)
			before := tree(t, root)
			var out bytes.Buffer
			err := cli(context.Background(), []string{"--path", root, "--apply"}, &out)
			if corrupt {
				if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
					t.Fatalf("expected checksum error, got %v", err)
				}
				if fmt.Sprint(before) != fmt.Sprint(tree(t, root)) {
					t.Fatal("checksum failure modified site")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPFailureAbortsRatherThanPreservingPlugin(t *testing.T) {
	mockOfficial(t)
	original := http.DefaultTransport
	http.DefaultTransport = roundTrip(func(q *http.Request) (*http.Response, error) {
		if strings.HasPrefix(q.URL.Path, "/plugin/") {
			return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable")), Header: http.Header{}}, nil
		}
		return original.RoundTrip(q)
	})
	root := fixture(t)
	before := tree(t, root)
	var out bytes.Buffer
	err := cli(context.Background(), []string{"--path", root, "--apply"}, &out)
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected server error, got %v", err)
	}
	if fmt.Sprint(before) != fmt.Sprint(tree(t, root)) {
		t.Fatal("server failure modified site")
	}
}

func TestSiteLockAndRecoveryProtection(t *testing.T) {
	root := fixture(t)
	lock, err := acquireLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(lock)
	if _, err := acquireLock(root); err == nil {
		t.Fatal("second writer acquired lock")
	}
	work := filepath.Join(filepath.Dir(root), "work")
	os.Mkdir(work, 0700)
	j := journal{Root: root, Operations: []operation{{Path: "wp-content/themes/custom", HadOriginal: true, Started: true}}}
	if err := rollback(work, &j); err == nil {
		t.Fatal("recovery accepted protected theme path")
	}
}
