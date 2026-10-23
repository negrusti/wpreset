package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

func testOptions() options { return options{"jsonl", "medium", 16 << 20, 64 << 20, 1 << 20, 3} }

func parseRows(sql string) ([]row, error) {
	var rows []row
	p := &parser{l: newLexer(strings.NewReader(sql), 16<<20), onRow: func(r row) error { rows = append(rows, r); return nil }}
	err := p.parse()
	return rows, err
}

const optionsSchema = "CREATE TABLE `wp_options` (`option_id` bigint NOT NULL, `option_name` varchar(191), `option_value` longtext, PRIMARY KEY (`option_id`), UNIQUE KEY `name` (`option_name`)) ENGINE=InnoDB;\n"

func TestMultiRowMappingAndSQLLiterals(t *testing.T) {
	sql := "-- ordinary dump\n/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;\nUSE `wordpress`;\n" + optionsSchema +
		"INSERT INTO `wp_options` VALUES (7,'safe','a,;() ''quoted'' \\'value\\' \\n second line'),(8,'evil','<script>location.href=\\\"https://example.invalid\\\"</script>');\n" +
		"/*!40000 ALTER TABLE `wp_options` DISABLE KEYS */;\n" +
		"INSERT INTO `wordpress`.`wp_options` (`option_value`,`option_id`,`option_name`) VALUES (X'3c3f706870206576616c2831293b',9,_utf8mb4 'snippet');\n" +
		"/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;"
	rows, err := parseRows(sql)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows: %d", len(rows))
	}
	if rows[0].values[2].text != "a,;() 'quoted' 'value' \n second line" {
		t.Fatalf("escaped string: %q", rows[0].values[2].text)
	}
	for i, want := range []string{"7", "8", "9"} {
		id, query := identify(rows[i])
		if id.Kind != "primary_key" || id.Ambiguous || len(id.Fields) != 1 || id.Fields[0].Value != want {
			t.Fatalf("row %d: %+v", i, id)
		}
		if query != "SELECT * FROM `wordpress`.`wp_options` WHERE `option_id` = "+want+";" {
			t.Fatal(query)
		}
	}
	if rows[2].values[0].text != "<?php eval(1);" {
		t.Fatal(rows[2].values)
	}
}

func TestCompositeUniqueAndKeylessIdentity(t *testing.T) {
	tests := []struct {
		name, sql, kind string
		fields          int
		ambiguous       bool
		query           string
	}{
		{"composite primary", "CREATE TABLE t (a int,b varchar(20),payload text,CONSTRAINT pk PRIMARY KEY(a,b)); INSERT INTO t VALUES(4,'ab','<script>x</script>');", "primary_key", 2, false, "`a` = 4 AND `b` = X'6162'"},
		{"unique fallback", "CREATE TABLE t (id int PRIMARY KEY,name varchar(20) UNIQUE,payload text); INSERT INTO t(name,payload) VALUES('bob','<script>x</script>');", "unique_key", 1, false, "`name` = X'626f62'"},
		{"null unique", "CREATE TABLE t (name varchar(20),payload text, UNIQUE KEY name(name)); INSERT INTO t VALUES(NULL,'<script>x</script>');", "non_unique_values", 1, true, "`payload` = X'"},
		{"composite nullable unique", "CREATE TABLE t (a int,b int,payload text, UNIQUE KEY ab(a,b)); INSERT INTO t VALUES(1,NULL,'<script>x</script>');", "non_unique_values", 2, true, "`a` = 1"},
		{"keyless", "CREATE TABLE t (name text,payload text); INSERT INTO t VALUES('some name','<script>x</script>');", "non_unique_values", 2, true, "`name` = X'"},
		{"data only", "INSERT INTO t(id,payload) VALUES(1,'<script>x</script>');", "non_unique_values", 2, true, "`id` = 1"},
		{"binary primary", "CREATE TABLE t (id varbinary(20) PRIMARY KEY,payload text); INSERT INTO t VALUES(0x00ff,'<script>x</script>');", "primary_key", 1, false, "`id` = X'00ff'"},
		{"prefix unique conservative", "CREATE TABLE t (a text,payload text, UNIQUE KEY a(a(10))); INSERT INTO t VALUES('key','<script>x</script>');", "non_unique_values", 2, true, "`a` = X'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := parseRows(tt.sql)
			if err != nil {
				t.Fatal(err)
			}
			id, query := identify(rows[0])
			if id.Kind != tt.kind || len(id.Fields) != tt.fields || id.Ambiguous != tt.ambiguous || !strings.Contains(query, tt.query) {
				t.Fatalf("id=%+v query=%s", id, query)
			}
		})
	}
}

func TestSQLModesCommentsAndLiteralKinds(t *testing.T) {
	sql := "\xef\xbb\xbf/*M!999999\\- enable the sandbox mode */\n/* comment */\n# another\n-- another\n/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE */;\n" +
		"SET SQL_MODE='NO_BACKSLASH_ESCAPES,ANSI_QUOTES';\n" +
		"CREATE TABLE \"odd``table\" (\"key\" int PRIMARY KEY,\"s\" text,\"n\" double,\"b\" blob);" +
		"INSERT INTO \"odd``table\" VALUES(1,'a\\n and ''q''',-1.5e+3,b'100000001');" +
		"/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;\n" +
		"REPLACE INTO `odd````table` VALUES(2,'a\\n',.5,0xabc);"
	rows, err := parseRows(sql)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].values[1].text != `a\n and 'q'` || rows[1].values[1].text != "a\n" {
		t.Fatalf("SQL mode escaped incorrectly: %+v %+v", rows[0].values, rows[1].values)
	}
	if rows[0].values[2].text != "-1.5e+3" || rows[1].values[2].text != ".5" {
		t.Fatal("numeric literal mismatch")
	}
	if rows[0].values[3].text != "\x01\x01" || rows[1].values[3].text != "\x0a\xbc" {
		t.Fatal("binary literal mismatch")
	}
}

func TestMalformedDumpFails(t *testing.T) {
	tests := []string{
		optionsSchema + "INSERT INTO wp_options VALUES(1,'x','unfinished",
		optionsSchema + "INSERT INTO wp_options VALUES(1,'x');",
		optionsSchema + "INSERT INTO wp_options VALUES(1,'x','a',4);",
		optionsSchema + "INSERT INTO wp_options VALUES(1,'x',CONCAT('a','b'));",
		optionsSchema + "INSERT INTO wp_options VALUES(1,'x',DEFAULT);",
		optionsSchema + "INSERT INTO wp_options SELECT * FROM another;",
		optionsSchema + "INSERT INTO wp_options VALUES(1,'x','a') ON DUPLICATE KEY UPDATE option_name='z';",
		"INSERT INTO t VALUES(1,'x');",
		"CREATE TABLE t (id int PRIMARY KEY,v text); INSERT INTO t(id,id) VALUES(1,2);",
		"CREATE TABLE t (id int PRIMARY KEY,v text); INSERT INTO t(id,missing) VALUES(1,2);",
		"CREATE TABLE t (id int PRIMARY KEY,v text); INSERT INTO t VALUES(1,0xzz);",
		"CREATE TABLE t (id int PRIMARY KEY,v text); INSERT INTO t VALUES(1,b'103');",
		"DELIMITER ;;\nCREATE TRIGGER x;",
		"UPDATE wp_options SET option_value='evil';",
		"ALTER TABLE t ADD COLUMN extra text;",
		"/* unterminated",
		"/*!40101 SET SQL_MODE='X';",
		"this is not a SQL dump",
	}
	for i, sql := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			_, err := parseRows(sql)
			if err == nil {
				t.Fatalf("accepted unsupported/malformed SQL: %s", sql)
			}
			if !strings.Contains(err.Error(), "line") || !strings.Contains(err.Error(), "byte") {
				t.Fatal(err)
			}
		})
	}
}

func compressPayload(t *testing.T, kind, s string) string {
	t.Helper()
	var b bytes.Buffer
	var w io.WriteCloser
	switch kind {
	case "gzip":
		w = gzip.NewWriter(&b)
	case "zlib":
		w = zlib.NewWriter(&b)
	case "deflate":
		var err error
		w, err = flate.NewWriter(&b, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestEncodedPayloads(t *testing.T) {
	payload := `<script>eval(atob("YWxlcnQoMSk="));location.href='https://example.invalid'</script>`
	cases := map[string]string{
		"raw":     payload,
		"base64":  "s:128:\"" + base64.StdEncoding.EncodeToString([]byte(payload)) + "\";",
		"hex":     hex.EncodeToString([]byte(payload)),
		"html":    "&lt;script&gt;eval(atob('a'));location.href='x'&lt;/script&gt;",
		"escaped": `\u003cscript\u003eeval(atob('a'))\u003c/script\u003e`,
		"percent": `%3Cscript%3Eeval(atob('a'))%3C/script%3E`,
	}
	for _, kind := range []string{"gzip", "zlib", "deflate"} {
		cases["base64+"+kind] = base64.StdEncoding.EncodeToString([]byte(compressPayload(t, kind, payload)))
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			hits, limited := (detector{3, 1 << 20, 2}).scan(text)
			if limited {
				t.Fatal("unexpected decoding limit")
			}
			foundScript, foundObfuscated := false, false
			for _, h := range hits {
				if h.Rule == "script-element" {
					foundScript = true
				}
				if h.Rule == "obfuscated-execution" {
					foundObfuscated = true
				}
			}
			if !foundScript || !foundObfuscated {
				t.Fatalf("missing payload detection: %+v", hits)
			}
		})
	}
}

func TestDetectionLimitsAndSeverity(t *testing.T) {
	payload := "<script>" + strings.Repeat(" ", 10000) + "</script>"
	encoded := base64.StdEncoding.EncodeToString([]byte(compressPayload(t, "gzip", payload)))
	_, limited := (detector{3, 512, 2}).scan(encoded)
	if !limited {
		t.Fatal("decompression budget not enforced")
	}
	hits, _ := (detector{0, 1024, 3}).scan("<script>eval(atob('x'))</script>")
	if len(hits) != 1 || hits[0].Rule != "obfuscated-execution" {
		t.Fatal(hits)
	}
	hits, _ = (detector{3, 1024, 2}).scan("ordinary article with no executable content")
	if len(hits) != 0 {
		t.Fatal(hits)
	}
	hits, _ = (detector{0, 1024, 2}).scan(base64.StdEncoding.EncodeToString([]byte(payload)))
	if len(hits) != 0 {
		t.Fatal("decode-depth=0 was ignored")
	}
	hits, _ = (detector{1, 1024, 1}).scan("<iframe src='video'></iframe>")
	if len(hits) != 1 || hits[0].Severity != "low" {
		t.Fatal(hits)
	}
	hits, _ = (detector{3, 1024, 2}).scan(base64.StdEncoding.EncodeToString([]byte("<?php eval(1);")))
	if len(hits) == 0 {
		t.Fatal("short encoded PHP payload missed")
	}
}

func TestBareSnippetRules(t *testing.T) {
	for _, tt := range []struct{ text, rule string }{
		{`require_once("https://example.invalid/payload.php");`, "remote-php-include"},
		{`include 'php://input';`, "remote-php-include"},
		{`document.write(String.fromCharCode(60,115,99,114,105,112,116,62));`, "javascript-decoder"},
	} {
		hits, _ := (detector{3, 1024, 2}).scan(tt.text)
		found := false
		for _, h := range hits {
			if h.Rule == tt.rule {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s: %+v", tt.rule, hits)
		}
	}
}

func TestExampleFile(t *testing.T) {
	var out, log bytes.Buffer
	code := cli([]string{"--format=jsonl", "testdata/example.sql"}, strings.NewReader(""), &out, &log)
	if code != 2 || !strings.Contains(log.String(), "Scanned 4 rows") {
		t.Fatalf("exit=%d log=%s", code, log.String())
	}
	dec := json.NewDecoder(&out)
	var ids []string
	for {
		var f finding
		err := dec.Decode(&f)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if f.Table == "wp_options" {
			if f.Row.Ambiguous {
				t.Fatal(f)
			}
			ids = append(ids, f.Row.Fields[0].Value)
		} else if f.Table == "wp_plugin_templates" && !f.Row.Ambiguous {
			t.Fatal(f)
		}
	}
	if !strings.Contains(strings.Join(ids, ","), "1843") {
		t.Fatal("encoded fixture not detected")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("report destination failed") }

func TestReportWriteFailure(t *testing.T) {
	for _, format := range []string{"jsonl", "text"} {
		o := testOptions()
		o.format = format
		_, err := scanDump(strings.NewReader(optionsSchema+"INSERT INTO wp_options VALUES(1,'x','<script>x</script>');"), o, failWriter{}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "report destination failed") {
			t.Fatal(err)
		}
	}
}

func TestCLIJSONAndGzip(t *testing.T) {
	sql := optionsSchema + "INSERT INTO wp_options VALUES(17,'widget_custom_html','<script>location.href=\\\"https://example.invalid\\\"</script>');"
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprint(compressed), func(t *testing.T) {
			input := sql
			if compressed {
				input = compressPayload(t, "gzip", sql)
			}
			var out, log bytes.Buffer
			code := cli([]string{"--format=jsonl", "-"}, strings.NewReader(input), &out, &log)
			if code != 2 {
				t.Fatalf("exit %d: %s", code, log.String())
			}
			dec := json.NewDecoder(&out)
			count := 0
			for {
				var f finding
				err := dec.Decode(&f)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count++
				if f.Row.Kind != "primary_key" || f.Row.Fields[0].Value != "17" || f.Column != "option_value" || f.Context["option_name"] != "widget_custom_html" || f.Query != "SELECT * FROM `wp_options` WHERE `option_id` = 17;" {
					t.Fatalf("bad finding: %+v", f)
				}
			}
			if count == 0 || !strings.Contains(log.String(), "Scanned 1 rows") {
				t.Fatal(log.String())
			}
		})
	}
}

func TestCLIErrorAndNoFindings(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		input   string
		code    int
		message string
	}{
		{"clean", []string{"-"}, optionsSchema + "INSERT INTO wp_options VALUES(1,'name','safe');", 0, "0 findings"},
		{"empty", []string{"-"}, "", 0, "no INSERT/REPLACE"},
		{"bad", []string{"-"}, optionsSchema + "INSERT INTO wp_options VALUES(1,'x','oops'", 1, "INCOMPLETE"},
		{"limit", []string{"--max-value-bytes=16", "-"}, "INSERT INTO t(v) VALUES('" + strings.Repeat("x", 17) + "');", 1, "max-value-bytes"},
		{"row limit", []string{"--max-row-bytes=4", "-"}, "INSERT INTO t(a,b) VALUES('abc','def');", 1, "max-row-bytes"},
		{"format", []string{"--format=invalid", "-"}, "", 1, "invalid"},
		{"args", nil, "", 1, "Usage:"},
		{"help", []string{"--help"}, "", 0, "Usage:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, log bytes.Buffer
			code := cli(tt.args, strings.NewReader(tt.input), &out, &log)
			if code != tt.code || !strings.Contains(log.String(), tt.message) {
				t.Fatalf("exit=%d log=%s", code, log.String())
			}
		})
	}
	compressed := compressPayload(t, "gzip", optionsSchema+"INSERT INTO wp_options VALUES(1,'x','safe');")
	var out, log bytes.Buffer
	if code := cli([]string{"-"}, strings.NewReader(compressed[:len(compressed)-4]), &out, &log); code != 1 || !strings.Contains(log.String(), "INCOMPLETE") {
		t.Fatalf("accepted corrupt gzip: %d %s", code, log.String())
	}
}

func TestLongValueAndManyRows(t *testing.T) {
	var sql strings.Builder
	sql.WriteString(optionsSchema)
	sql.WriteString("INSERT INTO wp_options VALUES ")
	for i := 0; i < 3000; i++ {
		if i != 0 {
			sql.WriteByte(',')
		}
		fmt.Fprintf(&sql, "(%d,'name%d','%s')", i, i, strings.Repeat("small ", 30))
	}
	sql.WriteString(",(9000,'long','" + strings.Repeat("x ", 100000) + "<script>alert(1)</script>');")
	var out, log bytes.Buffer
	s, err := scanDump(strings.NewReader(sql.String()), testOptions(), &out, &log)
	if err != nil {
		t.Fatal(err)
	}
	if s.rows != 3001 || s.findings != 1 || !strings.Contains(out.String(), `"value":"9000"`) {
		t.Fatalf("stats=%+v output=%s", s, out.String())
	}
}

func TestReportEscapesTerminalControlsAndSafeLookup(t *testing.T) {
	sql := "CREATE TABLE `bad``table` (`id` varchar(50) PRIMARY KEY,v text); INSERT INTO `bad``table` VALUES('a'' OR 1=1 --','<script>\\x1b[31m</script>');"
	rows, err := parseRows(sql)
	if err != nil {
		t.Fatal(err)
	}
	id, query := identify(rows[0])
	if strings.Contains(query, "OR 1=1") || !strings.Contains(query, "`bad``table`") {
		t.Fatal(query)
	}
	f := finding{Table: "t\x1b[31m", Row: id, Query: query, hit: hit{Severity: "medium", Excerpt: "<script>\x1b[31m\n"}}
	var out bytes.Buffer
	if err := writeText(&out, f); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Fatal("terminal control character leaked")
	}
}

func BenchmarkStreamingDump(b *testing.B) {
	sql := optionsSchema + "INSERT INTO wp_options VALUES" + strings.TrimSuffix(strings.Repeat("(1,'name','ordinary article content'),", 10000), ",") + ";"
	b.SetBytes(int64(len(sql)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := scanDump(strings.NewReader(sql), testOptions(), io.Discard, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}
