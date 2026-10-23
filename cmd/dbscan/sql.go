package main

// This is a streaming reader for table dumps, not a SQL execution engine. It
// deliberately rejects data expressions it cannot interpret rather than losing
// column alignment or reporting an incomplete scan as successful.
import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

type token struct {
	kind byte // w: word/number, i: quoted identifier, s: string, p: punctuation
	text string
}

func (t token) is(s string) bool    { return t.kind == 'w' && strings.EqualFold(t.text, s) }
func (t token) punct(s string) bool { return t.kind == 'p' && t.text == s }

type lexer struct {
	r           *bufio.Reader
	max         int
	offset      int64
	line        int64
	noBackslash bool
	ansiQuotes  bool
	executable  bool
	pending     *token
}

func newLexer(r io.Reader, max int) *lexer {
	l := &lexer{r: bufio.NewReaderSize(r, 128*1024), max: max, line: 1}
	if l.starts("\xef\xbb\xbf") {
		for i := 0; i < 3; i++ {
			l.read()
		}
	}
	return l
}

func (l *lexer) read() (byte, error) {
	b, err := l.r.ReadByte()
	if err == nil {
		l.offset++
		if b == '\n' {
			l.line++
		}
	}
	return b, err
}

func (l *lexer) starts(s string) bool {
	b, _ := l.r.Peek(len(s))
	return string(b) == s
}

func space(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' }

func (l *lexer) peek() (token, error) {
	if l.pending == nil {
		t, err := l.next()
		if err != nil {
			return token{}, err
		}
		l.pending = &t
	}
	return *l.pending, nil
}

func (l *lexer) next() (token, error) {
	if l.pending != nil {
		t := *l.pending
		l.pending = nil
		return t, nil
	}
	for {
		b, err := l.read()
		if err != nil {
			return token{}, err
		}
		if space(b) {
			continue
		}
		if b == '#' || (b == '-' && l.starts("-") && func() bool { p, _ := l.r.Peek(2); return len(p) == 1 || (len(p) == 2 && space(p[1])) }()) {
			for b != '\n' {
				b, err = l.read()
				if err == io.EOF {
					return token{}, io.EOF
				}
				if err != nil {
					return token{}, err
				}
			}
			continue
		}
		if b == '/' && l.starts("*") {
			l.read()
			// MySQL and MariaDB executable comments contain real SQL, including
			// SQL_MODE settings that affect how string literals are decoded.
			if l.starts("!") || l.starts("M!") {
				maria := l.starts("M!")
				if maria {
					l.read()
				}
				l.read()
				for {
					p, _ := l.r.Peek(1)
					if len(p) == 0 || p[0] < '0' || p[0] > '9' {
						break
					}
					l.read()
				}
				// Recent mariadb-dump emits a client sandbox directive which
				// does not affect the SQL values or schema being inspected.
				if maria && (l.starts("\\-") || l.starts(" \\-")) {
					for {
						c, err := l.read()
						if err != nil {
							return token{}, fmt.Errorf("unterminated sandbox comment: %w", err)
						}
						if c == '*' && l.starts("/") {
							l.read()
							break
						}
					}
					continue
				}
				l.executable = true
				continue
			}
			for {
				c, err := l.read()
				if err != nil {
					return token{}, fmt.Errorf("unterminated SQL comment: %w", err)
				}
				if c == '*' && l.starts("/") {
					l.read()
					break
				}
			}
			continue
		}
		if l.executable && b == '*' && l.starts("/") {
			l.read()
			l.executable = false
			continue
		}
		if b == '\'' || b == '"' || b == '`' {
			kind := byte('s')
			if b == '`' || (b == '"' && l.ansiQuotes) {
				kind = 'i'
			}
			var v strings.Builder
			for {
				c, err := l.read()
				if err != nil {
					return token{}, fmt.Errorf("unterminated quoted value: %w", err)
				}
				if c == b {
					if l.starts(string(b)) {
						l.read()
						v.WriteByte(b)
					} else {
						break
					}
				} else if c == '\\' && kind == 's' && !l.noBackslash {
					c, err = l.read()
					if err != nil {
						return token{}, fmt.Errorf("unfinished SQL escape: %w", err)
					}
					switch c {
					case '0':
						c = 0
					case 'b':
						c = '\b'
					case 'n':
						c = '\n'
					case 'r':
						c = '\r'
					case 't':
						c = '\t'
					case 'Z':
						c = 26
					case '%', '_':
						v.WriteByte('\\')
					}
					v.WriteByte(c)
				} else {
					v.WriteByte(c)
				}
				if v.Len() > l.max {
					return token{}, fmt.Errorf("value exceeds --max-value-bytes (%d)", l.max)
				}
			}
			return token{kind, v.String()}, nil
		}
		if strings.ContainsRune("(),;.=", rune(b)) {
			return token{'p', string(b)}, nil
		}
		var v strings.Builder
		v.WriteByte(b)
		numeric := (b >= '0' && b <= '9') || b == '-' || b == '+'
		for {
			p, err := l.r.Peek(1)
			if err != nil && err != io.EOF {
				return token{}, err
			}
			if len(p) == 0 || space(p[0]) || strings.ContainsRune("(),;='\"`", rune(p[0])) || (p[0] == '.' && !numeric) || (l.executable && p[0] == '*' && l.starts("*/")) {
				break
			}
			c, err := l.read()
			if err != nil {
				return token{}, err
			}
			v.WriteByte(c)
			if v.Len() > l.max {
				return token{}, fmt.Errorf("token exceeds --max-value-bytes (%d)", l.max)
			}
		}
		return token{'w', v.String()}, nil
	}
}

type tableName struct{ DB, Name string }

func (n tableName) String() string {
	if n.DB != "" {
		return n.DB + "." + n.Name
	}
	return n.Name
}
func quoteID(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }
func (n tableName) sql() string {
	if n.DB != "" {
		return quoteID(n.DB) + "." + quoteID(n.Name)
	}
	return quoteID(n.Name)
}

type schema struct {
	columns []string
	primary []string
	unique  [][]string
}

type value struct {
	text string
	kind byte
} // s: bytes, n: number, 0: NULL
type row struct {
	table   tableName
	schema  *schema
	columns []string
	values  []value
	number  int64 // supplemental dump row ordinal, never used as database identity
}

type parser struct {
	l        *lexer
	database string
	tables   map[tableName]*schema
	modes    map[string]string
	rows     int64
	maxRow   int
	onRow    func(row) error
	warn     func(string)
}

func (p *parser) need() (token, error) {
	t, err := p.l.next()
	if err == io.EOF {
		err = fmt.Errorf("unexpected end of dump")
	}
	return t, err
}

func (p *parser) expect(s string) error {
	t, err := p.need()
	if err != nil {
		return err
	}
	if !t.punct(s) {
		return fmt.Errorf("expected %q, got %q", s, t.text)
	}
	return nil
}

func identifier(t token) bool { return t.kind == 'i' || t.kind == 'w' }

func (p *parser) name() (tableName, error) {
	t, err := p.need()
	if err != nil {
		return tableName{}, err
	}
	if !identifier(t) {
		return tableName{}, fmt.Errorf("expected table name, got %q", t.text)
	}
	n := tableName{DB: p.database, Name: t.text}
	t, err = p.l.peek()
	if err == nil && t.punct(".") {
		p.l.next()
		t, err = p.need()
		if err != nil {
			return n, err
		}
		if !identifier(t) {
			return n, fmt.Errorf("expected qualified table name")
		}
		n.DB, n.Name = n.Name, t.text
	}
	return n, nil
}

func (p *parser) skip() error {
	for {
		t, err := p.l.next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if t.punct(";") {
			return nil
		}
	}
}

func (p *parser) parse() (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("near line %d, byte %d: %w", p.l.line, p.l.offset, err)
		}
	}()
	p.tables = make(map[tableName]*schema)
	p.modes = make(map[string]string)
	for {
		t, e := p.l.next()
		if e == io.EOF {
			if p.l.executable {
				return fmt.Errorf("unterminated executable comment")
			}
			return nil
		}
		if e != nil {
			return e
		}
		switch {
		case t.punct(";"):
		case t.is("DELIMITER"):
			return fmt.Errorf("custom DELIMITER is unsupported; export table data/schema with --skip-triggers and without --routines/--events; audit those objects separately")
		case t.is("USE"):
			t, e = p.need()
			if e != nil {
				return e
			}
			if !identifier(t) {
				return fmt.Errorf("invalid USE statement")
			}
			p.database = t.text
			if e = p.expect(";"); e != nil {
				return e
			}
		case t.is("SET"):
			if e = p.set(); e != nil {
				return e
			}
		case t.is("CREATE"):
			t, e = p.l.peek()
			if e != nil {
				return e
			}
			if t.is("TABLE") {
				p.l.next()
				if e = p.create(); e != nil {
					return e
				}
			} else {
				if p.warn != nil {
					p.warn("non-table CREATE statement is not audited")
				}
				if e = p.skip(); e != nil {
					return e
				}
			}
		case t.is("INSERT"), t.is("REPLACE"):
			if e = p.insert(); e != nil {
				return e
			}
		case t.is("UPDATE"), t.is("DELETE"), t.is("LOAD"), t.is("ALTER"), t.is("RENAME"), t.is("TRUNCATE"):
			// mysqldump emits ALTER TABLE ... DISABLE/ENABLE KEYS; those
			// do not change the column mapping. Reject all other alterations.
			if t.is("ALTER") {
				if e = p.alter(); e != nil {
					return e
				}
			} else {
				return fmt.Errorf("unsupported %s statement in table dump", t.text)
			}
		case t.is("DROP"), t.is("LOCK"), t.is("UNLOCK"), t.is("START"), t.is("COMMIT"), t.is("BEGIN"):
			if e = p.skip(); e != nil {
				return e
			}
		default:
			return fmt.Errorf("unsupported SQL statement %q", t.text)
		}
	}
}

func (p *parser) set() error {
	var ts []token
	for {
		t, err := p.need()
		if err != nil {
			return err
		}
		if t.punct(";") {
			break
		}
		if len(ts) >= 256 {
			return fmt.Errorf("SET statement too complex")
		}
		ts = append(ts, t)
	}
	// SQL_MODE and mysqldump's @OLD_SQL_MODE save/restore are supported.
	for i := 0; i+2 < len(ts); i++ {
		if !ts[i+1].punct("=") {
			continue
		}
		key := strings.ToUpper(ts[i].text)
		rhs := ts[i+2]
		v := rhs.text
		if rhs.kind != 's' {
			if strings.EqualFold(rhs.text, "@@SQL_MODE") || strings.EqualFold(rhs.text, "@@SESSION.SQL_MODE") {
				var modes []string
				if p.l.noBackslash {
					modes = append(modes, "NO_BACKSLASH_ESCAPES")
				}
				if p.l.ansiQuotes {
					modes = append(modes, "ANSI_QUOTES")
				}
				v = strings.Join(modes, ",")
			} else if saved, ok := p.modes[strings.ToUpper(rhs.text)]; ok {
				v = saved
			} else if key == "SQL_MODE" || key == "@@SQL_MODE" {
				return fmt.Errorf("unsupported SQL_MODE expression %q", rhs.text)
			}
		}
		if strings.HasPrefix(key, "@") && !strings.HasPrefix(key, "@@") {
			p.modes[key] = v
		}
		if key == "SQL_MODE" || key == "@@SQL_MODE" {
			p.l.noBackslash, p.l.ansiQuotes = false, false
			for _, m := range strings.Split(strings.ToUpper(v), ",") {
				if m == "NO_BACKSLASH_ESCAPES" {
					p.l.noBackslash = true
				}
				if m == "ANSI_QUOTES" {
					p.l.ansiQuotes = true
				}
			}
		}
	}
	return nil
}

func (p *parser) alter() error {
	t, err := p.need()
	if err != nil {
		return err
	}
	if !t.is("TABLE") {
		return fmt.Errorf("unsupported ALTER statement")
	}
	if _, err = p.name(); err != nil {
		return err
	}
	t, err = p.need()
	if err != nil {
		return err
	}
	if !t.is("DISABLE") && !t.is("ENABLE") {
		return fmt.Errorf("only ALTER TABLE ENABLE/DISABLE KEYS is supported")
	}
	t, err = p.need()
	if err != nil {
		return err
	}
	if !t.is("KEYS") {
		return fmt.Errorf("expected KEYS")
	}
	return p.expect(";")
}

func (p *parser) create() error {
	t, err := p.l.peek()
	if err != nil {
		return err
	}
	if t.is("IF") {
		for _, word := range []string{"IF", "NOT", "EXISTS"} {
			t, err = p.need()
			if err != nil {
				return err
			}
			if !t.is(word) {
				return fmt.Errorf("expected %s", word)
			}
		}
	}
	n, err := p.name()
	if err != nil {
		return err
	}
	if err = p.expect("("); err != nil {
		return fmt.Errorf("CREATE TABLE %s: %w", n, err)
	}
	s := &schema{}
	var part []token
	depth := 0
	for {
		t, err = p.need()
		if err != nil {
			return err
		}
		if depth == 0 && (t.punct(",") || t.punct(")")) {
			if err = definition(s, part); err != nil {
				return fmt.Errorf("table %s: %w", n, err)
			}
			part = nil
			if t.punct(")") {
				break
			}
			continue
		}
		if t.punct("(") {
			depth++
		}
		if t.punct(")") {
			depth--
			if depth < 0 {
				return fmt.Errorf("unbalanced table definition")
			}
		}
		part = append(part, t)
		if len(part) > 16384 {
			return fmt.Errorf("table definition too complex")
		}
		if len(s.columns) > 16384 {
			return fmt.Errorf("too many columns")
		}
	}
	if len(s.columns) == 0 {
		return fmt.Errorf("table %s has no columns", n)
	}
	for _, keys := range append([][]string{s.primary}, s.unique...) {
		for _, key := range keys {
			if columnIndex(s.columns, key) < 0 {
				return fmt.Errorf("unknown key column %q", key)
			}
		}
	}
	p.tables[n] = s
	return p.skip()
}

func definition(s *schema, ts []token) error {
	if len(ts) == 0 {
		return fmt.Errorf("empty column/constraint definition")
	}
	i := 0
	if ts[i].is("CONSTRAINT") {
		i += 2
		if i >= len(ts) {
			return fmt.Errorf("invalid constraint")
		}
	}
	primary, unique := ts[i].is("PRIMARY"), ts[i].is("UNIQUE")
	if primary || unique {
		for i < len(ts) && !ts[i].punct("(") {
			i++
		}
		if i == len(ts) {
			return fmt.Errorf("missing key columns")
		}
		var keys []string
		for i++; i < len(ts) && !ts[i].punct(")"); {
			if !identifier(ts[i]) {
				if unique {
					return nil
				}
				return fmt.Errorf("unsupported primary key expression")
			}
			key := ts[i].text
			i++
			if i < len(ts) && ts[i].punct("(") {
				// Prefix/expression index metadata is not modeled. Prefer
				// another key rather than infer its semantics.
				if unique {
					return nil
				}
				return fmt.Errorf("unsupported primary key prefix")
			}
			keys = append(keys, key)
			if i < len(ts) && (ts[i].is("ASC") || ts[i].is("DESC")) {
				i++
			}
			if i < len(ts) && ts[i].punct(",") {
				i++
			} else if i >= len(ts) || !ts[i].punct(")") {
				return fmt.Errorf("invalid key definition")
			}
		}
		if len(keys) == 0 {
			return fmt.Errorf("empty key")
		}
		if primary {
			s.primary = keys
		} else {
			s.unique = append(s.unique, keys)
		}
		return nil
	}
	if ts[0].is("KEY") || ts[0].is("INDEX") || ts[0].is("FULLTEXT") || ts[0].is("SPATIAL") || ts[0].is("FOREIGN") || ts[0].is("CHECK") || ts[0].is("CONSTRAINT") {
		return nil
	}
	if !identifier(ts[0]) || len(ts) < 2 {
		return fmt.Errorf("invalid column definition")
	}
	name := ts[0].text
	if columnIndex(s.columns, name) >= 0 {
		return fmt.Errorf("duplicate column %q", name)
	}
	s.columns = append(s.columns, name)
	depth := 0
	for j := 1; j < len(ts); j++ {
		if ts[j].punct("(") {
			depth++
		}
		if ts[j].punct(")") {
			depth--
		}
		if depth == 0 && ts[j].is("PRIMARY") && j+1 < len(ts) && ts[j+1].is("KEY") {
			s.primary = []string{name}
		}
		if depth == 0 && ts[j].is("UNIQUE") {
			s.unique = append(s.unique, []string{name})
		}
	}
	return nil
}

func columnIndex(columns []string, name string) int {
	for i, c := range columns {
		if strings.EqualFold(c, name) {
			return i
		}
	}
	return -1
}

var sqlNumber = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

func (p *parser) readValue() (value, error) {
	t, err := p.need()
	if err != nil {
		return value{}, err
	}
	if t.kind == 's' {
		return value{t.text, 's'}, nil
	}
	if t.is("NULL") {
		return value{kind: '0'}, nil
	}
	if t.is("DEFAULT") {
		return value{}, fmt.Errorf("DEFAULT does not contain the stored value; export literal column values")
	}
	if t.kind == 'w' && (strings.HasPrefix(t.text, "_") || t.is("N")) {
		t, err = p.need()
		if err != nil {
			return value{}, err
		}
		if t.kind != 's' {
			return value{}, fmt.Errorf("expected string after character set introducer")
		}
		return value{t.text, 's'}, nil
	}
	if t.is("X") {
		t, err = p.need()
		if err != nil {
			return value{}, err
		}
		if t.kind != 's' {
			return value{}, fmt.Errorf("expected hex string")
		}
		b, err := hex.DecodeString(t.text)
		if err != nil {
			return value{}, fmt.Errorf("invalid hex string: %w", err)
		}
		return value{string(b), 's'}, nil
	}
	if t.kind == 'w' && len(t.text) >= 2 && strings.EqualFold(t.text[:2], "0x") {
		s := t.text[2:]
		if len(s)%2 != 0 {
			s = "0" + s
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return value{}, fmt.Errorf("invalid hex literal: %w", err)
		}
		return value{string(b), 's'}, nil
	}
	if t.is("B") {
		t, err = p.need()
		if err != nil {
			return value{}, err
		}
		if t.kind != 's' || len(t.text) == 0 {
			return value{}, fmt.Errorf("invalid bit literal")
		}
		b := make([]byte, (len(t.text)+7)/8)
		for i, c := range t.text {
			if c != '0' && c != '1' {
				return value{}, fmt.Errorf("invalid bit literal")
			}
			if c == '1' {
				pos := len(t.text) - 1 - i
				b[len(b)-1-pos/8] |= 1 << uint(pos%8)
			}
		}
		return value{string(b), 's'}, nil
	}
	if t.punct(".") {
		next, e := p.need()
		if e != nil {
			return value{}, e
		}
		t = token{'w', "." + next.text}
	}
	if t.kind == 'w' && sqlNumber.MatchString(t.text) {
		return value{t.text, 'n'}, nil
	}
	return value{}, fmt.Errorf("unsupported value/expression %s; expected a literal", strconv.Quote(t.text))
}

func (p *parser) insert() error {
	for {
		t, err := p.l.peek()
		if err != nil {
			return err
		}
		if t.is("LOW_PRIORITY") || t.is("DELAYED") || t.is("HIGH_PRIORITY") || t.is("IGNORE") || t.is("INTO") {
			p.l.next()
		} else {
			break
		}
	}
	n, err := p.name()
	if err != nil {
		return err
	}
	s := p.tables[n]
	var columns []string
	t, err := p.l.peek()
	if err != nil {
		return err
	}
	if t.punct("(") {
		p.l.next()
		for {
			t, err = p.need()
			if err != nil {
				return err
			}
			if !identifier(t) {
				return fmt.Errorf("expected column name")
			}
			if columnIndex(columns, t.text) >= 0 {
				return fmt.Errorf("duplicate INSERT column %q", t.text)
			}
			if s != nil && columnIndex(s.columns, t.text) < 0 {
				return fmt.Errorf("unknown INSERT column %q", t.text)
			}
			columns = append(columns, t.text)
			if len(columns) > 16384 {
				return fmt.Errorf("too many INSERT columns")
			}
			t, err = p.need()
			if err != nil {
				return err
			}
			if t.punct(")") {
				break
			}
			if !t.punct(",") {
				return fmt.Errorf("invalid INSERT columns")
			}
		}
	} else if s != nil {
		columns = s.columns
	} else {
		return fmt.Errorf("table %s: INSERT without column names requires CREATE TABLE schema", n)
	}
	if s == nil && p.warn != nil {
		p.warn(fmt.Sprintf("table %q has no CREATE TABLE schema; row identity may be ambiguous", n.String()))
	}
	t, err = p.need()
	if err != nil {
		return err
	}
	if !t.is("VALUES") && !t.is("VALUE") {
		return fmt.Errorf("table %s: only INSERT/REPLACE VALUES is supported", n)
	}
	for {
		if err = p.expect("("); err != nil {
			return err
		}
		vs := make([]value, 0, len(columns))
		rowBytes := 0
		for {
			v, e := p.readValue()
			if e != nil {
				return fmt.Errorf("table %s: %w", n, e)
			}
			vs = append(vs, v)
			rowBytes += len(v.text)
			if p.maxRow > 0 && rowBytes > p.maxRow {
				return fmt.Errorf("table %s: row exceeds --max-row-bytes (%d)", n, p.maxRow)
			}
			if len(vs) > len(columns) {
				return fmt.Errorf("table %s: too many values", n)
			}
			t, err = p.need()
			if err != nil {
				return err
			}
			if t.punct(")") {
				break
			}
			if !t.punct(",") {
				return fmt.Errorf("table %s: unexpected expression after value %q", n, t.text)
			}
		}
		if len(vs) != len(columns) {
			return fmt.Errorf("table %s: got %d values for %d columns", n, len(vs), len(columns))
		}
		p.rows++
		if err = p.onRow(row{n, s, columns, vs, p.rows}); err != nil {
			return err
		}
		t, err = p.need()
		if err != nil {
			return err
		}
		if t.punct(";") {
			return nil
		}
		if !t.punct(",") {
			return fmt.Errorf("unsupported INSERT suffix %q", t.text)
		}
	}
}
