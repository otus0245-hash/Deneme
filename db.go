package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

var dbExts = map[string]bool{".db": true, ".sqlite": true, ".sqlite3": true, ".db3": true}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// Veritabanını açar. write=false ise sadece okuma modunda (query_only) açılır.
func openDB(w http.ResponseWriter, r *http.Request, write bool) (*sql.DB, bool) {
	b := mgr.get(r.URL.Query().Get("id"))
	if b == nil {
		http.Error(w, "bot bulunamadı", http.StatusNotFound)
		return nil, false
	}
	me := who(r)
	rawFile := r.URL.Query().Get("file")
	path, err := safePath(botDir(b.ID), rawFile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, false
	}
	if me.Denied(b.ID, cleanRel(rawFile), false) {
		http.Error(w, "bu dosyaya erişimin engellenmiş", http.StatusForbidden)
		return nil, false
	}
	if write && !me.Can("db.write") {
		http.Error(w, "veritabanına yazma yetkin yok (db.write)", http.StatusForbidden)
		return nil, false
	}
	if !dbExts[strings.ToLower(filepath.Ext(path))] {
		http.Error(w, "bu dosya bir veritabanı uzantısına sahip değil", http.StatusBadRequest)
		return nil, false
	}
	// Dosya yoksa SQLite sessizce yeni boş dosya oluşturur, bunu engelle
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		http.Error(w, "veritabanı dosyası bulunamadı", http.StatusNotFound)
		return nil, false
	}
	dsn := path + "?_pragma=busy_timeout(5000)"
	if !write {
		dsn += "&_pragma=query_only(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	db.SetMaxOpenConns(1)
	return db, true
}

func trunc(s string) string {
	if len(s) > 2000 {
		s = s[:2000]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
		s += "…"
	}
	return s
}

func cell(v any) any {
	switch x := v.(type) {
	case []byte:
		if utf8.Valid(x) {
			return trunc(string(x))
		}
		return fmt.Sprintf("<BLOB %d bayt>", len(x))
	case string:
		return trunc(x)
	case time.Time:
		return x.Format(time.RFC3339)
	}
	return v
}

func readRows(rows *sql.Rows, limit int) (cols []string, out [][]any, truncated bool, err error) {
	cols, err = rows.Columns()
	if err != nil {
		return
	}
	out = [][]any{}
	for rows.Next() {
		if len(out) >= limit {
			truncated = true
			break
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err = rows.Scan(ptrs...); err != nil {
			return
		}
		row := make([]any, len(cols))
		for i, v := range vals {
			row[i] = cell(v)
		}
		out = append(out, row)
	}
	err = rows.Err()
	return
}

type colInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	NotNull bool   `json:"notnull"`
	Dflt    string `json:"dflt"`
	PK      int    `json:"pk"`
}

func tableColumns(ctx context.Context, db *sql.DB, table string) ([]colInfo, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+quoteIdent(table)+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []colInfo{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		list = append(list, colInfo{name, ctype, notnull == 1, dflt.String, pk})
	}
	return list, rows.Err()
}

func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var t string
	err := db.QueryRowContext(ctx,
		`SELECT type FROM sqlite_master WHERE name=? AND type IN ('table','view')`, name).Scan(&t)
	return err == nil
}

func registerDB() {
	// Botun klasöründeki veritabanı dosyalarını bulur
	http.HandleFunc("/api/db/files", func(w http.ResponseWriter, r *http.Request) {
		b := mgr.get(r.URL.Query().Get("id"))
		if b == nil {
			http.Error(w, "bot bulunamadı", 404)
			return
		}
		base, _ := safePath(botDir(b.ID), "")
		type item struct {
			Path string `json:"path"`
			Size int64  `json:"size"`
		}
		list := []item{}
		filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case "venv", ".git", "__pycache__", "node_modules":
					return filepath.SkipDir
				}
				return nil
			}
			if dbExts[strings.ToLower(filepath.Ext(d.Name()))] {
				rel, _ := filepath.Rel(base, p)
				if who(r).Denied(b.ID, filepath.ToSlash(rel), false) {
					return nil
				}
				info, _ := d.Info()
				var size int64
				if info != nil {
					size = info.Size()
				}
				list = append(list, item{filepath.ToSlash(rel), size})
			}
			return nil
		})
		writeJSON(w, list)
	})

	http.HandleFunc("/api/db/tables", func(w http.ResponseWriter, r *http.Request) {
		db, ok := openDB(w, r, false)
		if !ok {
			return
		}
		defer db.Close()
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		rows, err := db.QueryContext(ctx,
			`SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name`)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		type tinfo struct {
			Name string `json:"name"`
			Type string `json:"type"`
			Rows int64  `json:"rows"`
		}
		list := []tinfo{}
		for rows.Next() {
			var t tinfo
			rows.Scan(&t.Name, &t.Type)
			list = append(list, t)
		}
		rows.Close() // tek bağlantı var, sayım sorgularından önce kapatılmalı
		for i := range list {
			if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdent(list[i].Name)).Scan(&list[i].Rows); err != nil {
				list[i].Rows = -1
			}
		}
		writeJSON(w, list)
	})

	http.HandleFunc("/api/db/browse", func(w http.ResponseWriter, r *http.Request) {
		db, ok := openDB(w, r, false)
		if !ok {
			return
		}
		defer db.Close()
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		q := r.URL.Query()
		table := q.Get("table")
		if !tableExists(ctx, db, table) {
			http.Error(w, "tablo bulunamadı", 404)
			return
		}
		page, _ := strconv.Atoi(q.Get("page"))
		if page < 1 {
			page = 1
		}
		const size = 50

		order := ""
		if s := q.Get("sort"); s != "" {
			cols, err := tableColumns(ctx, db, table)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			for _, c := range cols {
				if c.Name == s {
					order = " ORDER BY " + quoteIdent(s)
					if q.Get("dir") == "desc" {
						order += " DESC"
					}
				}
			}
		}

		var total int64
		db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdent(table)).Scan(&total)

		rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %s%s LIMIT %d OFFSET %d",
			quoteIdent(table), order, size, (page-1)*size))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer rows.Close()
		cols, out, _, err := readRows(rows, size)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		pages := int((total + size - 1) / size)
		if pages < 1 {
			pages = 1
		}
		writeJSON(w, map[string]any{
			"columns": cols, "rows": out, "total": total, "page": page, "pages": pages,
		})
	})

	http.HandleFunc("/api/db/structure", func(w http.ResponseWriter, r *http.Request) {
		db, ok := openDB(w, r, false)
		if !ok {
			return
		}
		defer db.Close()
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		table := r.URL.Query().Get("table")
		if !tableExists(ctx, db, table) {
			http.Error(w, "tablo bulunamadı", 404)
			return
		}
		cols, err := tableColumns(ctx, db, table)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		type idx struct {
			Name   string `json:"name"`
			Unique bool   `json:"unique"`
		}
		indexes := []idx{}
		if rows, err := db.QueryContext(ctx, "PRAGMA index_list("+quoteIdent(table)+")"); err == nil {
			for rows.Next() {
				var seq, unique, partial int
				var name, origin string
				if rows.Scan(&seq, &name, &unique, &origin, &partial) == nil {
					indexes = append(indexes, idx{name, unique == 1})
				}
			}
			rows.Close()
		}
		var createSQL sql.NullString
		db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE name=?`, table).Scan(&createSQL)
		writeJSON(w, map[string]any{"columns": cols, "indexes": indexes, "sql": createSQL.String})
	})

	// SQL çalıştırma. write=1 değilse sadece okuma yapar.
	http.HandleFunc("/api/db/query", post(func(w http.ResponseWriter, r *http.Request) {
		write := r.URL.Query().Get("write") == "1"
		db, ok := openDB(w, r, write)
		if !ok {
			return
		}
		defer db.Close()

		body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		query := strings.TrimSpace(string(body))
		if query == "" {
			http.Error(w, "sorgu boş", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		me := who(r)
		lower := strings.ToLower(query)
		// ATTACH başka bir botun (engelli olabilecek) veritabanını okumaya, VACUUM INTO ise
		// keyfi yere dosya yazmaya yarar; bunlar sadece admin içindir.
		if !me.Admin && (strings.Contains(lower, "attach") || strings.Contains(lower, "vacuum")) {
			http.Error(w, "ATTACH ve VACUUM komutlarını yalnızca admin kullanabilir", http.StatusForbidden)
			return
		}
		first := strings.ToLower(strings.Fields(query)[0])
		if !write {
			// Salt okunur modun "PRAGMA query_only=0" ile kapatılmasını önle
			if hasExtraStatement(query) {
				http.Error(w, "yazma kapalıyken tek seferde tek komut çalıştırılabilir", http.StatusForbidden)
				return
			}
			if first == "pragma" && !safePragma(query) {
				http.Error(w, "yazma kapalıyken sadece bilgi veren PRAGMA komutları çalışır", http.StatusForbidden)
				return
			}
		}
		isRead := first == "select" || first == "with" || first == "pragma" || first == "explain" || first == "values"
		if !isRead || write {
			logEvent(r, "SQL çalıştırdı", "dosya="+r.URL.Query().Get("file")+" | "+query)
		}
		start := time.Now()

		if isRead {
			rows, err := db.QueryContext(ctx, query)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			defer rows.Close()
			cols, out, truncated, err := readRows(rows, 1000)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			writeJSON(w, map[string]any{
				"columns": cols, "rows": out, "truncated": truncated,
				"ms": time.Since(start).Milliseconds(),
			})
			return
		}

		if !write {
			http.Error(w, "yazma kapalı. Değiştirmek için 'Yazmaya izin ver' kutusunu işaretle", 403)
			return
		}
		res, err := db.ExecContext(ctx, query)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		n, _ := res.RowsAffected()
		writeJSON(w, map[string]any{"affected": n, "ms": time.Since(start).Milliseconds()})
	}))
}
// Tırnak içindekiler hariç, sondaki dışında ';' var mı?
func hasExtraStatement(q string) bool {
	q = strings.TrimSpace(q)
	var quote rune
	for i, c := range q {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == ';':
			if strings.TrimSpace(q[i+1:]) != "" {
				return true
			}
		}
	}
	return false
}

var safePragmas = map[string]bool{
	"table_info": true, "table_xinfo": true, "table_list": true, "index_list": true,
	"index_info": true, "index_xinfo": true, "foreign_key_list": true, "database_list": true,
	"collation_list": true, "function_list": true, "compile_options": true,
	"integrity_check": true, "quick_check": true, "page_count": true, "page_size": true,
	"freelist_count": true, "encoding": true,
}

func safePragma(q string) bool {
	q = strings.TrimSpace(q)
	if len(q) < 6 || strings.Contains(q, "=") {
		return false
	}
	name := strings.TrimSpace(q[6:])
	if i := strings.IndexAny(name, "( \t\r\n;"); i >= 0 {
		name = name[:i]
	}
	return safePragmas[strings.ToLower(name)]
}
