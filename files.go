package main

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// rel yolunu base klasörünün içinde tutar (../ ile dışarı çıkılamaz)
func safePath(base, rel string) (string, error) {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	target := filepath.Join(baseAbs, filepath.FromSlash(rel))
	if target != baseAbs && !strings.HasPrefix(target, baseAbs+string(os.PathSeparator)) {
		return "", fmt.Errorf("geçersiz yol")
	}
	return target, nil
}

// İstekten bot klasörünü ve hedef yolu çıkarır; kullanıcının dosya engellerini uygular.
// mutate=true: silme ve yeniden adlandırma gibi tüm alt içeriği etkileyen işlemler;
// engelli bir yolun üst klasörüne yapılırlarsa da reddedilir. Yeni dosya yazma/yükleme/klasör
// açma için mutate=false: yolun kendisi veya altı engelli değilse serbesttir.
type fctx struct {
	bot    *Bot
	root   string
	target string
	rel    string // bot klasörüne göre temiz yol
	me     *Principal
}

func fileCtx(w http.ResponseWriter, r *http.Request, mutate bool) (*fctx, bool) {
	b := mgr.get(r.URL.Query().Get("id"))
	if b == nil {
		http.Error(w, "bot bulunamadı", http.StatusNotFound)
		return nil, false
	}
	base := botDir(b.ID)
	root, _ := safePath(base, "")
	raw := r.URL.Query().Get("path")
	t, err := safePath(base, raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, false
	}
	rel := cleanRel(raw)
	me := who(r)
	if me.Denied(b.ID, rel, mutate) {
		http.Error(w, "bu dosya veya klasöre erişimin engellenmiş", http.StatusForbidden)
		return nil, false
	}
	return &fctx{bot: b, root: root, target: t, rel: rel, me: me}, true
}

type fileItem struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size"`
	Mod  int64  `json:"mod"`
}

func registerFiles() {
	http.HandleFunc("/db", page("db.html", false))
	http.HandleFunc("/api/files/list", func(w http.ResponseWriter, r *http.Request) {
		c, ok := fileCtx(w, r, false)
		if !ok {
			return
		}
		entries, err := os.ReadDir(c.target)
		if err != nil {
			http.Error(w, "klasör okunamadı", 404)
			return
		}
		items := []fileItem{}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			if c.me.Denied(c.bot.ID, relJoin(c.rel, e.Name()), false) {
				continue // engelli girdiler listede görünmez
			}
			items = append(items, fileItem{e.Name(), e.IsDir(), info.Size(), info.ModTime().Unix()})
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Dir != items[j].Dir {
				return items[i].Dir
			}
			return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
		})
		writeJSON(w, items)
	})

	http.HandleFunc("/api/files/read", func(w http.ResponseWriter, r *http.Request) {
		c, ok := fileCtx(w, r, false)
		if !ok {
			return
		}
		t := c.target
		st, err := os.Stat(t)
		if err != nil || st.IsDir() {
			http.Error(w, "dosya bulunamadı", 404)
			return
		}
		if st.Size() > 1<<20 {
			http.Error(w, "dosya 1 MB'tan büyük, düzenlenemez. İndirip düzenle", 413)
			return
		}
		data, _ := os.ReadFile(t)
		if bytes.IndexByte(data, 0) >= 0 {
			http.Error(w, "ikili dosya, düzenlenemez", 415)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
	})

	http.HandleFunc("/api/files/write", post(func(w http.ResponseWriter, r *http.Request) {
		c, ok := fileCtx(w, r, false)
		if !ok {
			return
		}
		root, t := c.root, c.target
		if t == root {
			http.Error(w, "geçersiz yol", 400)
			return
		}
		data, _ := io.ReadAll(io.LimitReader(r.Body, 5<<20))
		os.MkdirAll(filepath.Dir(t), 0755)
		if err := os.WriteFile(t, data, 0644); err != nil {
			http.Error(w, err.Error(), 500)
		}
	}))

	http.HandleFunc("/api/files/mkdir", post(func(w http.ResponseWriter, r *http.Request) {
		c, ok := fileCtx(w, r, false)
		if !ok {
			return
		}
		root, t := c.root, c.target
		if t == root {
			http.Error(w, "geçersiz yol", 400)
			return
		}
		if err := os.MkdirAll(t, 0755); err != nil {
			http.Error(w, err.Error(), 500)
		}
	}))

	http.HandleFunc("/api/files/delete", post(func(w http.ResponseWriter, r *http.Request) {
		c, ok := fileCtx(w, r, true)
		if !ok {
			return
		}
		root, t := c.root, c.target
		if t == root {
			http.Error(w, "ana klasör silinemez", 400)
			return
		}
		if err := os.RemoveAll(t); err != nil {
			http.Error(w, err.Error(), 500)
		}
	}))

	http.HandleFunc("/api/files/rename", post(func(w http.ResponseWriter, r *http.Request) {
		c, ok := fileCtx(w, r, true)
		if !ok {
			return
		}
		root, t := c.root, c.target
		toRaw := r.URL.Query().Get("to")
		to, err := safePath(root, toRaw)
		if err != nil || t == root || to == root {
			http.Error(w, "geçersiz yol", 400)
			return
		}
		if c.me.Denied(c.bot.ID, cleanRel(toRaw), true) {
			http.Error(w, "hedef yola erişimin engellenmiş", http.StatusForbidden)
			return
		}
		if _, err := os.Stat(to); err == nil {
			http.Error(w, "bu isimde bir dosya zaten var", 409)
			return
		}
		if err := os.Rename(t, to); err != nil {
			http.Error(w, err.Error(), 500)
		}
	}))

	http.HandleFunc("/api/files/upload", post(func(w http.ResponseWriter, r *http.Request) {
		c, ok := fileCtx(w, r, false)
		if !ok {
			return
		}
		dir := c.target
		r.Body = http.MaxBytesReader(w, r.Body, 100<<20)
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, "yükleme başarısız (en fazla 100 MB)", 400)
			return
		}
		for _, fh := range r.MultipartForm.File["files"] {
			dst, err := safePath(dir, filepath.Base(fh.Filename))
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if c.me.Denied(c.bot.ID, relJoin(c.rel, filepath.Base(fh.Filename)), true) {
				http.Error(w, "'"+filepath.Base(fh.Filename)+"' için erişimin engellenmiş", http.StatusForbidden)
				return
			}
			src, err := fh.Open()
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			out, err := os.Create(dst)
			if err != nil {
				src.Close()
				http.Error(w, err.Error(), 500)
				return
			}
			io.Copy(out, src)
			out.Close()
			src.Close()
		}
	}))

	http.HandleFunc("/api/files/download", func(w http.ResponseWriter, r *http.Request) {
		c, ok := fileCtx(w, r, false)
		if !ok {
			return
		}
		t := c.target
		st, err := os.Stat(t)
		if err != nil || st.IsDir() {
			http.Error(w, "dosya bulunamadı", 404)
			return
		}
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(t)}))
		http.ServeFile(w, r, t)
	})
}
