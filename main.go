package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"time"
)

//go:embed web
var webFS embed.FS

func page(name string, exact bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if exact && r.URL.Path != "/" {
			fmt.Println("404: beklenmeyen adres:", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		data, err := webFS.ReadFile("web/" + name)
		if err != nil {
			fmt.Println("HATA: gömülü dosya okunamadı:", name, err)
			http.Error(w, "web/"+name+" bulunamadı", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

// Sadece POST isteklerini kabul eder (değişiklik yapan işlemler için)
func post(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "sadece POST", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func main() {
	os.MkdirAll("data/bots", 0755)
	mgr.load()
	initAuth()

	fs.WalkDir(webFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			fmt.Println("gömülü dosya:", p)
		}
		return nil
	})

	registerBots()    // bots.go
	registerConsole() // console.go
	registerFiles()   // files.go
	registerStats()   // mem.go
	registerDB()      // db.go
	registerAuth()    // auth.go, users_api.go
	registerSecurity() // security.go
	startSecurity()    // security.go

	static, _ := fs.Sub(webFS, "web")
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	http.HandleFunc("/", page("bots.html", true))
	http.HandleFunc("/console", page("console.html", false))
	http.HandleFunc("/files", page("files.html", false))

	srv := &http.Server{
		Addr:              "127.0.0.1:8080",
		Handler:           securityMiddleware(authMiddleware(http.DefaultServeMux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // 100 MB yükleme için
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	fmt.Println("Panel http://127.0.0.1:8080 adresinde başladı")
	if err := srv.ListenAndServe(); err != nil {
		fmt.Println("Hata:", err)
	}
}