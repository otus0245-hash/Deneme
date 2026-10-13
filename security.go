package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// IP
// ---------------------------------------------------------------------------

// Panel bir ters vekilin (nginx, cloudflared...) arkasındaysa PANEL_TRUST_PROXY=1 ver.
var trustProxy = os.Getenv("PANEL_TRUST_PROXY") == "1"

func clientIP(r *http.Request) string {
	if trustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			parts := strings.Split(xf, ",")
			return strings.TrimSpace(parts[len(parts)-1]) // vekilin eklediği son değer
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---------------------------------------------------------------------------
// Hız sınırı (token bucket)
// ---------------------------------------------------------------------------

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu    sync.Mutex
	m     map[string]*bucket
	rate  float64 // saniyede dolan jeton
	burst float64
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{m: map[string]*bucket{}, rate: rate, burst: burst}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.m[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) gc() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.m {
		if time.Since(b.last) > 10*time.Minute {
			delete(l.m, k)
		}
	}
}

var (
	apiLimit   = newLimiter(30, 100) // IP başına saniyede 30, ani 100 istek
	loginLimit = newLimiter(0.2, 5)  // IP başına ~dakikada 12 giriş denemesi

	ipMu    sync.Mutex
	strikes = map[string]int{}
	bans    = map[string]time.Time{}
)

const (
	strikeLimit = 30
	banTime     = 15 * time.Minute
)

func banRemaining(ip string) time.Duration {
	ipMu.Lock()
	defer ipMu.Unlock()
	if t, ok := bans[ip]; ok {
		if d := time.Until(t); d > 0 {
			return d
		}
		delete(bans, ip)
	}
	return 0
}

// Sınır aşımı sayar; çok olursa IP'yi geçici yasaklar.
func strike(ip, user string) {
	ipMu.Lock()
	strikes[ip]++
	ban := strikes[ip] >= strikeLimit
	if ban {
		bans[ip] = time.Now().Add(banTime)
		delete(strikes, ip)
	}
	ipMu.Unlock()
	if ban {
		writeAudit(AuditEntry{IP: ip, User: user, Action: "IP yasaklandı",
			Detail: fmt.Sprintf("aşırı istek, %d dk", int(banTime.Minutes())), Level: "alert"})
	}
}

// ---------------------------------------------------------------------------
// Denetim günlüğü
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Time   string `json:"time"`
	Level  string `json:"level"` // info | warn | alert
	IP     string `json:"ip"`
	User   string `json:"user"`
	Action string `json:"action"`
	Detail string `json:"detail,omitempty"`
	Status int    `json:"status,omitempty"`
}

const (
	auditFile = "data/audit.log"
	auditMax  = 5 << 20
)

var auditMu sync.Mutex

func writeAudit(e AuditEntry) {
	e.Time = time.Now().Format("2006-01-02 15:04:05")
	if len(e.Detail) > 500 {
		e.Detail = e.Detail[:500] + "…"
	}
	line, _ := json.Marshal(e) // JSON kaçışı satır sonu ile log sahteciliğini önler
	auditMu.Lock()
	defer auditMu.Unlock()
	if st, err := os.Stat(auditFile); err == nil && st.Size() > auditMax {
		os.Remove(auditFile + ".1")
		os.Rename(auditFile, auditFile+".1")
	}
	f, err := os.OpenFile(auditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	f.Write(append(line, '\n'))
	f.Close()
	fmt.Printf("[log] %s | %-5s | %s | %s | %s %s\n", e.Time, e.Level, e.IP, e.User, e.Action, e.Detail)
}

// Handler içinden ayrıntılı kayıt için
func logEvent(r *http.Request, action, detail string) {
	writeAudit(AuditEntry{Level: "info", IP: clientIP(r), User: who(r).Name, Action: action, Detail: detail})
}

func readAuditTail(n int) []AuditEntry {
	auditMu.Lock()
	defer auditMu.Unlock()
	out := []AuditEntry{}
	f, err := os.Open(auditFile)
	if err != nil {
		return out
	}
	defer f.Close()
	st, _ := f.Stat()
	const chunk = 768 << 10
	off := int64(0)
	if st.Size() > chunk {
		off = st.Size() - chunk
	}
	f.Seek(off, io.SeekStart)
	data, _ := io.ReadAll(f)
	lines := strings.Split(string(data), "\n")
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		var e AuditEntry
		if json.Unmarshal([]byte(lines[i]), &e) == nil && e.Action != "" {
			out = append(out, e) // en yeni başta
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Ara katman
// ---------------------------------------------------------------------------

type auditKey struct{}
type auditInfo struct{ user string }

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(c int) {
	s.code = c
	s.ResponseWriter.WriteHeader(c)
}

var actionNames = map[string]string{
	"/api/login":           "giriş denemesi",
	"/api/bot/start":       "bot başlattı",
	"/api/bot/stop":        "bot durdurdu",
	"/api/bot/kill":        "bot zorla kapattı",
	"/api/bot/restart":     "bot yeniden başlattı",
	"/api/bots/create":     "bot oluşturdu",
	"/api/bots/update":     "bot düzenledi",
	"/api/bots/delete":     "bot sildi",
	"/api/files/write":     "dosya yazdı",
	"/api/files/mkdir":     "klasör açtı",
	"/api/files/rename":    "yeniden adlandırdı",
	"/api/files/upload":    "dosya yükledi",
	"/api/files/delete":    "dosya sildi",
	"/api/files/read":      "dosya okudu",
	"/api/files/download":  "dosya indirdi",
	"/api/db/browse":       "tablo görüntüledi",
	"/api/me/password":     "şifre değiştirme",
	"/api/users/create":    "hesap oluşturma",
	"/api/users/delete":    "hesap silme",
	"/api/users/grant":     "yetki verme",
	"/api/users/revoke":    "yetki alma",
	"/api/users/deny/add":  "dosya engeli ekleme",
	"/api/users/deny/remove": "dosya engeli kaldırma",
	// /api/bot/send ve /api/db/query handler içinde logEvent ile (içerikle) kaydedilir
}

// Başarılıysa auditf zaten yazdığı için ara katman sadece hatayı kaydeder.
func coveredByAuditf(p string) bool {
	return p == "/api/login" || p == "/api/me/password" || strings.HasPrefix(p, "/api/users/")
}

func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		ai := &auditInfo{}
		r = r.WithContext(context.WithValue(r.Context(), auditKey{}, ai))
		sw := &statusWriter{ResponseWriter: w, code: 200}

		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if isHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}

		defer func() {
			p := r.URL.Path
			name, known := actionNames[p]
			code := sw.code
			bad := code == 403 || code == 404 || code == 429 || code >= 500 || (p == "/api/login" && code == 401)
			if !bad && (!known || coveredByAuditf(p)) {
				return
			}
			if name == "" {
				name = "istek reddedildi"
			}
			level := "info"
			switch {
			case code == 429 || strings.Contains(name, "yasak"):
				level = "alert"
			case code >= 400:
				level = "warn"
			}
			var parts []string
			q := r.URL.Query()
			for _, k := range []string{"id", "path", "to", "file", "table", "name"} {
				if v := q.Get(k); v != "" {
					parts = append(parts, k+"="+v)
				}
			}
			detail := r.Method + " " + p
			if len(parts) > 0 {
				detail += " (" + strings.Join(parts, ", ") + ")"
			}
			writeAudit(AuditEntry{Level: level, IP: ip, User: ai.user, Action: name, Detail: detail, Status: code})
		}()

		if d := banRemaining(ip); d > 0 {
			http.Error(sw, fmt.Sprintf("erişimin geçici olarak engellendi (%d dk)", int(d.Minutes())+1), http.StatusForbidden)
			return
		}
		if !apiLimit.allow(ip) {
			strike(ip, ai.user)
			sw.Header().Set("Retry-After", "5")
			http.Error(sw, "çok fazla istek, yavaşla", http.StatusTooManyRequests)
			return
		}
		if r.URL.Path == "/api/login" && !loginLimit.allow(ip) {
			strike(ip, ai.user)
			sw.Header().Set("Retry-After", "30")
			http.Error(sw, "çok fazla giriş denemesi, biraz bekle", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(sw, r)
	})
}

// ---------------------------------------------------------------------------
// Günlük API'si (sadece admin) + arka plan işleri
// ---------------------------------------------------------------------------

func registerSecurity() {
	http.HandleFunc("/audit", page("audit.html", false))
	http.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		if !who(r).Admin {
			http.Error(w, "sadece admin", http.StatusForbidden)
			return
		}
		writeJSON(w, readAuditTail(500))
	})
}

func startSecurity() {
	go func() {
		var ms runtime.MemStats
		tick := time.NewTicker(time.Minute)
		n := 0
		for range tick.C {
			n++
			apiLimit.gc()
			loginLimit.gc()
			ipMu.Lock()
			if n%10 == 0 {
				strikes = map[string]int{}
			}
			for ip, t := range bans {
				if time.Now().After(t) {
					delete(bans, ip)
				}
			}
			ipMu.Unlock()

			debug.FreeOSMemory() // kullanılmayan belleği işletim sistemine geri ver
			runtime.ReadMemStats(&ms)
			fmt.Printf("[bellek] canlı heap=%d MB, sys=%d MB, goroutine=%d\n",
				ms.HeapAlloc>>20, ms.Sys>>20, runtime.NumGoroutine())
		}
	}()
}