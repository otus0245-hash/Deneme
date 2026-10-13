package main

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Yetki kataloğu
// ---------------------------------------------------------------------------

type PermDef struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Group  string `json:"group"`
	Danger bool   `json:"danger,omitempty"`
}

var permCatalog = []PermDef{
	{"bots.view", "Botları ve konsol çıktısını görüntüle", "Botlar", false},
	{"bots.control", "Başlat / durdur / yeniden başlat / konsola komut gönder", "Botlar", true},
	{"bots.create", "Bot oluştur", "Botlar", false},
	{"bots.edit", "Bot adını ve başlangıç dosyasını düzenle", "Botlar", false},
	{"bots.delete", "Bot sil", "Botlar", false},
	{"files.view", "Dosyaları listele, oku ve indir", "Dosyalar", false},
	{"files.write", "Dosya düzenle / oluştur, klasör aç, yeniden adlandır", "Dosyalar", true},
	{"files.upload", "Dosya yükle", "Dosyalar", true},
	{"files.delete", "Dosya ve klasör sil", "Dosyalar", false},
	{"db.view", "Veritabanını görüntüle (salt okunur)", "Veritabanı", false},
	{"db.write", "Veritabanına yazma (SQL ile değiştirme)", "Veritabanı", false},
	{"users.create", "Alt hesap oluştur", "Hesaplar", false},
	{"users.delete", "Alt hesap sil", "Hesaplar", false},
	{"perms.grant", "Yetki ver (yalnızca kendinde olanları) ve dosya engelini kaldır", "Hesaplar", false},
	{"perms.revoke", "Yetki al ve dosya erişimini engelle", "Hesaplar", false},
}

var permValid = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range permCatalog {
		m[p.Key] = true
	}
	return m
}()

// ---------------------------------------------------------------------------
// Veri modeli
// ---------------------------------------------------------------------------

// DenyRule: bir bot içinde (ya da tüm botlarda "*") bir yola erişimi kapatır.
// Path boşsa botun tüm dosyaları kapalıdır.
type DenyRule struct {
	Bot  string `json:"bot"`
	Path string `json:"path"`
}

type User struct {
	Name    string     `json:"name"`
	Hash    string     `json:"hash"`
	Admin   bool       `json:"admin,omitempty"`
	Parent  string     `json:"parent,omitempty"` // hesabı oluşturan kişi
	Perms   []string   `json:"perms"`
	Deny    []DenyRule `json:"deny"`
	Created int64      `json:"created"`
}

type session struct {
	user string
	exp  time.Time
}

type failInfo struct {
	n     int
	until time.Time
}

type authState struct {
	mu       sync.RWMutex
	users    map[string]*User
	sessions map[string]*session
	fails    map[string]*failInfo
}

var A = &authState{
	users:    map[string]*User{},
	sessions: map[string]*session{},
	fails:    map[string]*failInfo{},
}

const (
	cookieName = "panel_session"
	sessionTTL = 12 * time.Hour
	usersFile  = "data/users.json"
	minPassLen = 8
	maxPassLen = 128
	pbkdfIter  = 600000
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,31}$`)

// ---------------------------------------------------------------------------
// İstek sırasında kullanılan değişmez "kimlik" kopyası
// ---------------------------------------------------------------------------

type Principal struct {
	Name  string
	Admin bool
	Perms map[string]bool
	Deny  []DenyRule // etkin engeller: kendi + üst hesapların engelleri
}

func (p *Principal) Can(perm string) bool { return p.Admin || p.Perms[perm] }

func (p *Principal) PermList() []string {
	out := []string{}
	for _, d := range permCatalog {
		if p.Can(d.Key) {
			out = append(out, d.Key)
		}
	}
	return out
}

func (p *Principal) CanManage() bool {
	return p.Can("users.create") || p.Can("users.delete") || p.Can("perms.grant") || p.Can("perms.revoke")
}

type principalKey struct{}

func who(r *http.Request) *Principal {
	p, _ := r.Context().Value(principalKey{}).(*Principal)
	if p == nil {
		// Ara katman atlanmışsa hiçbir yetkisi olmayan bir kimlik döner (güvenli varsayılan)
		return &Principal{Perms: map[string]bool{}}
	}
	return p
}

// a.mu kilitliyken çağır
func (a *authState) principalOf(u *User) *Principal {
	p := &Principal{Name: u.Name, Admin: u.Admin, Perms: map[string]bool{}}
	for _, k := range u.Perms {
		p.Perms[k] = true
	}
	if !u.Admin {
		cur := u
		for i := 0; cur != nil && i < 64; i++ {
			p.Deny = append(p.Deny, cur.Deny...)
			cur = a.users[cur.Parent]
		}
	}
	return p
}

// ---------------------------------------------------------------------------
// Dosya yolu engelleri
// ---------------------------------------------------------------------------

// cleanRel: yolu bot klasörüne göre temizler ("a/../b" -> "b", "" -> kök)
func cleanRel(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	return strings.TrimPrefix(path.Clean("/"+p), "/")
}

func relJoin(a, b string) string {
	if a == "" {
		return b
	}
	return a + "/" + b
}

// Denied: bu yola erişim engelli mi? mutate=true ise (silme, yeniden adlandırma,
// yazma) engelli bir yolun üst klasörüne yapılan işlemler de engellenir; çünkü
// engelli içeriği etkiler.
func (p *Principal) Denied(bot, rel string, mutate bool) bool {
	if p.Admin {
		return false
	}
	pl := strings.ToLower(cleanRel(rel))
	for _, d := range p.Deny {
		if d.Bot != "*" && d.Bot != bot {
			continue
		}
		r := strings.ToLower(cleanRel(d.Path))
		if r == "" {
			return true
		}
		if pl == r || strings.HasPrefix(pl, r+"/") {
			return true
		}
		if mutate && (pl == "" || strings.HasPrefix(r, pl+"/")) {
			return true
		}
	}
	return false
}

// Bu kullanıcının bu bot üzerinde herhangi bir engeli var mı?
func (p *Principal) HasDenyForBot(bot string) bool {
	if p.Admin {
		return false
	}
	for _, d := range p.Deny {
		if d.Bot == "*" || d.Bot == bot {
			return true
		}
	}
	return false
}

func pathsOverlap(a, b string) bool {
	a = strings.ToLower(cleanRel(a))
	b = strings.ToLower(cleanRel(b))
	return a == "" || b == "" || a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// Kural, yapan kişinin kendi engelleriyle (herhangi bir şekilde) kesişiyor mu?
// Kesişiyorsa kuralı kaldırmak, yapan kişinin erişemediği yere hedefe erişim vermek olur.
func (p *Principal) RuleOverlapsOwnDeny(rule DenyRule) bool {
	for _, d := range p.Deny {
		if (d.Bot == "*" || rule.Bot == "*" || d.Bot == rule.Bot) && pathsOverlap(d.Path, rule.Path) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Parola
// ---------------------------------------------------------------------------

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdfIter, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func verifyPassword(pw, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1000 || iter > 5000000 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func randomPassword() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

var dummyHash string // kullanıcı yoksa da aynı sürede doğrulama yapmak için

// ---------------------------------------------------------------------------
// Depolama
// ---------------------------------------------------------------------------

// a.mu yazma kilidiyle çağır
func (a *authState) saveLocked() error {
	list := make([]*User, 0, len(a.users))
	for _, u := range a.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Created != list[j].Created {
			return list[i].Created < list[j].Created
		}
		return list[i].Name < list[j].Name
	})
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := usersFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, usersFile)
}

func auditf(actor, format string, args ...any) {
	writeAudit(AuditEntry{Level: "warn", User: actor, Action: "yetki/hesap", Detail: fmt.Sprintf(format, args...)})
}

func initAuth() {
	dummyHash, _ = hashPassword(randomToken(8))

	A.mu.Lock()
	defer A.mu.Unlock()

	if data, err := os.ReadFile(usersFile); err == nil {
		var list []*User
		if err := json.Unmarshal(data, &list); err != nil {
			fmt.Println("HATA:", usersFile, "okunamadı:", err)
			os.Exit(1) // bozuk dosyanın üstüne yazıp hesapları kaybetme
		}
		for _, u := range list {
			if u.Perms == nil {
				u.Perms = []string{}
			}
			if u.Deny == nil {
				u.Deny = []DenyRule{}
			}
			A.users[u.Name] = u
		}
	}

	var admin *User
	for _, u := range A.users {
		if u.Admin {
			admin = u
		}
	}

	envPass := os.Getenv("PANEL_ADMIN_PASSWORD")
	switch {
	case admin == nil:
		pass := envPass
		generated := false
		if pass == "" {
			pass = randomPassword()
			generated = true
		}
		h, _ := hashPassword(pass)
		name := "admin"
		for A.users[name] != nil { // çok düşük ihtimal: ad dolu
			name = "admin-" + randomToken(2)
		}
		A.users[name] = &User{Name: name, Hash: h, Admin: true, Perms: []string{}, Deny: []DenyRule{}, Created: time.Now().Unix()}
		if err := A.saveLocked(); err != nil {
			fmt.Println("HATA: hesaplar kaydedilemedi:", err)
			os.Exit(1)
		}
		fmt.Println("==================================================")
		fmt.Println(" İlk kurulum: admin hesabı oluşturuldu")
		fmt.Println("   Kullanıcı adı:", name)
		if generated {
			fmt.Println("   Şifre        :", pass)
			fmt.Println(" Giriş yaptıktan sonra şifreni değiştir.")
		} else {
			fmt.Println("   Şifre        : PANEL_ADMIN_PASSWORD ortam değişkeninden alındı")
		}
		fmt.Println("==================================================")
	case envPass != "":
		if len(envPass) < minPassLen {
			fmt.Println("HATA: PANEL_ADMIN_PASSWORD en az", minPassLen, "karakter olmalı")
			os.Exit(1)
		}
		admin.Hash, _ = hashPassword(envPass)
		A.saveLocked()
		fmt.Println("Admin şifresi PANEL_ADMIN_PASSWORD ile güncellendi (hesap:", admin.Name+")")
	}

	go func() {
		for range time.Tick(10 * time.Minute) {
			A.mu.Lock()
			now := time.Now()
			for t, s := range A.sessions {
				if now.After(s.exp) {
					delete(A.sessions, t)
				}
			}
			A.mu.Unlock()
		}
	}()
}

// ---------------------------------------------------------------------------
// Oturum + ara katman
// ---------------------------------------------------------------------------

func principalFromRequest(r *http.Request) *Principal {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	A.mu.Lock()
	defer A.mu.Unlock()
	s := A.sessions[c.Value]
	if s == nil {
		return nil
	}
	if time.Now().After(s.exp) {
		delete(A.sessions, c.Value)
		return nil
	}
	u := A.users[s.user]
	if u == nil {
		delete(A.sessions, c.Value)
		return nil
	}
	s.exp = time.Now().Add(sessionTTL)
	return A.principalOf(u)
}

// Her API yolunun gerektirdiği yetki. Burada olmayan /api/ yolları reddedilir.
var routePerm = map[string]string{
	"/api/stats":          "bots.view",
	"/api/bots":           "bots.view",
	"/api/bots/create":    "bots.create",
	"/api/bots/update":    "bots.edit",
	"/api/bots/delete":    "bots.delete",
	"/api/bot/info":       "bots.view",
	"/api/bot/logs":       "bots.view",
	"/api/bot/start":      "bots.control",
	"/api/bot/stop":       "bots.control",
	"/api/bot/kill":       "bots.control",
	"/api/bot/restart":    "bots.control",
	"/api/bot/send":       "bots.control",
	"/api/files/list":     "files.view",
	"/api/files/read":     "files.view",
	"/api/files/download": "files.view",
	"/api/files/write":    "files.write",
	"/api/files/mkdir":    "files.write",
	"/api/files/rename":   "files.write",
	"/api/files/upload":   "files.upload",
	"/api/files/delete":   "files.delete",
	"/api/db/files":       "db.view",
	"/api/db/tables":      "db.view",
	"/api/db/browse":      "db.view",
	"/api/db/structure":   "db.view",
	"/api/db/query":       "db.view", // yazma için ayrıca db.write kontrol edilir
}

// Sadece giriş yapmış olmayı yeterli sayanlar (yetkiyi kendi içlerinde kontrol ederler)
var authOnly = map[string]bool{
	"/api/audit": 			  true,
	"/api/me":                true,
	"/api/me/password":       true,
	"/api/logout":            true,
	"/api/perms":             true,
	"/api/users":             true,
	"/api/users/create":      true,
	"/api/users/delete":      true,
	"/api/users/grant":       true,
	"/api/users/revoke":      true,
	"/api/users/deny/add":    true,
	"/api/users/deny/remove": true,
}

var pagePerm = map[string]string{
	"/console": "bots.view",
	"/files":   "files.view",
	"/db":      "db.view",
}

// Tarayıcılar çapraz site isteklerinde Sec-Fetch-Site gönderir; değiştiren isteklerde
// yalnızca aynı kökenden gelenleri kabul et. (Başlık yoksa istek tarayıcıdan değildir;
// çerez olmadan zaten giriş yapamaz.)
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	}
	return false
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		p := r.URL.Path
		isAPI := strings.HasPrefix(p, "/api/")
		if isAPI {
			h.Set("Cache-Control", "no-store")
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			http.Error(w, "geçersiz istek kaynağı", http.StatusForbidden)
			return
		}

		if p == "/login" || p == "/api/login" || strings.HasPrefix(p, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		pr := principalFromRequest(r)
		if pr == nil {
			if isAPI {
				http.Error(w, "giriş gerekli", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), principalKey{}, pr))
		if ai, ok := r.Context().Value(auditKey{}).(*auditInfo); ok {
			ai.user = pr.Name
		}


		if isAPI {
			if need, ok := routePerm[p]; ok {
				if !pr.Can(need) {
					http.Error(w, "bu işlem için yetkin yok ("+need+")", http.StatusForbidden)
					return
				}
			} else if !authOnly[p] {
				http.Error(w, "yetkisiz uç nokta", http.StatusForbidden)
				return
			}
		} else if need, ok := pagePerm[p]; ok && !pr.Can(need) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Giriş / çıkış / ben
// ---------------------------------------------------------------------------

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r),
	})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "geçersiz istek", http.StatusBadRequest)
		return false
	}
	return true
}

func lockWait(name string) time.Duration {
	A.mu.Lock()
	defer A.mu.Unlock()
	if f := A.fails[name]; f != nil {
		if d := time.Until(f.until); d > 0 {
			return d
		}
	}
	return 0
}

func noteFail(name string) {
	A.mu.Lock()
	defer A.mu.Unlock()
	if len(A.fails) > 10000 {
		A.fails = map[string]*failInfo{}
	}
	f := A.fails[name]
	if f == nil {
		f = &failInfo{}
		A.fails[name] = f
	}
	f.n++
	if f.n >= 5 {
		f.until = time.Now().Add(time.Duration(1<<uint(min(f.n-5, 4))) * 30 * time.Second)
	}
}

func clearFails(name string) {
	A.mu.Lock()
	delete(A.fails, name)
	A.mu.Unlock()
}

func registerAuth() {
	http.HandleFunc("/login", page("login.html", false))
	http.HandleFunc("/users", page("users.html", false))

	http.HandleFunc("/api/login", post(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		name := strings.ToLower(strings.TrimSpace(in.Name))
		if ai, ok := r.Context().Value(auditKey{}).(*auditInfo); ok {
			ai.user = name
		}
		ip := clientIP(r)
		if wait := max(lockWait(name), lockWait("ip:"+ip)); wait > 0 {
			http.Error(w, fmt.Sprintf("çok fazla başarısız deneme. %d sn sonra tekrar dene", int(wait.Seconds())+1), http.StatusTooManyRequests)
			return
		}
		A.mu.RLock()
		u := A.users[name]
		hash := dummyHash
		if u != nil {
			hash = u.Hash
		}
		A.mu.RUnlock()
		ok := len(in.Password) <= maxPassLen && verifyPassword(in.Password, hash) && u != nil
		if !ok {
			noteFail(name)
			noteFail("ip:" + ip)
			http.Error(w, "kullanıcı adı veya şifre hatalı", http.StatusUnauthorized)
			return
		}
		clearFails(name)
		token := randomToken(32)
		A.mu.Lock()
		A.sessions[token] = &session{user: name, exp: time.Now().Add(sessionTTL)}
		A.mu.Unlock()
		setSessionCookie(w, r, token, int(sessionTTL.Seconds()))
		auditf(name, "giriş yaptı")
		writeJSON(w, map[string]string{"ok": "1"})
	}))

	http.HandleFunc("/api/logout", post(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(cookieName); err == nil {
			A.mu.Lock()
			delete(A.sessions, c.Value)
			A.mu.Unlock()
		}
		setSessionCookie(w, r, "", -1)
	}))

	http.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		p := who(r)
		deny := p.Deny
		if deny == nil {
			deny = []DenyRule{}
		}
		writeJSON(w, map[string]any{
			"name": p.Name, "admin": p.Admin, "perms": p.PermList(),
			"manage": p.CanManage(), "deny": deny,
		})
	})

	http.HandleFunc("/api/perms", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, permCatalog)
	})

	http.HandleFunc("/api/me/password", post(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Old string `json:"old"`
			New string `json:"new"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if len(in.New) < minPassLen || len(in.New) > maxPassLen {
			http.Error(w, fmt.Sprintf("yeni şifre %d-%d karakter olmalı", minPassLen, maxPassLen), http.StatusBadRequest)
			return
		}
		p := who(r)
		A.mu.RLock()
		u := A.users[p.Name]
		var cur string
		if u != nil {
			cur = u.Hash
		}
		A.mu.RUnlock()
		if u == nil || len(in.Old) > maxPassLen || !verifyPassword(in.Old, cur) {
			http.Error(w, "mevcut şifre hatalı", http.StatusForbidden)
			return
		}
		h, err := hashPassword(in.New)
		if err != nil {
			http.Error(w, "şifre kaydedilemedi", 500)
			return
		}
		keep := ""
		if c, err := r.Cookie(cookieName); err == nil {
			keep = c.Value
		}
		A.mu.Lock()
		defer A.mu.Unlock()
		if u = A.users[p.Name]; u == nil {
			http.Error(w, "hesap bulunamadı", 404)
			return
		}
		u.Hash = h
		for t, s := range A.sessions { // diğer oturumları kapat
			if s.user == p.Name && t != keep {
				delete(A.sessions, t)
			}
		}
		if err := A.saveLocked(); err != nil {
			http.Error(w, "kaydedilemedi: "+err.Error(), 500)
			return
		}
		auditf(p.Name, "şifresini değiştirdi")
	}))

	registerUserAPI()
}
