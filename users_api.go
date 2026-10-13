package main

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

// Hesap yönetimi kuralları (özet):
//   - Admin her şeyi yapabilir; silinemez, değiştirilemez.
//   - Herkes yalnızca kendi oluşturduğu hesapları ve onların altındakileri yönetebilir
//     (kendini, üstünü veya yan hesapları yönetemez).
//   - Yetki verirken: yetkiyi veren kişide VE hedef hesabın üstünde de o yetki olmalı.
//     Yani "yetki ver" yetkisi olup "yetki al" yetkisi olmayan biri "yetki al"ı kimseye veremez.
//   - Alt hesap, üst hesabından fazla yetkiye sahip olamaz. Yetki alınınca alttakilerden de alınır.
//   - Dosya engelleri alt hesaplara miras kalır. Engel eklemek "yetki al", kaldırmak
//     "yetki ver" yetkisi ister; ayrıca kişi kendisine uygulanan bir engeli başkası için kaldıramaz.

// a.mu kilitliyken çağır. target, actor'un yönetebileceği bir hesap mı?
func (a *authState) manageable(actor *Principal, target *User) bool {
	if target == nil || target.Admin || target.Name == actor.Name {
		return false
	}
	if actor.Admin {
		return true
	}
	cur := a.users[target.Parent]
	for i := 0; cur != nil && i < 64; i++ {
		if cur.Name == actor.Name {
			return true
		}
		cur = a.users[cur.Parent]
	}
	return false
}

// a.mu kilitliyken çağır. u'nun altındaki tüm hesaplar (kendisi dahil değil)
func (a *authState) descendants(name string) []*User {
	children := map[string][]*User{}
	for _, u := range a.users {
		children[u.Parent] = append(children[u.Parent], u)
	}
	var out []*User
	var walk func(n string, depth int)
	walk = func(n string, depth int) {
		if depth > 64 {
			return
		}
		kids := children[n]
		sort.Slice(kids, func(i, j int) bool { return kids[i].Name < kids[j].Name })
		for _, k := range kids {
			out = append(out, k)
			walk(k.Name, depth+1)
		}
	}
	walk(name, 0)
	return out
}

func hasPerm(u *User, perm string) bool {
	if u == nil {
		return false
	}
	if u.Admin {
		return true
	}
	for _, p := range u.Perms {
		if p == perm {
			return true
		}
	}
	return false
}

func removeStr(list []string, drop map[string]bool) []string {
	out := []string{}
	for _, s := range list {
		if !drop[s] {
			out = append(out, s)
		}
	}
	return out
}

type userView struct {
	Name      string     `json:"name"`
	Parent    string     `json:"parent"`
	Depth     int        `json:"depth"`
	Perms     []string   `json:"perms"`
	Deny      []DenyRule `json:"deny"`
	Grantable []string   `json:"grantable"` // bu hesaba şu an verebileceğin yetkiler
	Created   int64      `json:"created"`
}

func registerUserAPI() {
	// Yönetebildiğin hesaplar (ağaç sırasıyla)
	http.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		me := who(r)
		if !me.CanManage() {
			http.Error(w, "hesap yönetimi yetkin yok", http.StatusForbidden)
			return
		}
		A.mu.RLock()
		defer A.mu.RUnlock()
		depth := map[string]int{me.Name: 0}
		out := []userView{}
		for _, u := range A.descendants(me.Name) {
			depth[u.Name] = depth[u.Parent] + 1
			v := userView{
				Name: u.Name, Parent: u.Parent, Depth: depth[u.Name] - 1,
				Perms: append([]string{}, u.Perms...), Deny: append([]DenyRule{}, u.Deny...),
				Grantable: []string{}, Created: u.Created,
			}
			if me.Can("perms.grant") {
				parent := A.users[u.Parent]
				for _, d := range permCatalog {
					if me.Can(d.Key) && hasPerm(parent, d.Key) && !hasPerm(u, d.Key) {
						v.Grantable = append(v.Grantable, d.Key)
					}
				}
			}
			out = append(out, v)
		}
		writeJSON(w, out)
	})

	http.HandleFunc("/api/users/create", post(func(w http.ResponseWriter, r *http.Request) {
		me := who(r)
		if !me.Can("users.create") {
			http.Error(w, "hesap oluşturma yetkin yok", http.StatusForbidden)
			return
		}
		var in struct {
			Name     string   `json:"name"`
			Password string   `json:"password"`
			Perms    []string `json:"perms"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		name := strings.ToLower(strings.TrimSpace(in.Name))
		if !nameRe.MatchString(name) {
			http.Error(w, "kullanıcı adı 3-32 karakter olmalı (a-z, 0-9, _ . -)", http.StatusBadRequest)
			return
		}
		if len(in.Password) < minPassLen || len(in.Password) > maxPassLen {
			http.Error(w, "şifre 8-128 karakter olmalı", http.StatusBadRequest)
			return
		}
		perms := []string{}
		seen := map[string]bool{}
		for _, k := range in.Perms {
			if !permValid[k] {
				http.Error(w, "bilinmeyen yetki: "+k, http.StatusBadRequest)
				return
			}
			if !seen[k] {
				seen[k] = true
				perms = append(perms, k)
			}
		}
		if len(perms) > 0 && !me.Can("perms.grant") {
			http.Error(w, "yetki verme yetkin olmadığı için hesabı yetkisiz oluşturabilirsin; yetkileri sonra biri verir", http.StatusForbidden)
			return
		}
		for _, k := range perms {
			if !me.Can(k) {
				http.Error(w, "'"+k+"' yetkisini veremezsin: bu yetki sende yok", http.StatusForbidden)
				return
			}
		}
		hash, err := hashPassword(in.Password)
		if err != nil {
			http.Error(w, "şifre işlenemedi", 500)
			return
		}
		A.mu.Lock()
		defer A.mu.Unlock()
		if A.users[name] != nil {
			http.Error(w, "bu kullanıcı adı kullanılıyor", http.StatusConflict)
			return
		}
		A.users[name] = &User{
			Name: name, Hash: hash, Parent: me.Name, Perms: perms,
			Deny: []DenyRule{}, Created: time.Now().Unix(),
		}
		if err := A.saveLocked(); err != nil {
			delete(A.users, name)
			http.Error(w, "kaydedilemedi: "+err.Error(), 500)
			return
		}
		auditf(me.Name, "hesap oluşturdu: %s yetkiler=%v", name, perms)
		writeJSON(w, map[string]string{"name": name})
	}))

	http.HandleFunc("/api/users/delete", post(func(w http.ResponseWriter, r *http.Request) {
		me := who(r)
		if !me.Can("users.delete") {
			http.Error(w, "hesap silme yetkin yok", http.StatusForbidden)
			return
		}
		name := strings.ToLower(r.URL.Query().Get("name"))
		A.mu.Lock()
		defer A.mu.Unlock()
		target := A.users[name]
		if !A.manageable(me, target) {
			http.Error(w, "bu hesabı yönetemezsin", http.StatusForbidden)
			return
		}
		doomed := map[string]bool{name: true}
		for _, d := range A.descendants(name) { // altındaki hesaplar da gider
			doomed[d.Name] = true
		}
		backup := map[string]*User{}
		for n := range doomed {
			backup[n] = A.users[n]
			delete(A.users, n)
		}
		if err := A.saveLocked(); err != nil {
			for n, u := range backup {
				A.users[n] = u
			}
			http.Error(w, "kaydedilemedi: "+err.Error(), 500)
			return
		}
		for t, s := range A.sessions {
			if doomed[s.user] {
				delete(A.sessions, t)
			}
		}
		names := []string{}
		for n := range doomed {
			names = append(names, n)
		}
		sort.Strings(names)
		auditf(me.Name, "hesap sildi: %v", names)
		writeJSON(w, map[string]any{"deleted": names})
	}))

	http.HandleFunc("/api/users/grant", post(func(w http.ResponseWriter, r *http.Request) {
		me := who(r)
		if !me.Can("perms.grant") {
			http.Error(w, "yetki verme yetkin yok", http.StatusForbidden)
			return
		}
		var in struct {
			Name  string   `json:"name"`
			Perms []string `json:"perms"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		A.mu.Lock()
		defer A.mu.Unlock()
		target := A.users[strings.ToLower(in.Name)]
		if !A.manageable(me, target) {
			http.Error(w, "bu hesabı yönetemezsin", http.StatusForbidden)
			return
		}
		parent := A.users[target.Parent]
		for _, k := range in.Perms {
			if !permValid[k] {
				http.Error(w, "bilinmeyen yetki: "+k, http.StatusBadRequest)
				return
			}
			if !me.Can(k) {
				http.Error(w, "'"+k+"' yetkisini veremezsin: bu yetki sende yok", http.StatusForbidden)
				return
			}
			if !hasPerm(parent, k) {
				http.Error(w, "'"+k+"' yetkisi bu hesabın üst hesabında ("+target.Parent+") yok; alt hesap üstünden fazla yetkiye sahip olamaz", http.StatusForbidden)
				return
			}
		}
		added := []string{}
		for _, k := range in.Perms {
			if !hasPerm(target, k) {
				target.Perms = append(target.Perms, k)
				added = append(added, k)
			}
		}
		if err := A.saveLocked(); err != nil {
			http.Error(w, "kaydedilemedi: "+err.Error(), 500)
			return
		}
		auditf(me.Name, "yetki verdi: %s += %v", target.Name, added)
	}))

	http.HandleFunc("/api/users/revoke", post(func(w http.ResponseWriter, r *http.Request) {
		me := who(r)
		if !me.Can("perms.revoke") {
			http.Error(w, "yetki alma yetkin yok", http.StatusForbidden)
			return
		}
		var in struct {
			Name  string   `json:"name"`
			Perms []string `json:"perms"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		drop := map[string]bool{}
		for _, k := range in.Perms {
			if !permValid[k] {
				http.Error(w, "bilinmeyen yetki: "+k, http.StatusBadRequest)
				return
			}
			drop[k] = true
		}
		A.mu.Lock()
		defer A.mu.Unlock()
		target := A.users[strings.ToLower(in.Name)]
		if !A.manageable(me, target) {
			http.Error(w, "bu hesabı yönetemezsin", http.StatusForbidden)
			return
		}
		// Alt hesap üstünden fazlasına sahip olamayacağı için alttakilerden de alınır
		for _, u := range append([]*User{target}, A.descendants(target.Name)...) {
			u.Perms = removeStr(u.Perms, drop)
		}
		if err := A.saveLocked(); err != nil {
			http.Error(w, "kaydedilemedi: "+err.Error(), 500)
			return
		}
		auditf(me.Name, "yetki aldı: %s -= %v (altındakilerden de)", target.Name, in.Perms)
	}))

	type denyIn struct {
		Name string `json:"name"`
		Bot  string `json:"bot"`
		Path string `json:"path"`
	}

	http.HandleFunc("/api/users/deny/add", post(func(w http.ResponseWriter, r *http.Request) {
		me := who(r)
		if !me.Can("perms.revoke") {
			http.Error(w, "erişim engelleme için 'yetki al' yetkisi gerekir", http.StatusForbidden)
			return
		}
		var in denyIn
		if !readJSON(w, r, &in) {
			return
		}
		rule := DenyRule{Bot: strings.TrimSpace(in.Bot), Path: cleanRel(in.Path)}
		if rule.Bot != "*" && mgr.get(rule.Bot) == nil {
			http.Error(w, "bot bulunamadı", http.StatusBadRequest)
			return
		}
		A.mu.Lock()
		defer A.mu.Unlock()
		target := A.users[strings.ToLower(in.Name)]
		if !A.manageable(me, target) {
			http.Error(w, "bu hesabı yönetemezsin", http.StatusForbidden)
			return
		}
		for _, d := range target.Deny {
			if d.Bot == rule.Bot && strings.EqualFold(d.Path, rule.Path) {
				http.Error(w, "bu engel zaten var", http.StatusConflict)
				return
			}
		}
		target.Deny = append(target.Deny, rule)
		if err := A.saveLocked(); err != nil {
			http.Error(w, "kaydedilemedi: "+err.Error(), 500)
			return
		}
		auditf(me.Name, "erişim engelledi: %s bot=%s yol=%q", target.Name, rule.Bot, rule.Path)
	}))

	http.HandleFunc("/api/users/deny/remove", post(func(w http.ResponseWriter, r *http.Request) {
		me := who(r)
		if !me.Can("perms.grant") {
			http.Error(w, "engeli kaldırmak için 'yetki ver' yetkisi gerekir", http.StatusForbidden)
			return
		}
		var in denyIn
		if !readJSON(w, r, &in) {
			return
		}
		rule := DenyRule{Bot: strings.TrimSpace(in.Bot), Path: cleanRel(in.Path)}
		if me.RuleOverlapsOwnDeny(rule) {
			http.Error(w, "bu engelle kesişen bir engel sana da uygulanıyor; kaldırırsan hedef hesap senin erişemediğin yere erişirdi", http.StatusForbidden)
			return
		}
		A.mu.Lock()
		defer A.mu.Unlock()
		target := A.users[strings.ToLower(in.Name)]
		if !A.manageable(me, target) {
			http.Error(w, "bu hesabı yönetemezsin", http.StatusForbidden)
			return
		}
		kept := []DenyRule{}
		found := false
		for _, d := range target.Deny {
			if d.Bot == rule.Bot && strings.EqualFold(d.Path, rule.Path) {
				found = true
				continue
			}
			kept = append(kept, d)
		}
		if !found {
			http.Error(w, "böyle bir engel yok (üst hesaptan miras kalan engeller buradan kaldırılamaz)", http.StatusNotFound)
			return
		}
		target.Deny = kept
		if err := A.saveLocked(); err != nil {
			http.Error(w, "kaydedilemedi: "+err.Error(), 500)
			return
		}
		auditf(me.Name, "engel kaldırdı: %s bot=%s yol=%q", target.Name, rule.Bot, rule.Path)
	}))
}
