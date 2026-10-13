package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type BotConfig struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Startup string `json:"startup"`
}

type BotInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Startup string `json:"startup"`
	Dir     string `json:"dir"`
	Running bool   `json:"running"`
	Uptime  int    `json:"uptime"`
	Mem     int    `json:"mem"`
}

type Bot struct {
	BotConfig // Name ve Startup'a sadece mgr.mu kilidiyle dokun

	mu      sync.Mutex // süreç durumu
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	running bool
	started time.Time

	lm      sync.Mutex // log listesi
	logs    []string
	dropped int
}

type Manager struct {
	mu    sync.Mutex
	bots  map[string]*Bot
	order []string
}

var mgr = &Manager{bots: map[string]*Bot{}}

const configFile = "data/bots.json"

func botDir(id string) string { return filepath.Join("data", "bots", id) }

func (m *Manager) load() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}
	var list []BotConfig
	json.Unmarshal(data, &list)
	for _, c := range list {
		m.bots[c.ID] = &Bot{BotConfig: c}
		m.order = append(m.order, c.ID)
	}
}

// m.mu kilitliyken çağır
func (m *Manager) save() {
	list := []BotConfig{}
	for _, id := range m.order {
		list = append(list, m.bots[id].BotConfig)
	}
	data, _ := json.MarshalIndent(list, "", "  ")
	os.WriteFile(configFile, data, 0644)
}

func (m *Manager) get(id string) *Bot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bots[id]
}

func (m *Manager) all() []*Bot {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := make([]*Bot, 0, len(m.order))
	for _, id := range m.order {
		list = append(list, m.bots[id])
	}
	return list
}

func newID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------- Süreç yönetimi ----------

func findPython(dir string) (string, error) {
	// 1) Botun kendi venv'i varsa onu kullan
	for _, p := range []string{
		filepath.Join(dir, "venv", "Scripts", "python.exe"),
		filepath.Join(dir, "venv", "bin", "python"),
	} {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs, nil
		}
	}
	// 2) PYTHON ortam değişkeni
	if p := os.Getenv("PYTHON"); p != "" {
		return p, nil
	}
	// 3) Sistemdeki Python (Windows'taki sahte Store kısayolunu eler)
	candidates := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		candidates = []string{"py", "python", "python3"}
	}
	for _, c := range candidates {
		path, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		out, err := exec.Command(path, "-c", "import sys;print(sys.executable)").Output()
		exe := strings.TrimSpace(string(out))
		if err == nil && exe != "" {
			return exe, nil
		}
	}
	return "", fmt.Errorf("Python bulunamadı. python.org'dan kur ve kurulumda 'Add python.exe to PATH' kutusunu işaretle")
}

func (b *Bot) addLog(line string) {
	if len(line) > 4096 {
		line = line[:4096] + "…"
	}
	b.lm.Lock()
	defer b.lm.Unlock()
	b.logs = append(b.logs, line)
	if len(b.logs) > 1000 {
		n := copy(b.logs, b.logs[1:])
		b.logs[n] = ""
		b.logs = b.logs[:n]
		b.dropped++
	}
}

func (b *Bot) isRunning() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.running
}

func (b *Bot) Start() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running {
		return fmt.Errorf("bot zaten çalışıyor")
	}

	mgr.mu.Lock()
	startup := b.Startup
	mgr.mu.Unlock()

	dir := botDir(b.ID)
	file, err := safePath(dir, startup)
	if err != nil {
		return err
	}
	if _, err := os.Stat(file); err != nil {
		return fmt.Errorf("%s dosyası yok. Dosyalar sekmesinden yükle", startup)
	}
	py, err := findPython(dir)
	if err != nil {
		return err
	}

	cmd := exec.Command(py, "-u", startup)
	cmd.Dir = dir
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	stdin, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		return err
	}
	b.cmd = cmd
	b.stdin = stdin
	b.running = true
	b.started = time.Now()

	b.addLog("[panel] Bot başlatıldı")

	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			b.addLog(sc.Text())
		}
		cmd.Wait()
		b.mu.Lock()
		b.running = false
		b.mu.Unlock()
		b.addLog("[panel] Bot kapandı")
	}()
	return nil
}

func (b *Bot) Stop() {
	b.mu.Lock()
	cmd := b.cmd
	b.mu.Unlock()
	if cmd == nil || !b.isRunning() {
		return
	}
	b.addLog("[panel] Durduruluyor...")
	if err := cmd.Process.Signal(sigInterrupt()); err != nil {
		cmd.Process.Kill() // Windows'ta Interrupt çalışmaz
	}
	for i := 0; i < 50; i++ {
		if !b.isRunning() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	b.Kill()
}

func (b *Bot) Kill() {
	b.mu.Lock()
	cmd := b.cmd
	b.mu.Unlock()
	if cmd != nil && b.isRunning() {
		b.addLog("[panel] Zorla kapatıldı")
		cmd.Process.Kill()
	}
}

func (b *Bot) Send(text string) {
	b.mu.Lock()
	stdin := b.stdin
	running := b.running
	b.mu.Unlock()
	if running && stdin != nil {
		b.addLog("> " + text)
		io.WriteString(stdin, text+"\n")
	}
}

func (b *Bot) memKB() int {
	b.mu.Lock()
	cmd := b.cmd
	running := b.running
	b.mu.Unlock()
	if !running || cmd == nil || cmd.Process == nil {
		return 0
	}
	return processRSS(cmd.Process.Pid)
}

func (b *Bot) info() BotInfo {
	mgr.mu.Lock()
	i := BotInfo{ID: b.ID, Name: b.Name, Startup: b.Startup}
	i.Dir, _ = filepath.Abs(botDir(b.ID))
	mgr.mu.Unlock()
	b.mu.Lock()
	i.Running = b.running
	if b.running {
		i.Uptime = int(time.Since(b.started).Seconds())
	}
	b.mu.Unlock()
	i.Mem = b.memKB()
	return i
}

// ---------- HTTP: bot listesi, oluştur, düzenle, sil ----------

func withBot(h func(w http.ResponseWriter, r *http.Request, b *Bot)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b := mgr.get(r.URL.Query().Get("id"))
		if b == nil {
			http.Error(w, "bot bulunamadı", http.StatusNotFound)
			return
		}
		h(w, r, b)
	}
}

type botForm struct {
	Name    string `json:"name"`
	Startup string `json:"startup"`
}

func readForm(r *http.Request) (botForm, error) {
	var f botForm
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&f); err != nil {
		return f, fmt.Errorf("geçersiz istek")
	}
	f.Name = strings.TrimSpace(f.Name)
	f.Startup = strings.TrimSpace(f.Startup)
	if f.Startup == "" {
		f.Startup = "main.py"
	}
	if f.Name == "" || len([]rune(f.Name)) > 40 {
		return f, fmt.Errorf("isim 1-40 karakter olmalı")
	}
	return f, nil
}

const starterFile = `import time

print("Bot basladi", flush=True)
i = 0
while True:
    i += 1
    print(f"Calisiyor... {i}", flush=True)
    time.sleep(2)
`

func registerBots() {
	http.HandleFunc("/api/bots", func(w http.ResponseWriter, r *http.Request) {
		list := []BotInfo{}
		for _, b := range mgr.all() {
			list = append(list, b.info())
		}
		writeJSON(w, list)
	})

	http.HandleFunc("/api/bots/create", post(func(w http.ResponseWriter, r *http.Request) {
		f, err := readForm(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		id := newID()
		d := botDir(id)
		file, err := safePath(d, f.Startup)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		os.WriteFile(file, []byte(starterFile), 0644)

		mgr.mu.Lock()
		mgr.bots[id] = &Bot{BotConfig: BotConfig{ID: id, Name: f.Name, Startup: f.Startup}}
		mgr.order = append(mgr.order, id)
		mgr.save()
		mgr.mu.Unlock()
		writeJSON(w, map[string]string{"id": id})
	}))

	http.HandleFunc("/api/bots/update", post(withBot(func(w http.ResponseWriter, r *http.Request, b *Bot) {
		f, err := readForm(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if _, err := safePath(botDir(b.ID), f.Startup); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mgr.mu.Lock()
		b.Name = f.Name
		b.Startup = f.Startup
		mgr.save()
		mgr.mu.Unlock()
	})))

	http.HandleFunc("/api/bots/delete", post(withBot(func(w http.ResponseWriter, r *http.Request, b *Bot) {
		// Botu silmek engelli dosyaları da siler; engeli olan hesap bunu yapamaz
		if who(r).HasDenyForBot(b.ID) {
			http.Error(w, "bu botta sana uygulanan dosya engelleri var; botu silemezsin", http.StatusForbidden)
			return
		}
		b.Kill()
		for i := 0; i < 30 && b.isRunning(); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		mgr.mu.Lock()
		delete(mgr.bots, b.ID)
		for i, id := range mgr.order {
			if id == b.ID {
				mgr.order = append(mgr.order[:i], mgr.order[i+1:]...)
				break
			}
		}
		mgr.save()
		mgr.mu.Unlock()
		if err := os.RemoveAll(botDir(b.ID)); err != nil {
			http.Error(w, "klasör silinemedi: "+err.Error(), 500)
		}
	})))
}
