package main

import (
	"io"
	"net/http"
	"strconv"
)

func registerConsole() {
	http.HandleFunc("/api/bot/info", withBot(func(w http.ResponseWriter, r *http.Request, b *Bot) {
		writeJSON(w, b.info())
	}))

	http.HandleFunc("/api/bot/start", post(withBot(func(w http.ResponseWriter, r *http.Request, b *Bot) {
		if err := b.Start(); err != nil {
			b.addLog("[panel] Hata: " + err.Error())
		}
	})))

	http.HandleFunc("/api/bot/stop", post(withBot(func(w http.ResponseWriter, r *http.Request, b *Bot) {
		b.Stop()
	})))

	http.HandleFunc("/api/bot/kill", post(withBot(func(w http.ResponseWriter, r *http.Request, b *Bot) {
		b.Kill()
	})))

	http.HandleFunc("/api/bot/restart", post(withBot(func(w http.ResponseWriter, r *http.Request, b *Bot) {
		b.Stop()
		if err := b.Start(); err != nil {
			b.addLog("[panel] Hata: " + err.Error())
		}
	})))

	http.HandleFunc("/api/bot/send", post(withBot(func(w http.ResponseWriter, r *http.Request, b *Bot) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		text := string(body)
		logEvent(r, "konsola komut gönderdi", "bot="+b.ID+" > "+text)
		b.Send(text)
		b.Send(string(body))
	})))

	http.HandleFunc("/api/bot/logs", withBot(func(w http.ResponseWriter, r *http.Request, b *Bot) {
		from, _ := strconv.Atoi(r.URL.Query().Get("from"))
		b.lm.Lock()
		start := from - b.dropped
		if start < 0 {
			start = 0
		}
		lines := []string{}
		if start < len(b.logs) {
			lines = append(lines, b.logs[start:]...)
		}
		next := b.dropped + len(b.logs)
		b.lm.Unlock()

		writeJSON(w, struct {
			BotInfo
			Lines []string `json:"lines"`
			Next  int      `json:"next"`
		}{b.info(), lines, next})
	}))
}
