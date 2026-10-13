package main

import (
	"net/http"
	"os"
)

func registerStats() {
	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		botsKB := 0
		for _, b := range mgr.all() {
			botsKB += b.memKB()
		}
		total, used := systemMem()
		writeJSON(w, map[string]int{
			"panel_kb":     processRSS(os.Getpid()),
			"bots_kb":      botsKB,
			"sys_total_kb": total,
			"sys_used_kb":  used,
		})
	})
}