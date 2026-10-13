//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

func readKB(path, key string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, key+":") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				n, _ := strconv.Atoi(f[1])
				return n
			}
		}
	}
	return 0
}

func processRSS(pid int) int {
	return readKB("/proc/"+strconv.Itoa(pid)+"/status", "VmRSS")
}

func systemMem() (totalKB, usedKB int) {
	total := readKB("/proc/meminfo", "MemTotal")
	avail := readKB("/proc/meminfo", "MemAvailable")
	return total, total - avail
}