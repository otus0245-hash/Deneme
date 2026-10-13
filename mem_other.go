//go:build !linux && !windows

package main

func processRSS(pid int) int          { return 0 }
func systemMem() (totalKB, usedKB int) { return 0, 0 }