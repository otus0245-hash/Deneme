package main

import "os"

func sigInterrupt() os.Signal {
	return os.Interrupt
}
