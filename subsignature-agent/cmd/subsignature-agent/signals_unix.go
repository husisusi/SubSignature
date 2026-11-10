//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// stopSignals terminate the agent cleanly.
var stopSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM}

// reloadChannel reports SIGHUP: reload the configuration and sync immediately.
func reloadChannel() <-chan struct{} {
	reload := make(chan struct{}, 1)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			select {
			case reload <- struct{}{}:
			default:
			}
		}
	}()
	return reload
}
