//go:build windows

package main

import "os"

// stopSignals: on Windows there is only Ctrl+C (or closing the console).
var stopSignals = []os.Signal{os.Interrupt}

// reloadChannel: Windows has no SIGHUP. The configuration is re-read before every
// scheduled sync anyway; there is no immediate reload.
func reloadChannel() <-chan struct{} { return nil }
