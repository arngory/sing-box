//go:build !linux

package udpdesync

import "testing"

func checkTuned(*testing.T, uintptr) {}
