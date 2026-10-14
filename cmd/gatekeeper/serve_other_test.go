//go:build !linux

package main

import (
	"strings"
	"testing"
)

func TestServeReportsItIsLinuxOnly(t *testing.T) {
	err := runServe([]string{"--socket", "/unused"})
	if err == nil || !strings.Contains(err.Error(), "only supported on linux") {
		t.Fatalf("got %v", err)
	}
}
