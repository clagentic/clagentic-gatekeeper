//go:build !linux

package main

import "errors"

// errServeLinuxOnly is the one place the platform limit is stated. The client
// commands (issue-session, issue-child) and mint build and run everywhere.
var errServeLinuxOnly = errors.New("serve is only supported on linux")

func runServe([]string) error { return errServeLinuxOnly }
