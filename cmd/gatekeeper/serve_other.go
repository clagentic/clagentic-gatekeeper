//go:build !linux

package main

import "errors"

// errServeLinuxOnly is the one place the platform limit is stated: the issuer
// reads SO_PEERCRED and /proc, which exist only on linux. The client commands
// (issue-session, issue-child) and mint build and run everywhere.
var errServeLinuxOnly = errors.New("serve is only supported on linux: it needs SO_PEERCRED and /proc to attest its peers")

func runServe([]string) error { return errServeLinuxOnly }
