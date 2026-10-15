//go:build windows

package hook

import "os"

// ownedByUs cannot compare uids on windows. The issuer is linux-only, so no
// delivery directory exists here to remove; the hook is built for parity of the
// client commands and treats ownership as unverifiable.
func ownedByUs(os.FileInfo) bool { return false }

// chownLike has no meaning on windows, where ownership is not a uid pair.
func chownLike(*os.File, os.FileInfo) error { return nil }

// syncDir is a no-op on windows, which cannot open a directory for flushing.
func syncDir(string) error { return nil }
