//go:build !unix

package hook

import "os"

// ownedByUs cannot compare uids off unix. The issuer is linux-only, so no
// delivery directory exists here to remove; the hook is built for parity of the
// client commands and treats ownership as unverifiable.
func ownedByUs(os.FileInfo) bool { return false }

// chownLike has no meaning off unix, where ownership is not a uid pair.
func chownLike(*os.File, os.FileInfo) error { return nil }

// syncDir is a no-op off unix, where a directory cannot be opened for flushing.
func syncDir(string) error { return nil }
