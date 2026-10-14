//go:build windows

package hook

import "os"

// ownedByUs cannot compare uids on windows. The issuer is linux-only, so no
// delivery directory exists here to remove; the hook is built for parity of the
// client commands and treats ownership as unverifiable.
func ownedByUs(os.FileInfo) bool { return false }
