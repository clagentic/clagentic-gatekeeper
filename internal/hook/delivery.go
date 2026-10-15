package hook

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// EnvDir is the delivery variable of the identity contract's section 6.
const EnvDir = "CLAGENTIC_IDENTITY_DIR"

// exportPrefix opens the one statement the pre-tool-use hook adds. A command
// that already starts with it is not rewritten again.
const exportPrefix = "export " + EnvDir + "="

// deliverable admits the characters a spawn directory path has. The path is
// placed in a shell statement unquoted, so anything outside this set (space,
// quote, dollar, brace, backtick, glob) is refused rather than escaped.
var deliverable = regexp.MustCompile(`^/[A-Za-z0-9._/+-]+$`)

// spawnDirName is the name the issuer gives a delivery directory.
var spawnDirName = regexp.MustCompile(`^[0-9a-f]{10}-[0-9a-f]{32}$`)

// CheckDeliverable refuses a directory path that is not safe to place in a
// shell statement.
func CheckDeliverable(dir string) error {
	if !deliverable.MatchString(dir) || filepath.Clean(dir) != dir {
		return errors.New("the delivery directory path is not a plain absolute path")
	}
	return nil
}

// ExportStatement returns the single statement that precedes the original
// command. The original text follows it byte for byte.
func ExportStatement(dir string) (string, error) {
	if err := CheckDeliverable(dir); err != nil {
		return "", err
	}
	return exportPrefix + dir + "; ", nil
}

// AlreadyDelivers reports whether command starts with the delivery statement.
func AlreadyDelivers(command string) bool {
	return strings.HasPrefix(strings.TrimLeft(command, " \t"), exportPrefix)
}

// dirUsable confirms the delivery directory still holds an assertion, so a
// removed or reaped directory is not handed to a command.
func dirUsable(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	jwt, err := os.Lstat(filepath.Join(dir, identity.DeliveryFile))
	if err != nil {
		return err
	}
	if !jwt.Mode().IsRegular() {
		return fmt.Errorf("%s in %s is not a regular file", identity.DeliveryFile, dir)
	}
	return nil
}

// RemoveDelivery deletes a delivery directory the issuer created. It refuses
// anything that is not a real directory named the way the issuer names them,
// owned by this user and holding an assertion, so a state record naming another
// path can never turn a stop event into a deletion of something else.
func RemoveDelivery(dir string) error {
	if err := CheckDeliverable(dir); err != nil {
		return err
	}
	if !spawnDirName.MatchString(filepath.Base(dir)) {
		return fmt.Errorf("%s is not named like a delivery directory", dir)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a plain directory", dir)
	}
	if !ownedByUs(fi) {
		return fmt.Errorf("%s is not owned by this user", dir)
	}
	if _, err := os.Lstat(filepath.Join(dir, identity.DeliveryFile)); err != nil {
		return fmt.Errorf("%s holds no assertion: %w", dir, err)
	}
	return os.RemoveAll(dir)
}
