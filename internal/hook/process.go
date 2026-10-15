package hook

import (
	"fmt"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// ProcessAssignment is the process adapter: a launcher that starts a runtime as
// a child asks for a session before exec and passes the returned assignment to
// the child's environment. The child then holds its assertion for its whole
// life with no per-command step.
//
// A launcher whose session a human drives passes origin driven: the issuer
// grades it workload like any other launched session, and whether a human is
// present stays a per-turn reading that this value is never evidence of.
//
// The assertion is bound by the issuer to the runtime above the requesting
// process, which for a launcher is the launcher itself. The adapter never
// requests a human grade.
func ProcessAssignment(is Issuer, definition, origin string) (string, error) {
	if origin == "human" {
		return "", ErrOriginHuman
	}
	req := identity.SessionRequest{Origin: origin}
	if definition != "" {
		if !safeName.MatchString(definition) {
			return "", fmt.Errorf("definition %q is not a plain name", definition)
		}
		req.Definition = definition
	}
	issued, err := is.IssueSession(req)
	if err != nil {
		return "", err
	}
	if err := CheckDeliverable(issued.Dir); err != nil {
		return "", err
	}
	return EnvDir + "=" + issued.Dir, nil
}
