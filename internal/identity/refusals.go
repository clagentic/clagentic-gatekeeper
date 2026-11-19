//go:build linux

package identity

// publicMessages is the one message each public code carries. A client sees
// only this text, so it cannot learn a uid, a pid, a path, a name it sent or a
// parser's wording; the variable detail goes to the server log through refuse.
var publicMessages = map[string]string{
	CodeBadRequest:        "the request is malformed or names a value the issuer does not accept",
	CodePeerUnattested:    "the calling process could not be attested",
	CodePeerUIDRefused:    "this issuer serves only the user it runs as",
	CodeRuntimeUnbound:    "the calling process is not running under a runtime this issuer can bind the request to",
	CodeRuntimeMismatch:   "the declared runtime does not match the attested runtime",
	CodeOriginForbidden:   "the requested origin is not permitted for the calling user",
	CodeDefinitionUnknown: "the requested definition is not available",
	CodeParentInvalid:     "the parent token is not a valid assertion issued by this server",
	CodeParentExpired:     "the parent token has expired",
	CodeParentUnknown:     "the parent token was not recognised; request a new session and issue the child from it",
	CodeUIDMismatch:       "the parent token was issued to a different user than the caller",
	CodePIDMismatch:       "the caller is not the process the parent token was issued to",
	CodeExeMismatch:       "the caller is running a different executable than the one the parent token was issued to",
	CodeLifetimeEmpty:     "the assertion would not outlive its issue time",
	CodeSpawnDir:          "the assertion could not be delivered; retry the request, and if it fails again ask the operator to check the issuer log",
	CodeInternal:          "the issuer failed to complete the request; see the issuer log",
}

// refuse builds a refusal. The message is looked up by code and takes no
// arguments, so nothing about the request or the host can reach a client
// through it. detail, which may be nil, is for the server log only.
func refuse(status int, code string, detail error) *IssueError {
	msg, ok := publicMessages[code]
	if !ok {
		msg = publicMessages[CodeInternal]
	}
	return &IssueError{Code: code, Message: msg, Status: status, detail: detail}
}
