package hook

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// phrasePattern is the approval phrase an operator types: the word approve, one
// space and the request id the issuer handed out. Surrounding whitespace is
// ignored; nothing else is, so a sentence that merely contains the phrase is not
// one.
var phrasePattern = regexp.MustCompile(`^` + regexp.QuoteMeta(identity.ApprovalPhrasePrefix) + `([0-9a-f]{32})$`)

// phraseRid returns the request id when prompt is exactly the approval phrase.
func phraseRid(prompt string) (string, bool) {
	m := phrasePattern.FindStringSubmatch(strings.TrimSpace(prompt))
	if m == nil {
		return "", false
	}
	return m[1], true
}

func (h *ClaudeCode) getenv(name string) string {
	if h.Getenv != nil {
		return h.Getenv(name)
	}
	return os.Getenv(name)
}

// approvePhrase signs the approval a typed phrase asks for. It does nothing for
// a prompt that is not exactly the phrase, which is every prompt but the rare
// one, so the origin provider is never run for them. It never blocks, rewrites
// or answers the prompt: every outcome is a log line and the event goes on.
func (h *ClaudeCode) approvePhrase(p Payload, raw []byte) {
	rid, ok := phraseRid(p.Prompt)
	if !ok {
		return
	}
	const event = EventUserPromptSubmit
	verdict := ClassifyTurn(p, raw, h.TurnOrigin, h.getenv)
	if !verdict.Typed {
		h.Log.Printf("%s session=%s: approval %s not granted, turn-origin rung %d: %s", event, p.SessionID, rid, verdict.Rung, verdict.Reason)
		return
	}
	if h.Granter == nil {
		h.Log.Printf("%s session=%s: approval %s not granted: no issuer to ask", event, p.SessionID, rid)
		return
	}
	rec, found, err := h.Store.Get(p.SessionID, "")
	if err != nil || !found {
		h.Log.Printf("%s session=%s: approval %s not granted: no session assertion recorded (%v)", event, p.SessionID, rid, err)
		return
	}
	token, err := os.ReadFile(filepath.Join(rec.Dir, identity.DeliveryFile))
	if err != nil {
		h.Log.Printf("%s session=%s: approval %s not granted: read the session assertion: %v", event, p.SessionID, rid, err)
		return
	}
	granted, err := h.Granter.GrantApproval(identity.ApprovalGrantRequest{Token: strings.TrimSpace(string(token)), Rid: rid})
	if err != nil {
		h.Log.Printf("%s session=%s: approval %s not granted: %v", event, p.SessionID, rid, err)
		return
	}
	h.Log.Printf("%s session=%s: approval %s granted (turn-origin rung %d)", event, p.SessionID, granted.Rid, verdict.Rung)
}
