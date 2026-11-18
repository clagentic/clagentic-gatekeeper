package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// EnvHostScheduledRun is the variable the runtime's host sets in a process that
// runs injected turns (scheduled or sent by something other than the operator).
// It is the only environment variable the hook reads, and only to tell a plain
// terminal launch from a host that can inject turns.
const EnvHostScheduledRun = "CLAUDE_CODE_HOST_SCHEDULED_RUN"

// OriginKindHuman is the provider answer that says the operator typed the turn.
const OriginKindHuman = "human"

// SourceUser is the payload source of a turn the operator typed.
const SourceUser = "user"

// MaxProviderTimeout is the longest a turn-origin provider may run. The
// registration timeout of a hook that can run one is extended by it.
const MaxProviderTimeout = 5 * time.Second

// maxProviderOutput bounds what a provider can make the hook read.
const maxProviderOutput = 4 << 10

// OriginProvider says how the turn that fired a hook was started. It is how a
// host that does not put the origin in the hook payload still lets the hook
// tell an operator-typed turn from an injected one.
type OriginProvider interface {
	// TurnOrigin is given the hook payload and returns the origin kind of the
	// turn, in the runtime's vocabulary: "human" for a turn the operator typed,
	// any other value for a turn something else started.
	TurnOrigin(payload []byte) (kind string, err error)
}

// Rungs of the turn-origin order, named in every not-typed log line.
const (
	RungSourceUser  = 1
	RungSourceOther = 2
	RungProvider    = 3
	RungHostEnv     = 4
	RungNoOrigin    = 5
)

// TurnVerdict is the outcome of ClassifyTurn: whether the turn is shown to be
// operator-typed, the rung of the order that decided, and why.
type TurnVerdict struct {
	Typed  bool
	Rung   int
	Reason string
}

// ClassifyTurn decides whether the turn that fired a UserPromptSubmit hook was
// typed by the operator. It is the one place the order lives:
//
//  1. a payload source of "user" is typed;
//  2. any other source value is not typed;
//  3. else, when a provider is configured, its answer decides: origin kind
//     "human" is typed, anything else, a failure or a timeout is not typed;
//  4. else, when the process's host declares no injected turns (the variable
//     EnvHostScheduledRun is unset or empty) the turn is typed, which is the
//     plain terminal baseline;
//  5. else there is no grant: no origin was available.
//
// lookup is called only at rung 3, so a payload that decides earlier never
// loads a provider. It returns a nil provider when none is configured.
func ClassifyTurn(p Payload, raw []byte, lookup func() (OriginProvider, error), getenv func(string) string) TurnVerdict {
	switch {
	case p.SourcePresent && p.Source == SourceUser:
		return TurnVerdict{Typed: true, Rung: RungSourceUser, Reason: "payload source is user"}
	case p.SourcePresent:
		return TurnVerdict{Rung: RungSourceOther, Reason: fmt.Sprintf("payload source is %s, not user", quoteBounded(p.Source))}
	}
	var provider OriginProvider
	if lookup != nil {
		var err error
		if provider, err = lookup(); err != nil {
			return TurnVerdict{Rung: RungProvider, Reason: fmt.Sprintf("the turn-origin provider could not be set up: %v", err)}
		}
	}
	if provider != nil {
		kind, err := provider.TurnOrigin(raw)
		switch {
		case err != nil:
			return TurnVerdict{Rung: RungProvider, Reason: fmt.Sprintf("the turn-origin provider gave no answer: %v", err)}
		case kind != OriginKindHuman:
			return TurnVerdict{Rung: RungProvider, Reason: fmt.Sprintf("the turn-origin provider answered origin kind %s, not %s", quoteBounded(kind), OriginKindHuman)}
		}
		return TurnVerdict{Typed: true, Rung: RungProvider, Reason: "the turn-origin provider answered origin kind human"}
	}
	if getenv == nil || getenv(EnvHostScheduledRun) == "" {
		return TurnVerdict{Typed: true, Rung: RungHostEnv, Reason: "no source and no provider, and the host declares no injected turns"}
	}
	return TurnVerdict{Rung: RungNoOrigin, Reason: "no origin was available: no source, no provider, and the host can inject turns"}
}

// quoteBounded quotes an untrusted value for a log line, cut to a fixed length.
func quoteBounded(s string) string {
	const limit = 32
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	return fmt.Sprintf("%q", s)
}

// CommandProvider runs a command as the turn-origin provider: the hook payload
// on its stdin, one JSON object on its stdout.
//
//	{"origin": {"kind": "human"}}
//
// Anything else, a non-zero exit, output that is not that object, output over
// 4 KiB or a run past Timeout is an error, which the order reads as not typed.
// Argv is executed directly and never through a shell.
type CommandProvider struct {
	Argv    []string
	Timeout time.Duration
}

// capWriter keeps what is written up to max bytes and notes any overflow.
type capWriter struct {
	buf   bytes.Buffer
	limit int
	over  bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	n := len(p)
	if room := c.limit - c.buf.Len(); n > room {
		c.over = true
		p = p[:max(room, 0)]
	}
	c.buf.Write(p)
	// The full length is reported so a short write never stops the child's copy.
	return n, nil
}

// TurnOrigin runs the provider once.
func (c CommandProvider) TurnOrigin(payload []byte) (string, error) {
	if len(c.Argv) == 0 || c.Argv[0] == "" {
		return "", errors.New("no command")
	}
	timeout := min(c.Timeout, MaxProviderTimeout)
	if timeout <= 0 {
		return "", errors.New("no positive timeout")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Stdin = bytes.NewReader(payload)
	out := &capWriter{limit: maxProviderOutput}
	cmd.Stdout = out
	// A provider that leaves a grandchild holding its pipes open must not hold the
	// hook past its timeout.
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("timed out after %s", timeout)
	}
	if err != nil {
		return "", fmt.Errorf("run: %w", err)
	}
	if out.over {
		return "", fmt.Errorf("output is over %d bytes", maxProviderOutput)
	}
	return parseProviderAnswer(out.buf.Bytes())
}

// parseProviderAnswer reads exactly one JSON object and returns its
// origin.kind. Members it does not know are ignored, so a provider can say more
// than the hook reads.
func parseProviderAnswer(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var ans struct {
		Origin struct {
			Kind string `json:"kind"`
		} `json:"origin"`
	}
	if err := dec.Decode(&ans); err != nil {
		return "", errors.New("output is not a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", errors.New("output holds more than one JSON value")
	}
	if ans.Origin.Kind == "" {
		return "", errors.New("output carries no origin.kind")
	}
	return ans.Origin.Kind, nil
}
