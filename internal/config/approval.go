package config

import (
	"fmt"
	"regexp"
	"time"
)

const (
	// MaxApprovalTTLSeconds caps identity.approval.ttl_seconds, which is both how
	// long a request stays pending and how long a granted approval stays valid.
	MaxApprovalTTLSeconds = 300

	// DefaultTurnOriginTimeoutSeconds is the provider timeout when none is set.
	DefaultTurnOriginTimeoutSeconds = 2
	// MaxTurnOriginTimeoutSeconds bounds the provider, which runs inside a hook
	// the user is waiting on.
	MaxTurnOriginTimeoutSeconds = 5
)

// reApprover is the shape of the approver name, which is signed into every
// approval as acked_by.
var reApprover = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{1,128}$`)

// ApprovalConfig configures operator approval of a single operation
// (docs/identity-contract.md, section 13).
type ApprovalConfig struct {
	// Approver is the name signed into every approval as acked_by. It is a
	// setting of the deployment, never read from a request or a prompt. Empty
	// means operator approval is off: serve refuses every approval operation.
	Approver string `yaml:"approver,omitempty"`
	// TTLSeconds is how long a request stays pending and how long a granted
	// approval stays valid. Default and maximum 300.
	TTLSeconds int `yaml:"ttl_seconds,omitempty"`
	// TurnOrigin is the optional provider the hook asks how a turn was started
	// when the hook payload does not say (docs/RUNTIME-HOOKS.md).
	TurnOrigin *TurnOriginConfig `yaml:"turn_origin,omitempty"`
}

// TurnOriginConfig names the command that answers how a turn was started.
type TurnOriginConfig struct {
	// Command is the argv of the provider; Command[0] must be an absolute path.
	// It is executed directly, never through a shell.
	Command []string `yaml:"command"`
	// TimeoutSeconds bounds one run of the provider. Default 2, maximum 5. A
	// provider that has not answered by then has not said the turn was typed.
	TimeoutSeconds int `yaml:"timeout_seconds,omitempty"`
}

// Timeout is the effective provider timeout.
func (t TurnOriginConfig) Timeout() time.Duration {
	if t.TimeoutSeconds == 0 {
		return DefaultTurnOriginTimeoutSeconds * time.Second
	}
	return time.Duration(t.TimeoutSeconds) * time.Second
}

// TTL is the effective approval lifetime.
func (a ApprovalConfig) TTL() time.Duration {
	if a.TTLSeconds == 0 {
		return MaxApprovalTTLSeconds * time.Second
	}
	return time.Duration(a.TTLSeconds) * time.Second
}

func (a ApprovalConfig) validate() error {
	if a.Approver != "" && !reApprover.MatchString(a.Approver) {
		return fmt.Errorf("identity.approval.approver %q must match %s", a.Approver, reApprover)
	}
	if a.TTLSeconds < 0 || a.TTLSeconds > MaxApprovalTTLSeconds {
		return fmt.Errorf("identity.approval.ttl_seconds %d must be between 1 and %d", a.TTLSeconds, MaxApprovalTTLSeconds)
	}
	t := a.TurnOrigin
	if t == nil {
		return nil
	}
	if len(t.Command) == 0 || t.Command[0] == "" {
		return fmt.Errorf("identity.approval.turn_origin.command must name a program")
	}
	if err := CheckAbsPath("identity.approval.turn_origin.command[0]", t.Command[0]); err != nil {
		return err
	}
	if t.TimeoutSeconds < 0 || t.TimeoutSeconds > MaxTurnOriginTimeoutSeconds {
		return fmt.Errorf("identity.approval.turn_origin.timeout_seconds %d must be between 1 and %d", t.TimeoutSeconds, MaxTurnOriginTimeoutSeconds)
	}
	return nil
}
