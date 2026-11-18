package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// One table for identity.approval: what loads, what it means, and what is
// refused naming the key.
func TestIdentityApproval(t *testing.T) {
	const head = "identity:\n  key_path: /k\n  approval:\n"
	for _, tc := range []struct {
		name string
		body string
		fail string
		want func(t *testing.T, a ApprovalConfig)
	}{
		{"absent means off", "identity:\n  key_path: /k\n", "", func(t *testing.T, a ApprovalConfig) {
			if a.Approver != "" || a.TurnOrigin != nil || a.TTL() != 300*time.Second {
				t.Fatalf("%+v", a)
			}
		}},
		{"approver and default ttl", head + "    approver: example-operator\n", "", func(t *testing.T, a ApprovalConfig) {
			if a.Approver != "example-operator" || a.TTL() != 300*time.Second {
				t.Fatalf("%+v", a)
			}
		}},
		{"ttl at the cap", head + "    approver: a\n    ttl_seconds: 300\n", "", func(t *testing.T, a ApprovalConfig) {
			if a.TTL() != 300*time.Second {
				t.Fatalf("%+v", a)
			}
		}},
		{"ttl below the cap", head + "    approver: a\n    ttl_seconds: 60\n", "", func(t *testing.T, a ApprovalConfig) {
			if a.TTL() != time.Minute {
				t.Fatalf("%+v", a)
			}
		}},
		{"turn origin with a default timeout", head + "    turn_origin:\n      command: [/opt/example/origin, --json]\n", "", func(t *testing.T, a ApprovalConfig) {
			if !reflect.DeepEqual(a.TurnOrigin.Command, []string{"/opt/example/origin", "--json"}) || a.TurnOrigin.Timeout() != 2*time.Second {
				t.Fatalf("%+v", a.TurnOrigin)
			}
		}},
		{"turn origin with a timeout", head + "    turn_origin:\n      command: [/opt/example/origin]\n      timeout_seconds: 5\n", "", func(t *testing.T, a ApprovalConfig) {
			if a.TurnOrigin.Timeout() != 5*time.Second {
				t.Fatalf("%+v", a.TurnOrigin)
			}
		}},
		{"ttl over the cap", head + "    approver: a\n    ttl_seconds: 301\n", "identity.approval.ttl_seconds", nil},
		{"negative ttl", head + "    approver: a\n    ttl_seconds: -1\n", "identity.approval.ttl_seconds", nil},
		{"approver with a space", head + "    approver: two words\n", "identity.approval.approver", nil},
		{"turn origin without a command", head + "    turn_origin:\n      timeout_seconds: 1\n", "identity.approval.turn_origin.command", nil},
		{"turn origin with an empty command", head + "    turn_origin:\n      command: []\n", "identity.approval.turn_origin.command", nil},
		{"turn origin with a relative program", head + "    turn_origin:\n      command: [origin]\n", "identity.approval.turn_origin.command[0]", nil},
		{"turn origin timeout over the cap", head + "    turn_origin:\n      command: [/o]\n      timeout_seconds: 6\n", "identity.approval.turn_origin.timeout_seconds", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeTemp(t, tc.body))
			if tc.fail != "" {
				if err == nil || !strings.Contains(err.Error(), tc.fail) {
					t.Fatalf("got %v, want a refusal naming %s", err, tc.fail)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.want(t, cfg.Identity.Approval)
		})
	}
}

// A misspelt approval key is reported like any other unknown key, with its full
// path.
func TestIdentityApprovalUnknownKeysAreReported(t *testing.T) {
	cfg := loadIdentity(t, "identity:\n  key_path: /k\n  approval:\n    aprover: x\n    turn_origin:\n      command: [/o]\n      timeout: 1\n")
	want := []string{"identity.approval.aprover", "identity.approval.turn_origin.timeout"}
	if !reflect.DeepEqual(cfg.UnknownKeys(), want) {
		t.Fatalf("got %v, want %v", cfg.UnknownKeys(), want)
	}
}
