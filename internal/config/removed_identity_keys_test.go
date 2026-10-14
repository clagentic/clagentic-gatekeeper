package config

import "testing"

func TestRemovedIdentityKeysWarning(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"none", "identity:\n  key_path: /k\n", ""},
		{"one", "identity:\n  key_path: /k\n  operator_uid: 1000\n",
			"identity: deprecated config key(s) operator_uid have no effect; serve issues no human assertions"},
		{"all three", "identity:\n  key_path: /k\n  operator_roles: [reader]\n  operator_name: example-operator\n  operator_uid: 1000\n",
			"identity: deprecated config key(s) operator_uid, operator_name, operator_roles have no effect; serve issues no human assertions"},
		{"key text only in a comment", "identity:\n  key_path: /k\n  # operator_uid: 1000\n", ""},
		{"key text only in a value", "identity:\n  key_path: /k\n  issuer: operator_uid\n", ""},
		{"empty value still counts", "identity:\n  key_path: /k\n  operator_name:\n",
			"identity: deprecated config key(s) operator_name have no effect; serve issues no human assertions"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := loadIdentity(t, c.body).RemovedIdentityKeysWarning(); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}
