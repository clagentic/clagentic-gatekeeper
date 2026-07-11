package attestation

import (
	"context"
	"errors"
	"os/user"
	"testing"
)

func TestBuiltinProvider_Resolves(t *testing.T) {
	orig := currentUser
	defer func() { currentUser = orig }()

	currentUser = func() (*user.User, error) {
		return &user.User{Username: "os-user"}, nil
	}

	p := NewBuiltinProvider()
	id, err := p.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve(): unexpected error: %v", err)
	}
	if id.Subject != "os-user" {
		t.Errorf("Subject = %q, want %q", id.Subject, "os-user")
	}
	if id.Source != "builtin" {
		t.Errorf("Source = %q, want %q", id.Source, "builtin")
	}
}

func TestBuiltinProvider_ErrorDeclines(t *testing.T) {
	orig := currentUser
	defer func() { currentUser = orig }()

	currentUser = func() (*user.User, error) {
		return nil, errors.New("os user lookup failed")
	}

	p := NewBuiltinProvider()
	_, err := p.Resolve(context.Background())
	if !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
	}
}

func TestBuiltinProvider_EmptyUsernameDeclines(t *testing.T) {
	orig := currentUser
	defer func() { currentUser = orig }()

	currentUser = func() (*user.User, error) {
		return &user.User{Username: ""}, nil
	}

	p := NewBuiltinProvider()
	_, err := p.Resolve(context.Background())
	if !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
	}
}
