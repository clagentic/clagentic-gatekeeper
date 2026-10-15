package hook

import (
	"errors"
	"fmt"
)

// AllowRule is the one permissions allow rule hooks-install registers. A hook
// rewrite never carries a permission decision, so the harness checks the
// rewritten command against the operator's rules; this rule is what lets the
// leading export statement through without a prompt.
const AllowRule = "Bash(export " + EnvDir + "=*)"

// permissionsOf returns the settings "permissions" object, creating it when
// create is set. A nil result with a nil error means it is absent.
func permissionsOf(root settings, create bool) (settings, error) {
	raw, ok := root["permissions"]
	if !ok {
		if !create {
			return nil, nil
		}
		p := settings{}
		root["permissions"] = p
		return p, nil
	}
	p, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New(`settings "permissions" is not an object`)
	}
	return p, nil
}

func allowOf(p settings) ([]any, error) {
	raw, ok := p["allow"]
	if !ok {
		return nil, nil
	}
	allow, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf(`settings "permissions.allow" is not an array`)
	}
	return allow, nil
}

// addAllowRule appends AllowRule to permissions.allow unless it is present, and
// reports whether root changed. No other rule is read for its meaning or edited.
func addAllowRule(root settings) (bool, error) {
	p, err := permissionsOf(root, false)
	if err != nil {
		return false, err
	}
	var allow []any
	if p != nil {
		if allow, err = allowOf(p); err != nil {
			return false, err
		}
	}
	for _, rule := range allow {
		if s, _ := rule.(string); s == AllowRule {
			return false, nil
		}
	}
	if p == nil {
		if p, err = permissionsOf(root, true); err != nil {
			return false, err
		}
	}
	p["allow"] = append(allow, AllowRule)
	return true, nil
}

// removeAllowRule deletes every exact copy of AllowRule and nothing else. An
// allow list or permissions object that removing the rule leaves empty is
// dropped, so a register followed by a removal restores a file that had no
// permissions. A removal that finds no rule changes nothing at all, so a
// permissions object the user left empty is never touched by it. (A user's empty
// object that held our rule and nothing else cannot be told from one the
// registration created, and is dropped with it.)
func removeAllowRule(root settings) (bool, error) {
	p, err := permissionsOf(root, false)
	if err != nil || p == nil {
		return false, err
	}
	allow, err := allowOf(p)
	if err != nil {
		return false, err
	}
	kept := make([]any, 0, len(allow))
	for _, rule := range allow {
		if s, _ := rule.(string); s != AllowRule {
			kept = append(kept, rule)
		}
	}
	if len(kept) == len(allow) {
		return false, nil
	}
	if len(kept) == 0 {
		delete(p, "allow")
	} else {
		p["allow"] = kept
	}
	if len(p) == 0 {
		delete(root, "permissions")
	}
	return true, nil
}
