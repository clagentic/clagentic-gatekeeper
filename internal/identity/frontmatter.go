package identity

import (
	"bytes"
	"errors"
)

// SplitFrontmatter separates a definition file into its YAML frontmatter and
// the body after the closing fence. The closing fence is a whole line equal to
// "---": "---junk" or "--- " is not a fence, so a malformed definition fails
// closed. It builds on every platform because the render command shares it
// with the issuer's reader.
func SplitFrontmatter(raw []byte) (front, body []byte, err error) {
	raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	if !bytes.HasPrefix(raw, []byte("---\n")) {
		return nil, nil, errors.New("no YAML frontmatter")
	}
	rest := raw[len("---\n"):]
	offset := 0
	for _, line := range bytes.SplitAfter(rest, []byte("\n")) {
		if string(bytes.TrimSuffix(line, []byte("\n"))) == "---" {
			return rest[:offset], rest[offset+len(line):], nil
		}
		offset += len(line)
	}
	return nil, nil, errors.New("frontmatter is not closed")
}
