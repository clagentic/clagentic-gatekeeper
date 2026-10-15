package hook

import "strings"

// The delivery statement turns every command it is put in front of into a
// compound command, and a runtime's read-only auto-approval (date, ls, cat and
// the like run with no rule on their own) does not apply to a compound command.
// A rewrite therefore costs a prompt for any command no allow rule covers. This
// file decides the one class of commands for which the rewrite is skipped: a
// command that provably cannot consume the identity.
//
// CannotUseIdentity is true only when ALL of the following hold; anything else,
// and any doubt, is false and the command is rewritten (fail toward delivery):
//
//   - the command is one or more simple commands joined by ;  &&  ||  or |;
//   - every simple command names, as its unquoted first word, a utility of the
//     closed set below (readOnlyUtilities). Every member only reads files and
//     prints, and none executes another program, so none can run a minting tool
//     or hand it the environment;
//   - no word expands anything: no $ or backtick outside single quotes (so no
//     variable, no command substitution), no ( ) (so no subshell or process
//     substitution), no backslash, no unquoted glob character, and no comment,
//     newline or control character;
//   - no redirection other than the three exact words in discardRedirects, none
//     of which writes anywhere that matters, and no background operator (&);
//   - no word names the process environment (/proc, environ), the one file
//     path through which a reader could still see a delivered variable;
//   - date takes only the display options in dateOptions, never an operand that
//     would set the clock.
//
// The closed set is not a list of commands that "look harmless". A utility is
// in it only if it has no option that executes a program or writes a file.
// printenv is deliberately absent: the delivered variable lives in the
// environment, so printing the environment is a use of the identity.
//
// The set trusts that the names resolve to the system utilities. A shell
// function or alias that shadows one of them is the operator's own and is
// outside what a hook can see.
var readOnlyUtilities = map[string]func(args []shellWord) bool{
	"cat":  anyArgs,
	"date": dateArgs,
	"echo": anyArgs,
	"grep": anyArgs,
	"head": anyArgs,
	"ls":   anyArgs,
	"pwd":  anyArgs,
	"tail": anyArgs,
	"wc":   anyArgs,
}

// discardRedirects are the only redirections admitted, each as one unquoted word.
// They send output to the null device or join stderr to stdout; none creates or
// changes a file.
var discardRedirects = []string{"2>/dev/null", ">/dev/null", "2>&1"}

// dateOptions are the options and the only non-format operands date may carry.
// Setting the clock (-s, --set, a bare MMDDhhmm operand) is not display.
var dateOptions = map[string]bool{
	"-u": true, "--utc": true, "--universal": true,
	"-R": true, "--rfc-email": true,
	"-I": true, "--iso-8601": true,
}

// shellWord is one word of a command with its quotes removed.
type shellWord struct {
	text   string
	quoted bool
}

func anyArgs([]shellWord) bool { return true }

func dateArgs(args []shellWord) bool {
	for _, a := range args {
		if strings.HasPrefix(a.text, "+") || dateOptions[a.text] {
			continue
		}
		return false
	}
	return true
}

// CannotUseIdentity reports whether command provably cannot consume the
// delivered identity, so that the delivery statement may be left off it. See the
// rules at the top of this file.
func CannotUseIdentity(command string) bool {
	segments, ok := splitSimpleCommands(command)
	if !ok || len(segments) == 0 {
		return false
	}
	for _, words := range segments {
		check, known := readOnlyUtilities[words[0].text]
		if !known || words[0].quoted {
			return false
		}
		args := words[1:]
		for _, w := range args {
			if namesEnvironment(w.text) {
				return false
			}
		}
		if !check(args) {
			return false
		}
	}
	return true
}

// namesEnvironment reports whether a word could name the process environment
// as a file.
func namesEnvironment(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "/proc") || strings.Contains(s, "environ")
}

// splitSimpleCommands cuts command at ; && || and | into its simple commands,
// each a non-empty list of words. ok is false for anything outside the grammar
// described at the top of this file.
func splitSimpleCommands(command string) (segments [][]shellWord, ok bool) {
	var (
		words   []shellWord
		text    strings.Builder
		inWord  bool
		quoted  bool
		current = func() {
			if inWord {
				words = append(words, shellWord{text: text.String(), quoted: quoted})
			}
			text.Reset()
			inWord, quoted = false, false
		}
		endCommand = func() bool {
			current()
			if len(words) == 0 {
				return false
			}
			segments = append(segments, words)
			words = nil
			return true
		}
	)
	for i := 0; i < len(command); {
		c := command[i]
		if !inWord {
			if n := discardRedirectAt(command, i); n > 0 {
				i += n
				continue
			}
		}
		switch {
		case c == ' ' || c == '\t':
			current()
			i++
		case c == '\'':
			end := strings.IndexByte(command[i+1:], '\'')
			if end < 0 {
				return nil, false
			}
			text.WriteString(command[i+1 : i+1+end])
			inWord, quoted = true, true
			i += end + 2
		case c == '"':
			j := i + 1
			for ; j < len(command) && command[j] != '"'; j++ {
				if command[j] == '$' || command[j] == '`' || command[j] == '\\' {
					return nil, false
				}
			}
			if j >= len(command) {
				return nil, false
			}
			text.WriteString(command[i+1 : j])
			inWord, quoted = true, true
			i = j + 1
		case c == ';':
			if !endCommand() {
				return nil, false
			}
			i++
		case c == '|':
			if !endCommand() {
				return nil, false
			}
			i++
			if i < len(command) && command[i] == '|' {
				i++
			} else if i < len(command) && command[i] == '&' {
				return nil, false
			}
		case c == '&':
			if i+1 >= len(command) || command[i+1] != '&' || !endCommand() {
				return nil, false
			}
			i += 2
		case c < 0x20 || c == 0x7f,
			c == '$' || c == '`' || c == '\\' || c == '(' || c == ')' || c == '<' || c == '>',
			c == '*' || c == '?' || c == '[',
			c == '#' && !inWord:
			return nil, false
		default:
			text.WriteByte(c)
			inWord = true
			i++
		}
	}
	if !endCommand() {
		return nil, false
	}
	return segments, true
}

// discardRedirectAt returns the length of the discard redirection that starts at
// command[i] as a whole word, or 0.
func discardRedirectAt(command string, i int) int {
	for _, r := range discardRedirects {
		if !strings.HasPrefix(command[i:], r) {
			continue
		}
		end := i + len(r)
		if end == len(command) || strings.IndexByte(" \t;|&", command[end]) >= 0 {
			return len(r)
		}
	}
	return 0
}
