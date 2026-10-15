package hook

import "testing"

// Commands that run only closed-set utilities, read, and write nowhere: the
// delivery statement is left off them.
func TestCannotUseIdentityForReadOnlyCommands(t *testing.T) {
	for _, command := range []string{
		"date",
		"date +%s",
		"date -u",
		"date -u +%Y-%m-%d",
		"date --iso-8601",
		"ls",
		"ls -la",
		"ls -la /var/log",
		"  ls   -l\t",
		"pwd",
		"cat README.md",
		"cat a.txt b.txt",
		"head -n 5 file",
		"tail -n 20 file",
		"wc -l file",
		"echo hello",
		`echo "a;b|c&&d"`,
		`echo 'a $b ` + "`c`" + ` (d)'`,
		`grep -rn 'foo$' src`,
		`grep -E "a{1,3}" f`,
		"ls | wc -l",
		"cat f | grep x | head -n 3",
		"ls; pwd",
		"ls && pwd",
		"ls || pwd",
		"ls 2>/dev/null",
		"ls >/dev/null 2>&1",
		"ls foo 2>&1 | head",
		"cat ~/notes.txt",
		"echo a#b",
		"ls -- -weird",
	} {
		if !CannotUseIdentity(command) {
			t.Errorf("%q needs the statement dropped, got it kept", command)
		}
	}
}

// Anything that runs another program, expands, redirects to a file, or that the
// scanner cannot read with certainty is rewritten. Each case names why.
func TestCanUseIdentityMeansRewrite(t *testing.T) {
	cases := map[string]string{
		"":                                    "empty",
		"   ":                                 "blank",
		"make build":                          "a program",
		"gatekeeper mint --role builder":      "a minting command",
		"./gatekeeper mint":                   "a path",
		"/bin/ls":                             "not the bare name",
		`"ls"`:                                "quoted command name",
		`l\s`:                                 "backslash",
		"ls; gatekeeper mint --role builder":  "a program after a read-only command",
		"gatekeeper mint && ls":               "a program before a read-only command",
		"ls | sh":                             "a shell at the end of a pipe",
		"cat f | xargs rm":                    "xargs",
		"find . -exec sh {} ;":                "find is not in the set",
		"find . -name x":                      "find is not in the set",
		"ls $(gatekeeper mint)":               "command substitution",
		"ls `gatekeeper mint`":                "backtick substitution",
		`echo "$(gatekeeper mint)"`:           "substitution in double quotes",
		"echo \"`gatekeeper mint`\"":          "backtick in double quotes",
		`echo "$HOME"`:                        "variable in double quotes",
		"echo $HOME":                          "variable",
		"echo ${HOME}":                        "braced variable",
		"cat <(gatekeeper mint)":              "process substitution",
		"cat < file":                          "input redirection",
		"echo hi > file":                      "output redirection",
		"echo hi >> file":                     "append redirection",
		"echo hi 2> err.log":                  "stderr to a file",
		"echo hi >/dev/null2":                 "not the exact discard word",
		"echo hi 2>&1x":                       "not the exact discard word",
		"echo hi &> out":                      "both streams to a file",
		"ls &":                                "background",
		"ls & gatekeeper mint":                "background then a program",
		"ls |& cat":                           "pipe and stderr",
		"ls\ngatekeeper mint":                 "newline separator",
		"ls\r":                                "control character",
		"ls;":                                 "trailing separator",
		"ls &&":                               "trailing operator",
		"; ls":                                "leading separator",
		"ls ;; pwd":                           "empty command",
		"ls | | wc":                           "empty command in a pipe",
		"(ls)":                                "subshell",
		"{ ls; }":                             "group",
		"FOO=1 ls":                            "assignment prefix",
		"! ls":                                "negation",
		"time ls":                             "keyword",
		"env ls":                              "env runs programs",
		"exec ls":                             "exec",
		"eval ls":                             "eval",
		"printenv CLAGENTIC_IDENTITY_DIR":     "reads the delivered variable",
		"printenv":                            "dumps the environment",
		"cat /proc/self/environ":              "reads the environment as a file",
		`cat "/PROC/self/Environ"`:            "reads the environment as a file, quoted",
		"cat /proc/1/environ":                 "reads an environment as a file",
		"ls *":                                "unquoted glob",
		"cat /pr?c/self/environ":              "glob",
		"cat [a]b":                            "glob class",
		"# ls":                                "comment",
		"ls # gatekeeper mint":                "comment",
		"echo 'unterminated":                  "open single quote",
		`echo "unterminated`:                  "open double quote",
		`echo "a\"b"`:                         "backslash in double quotes",
		"date 010100002026":                   "would set the clock",
		"date -s '2026-01-01'":                "would set the clock",
		"date --set=x":                        "would set the clock",
		"date -d tomorrow":                    "date option outside the display set",
		"date -f file":                        "date option outside the display set",
		"for f in a b; do cat $f; done":       "loop",
		"if true; then ls; fi":                "conditional",
		"cd /tmp && ls":                       "cd is not in the set",
		"cat file | sort":                     "sort is not in the set",
		"cat\x00 file":                        "NUL",
		"echo \"it's\" 'x' ; gatekeeper mint": "program after quotes",
	}
	for command, why := range cases {
		if CannotUseIdentity(command) {
			t.Errorf("%q (%s) would be left without the statement", command, why)
		}
	}
}

// The set is closed: every member only reads, and none is a utility that
// executes another program.
func TestReadOnlySetIsExactlyTheDocumentedMembers(t *testing.T) {
	want := map[string]bool{"cat": true, "date": true, "echo": true, "grep": true, "head": true, "ls": true, "pwd": true, "tail": true, "wc": true}
	if len(readOnlyUtilities) != len(want) {
		t.Fatalf("the closed set has %d members, documented %d", len(readOnlyUtilities), len(want))
	}
	for name := range readOnlyUtilities {
		if !want[name] {
			t.Errorf("%q is in the set but not documented", name)
		}
	}
	for _, banned := range []string{"printenv", "env", "find", "xargs", "sh", "bash", "sort", "sed", "awk", "tee", "time", "nice", "timeout", "watch", "git", "make", "gatekeeper"} {
		if _, in := readOnlyUtilities[banned]; in {
			t.Errorf("%q must never be in the closed set", banned)
		}
	}
}
