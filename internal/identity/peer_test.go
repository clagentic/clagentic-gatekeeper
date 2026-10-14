package identity

import (
	"os"
	"testing"
)

func TestRuntimeID(t *testing.T) {
	cases := []struct {
		exe  string
		args []string
		want string
		ok   bool
	}{
		{"/opt/example/example-runtime", []string{"example-runtime"}, "example-runtime", true},
		{"/usr/bin/node", []string{"node", "--flag", "/srv/app/example-cli.js"}, "example-cli", true},
		{"/usr/bin/python3.12", []string{"python3.12", "-u", "tool.py", "x"}, "tool", true},
		{"/usr/bin/bash", []string{"bash"}, "bash", true},
		{"/opt/odd name/run time (deleted)", nil, "run-time--deleted-", true},
		{"/", nil, "", false},
	}
	for _, c := range cases {
		got, err := RuntimeID(c.exe, c.args)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%q %v: got %q err=%v, want %q ok=%v", c.exe, c.args, got, err, c.want, c.ok)
		}
	}
}

func TestParseStartTimeSurvivesParenthesesInName(t *testing.T) {
	stat := "123 (we ) ird (name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 7777 23 24"
	got, err := parseStartTime(stat)
	if err != nil || got != 7777 {
		t.Fatalf("got %d %v", got, err)
	}
}

func TestReadProcOfThisProcess(t *testing.T) {
	info, err := ReadProc(int32(os.Getpid()))
	if err != nil || info.Exe == "" || info.StartTime == 0 || len(info.Args) == 0 {
		t.Fatalf("%+v %v", info, err)
	}
}
