package identity

import (
	"os"
	"strings"
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

// scriptedProc answers each stat read from a list, so a test can make the
// start time change, or the pid vanish, between the two reads.
type scriptedProc struct {
	stats    []string
	statErrs []error
	reads    int
}

func (s *scriptedProc) readlink(int32, string) (string, error) { return "/opt/example/runtime", nil }

func (s *scriptedProc) readFile(_ int32, name string) ([]byte, error) {
	if name == "cmdline" {
		return []byte("runtime\x00"), nil
	}
	i := s.reads
	s.reads++
	if i < len(s.statErrs) && s.statErrs[i] != nil {
		return nil, s.statErrs[i]
	}
	return []byte(s.stats[i]), nil
}

func statWithStart(start string) string {
	return "9 (runtime) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 " + start + " 23 24"
}

func TestReadProcRefusesWhenStartTimeChangesBetweenReads(t *testing.T) {
	fs := &scriptedProc{stats: []string{statWithStart("100"), statWithStart("200")}}
	if _, err := readProcFrom(fs, 9); err == nil || !strings.Contains(err.Error(), "changed process") {
		t.Fatalf("pid reuse mid-read accepted: %v", err)
	}
}

func TestReadProcRefusesWhenPidVanishesBetweenReads(t *testing.T) {
	fs := &scriptedProc{stats: []string{statWithStart("100"), ""}, statErrs: []error{nil, os.ErrNotExist}}
	if _, err := readProcFrom(fs, 9); err == nil {
		t.Fatal("a pid that vanished mid-read was accepted")
	}
}

func TestReadProcReturnsStableStartTime(t *testing.T) {
	fs := &scriptedProc{stats: []string{statWithStart("100"), statWithStart("100")}}
	info, err := readProcFrom(fs, 9)
	if err != nil || info.StartTime != 100 || info.Exe != "/opt/example/runtime" {
		t.Fatalf("%+v %v", info, err)
	}
}

func TestIssuedAssertionIsBoundToPeerStartTime(t *testing.T) {
	f := newFixture(t, nil)
	out, _ := mustSession(t, f, selfPeer(10), SessionRequest{})
	claims, err := f.issuer.Keys.ParseOwn(out.Token)
	if err != nil {
		t.Fatal(err)
	}
	bound, ok := f.issuer.Registry.get(claims.Jti)
	if !ok || bound.pid != 10 || bound.startTime != 100 {
		t.Fatalf("registry entry %+v ok=%v", bound, ok)
	}
}

func TestReadProcOfThisProcess(t *testing.T) {
	info, err := ReadProc(int32(os.Getpid()))
	if err != nil || info.Exe == "" || info.StartTime == 0 || len(info.Args) == 0 {
		t.Fatalf("%+v %v", info, err)
	}
}
