package config

import (
	"strings"
	"testing"
)

func TestLoad_MintRecordPath(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		want    string
		wantErr string
	}{
		{name: "absent means off", yaml: "github:\n  owner: o\n", want: ""},
		{name: "absolute", yaml: "mint_record_path: /var/lib/gatekeeper/mints.jsonl\n", want: "/var/lib/gatekeeper/mints.jsonl"},
		{name: "relative is refused naming the key", yaml: "mint_record_path: mints.jsonl\n", wantErr: "mint_record_path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeTemp(t, tc.yaml))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "absolute") {
					t.Fatalf("err = %v, want one naming %q and absolute", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MintRecordPath != tc.want {
				t.Errorf("MintRecordPath = %q, want %q", cfg.MintRecordPath, tc.want)
			}
		})
	}
}
