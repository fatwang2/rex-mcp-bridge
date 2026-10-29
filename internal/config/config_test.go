package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMissingIsDefault(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "none.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Names(); len(got) != 1 || got[0] != "local" {
		t.Errorf("default hosts = %v, want [local]", got)
	}
	if err := c.Check("local", ModeRun); err == nil {
		t.Error("default config allows run on local")
	}
}

func TestLoadRejectsUnknownMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"hosts":{"studio":{"mode":"admin"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load accepted mode admin")
	}
}

func TestCheck(t *testing.T) {
	c := &Config{Hosts: map[string]Host{
		"studio": {Mode: ModeRun},
		"laptop": {Mode: ModeRead},
	}}
	tests := []struct {
		host string
		want Mode
		ok   bool
	}{
		{"studio", ModeRead, true},
		{"studio", ModeRun, true},
		{"studio", ModeInteractive, false},
		{"laptop", ModeRun, false},
		{"unlisted", ModeRead, false},
	}
	for _, tt := range tests {
		if err := c.Check(tt.host, tt.want); (err == nil) != tt.ok {
			t.Errorf("Check(%q, %s) error = %v, want ok=%v", tt.host, tt.want, err, tt.ok)
		}
	}
}

func TestSourceReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s := &Source{Path: path, Fallback: Default}
	if got := s.Get(); len(got.Hosts) != 1 || !got.IsThisMachine(got.Names()[0]) {
		t.Fatalf("without a file: %v", got.Hosts)
	}
	c := &Config{Hosts: map[string]Host{"studio": {Mode: ModeRun}}}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	s.checked = s.checked.Add(-reloadCheck) // skip the wait between checks
	if got := s.Get(); got.Hosts["studio"].Mode != ModeRun || !s.Exists() {
		t.Errorf("after saving: %+v", got)
	}
	// A broken file keeps the last good configuration.
	os.WriteFile(path, []byte("{"), 0o600)
	future := time.Now().Add(time.Hour)
	os.Chtimes(path, future, future)
	s.checked = s.checked.Add(-reloadCheck)
	if got := s.Get(); got.Hosts["studio"].Mode != ModeRun {
		t.Errorf("after breaking the file: %+v", got)
	}
}

func TestNamed(t *testing.T) {
	c := &Config{LocalName: "box", Hosts: map[string]Host{"local": {Mode: ModeRun}, "studio": {Mode: ModeRead}}}
	n := c.Named()
	if _, ok := n.Hosts["local"]; ok || n.Hosts["box"].Mode != ModeRun {
		t.Fatalf("Named hosts = %v", n.Hosts)
	}
	if n.RexHost("box") != "local" || n.RexHost("studio") != "studio" || n.Canonical("local") != "box" {
		t.Error("box is not this machine")
	}
	if c.Hosts["local"].Mode != ModeRun {
		t.Error("Named changed the original")
	}
	// A remote host with the same name keeps "local" as it is.
	c = &Config{LocalName: "studio", Hosts: map[string]Host{"local": {Mode: ModeRun}, "studio": {Mode: ModeRead}}}
	if n := c.Named(); n.Hosts["local"].Mode != ModeRun || n.RexHost("studio") != "studio" {
		t.Errorf("collision: %v", n.Hosts)
	}
}
