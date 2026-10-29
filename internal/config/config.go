// Package config loads which Rex hosts the bridge exposes and what agents
// may do on each.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/fatwang2/rex-mcp-bridge/internal/rex"
)

// Mode is what agents may do on a host. Each mode includes the ones before
// it.
type Mode string

const (
	// ModeRead lets agents list panes and read their contents.
	ModeRead Mode = "read"
	// ModeRun also lets agents run commands in new panes.
	ModeRun Mode = "run"
	// ModeInteractive also lets agents type into existing panes.
	ModeInteractive Mode = "interactive"
)

var modeRank = map[Mode]int{ModeRead: 1, ModeRun: 2, ModeInteractive: 3}

// Allows reports whether m includes want.
func (m Mode) Allows(want Mode) bool {
	return modeRank[m] >= modeRank[want]
}

// Host is the policy for one Rex host.
type Host struct {
	Mode Mode `json:"mode"`
}

// DefaultSession is the label of the Rex session agents open windows in
// when the configuration names none.
const DefaultSession = "mcp"

// Config is the bridge configuration.
type Config struct {
	// Session is the label of the Rex session, on every host, where agents
	// open windows and shells. Default "mcp".
	Session string `json:"session,omitempty"`
	// Hosts maps a host label from "rex hosts", or "local" for this
	// machine's server, to its policy. Hosts that are not listed are not
	// exposed.
	Hosts map[string]Host `json:"hosts"`
	// LocalName is the name agents and the approval page show for this
	// machine. Default: its host name.
	LocalName string `json:"local_name,omitempty"`

	// local is what "local" was renamed to by Named.
	local string
}

// Default exposes only this machine's Rex server, read only.
func Default() *Config {
	return &Config{Hosts: map[string]Host{rex.LocalHost: {Mode: ModeRead}}}
}

// DefaultPath is where the configuration lives when no path is given.
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "rex-mcp-bridge", "config.json"), nil
}

// Load reads the configuration at path. A missing file yields Default.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// AgentSession returns the label of the agents' session.
func (c *Config) AgentSession() string {
	if c.Session == "" {
		return DefaultSession
	}
	return c.Session
}

// Validate checks that every host has a known mode.
func (c *Config) Validate() error {
	for name, h := range c.Hosts {
		if name == "" {
			return errors.New("hosts: empty host name")
		}
		if _, ok := modeRank[h.Mode]; !ok {
			return fmt.Errorf("hosts.%s: mode must be read, run, or interactive, not %q", name, h.Mode)
		}
	}
	return nil
}

// Check returns an error unless host is exposed with at least mode want.
func (c *Config) Check(host string, want Mode) error {
	h, ok := c.Hosts[host]
	if !ok {
		return fmt.Errorf("host %q is not exposed by this bridge; call list_hosts for the hosts you can use", host)
	}
	if !h.Mode.Allows(want) {
		return fmt.Errorf("host %q allows %s access, and this needs %s", host, h.Mode, want)
	}
	return nil
}

// MaxMode returns the broadest mode of any host.
func (c *Config) MaxMode() Mode {
	var max Mode
	for _, h := range c.Hosts {
		if modeRank[h.Mode] > modeRank[max] {
			max = h.Mode
		}
	}
	return max
}

// Modes returns the modes up to and including max, narrowest first.
func Modes(max Mode) []Mode {
	var modes []Mode
	for _, m := range []Mode{ModeRead, ModeRun, ModeInteractive} {
		if max.Allows(m) {
			modes = append(modes, m)
		}
	}
	return modes
}

// Names returns the exposed host names, sorted.
func (c *Config) Names() []string {
	names := make([]string, 0, len(c.Hosts))
	for name := range c.Hosts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
