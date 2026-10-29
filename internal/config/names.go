package config

import (
	"os"
	"strings"

	"github.com/fatwang2/rex-mcp-bridge/internal/rex"
)

// The configuration names the machine the bridge runs on "local", so it
// can move between machines unchanged. Agents and people see its real name
// instead: "local" means nothing to them, and an agent may take it for its
// own computer.

// ThisMachine returns the name shown for the machine the bridge runs on:
// LocalName if set, or else the first label of its host name, in lower case.
func (c *Config) ThisMachine() string {
	if c.LocalName != "" {
		return c.LocalName
	}
	h, _ := os.Hostname()
	h, _, _ = strings.Cut(h, ".")
	if h = strings.ToLower(h); h != "" {
		return h
	}
	return rex.LocalHost
}

// Named returns a copy of c with "local" renamed to ThisMachine, unless
// another host already has that name.
func (c *Config) Named() *Config {
	n := *c
	n.Hosts = make(map[string]Host, len(c.Hosts))
	for k, v := range c.Hosts {
		n.Hosts[k] = v
	}
	n.local = rex.LocalHost
	if h, ok := n.Hosts[rex.LocalHost]; ok {
		name := c.ThisMachine()
		if _, taken := n.Hosts[name]; !taken {
			delete(n.Hosts, rex.LocalHost)
			n.Hosts[name] = h
			n.local = name
		}
	}
	return &n
}

// IsThisMachine reports whether name is the machine the bridge runs on.
func (c *Config) IsThisMachine(name string) bool {
	return name == c.local || name == rex.LocalHost
}

// Canonical returns the name a host is listed under, accepting "local" for
// the machine the bridge runs on.
func (c *Config) Canonical(name string) string {
	if name == rex.LocalHost && c.local != "" {
		return c.local
	}
	return name
}

// RexHost returns the name to give rex for a listed host.
func (c *Config) RexHost(name string) string {
	if c.IsThisMachine(name) {
		return rex.LocalHost
	}
	return name
}
