// Package tools defines the MCP tools the bridge offers.
package tools

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fatwang2/rex-mcp-bridge/internal/config"
	"github.com/fatwang2/rex-mcp-bridge/internal/oauth"
	"github.com/fatwang2/rex-mcp-bridge/internal/rex"
)

const (
	defaultCaptureLines = 200
	maxCaptureLines     = 2000
	// maxOutputBytes caps any text returned to the agent.
	maxOutputBytes = 64 << 10
)

// Bridge holds what the tools need.
type Bridge struct {
	// Config returns the current configuration, which may change while the
	// bridge runs.
	Config func() *config.Config
	Rex    *rex.Client
	// Audit, if set, records every command run for an agent.
	Audit *log.Logger
}

// check returns an error unless the caller may use host with mode want.
// Over HTTP, the mode granted to the caller's token also limits it.
func (b *Bridge) check(req *mcp.CallToolRequest, host string, want config.Mode) error {
	if err := b.Config().Check(host, want); err != nil {
		return err
	}
	ti := tokenInfo(req)
	if ti == nil {
		return nil
	}
	switch granted := oauth.GrantedMode(ti, host); {
	case granted == "":
		return fmt.Errorf("this client was not approved for host %q; call list_hosts for the hosts it may use", host)
	case !granted.Allows(want):
		return fmt.Errorf("this client was approved for %s access on %q, and this needs %s", granted, host, want)
	}
	return nil
}

func tokenInfo(req *mcp.CallToolRequest) *auth.TokenInfo {
	if req.Extra == nil {
		return nil
	}
	return req.Extra.TokenInfo
}

// grantedMode returns the mode allowed on host for the caller.
func (b *Bridge) grantedMode(req *mcp.CallToolRequest, host string) config.Mode {
	m := b.Config().Hosts[host].Mode
	if ti := tokenInfo(req); ti != nil {
		if granted := oauth.GrantedMode(ti, host); !granted.Allows(m) {
			m = granted
		}
	}
	return m
}

// Register adds the bridge's tools to server.
func (b *Bridge) Register(server *mcp.Server) {
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_hosts",
		Description: "List the Rex hosts (machines) this bridge exposes and what you may do on each. Pass a host's name to the other tools.",
		Annotations: titled(readOnly, "List hosts"),
	}, b.listHosts)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_panes",
		Description: "List the terminal panes on a host, grouped by Rex session and window, with the block ID to pass to capture.",
		Annotations: titled(readOnly, "List panes"),
	}, b.listPanes)

	mcp.AddTool(server, &mcp.Tool{
		Name: "capture",
		Description: "Read the last lines of a terminal pane's screen and scrollback. " +
			"Full-screen programs such as editors show only their current screen.",
		Annotations: titled(readOnly, "Read pane"),
	}, b.capture)

	b.registerRun(server)
}

// HostInfo describes an exposed host.
type HostInfo struct {
	Name        string      `json:"name"`
	ThisMachine bool        `json:"this_machine,omitempty" jsonschema:"true for the machine the bridge itself runs on"`
	Mode        config.Mode `json:"mode" jsonschema:"read: list and read panes; run: also run commands; interactive: also type into panes"`
	Endpoints   []string    `json:"endpoints,omitempty"`
	Problem     string      `json:"problem,omitempty" jsonschema:"why the host cannot be used, if it cannot"`
}

type listHostsIn struct{}

type listHostsOut struct {
	Hosts []HostInfo `json:"hosts"`
}

func (b *Bridge) listHosts(ctx context.Context, req *mcp.CallToolRequest, _ listHostsIn) (*mcp.CallToolResult, listHostsOut, error) {
	known, err := b.Rex.Hosts(ctx)
	if err != nil {
		return nil, listHostsOut{}, err
	}
	var out listHostsOut
	cfg := b.Config()
	for _, name := range cfg.Names() {
		info := HostInfo{Name: name, Mode: b.grantedMode(req, name), ThisMachine: cfg.IsThisMachine(name)}
		if info.Mode == "" {
			continue // not approved for this client
		}
		if !info.ThisMachine {
			if h, ok := known[name]; ok {
				info.Endpoints = h.Endpoints
			} else {
				info.Problem = "not in this machine's rex hosts list"
			}
		}
		out.Hosts = append(out.Hosts, info)
	}
	return nil, out, nil
}

type hostIn struct {
	Host string `json:"host" jsonschema:"host name from list_hosts"`
}

type listPanesOut struct {
	Panes []rex.Pane `json:"panes"`
}

func (b *Bridge) listPanes(ctx context.Context, req *mcp.CallToolRequest, in hostIn) (*mcp.CallToolResult, listPanesOut, error) {
	cfg := b.Config()
	host := cfg.Canonical(in.Host)
	if err := b.check(req, host, config.ModeRead); err != nil {
		return nil, listPanesOut{}, err
	}
	panes, err := b.Rex.Panes(ctx, cfg.RexHost(host))
	if err != nil {
		return nil, listPanesOut{}, err
	}
	if panes == nil {
		panes = []rex.Pane{}
	}
	return nil, listPanesOut{Panes: panes}, nil
}

type captureIn struct {
	Host  string `json:"host" jsonschema:"host name from list_hosts"`
	Block string `json:"block" jsonschema:"block ID or label from list_panes"`
	Lines int    `json:"lines,omitempty" jsonschema:"how many of the last lines to return; default 200, at most 2000"`
}

type captureOut struct {
	Text      string `json:"text"`
	Truncated bool   `json:"truncated" jsonschema:"true when earlier lines were left out"`
}

func (b *Bridge) capture(ctx context.Context, req *mcp.CallToolRequest, in captureIn) (*mcp.CallToolResult, captureOut, error) {
	cfg := b.Config()
	host := cfg.Canonical(in.Host)
	if err := b.check(req, host, config.ModeRead); err != nil {
		return nil, captureOut{}, err
	}
	if in.Block == "" {
		return nil, captureOut{}, fmt.Errorf("block is required; call list_panes to find one")
	}
	lines := in.Lines
	if lines <= 0 {
		lines = defaultCaptureLines
	}
	lines = min(lines, maxCaptureLines)

	text, err := b.Rex.Capture(ctx, cfg.RexHost(host), in.Block)
	if err != nil {
		return nil, captureOut{}, err
	}
	text, truncated := Tail(text, lines, maxOutputBytes)
	return nil, captureOut{Text: text, Truncated: truncated}, nil
}

// Tail returns at most the last n lines of s, and at most maxBytes bytes of
// them, and reports whether anything was left out.
func Tail(s string, n, maxBytes int) (string, bool) {
	s = strings.TrimRight(s, "\n")
	truncated := false
	if lines := strings.Split(s, "\n"); len(lines) > n {
		s = strings.Join(lines[len(lines)-n:], "\n")
		truncated = true
	}
	if len(s) > maxBytes {
		s = s[len(s)-maxBytes:]
		// Start at a whole line, which also avoids a split UTF-8 sequence.
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
		truncated = true
	}
	return s, truncated
}

func titled(a *mcp.ToolAnnotations, title string) *mcp.ToolAnnotations {
	c := *a
	c.Title = title
	return &c
}

func ptr[T any](v T) *T { return &v }
