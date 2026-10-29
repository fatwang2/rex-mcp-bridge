package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fatwang2/rex-mcp-bridge/internal/config"
	"github.com/fatwang2/rex-mcp-bridge/internal/oauth"
	"github.com/fatwang2/rex-mcp-bridge/internal/rex"
)

const (
	defaultRunTimeout = 60 * time.Second
	maxRunTimeout     = 10 * time.Minute
	maxCommandLen     = 8 << 10
)

func (b *Bridge) registerRun(server *mcp.Server) {
	session := b.Config().AgentSession()
	mcp.AddTool(server, &mcp.Tool{
		Name: "run",
		Description: "Run a shell command on a host, where the user can watch it in Rex and take over.\n\n" +
			"With pane, the command is typed into that shell, which must be at its prompt. The shell keeps its state " +
			"between commands, so cd, exported variables, and activated environments carry over. Open one with open_shell. " +
			"Shells outside the \"" + session + "\" session need interactive access.\n\n" +
			"Without pane, the command runs with /bin/sh -c in a new window of the \"" + session + "\" session, " +
			"which suits one-off commands and long-running servers (with wait false).\n\n" +
			"By default run waits for the command to finish and returns its exit code and output. " +
			"A command still running at the timeout keeps running; read it later with capture. " +
			"Avoid commands that wait for input, such as password prompts.",
		Annotations: &mcp.ToolAnnotations{Title: "Run command", DestructiveHint: ptr(true), OpenWorldHint: ptr(true)},
	}, b.run)

	mcp.AddTool(server, &mcp.Tool{
		Name: "open_shell",
		Description: "Open an interactive shell in a new window of the \"" + session + "\" session on a host and return its pane, " +
			"for running several commands in one place with run.",
		Annotations: &mcp.ToolAnnotations{Title: "Open shell", DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, b.openShell)
}

type runIn struct {
	Host    string `json:"host" jsonschema:"host name from list_hosts"`
	Command string `json:"command" jsonschema:"shell command line"`
	Pane    string `json:"pane,omitempty" jsonschema:"block ID of a shell to type the command into; leave out to run it in a new window"`
	Cwd     string `json:"cwd,omitempty" jsonschema:"working directory for a new window; default is the home directory. Ignored with pane: use cd"`
	Timeout int    `json:"timeout_seconds,omitempty" jsonschema:"how long to wait for the command to finish; default 60, at most 600"`
	Wait    *bool  `json:"wait,omitempty" jsonschema:"false returns once the command has started; default true"`
	Lines   int    `json:"lines,omitempty" jsonschema:"how many of the last output lines to return; default 200, at most 2000"`
}

type runOut struct {
	Pane      string `json:"pane" jsonschema:"block ID of the terminal, for capture or another run"`
	Running   bool   `json:"running" jsonschema:"true when the command had not finished when this returned"`
	ExitCode  *int   `json:"exit_code,omitempty" jsonschema:"the command's exit status, once it has finished"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated" jsonschema:"true when earlier output lines were left out"`
}

func (b *Bridge) run(ctx context.Context, req *mcp.CallToolRequest, in runIn) (*mcp.CallToolResult, runOut, error) {
	cfg := b.Config()
	host := cfg.Canonical(in.Host)
	if err := b.check(req, host, config.ModeRun); err != nil {
		return nil, runOut{}, err
	}
	command := strings.TrimSpace(in.Command)
	if command == "" {
		return nil, runOut{}, errors.New("command is required")
	}
	if len(command) > maxCommandLen {
		return nil, runOut{}, fmt.Errorf("command is longer than %d bytes", maxCommandLen)
	}
	timeout := defaultRunTimeout
	if in.Timeout > 0 {
		timeout = min(time.Duration(in.Timeout)*time.Second, maxRunTimeout)
	}
	if in.Wait != nil && !*in.Wait {
		timeout = 0
	}
	lines := in.Lines
	if lines <= 0 {
		lines = defaultCaptureLines
	}
	lines = min(lines, maxCaptureLines)
	ctx, cancel := context.WithTimeout(ctx, timeout+time.Minute)
	defer cancel()

	session := cfg.AgentSession()
	var (
		r   *rex.Result
		err error
	)
	if in.Pane != "" {
		allowAny := b.grantedMode(req, host).Allows(config.ModeInteractive)
		r, err = b.Rex.RunInShell(ctx, cfg.RexHost(host), in.Pane, command, markerID(), session, allowAny, timeout)
	} else {
		r, err = b.Rex.RunInWindow(ctx, cfg.RexHost(host), session, windowLabel(command), in.Cwd, []string{"/bin/sh", "-c", command}, timeout)
	}
	if err != nil {
		b.audit(req, "run-failed host=%s pane=%q cmd=%q err=%q", host, in.Pane, command, err)
		return nil, runOut{}, err
	}
	b.audit(req, "run host=%s pane=%s cmd=%q exit=%s", host, r.Block, command, exitText(r))

	out := runOut{Pane: r.Block, Running: !r.Exited, ExitCode: r.ExitCode}
	out.Output, out.Truncated = Tail(r.Output, lines, maxOutputBytes)
	return nil, out, nil
}

type openShellIn struct {
	Host string `json:"host" jsonschema:"host name from list_hosts"`
	Cwd  string `json:"cwd,omitempty" jsonschema:"working directory; default is the home directory"`
}

type openShellOut struct {
	Pane  string `json:"pane" jsonschema:"block ID of the shell, to pass to run"`
	Shell string `json:"shell,omitempty" jsonschema:"the shell program, such as zsh or bash"`
	Ready bool   `json:"ready" jsonschema:"false if the shell had not reached its prompt yet"`
}

func (b *Bridge) openShell(ctx context.Context, req *mcp.CallToolRequest, in openShellIn) (*mcp.CallToolResult, openShellOut, error) {
	cfg := b.Config()
	host := cfg.Canonical(in.Host)
	if err := b.check(req, host, config.ModeRun); err != nil {
		return nil, openShellOut{}, err
	}
	s, err := b.Rex.OpenShell(ctx, cfg.RexHost(host), cfg.AgentSession(), "shell", in.Cwd)
	if err != nil {
		return nil, openShellOut{}, err
	}
	b.audit(req, "open-shell host=%s pane=%s cwd=%q", host, s.Block, in.Cwd)
	return nil, openShellOut{Pane: s.Block, Shell: s.Shell, Ready: s.Ready}, nil
}

func exitText(r *rex.Result) string {
	if r.ExitCode == nil {
		return "running"
	}
	return fmt.Sprint(*r.ExitCode)
}

// markerID returns a fresh ID for the markers around a command's output.
func markerID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// windowLabel names a window after the start of its command.
func windowLabel(command string) string {
	first, _, _ := strings.Cut(command, "\n")
	r := []rune(strings.TrimSpace(first))
	if len(r) > 40 {
		r = append(r[:39], '…')
	}
	return string(r)
}

// audit logs an action with the client that asked for it.
func (b *Bridge) audit(req *mcp.CallToolRequest, format string, args ...any) {
	if b.Audit == nil {
		return
	}
	client := "stdio"
	if req.Extra != nil && req.Extra.TokenInfo != nil {
		client = req.Extra.TokenInfo.UserID
		if name, ok := req.Extra.TokenInfo.Extra[oauth.ExtraClient].(string); ok {
			client = fmt.Sprintf("%s(%s)", name, client[:min(8, len(client))])
		}
	}
	b.Audit.Printf("tool client=%s "+format, append([]any{client}, args...)...)
}
