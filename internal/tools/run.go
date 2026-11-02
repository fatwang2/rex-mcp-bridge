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
	// interruptLines is how much of the screen interrupt returns.
	interruptLines = 50
)

func (b *Bridge) registerRun(server *mcp.Server) {
	session := b.Config().AgentSession()
	mcp.AddTool(server, &mcp.Tool{
		Name: "run",
		Description: "Run a shell command on a host, where the user can watch it in Rex and take over.\n\n" +
			"Without pane, the command runs with /bin/sh -c in a new window of the \"" + session + "\" session. " +
			"If it finishes before run returns, its window closes once the output is read, unless keep_open is true. " +
			"If it is still running, as at the timeout or with wait false, the window stays open, also after the command " +
			"finishes later: read it with capture, stop it with interrupt, and close it with close_pane when you are done. " +
			"This suits one-off commands and long-running servers (with wait false).\n\n" +
			"With pane, the command is typed into that shell, which must be at its prompt. The shell keeps its state " +
			"between commands, so cd, exported variables, and activated environments carry over. " +
			"To run several commands, open one shell with open_shell and pass it as pane, rather than opening a window for each. " +
			"Shells outside the \"" + session + "\" session need interactive access.\n\n" +
			"By default run waits for the command to finish and returns its exit code and output. " +
			"Avoid commands that wait for input, such as password prompts.",
		Annotations: &mcp.ToolAnnotations{Title: "Run command", DestructiveHint: ptr(true), OpenWorldHint: ptr(true)},
	}, b.run)

	mcp.AddTool(server, &mcp.Tool{
		Name: "open_shell",
		Description: "Open an interactive shell in a new window of the \"" + session + "\" session on a host and return its pane, " +
			"for running several commands in one place with run. The window stays open until the shell exits or you " +
			"close it: call close_pane when you have finished with it.",
		Annotations: &mcp.ToolAnnotations{Title: "Open shell", DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, b.openShell)

	mcp.AddTool(server, &mcp.Tool{
		Name: "interrupt",
		Description: "Press Ctrl-C in a terminal pane to stop the program running in it, such as a command run left running " +
			"or a server, and return the pane's screen a moment later. It does not close the pane: a shell stays open, " +
			"ready for the next run, and a window from run stays open with its output until you close it with close_pane. " +
			"Panes outside the \"" + session + "\" session need interactive access.",
		Annotations: &mcp.ToolAnnotations{Title: "Interrupt", DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, b.interrupt)

	mcp.AddTool(server, &mcp.Tool{
		Name: "close_pane",
		Description: "Close a pane in the \"" + session + "\" session and its window, ending the program running in it. " +
			"Close what you opened once you no longer need it, so the user's view stays tidy: " +
			"shells from open_shell, windows from run that were still running when run returned or that you kept with keep_open, " +
			"and windows you interrupted. Windows of commands that finished before run returned are already closed. " +
			"Panes in other sessions cannot be closed.",
		Annotations: &mcp.ToolAnnotations{Title: "Close pane", DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, b.closePane)
}

type runIn struct {
	Host     string `json:"host" jsonschema:"host name from list_hosts"`
	Command  string `json:"command" jsonschema:"shell command line"`
	Pane     string `json:"pane,omitempty" jsonschema:"block ID of a shell to type the command into; leave out to run it in a new window"`
	Cwd      string `json:"cwd,omitempty" jsonschema:"working directory for a new window; default is the home directory. Ignored with pane: use cd"`
	Timeout  int    `json:"timeout_seconds,omitempty" jsonschema:"how long to wait for the command to finish; default 60, at most 600"`
	Wait     *bool  `json:"wait,omitempty" jsonschema:"false returns once the command has started; default true"`
	Lines    int    `json:"lines,omitempty" jsonschema:"how many of the last output lines to return; default 200, at most 2000"`
	KeepOpen bool   `json:"keep_open,omitempty" jsonschema:"true keeps a new window open after its command finishes, for the user to look at; close it with close_pane later. Default false. Ignored with pane"`
}

type runOut struct {
	Pane      string `json:"pane" jsonschema:"block ID of the terminal, for capture or another run, unless closed is true"`
	Running   bool   `json:"running" jsonschema:"true when the command had not finished when this returned"`
	Closed    bool   `json:"closed,omitempty" jsonschema:"true when the pane no longer exists: a new window closes when its command finishes in time, and a shell's window closes when the shell exits"`
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
		r, err = b.Rex.RunInWindow(ctx, cfg.RexHost(host), session, windowLabel(command), in.Cwd, []string{"/bin/sh", "-c", command}, timeout, in.KeepOpen)
	}
	if err != nil {
		b.audit(req, "run-failed host=%s pane=%q cmd=%q err=%q", host, in.Pane, command, err)
		return nil, runOut{}, err
	}
	b.audit(req, "run host=%s pane=%s cmd=%q exit=%s", host, r.Block, command, exitText(r))

	out := runOut{Pane: r.Block, Running: !r.Exited, Closed: r.Closed, ExitCode: r.ExitCode}
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

type paneIn struct {
	Host string `json:"host" jsonschema:"host name from list_hosts"`
	Pane string `json:"pane" jsonschema:"block ID of the pane"`
}

type interruptOut struct {
	Pane       string `json:"pane"`
	Exited     bool   `json:"exited" jsonschema:"true when the pane's own program has exited, as a command run in a new window does"`
	ExitCode   *int   `json:"exit_code,omitempty" jsonschema:"the exit status, once exited; -1 for a program a signal stopped"`
	Foreground string `json:"foreground,omitempty" jsonschema:"the program now in the foreground; a shell such as zsh means it is back at its prompt"`
	Output     string `json:"output" jsonschema:"the last lines on the pane's screen"`
	Truncated  bool   `json:"truncated"`
}

func (b *Bridge) interrupt(ctx context.Context, req *mcp.CallToolRequest, in paneIn) (*mcp.CallToolResult, interruptOut, error) {
	cfg := b.Config()
	host := cfg.Canonical(in.Host)
	if err := b.check(req, host, config.ModeRun); err != nil {
		return nil, interruptOut{}, err
	}
	if in.Pane == "" {
		return nil, interruptOut{}, errors.New("pane is required; call list_panes to find one")
	}
	allowAny := b.grantedMode(req, host).Allows(config.ModeInteractive)
	r, err := b.Rex.Interrupt(ctx, cfg.RexHost(host), in.Pane, cfg.AgentSession(), allowAny)
	if err != nil {
		b.audit(req, "interrupt-failed host=%s pane=%q err=%q", host, in.Pane, err)
		return nil, interruptOut{}, err
	}
	b.audit(req, "interrupt host=%s pane=%s", host, in.Pane)
	out := interruptOut{Pane: in.Pane, Exited: r.Exited, ExitCode: r.ExitCode, Foreground: r.Foreground}
	out.Output, out.Truncated = Tail(r.Output, interruptLines, maxOutputBytes)
	return nil, out, nil
}

type closePaneOut struct {
	Closed string `json:"closed" jsonschema:"block ID of the pane closed"`
}

func (b *Bridge) closePane(ctx context.Context, req *mcp.CallToolRequest, in paneIn) (*mcp.CallToolResult, closePaneOut, error) {
	cfg := b.Config()
	host := cfg.Canonical(in.Host)
	if err := b.check(req, host, config.ModeRun); err != nil {
		return nil, closePaneOut{}, err
	}
	if in.Pane == "" {
		return nil, closePaneOut{}, errors.New("pane is required; call list_panes to find one")
	}
	if err := b.Rex.ClosePane(ctx, cfg.RexHost(host), in.Pane, cfg.AgentSession()); err != nil {
		b.audit(req, "close-failed host=%s pane=%q err=%q", host, in.Pane, err)
		return nil, closePaneOut{}, err
	}
	b.audit(req, "close host=%s pane=%s", host, in.Pane)
	return nil, closePaneOut{Closed: in.Pane}, nil
}

func exitText(r *rex.Result) string {
	if r.ExitCode == nil {
		if r.Closed {
			return "closed"
		}
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
