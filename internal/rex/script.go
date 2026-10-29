package rex

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"time"
)

// Each operation that needs several calls to a server runs as one Lua script
// on a worker's open connection; see worker.go.

//go:embed lua/*.lua
var scripts embed.FS

// Script runs lua/NAME.lua on host with args and decodes the value it
// returns into out. readOnly scripts are retried on a fresh connection.
func (c *Client) Script(ctx context.Context, host, name string, args, out any, readOnly bool) error {
	res, err := c.call(ctx, host, name, args, readOnly)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(res, out); err != nil {
		return fmt.Errorf("decoding %s.lua result: %w", name, err)
	}
	return nil
}

// list decodes a JSON array that Lua may have encoded as {} when empty.
type list[T any] []T

func (l *list[T]) UnmarshalJSON(b []byte) error {
	if string(bytes.TrimSpace(b)) == "{}" {
		*l = nil
		return nil
	}
	return json.Unmarshal(b, (*[]T)(l))
}

// Panes lists every block in every session on host.
func (c *Client) Panes(ctx context.Context, host string) ([]Pane, error) {
	var out struct {
		Panes list[Pane] `json:"panes"`
	}
	if err := c.Script(ctx, host, "panes", map[string]any{}, &out, true); err != nil {
		return nil, err
	}
	return out.Panes, nil
}

// Capture returns the screen and scrollback of a block as plain text.
func (c *Client) Capture(ctx context.Context, host, block string) (string, error) {
	var out struct {
		Text string `json:"text"`
	}
	err := c.Script(ctx, host, "capture", map[string]any{"block": block}, &out, true)
	return out.Text, err
}

// Result is what a command left behind.
type Result struct {
	Block    string `json:"block"`
	Exited   bool   `json:"exited"`
	ExitCode *int   `json:"exit_code"`
	Output   string `json:"output"`
}

// RunInWindow runs argv in a new window of session, which is created when
// missing, and waits up to timeout for it to exit. The window stays open.
func (c *Client) RunInWindow(ctx context.Context, host, session, label, cwd string, argv []string, timeout time.Duration) (*Result, error) {
	var r Result
	args := map[string]any{"session": session, "label": label, "argv": argv, "timeout": int(timeout.Seconds())}
	if cwd != "" {
		args["cwd"] = cwd
	}
	err := c.Script(ctx, host, "run", args, &r, false)
	return &r, err
}

// RunInShell types command into the shell in block, which must be at its
// prompt, and waits up to timeout for it to finish. Unless allowAny, the
// block must be in session agentSession. id must be unique and
// alphanumeric; it marks where the output starts and ends.
func (c *Client) RunInShell(ctx context.Context, host, block, command, id, agentSession string, allowAny bool, timeout time.Duration) (*Result, error) {
	var r Result
	err := c.Script(ctx, host, "shell", map[string]any{
		"block": block, "command": command, "id": id, "agent_session": agentSession,
		"allow_any": allowAny, "timeout": int(timeout.Seconds()),
	}, &r, false)
	return &r, err
}

// Shell is a newly opened shell.
type Shell struct {
	Block string `json:"block"`
	Shell string `json:"shell"`
	Ready bool   `json:"ready"`
}

// OpenShell opens an interactive shell in a new window of session.
func (c *Client) OpenShell(ctx context.Context, host, session, label, cwd string) (*Shell, error) {
	var s Shell
	args := map[string]any{"session": session, "label": label}
	if cwd != "" {
		args["cwd"] = cwd
	}
	err := c.Script(ctx, host, "open_shell", args, &s, false)
	return &s, err
}
