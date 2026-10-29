// Package rex runs the rex CLI against a local or remote Rex server.
package rex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// LocalHost is the host name for the Rex server on this machine. Commands
// for it run without --server, so rex uses its default server.
const LocalHost = "local"

// Client runs rex commands and scripts.
type Client struct {
	// Bin is the rex executable. Empty means "rex" from PATH.
	Bin string
	// ConnectTimeout is passed to rex as --timeout. A first connection to a
	// tailnet host can take longer than rex's 10s default while its TLS
	// certificate is issued.
	ConnectTimeout time.Duration

	pool pool
}

func (c *Client) bin() string {
	if c.Bin == "" {
		return "rex"
	}
	return c.Bin
}

// globalArgs are the options that start every rex command for host.
func (c *Client) globalArgs(host string) []string {
	var args []string
	if host != LocalHost {
		args = append(args, "--server="+host)
	}
	if c.ConnectTimeout > 0 {
		args = append(args, "--timeout="+c.ConnectTimeout.String())
	}
	return append(args, "--color=never", "--autostart=false")
}

// Error is a failed rex command.
type Error struct {
	Args   []string
	Stdout []byte
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = e.Err.Error()
	}
	return fmt.Sprintf("rex %s: %s", strings.Join(e.Args, " "), msg)
}

func (e *Error) Unwrap() error { return e.Err }

// Run runs rex with args against host and returns its standard output.
func (c *Client) Run(ctx context.Context, host string, args ...string) ([]byte, error) {
	return c.run(ctx, host, nil, args...)
}

func (c *Client) run(ctx context.Context, host string, stdin io.Reader, args ...string) ([]byte, error) {
	full := append(c.globalArgs(host), args...)
	cmd := exec.CommandContext(ctx, c.bin(), full...)
	cmd.Env = cleanEnv()
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &Error{Args: full, Stdout: stdout.Bytes(), Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

// cleanEnv drops the variables that tie rex to the terminal the bridge was
// started in. With them, rex looks for targets only in that session.
func cleanEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "REX_SESSION=") && !strings.HasPrefix(kv, "REX_BLOCK=") {
			env = append(env, kv)
		}
	}
	return env
}

// RunJSON runs rex and decodes its standard output into v.
func (c *Client) RunJSON(ctx context.Context, host string, v any, args ...string) error {
	out, err := c.Run(ctx, host, args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("decoding rex %s output: %w", strings.Join(args, " "), err)
	}
	return nil
}

// Host is an entry in the local machine's Rex host list.
type Host struct {
	Label     string   `json:"label"`
	Endpoints []string `json:"endpoints"`
}

// Hosts returns the hosts known to this machine's rex, keyed by label.
func (c *Client) Hosts(ctx context.Context) (map[string]Host, error) {
	var resp struct {
		Hosts []struct {
			Host Host `json:"host"`
		} `json:"hosts"`
	}
	if err := c.RunJSON(ctx, LocalHost, &resp, "hosts", "--json"); err != nil {
		return nil, err
	}
	hosts := make(map[string]Host, len(resp.Hosts))
	for _, h := range resp.Hosts {
		hosts[h.Host.Label] = h.Host
	}
	return hosts, nil
}

// Pane is a terminal block and where it sits.
type Pane struct {
	SessionID    string `json:"session_id"`
	SessionLabel string `json:"session_label,omitempty"`
	WindowID     string `json:"window_id"`
	WindowLabel  string `json:"window_label,omitempty"`
	BlockID      string `json:"block_id"`
	BlockLabel   string `json:"block_label,omitempty"`
	Flavor       string `json:"flavor,omitempty"`
	Focused      bool   `json:"focused"`
}
