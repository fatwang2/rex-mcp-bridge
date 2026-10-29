//go:build e2e

// The end-to-end test runs the bridge against real Rex servers:
//
//	REX_E2E_HOSTS=studio,laptop go test -tags e2e -v .
//
// It always uses "local"; REX_E2E_HOSTS adds hosts from "rex hosts". It runs
// commands on every host in an "mcp" session, and removes that session
// afterwards if it did not exist before.
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestE2E(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "rex-mcp-bridge")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	hosts := []string{"local"}
	if v := os.Getenv("REX_E2E_HOSTS"); v != "" {
		hosts = append(hosts, strings.Split(v, ",")...)
	}
	policy := map[string]any{"readonly-alias": map[string]string{"mode": "read"}}
	for _, h := range hosts {
		policy[h] = map[string]string{"mode": "run"}
		if !hasSession(h, "mcp") {
			t.Cleanup(func() { rexCmd(h, "kill", "mcp").Run() })
		}
	}
	cfg, _ := json.Marshal(map[string]any{"hosts": policy})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "v0"}, nil)
	cmd := exec.Command(bin, "stdio", "--config", cfgPath)
	stateHome := filepath.Join(dir, "state")
	cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+stateHome)
	cmd.Stderr = os.Stderr
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	call := func(name string, args map[string]any) (map[string]any, string) {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.IsError {
			return nil, res.Content[0].(*mcp.TextContent).Text
		}
		var out map[string]any
		b, _ := json.Marshal(res.StructuredContent)
		json.Unmarshal(b, &out)
		return out, ""
	}
	mustCall := func(name string, args map[string]any) map[string]any {
		t.Helper()
		out, errText := call(name, args)
		if errText != "" {
			t.Fatalf("%s %v: %s", name, args, errText)
		}
		return out
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			start := time.Now()
			out := mustCall("run", map[string]any{"host": host, "command": "echo hello-$((1+2)); hostname; exit 3"})
			if out["running"] != false || out["exit_code"] != float64(3) || !strings.Contains(out["output"].(string), "hello-3") {
				t.Errorf("run: %v", out)
			}
			t.Logf("run in a window on %s took %v:\n%s", host, time.Since(start).Round(time.Millisecond), out["output"])

			out = mustCall("run", map[string]any{"host": host, "command": "pwd", "cwd": "/tmp"})
			if !strings.Contains(out["output"].(string), "/tmp") || out["exit_code"] != float64(0) {
				t.Errorf("run with cwd: %v", out)
			}

			out = mustCall("run", map[string]any{"host": host, "command": "echo started; sleep 20", "timeout_seconds": 2})
			if out["running"] != true || out["exit_code"] != nil || !strings.Contains(out["output"].(string), "started") {
				t.Errorf("run past timeout: %v", out)
			}
			// The command keeps running and can be read later.
			later := mustCall("capture", map[string]any{"host": host, "block": out["pane"], "lines": 5})
			if !strings.Contains(later["text"].(string), "started") {
				t.Errorf("capture after timeout: %v", later)
			}

			// A shell keeps its state between commands.
			shell := mustCall("open_shell", map[string]any{"host": host})
			if shell["ready"] != true {
				t.Fatalf("open_shell: %v", shell)
			}
			pane := shell["pane"]
			start = time.Now()
			if out := mustCall("run", map[string]any{"host": host, "pane": pane, "command": "cd /tmp && export RMB_E2E=kept"}); out["exit_code"] != float64(0) {
				t.Errorf("cd in shell: %v", out)
			}
			t.Logf("run in a shell on %s took %v", host, time.Since(start).Round(time.Millisecond))
			out = mustCall("run", map[string]any{"host": host, "pane": pane, "command": "pwd\necho \"var=$RMB_E2E\""})
			text := out["output"].(string)
			if out["exit_code"] != float64(0) || !strings.Contains(text, "/tmp") || !strings.Contains(text, "var=kept") {
				t.Errorf("state did not carry over: %v", out)
			}
			if strings.Contains(text, "__rmb") {
				t.Errorf("output shows markers: %q", text)
			}
			if out := mustCall("run", map[string]any{"host": host, "pane": pane, "command": "false"}); out["exit_code"] != float64(1) {
				t.Errorf("false in shell: %v", out)
			}
			// A command waiting for input is reported as running, and the
			// shell refuses another command until it finishes.
			if out := mustCall("run", map[string]any{"host": host, "pane": pane, "command": "read x; echo got-$x", "timeout_seconds": 2}); out["running"] != true {
				t.Errorf("read in shell: %v", out)
			}
			if _, errText := call("run", map[string]any{"host": host, "pane": pane, "command": "true"}); !strings.Contains(errText, "busy") {
				t.Errorf("run in a busy shell: %q", errText)
			}

			panes := mustCall("list_panes", map[string]any{"host": host})["panes"].([]any)
			found := false
			for _, p := range panes {
				if p.(map[string]any)["session_label"] == "mcp" {
					found = true
				}
			}
			if !found {
				t.Error("list_panes does not show the mcp session")
			}
		})
	}

	// With run access, shells outside the agents' session are off limits.
	// The test makes its own session for this, never touching the user's.
	other := strings.TrimSpace(string(must(rexCmd("local", "new", "--json", "zz-e2e-other").Output())))
	t.Cleanup(func() { rexCmd("local", "kill", "zz-e2e-other").Run() })
	var created struct {
		Windows []struct {
			BlockIDs []string `json:"block_ids"`
		} `json:"initial_windows"`
	}
	json.Unmarshal([]byte(other), &created)
	if len(created.Windows) == 0 {
		t.Fatalf("rex new: %s", other)
	}
	time.Sleep(time.Second)
	if _, errText := call("run", map[string]any{"host": "local", "pane": created.Windows[0].BlockIDs[0], "command": "echo should-not-run"}); !strings.Contains(errText, "interactive") {
		t.Errorf("run in a shell outside the agents' session: %q", errText)
	}

	// After the user closes the agents' session, run makes a new one.
	if err := rexCmd("local", "kill", "mcp").Run(); err != nil {
		t.Fatal(err)
	}
	if out := mustCall("run", map[string]any{"host": "local", "command": "echo again"}); out["exit_code"] != float64(0) {
		t.Errorf("run after the session was closed: %v", out)
	}

	if _, errText := call("run", map[string]any{"host": "readonly-alias", "command": "true"}); !strings.Contains(errText, "allows read") {
		t.Errorf("run on a read-only host: %q", errText)
	}
	if _, errText := call("list_panes", map[string]any{"host": "not-configured"}); errText == "" {
		t.Error("list_panes on an unconfigured host succeeded")
	}

	audit, _ := os.ReadFile(filepath.Join(stateHome, "rex-mcp-bridge", "audit.log"))
	if !strings.Contains(string(audit), `cmd="pwd"`) {
		t.Errorf("audit log lacks the commands run:\n%s", audit)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func rexCmd(host string, args ...string) *exec.Cmd {
	if host != "local" {
		args = append([]string{"--server=" + host, "--timeout=40s"}, args...)
	}
	return exec.Command("rex", args...)
}

func hasSession(host, label string) bool {
	out, err := rexCmd(host, "session", "ls", "--json").Output()
	if err != nil {
		return false
	}
	var list struct {
		Sessions []struct {
			Label string `json:"label"`
		} `json:"sessions"`
	}
	json.Unmarshal(out, &list)
	for _, s := range list.Sessions {
		if s.Label == label {
			return true
		}
	}
	return false
}
