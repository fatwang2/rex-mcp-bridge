package rex

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// A worker is a long-lived "rex do" process connected to one host. It reads
// one JSON request per line on stdin, runs the named script on its open
// connection, and writes one JSON response per line. Connecting to a remote
// host takes seconds; a call on an open connection takes a round trip.

const (
	maxWorkersPerHost = 4
	workerIdleTimeout = 10 * time.Minute
	// A worker idle longer than this is pinged before use, in case its
	// server restarted or the network dropped while it waited.
	workerPingAfter = 30 * time.Second
	// responsePrefix starts every response line, so other output, such as a
	// warning rex prints, is not mistaken for one. It is plain ASCII because
	// it is written into Lua 5.1 source, which has no \x escapes.
	responsePrefix = "@@rex-mcp-bridge@@ "
)

// workerSource builds the Lua program a worker runs: the prelude, each
// script wrapped as a handler, and the request loop.
func workerSource() (string, error) {
	var b strings.Builder
	prelude, err := scripts.ReadFile("lua/prelude.lua")
	if err != nil {
		return "", err
	}
	b.Write(prelude)
	b.WriteString("\nlocal handlers = { ping = function() return true end }\n")
	entries, err := fs.ReadDir(scripts, "lua")
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".lua")
		if !ok || name == "prelude" {
			continue
		}
		body, err := scripts.ReadFile("lua/" + e.Name())
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "handlers[%q] = function()\n%s\nend\n", name, body)
	}
	fmt.Fprintf(&b, `
io.stdout:setvbuf("no")
while true do
  local line = io.read("*l")
  if line == nil then break end
  local ok, req = pcall(rex.json.decode, line)
  local resp
  if not ok then
    resp = { ok = false, error = "bad request: " .. tostring(req) }
  elseif handlers[req.script] == nil then
    resp = { id = req.id, ok = false, error = "no script " .. tostring(req.script) }
  else
    rex.args = req.args or {}
    local done, result = pcall(handlers[req.script])
    if done then
      resp = { id = req.id, ok = true, result = result }
    else
      resp = { id = req.id, ok = false, error = tostring(result) }
    end
  end
  io.write(%q, rex.json.encode(resp), "\n")
  io.stdout:flush()
end
`, responsePrefix)
	return b.String(), nil
}

type worker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *bytes.Buffer
	nextID int
	idle   time.Time
}

// ScriptError is an error a script raised, as opposed to a failure to run
// it. Retrying on a new connection would not help.
type ScriptError struct{ Msg string }

func (e *ScriptError) Error() string { return e.Msg }

func (w *worker) call(ctx context.Context, name string, args any) (json.RawMessage, error) {
	w.nextID++
	req, err := json.Marshal(map[string]any{"id": w.nextID, "script": name, "args": args})
	if err != nil {
		return nil, err
	}
	type reply struct {
		line string
		err  error
	}
	done := make(chan reply, 1)
	go func() {
		if _, err := w.stdin.Write(append(req, '\n')); err != nil {
			done <- reply{err: err}
			return
		}
		for {
			line, err := w.stdout.ReadString('\n')
			if err != nil {
				done <- reply{err: err}
				return
			}
			if rest, ok := strings.CutPrefix(line, responsePrefix); ok {
				done <- reply{line: rest}
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		// The script may still be running; this worker cannot be reused.
		w.kill()
		return nil, ctx.Err()
	case r := <-done:
		if r.err != nil {
			w.kill()
			msg := strings.TrimSpace(w.stderr.String())
			if msg == "" {
				msg = r.err.Error()
			}
			return nil, fmt.Errorf("rex connection: %s", msg)
		}
		var resp struct {
			ID     int             `json:"id"`
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := json.Unmarshal([]byte(r.line), &resp); err != nil {
			w.kill()
			return nil, fmt.Errorf("decoding worker response: %w", err)
		}
		if !resp.OK {
			return nil, &ScriptError{Msg: resp.Error}
		}
		return resp.Result, nil
	}
}

func (w *worker) kill() {
	w.stdin.Close()
	if w.cmd.Process != nil {
		w.cmd.Process.Kill()
	}
	go w.cmd.Wait()
}

func (w *worker) alive() bool { return w.cmd.ProcessState == nil }

// pool keeps workers for each host.
type pool struct {
	mu    sync.Mutex
	idle  map[string][]*worker
	count map[string]int
	ready chan struct{}
}

func (c *Client) startWorker(host string) (*worker, error) {
	src, err := workerSource()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(c.bin(), append(c.globalArgs(host), "do", "-e", src)...)
	cmd.Env = cleanEnv()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &worker{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: stderr}, nil
}

// get returns an idle worker for host, starting one if there is room, or
// waits for one to come back.
func (c *Client) get(ctx context.Context, host string) (*worker, error) {
	p := &c.pool
	for {
		p.mu.Lock()
		if p.idle == nil {
			p.idle, p.count, p.ready = map[string][]*worker{}, map[string]int{}, make(chan struct{})
		}
		for len(p.idle[host]) > 0 {
			ws := p.idle[host]
			w := ws[len(ws)-1]
			p.idle[host] = ws[:len(ws)-1]
			idleFor := time.Since(w.idle)
			if idleFor < workerIdleTimeout {
				p.mu.Unlock()
				if idleFor < workerPingAfter {
					return w, nil
				}
				if _, err := w.call(ctx, "ping", nil); err == nil {
					return w, nil
				}
				c.drop(host)
				p.mu.Lock()
				continue
			}
			p.count[host]--
			w.kill()
		}
		if p.count[host] < maxWorkersPerHost {
			p.count[host]++
			p.mu.Unlock()
			w, err := c.startWorker(host)
			if err != nil {
				c.drop(host)
				return nil, err
			}
			return w, nil
		}
		ready := p.ready
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ready:
		}
	}
}

// put returns w to the pool, or forgets it if it died.
func (c *Client) put(host string, w *worker, dead bool) {
	p := &c.pool
	p.mu.Lock()
	if dead {
		p.count[host]--
	} else {
		w.idle = time.Now()
		p.idle[host] = append(p.idle[host], w)
	}
	close(p.ready)
	p.ready = make(chan struct{})
	p.mu.Unlock()
}

func (c *Client) drop(host string) { c.put(host, nil, true) }

// Close stops every worker.
func (c *Client) Close() {
	p := &c.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	for host, ws := range p.idle {
		for _, w := range ws {
			w.kill()
		}
		p.count[host] -= len(ws)
		p.idle[host] = nil
	}
}

// call runs a script on a pooled worker. If the connection fails and the
// script only reads, it tries once more on a fresh worker. A script that
// changes something is not retried, since it may already have run.
func (c *Client) call(ctx context.Context, host, name string, args any, readOnly bool) (json.RawMessage, error) {
	tries := 1
	if readOnly {
		tries = 2
	}
	var lastErr error
	for range tries {
		w, err := c.get(ctx, host)
		if err != nil {
			return nil, err
		}
		res, err := w.call(ctx, name, args)
		var serr *ScriptError
		switch {
		case err == nil || errors.As(err, &serr):
			c.put(host, w, false)
			return res, err
		case ctx.Err() != nil:
			c.put(host, w, true)
			return nil, err
		}
		c.put(host, w, true)
		lastErr = err
	}
	return nil, lastErr
}
