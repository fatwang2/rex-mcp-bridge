# rex-mcp-bridge

> Unofficial. Not affiliated with or endorsed by Superlogical.

Let AI agents use the terminals on your machines through
[Rex](https://www.superlogical.com/rex). Claude on the web or your phone,
Claude Desktop, Claude Code, and other MCP clients can read what your
terminals show and run commands, in Rex windows you can watch and take
over at any time.

It is for running commands on your machines, not for driving coding agents.

```
claude.ai ── HTTPS + OAuth ──▶ rex-mcp-bridge ── rex ──▶ Rex on each machine
             (Tailscale Funnel)   (one machine)    (your tailnet)
```

- **Watchable.** Every command runs in a Rex window, so you see what the
  agent does and can step in.
- **Shells that keep state.** `cd`, exported variables, and activated
  environments carry over between commands in the same shell.
- **Many machines, one connector.** The bridge reaches every machine in
  `rex hosts`; you choose which ones each client may use, and how.
- **Built for remote access.** It serves HTTPS on your tailnet, and on the
  internet through Tailscale Funnel, with standard MCP OAuth sign-in.

## Status

Early, and built on Rex, which is in beta: Rex's API may change under it.
It runs on macOS and Linux.

## Requirements

- [Rex](https://www.superlogical.com/rex) on the machine that runs the
  bridge, with the other machines added to `rex hosts`.
- For remote agents such as claude.ai: a [Tailscale](https://tailscale.com)
  tailnet with MagicDNS, HTTPS, and Funnel allowed (the default policy
  allows it). Or your own HTTPS reverse proxy.
- Go 1.27.3 or later, only to build it yourself.

## Install

Download a binary for macOS or Linux from
[Releases](https://github.com/fatwang2/rex-mcp-bridge/releases), or build
it with Go:

```sh
go install github.com/fatwang2/rex-mcp-bridge@latest
```

## Use with claude.ai

```sh
rex-mcp-bridge serve
```

The first run prints a Tailscale sign-in link. The bridge joins your tailnet
as its own node, `rex-mcp`, and serves `https://rex-mcp.<tailnet>.ts.net/mcp`
on the internet through [Tailscale Funnel](https://tailscale.com/kb/1223/funnel).

In claude.ai, add a custom connector with that URL and keep the defaults
(sign in now, Claude's published identity). On the sign-in page:

1. Check that it sends access where you expect, such as `claude.ai`.
2. Tick the machines it may use and pick a level for each (see
   [Access levels](#access-levels)).
3. Approve. From a device on your tailnet, the page recognizes you through
   Tailscale. From anywhere else, it asks for a pairing code: run
   `rex-mcp-bridge pair` on the bridge's machine.

Other remote MCP clients that support OAuth, such as Claude Code pointed at
the URL, should sign in the same way; so far it has been tested with
claude.ai.

| Flag | Does |
| --- | --- |
| `--funnel=false` | Serve on your tailnet only, for agents on your own devices |
| `--hostname NAME` | Use another Tailscale node name |
| `--listen ADDR --public-url URL` | Serve plain HTTP on `ADDR` behind your own HTTPS proxy at `URL`, without Tailscale |
| `--rex PATH` | Use this `rex` executable instead of the one on `PATH` |

To keep it running on a Linux server, use the systemd user service in
[`contrib/rex-mcp-bridge.service`](contrib/rex-mcp-bridge.service).

### Managing access

```sh
rex-mcp-bridge clients              # approved clients and their machines
rex-mcp-bridge clients revoke ID    # cut one off immediately
rex-mcp-bridge clients revoke --all
```

An approval lasts 30 days.

## Use with Claude Code or Claude Desktop on the same machine

Over stdio, there is no sign-in; the configuration alone decides what the
agent may do, and without one it may only read this machine's terminals.

```sh
claude mcp add -s user rex-bridge -- rex-mcp-bridge stdio
```

For Claude Desktop, add it to `claude_desktop_config.json`. Desktop does
not use your shell's `PATH`, so give full paths (`which rex` prints rex's):

```json
{
  "mcpServers": {
    "rex-bridge": {
      "command": "/Users/you/go/bin/rex-mcp-bridge",
      "args": ["stdio", "--rex", "/path/to/rex"]
    }
  }
}
```

Name it something other than `rex`, so it does not collide with the Rex
skill and CLI.

## Tools

| Tool | Does | Needs |
| --- | --- | --- |
| `list_hosts` | Lists the machines the client may use, and how | — |
| `list_panes` | Lists sessions, windows, and terminals on a machine | `read` |
| `capture` | Reads the last lines of a terminal | `read` |
| `open_shell` | Opens a shell in a new window | `run` |
| `run` | Runs a command and returns its exit code and output | `run` |

`run` works two ways:

- **In a shell** (`pane` set): the command is typed into a shell at its
  prompt, usually one from `open_shell`, and the shell keeps its state.
  It runs one command at a time; a shell still busy, such as one waiting
  for input, is refused.
- **In a new window** (no `pane`): the command runs with `/bin/sh -c` in its
  own window, which suits one-off commands and long-running servers.

It waits up to 60 seconds by default, at most 600. A command still running
then keeps running, and the agent can read it later with `capture`. Avoid
commands that prompt for input, such as `sudo` asking for a password.

Agents' windows and shells go in a Rex session named `mcp` on each machine,
created when first needed.

## Access levels

| Level | Allows |
| --- | --- |
| `read` | Listing terminals and reading their output, including yours |
| `run` | Also opening shells and running commands in the agent's own windows and shells |
| `interactive` | Also running commands in any shell, including the ones you are using |

`run` runs commands as your account, so it can do anything you can. Keeping
agents to their own session separates their work from yours and keeps it
visible; it is not a sandbox.

## Configuration

Two things decide what a client may do on a machine: the configuration,
which sets the most any client may do there, and, for remote clients, what
you ticked when approving it.

Manage the configuration with `hosts`. Changes apply without a restart.

```sh
rex-mcp-bridge hosts                     # list
rex-mcp-bridge hosts set local run       # this machine (or its name)
rex-mcp-bridge hosts set studio read     # a label from "rex hosts"
rex-mcp-bridge hosts remove studio
```

Without a configuration, `serve` offers every machine in `rex hosts` on the
sign-in page, unticked, up to `interactive`; `stdio` allows only this
machine, read only.

The file is `~/.config/rex-mcp-bridge/config.json`:

```json
{
  "hosts": {
    "local":  { "mode": "run" },
    "studio": { "mode": "read" }
  },
  "local_name": "laptop",
  "session": "mcp"
}
```

- `local` is the machine the bridge runs on, so the file can move between
  machines. Agents and the sign-in page see it by its real name: its host
  name, or `local_name`.
- `session` names the Rex session agents work in. Default `mcp`.

## How it works

The bridge drives Rex only through `rex do` Lua scripts and Rex's
documented API. For each machine it keeps a few `rex do` processes
connected and sends them requests, so a call costs a network round trip
rather than a new connection, which takes seconds over a tailnet.

To run a command in a shell, it types the command between two markers that
the shell prints, and reads the output and exit status between them.

## Security

- **Sign-in** follows the
  [MCP authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization):
  OAuth 2.1 with PKCE, Client ID Metadata Documents, and Dynamic Client
  Registration for older clients. Refresh tokens rotate, and reusing an
  old one revokes the approval.
- **Approving** needs you: either a single-use pairing code from the
  bridge's machine, or a request from one of your own Tailscale devices.
  Requests through Funnel, from the internet, are never recognized as you.
  The sign-in page only accepts a submission from the browser that opened
  it, so another site cannot approve in your browser's name.
- **Exposure.** Funnel makes the address public, and scanners find
  `*.ts.net` names through certificate transparency logs. Everything but
  discovery metadata and the sign-in page needs a token.
- **Client metadata** documents are fetched only from public addresses,
  never from your local network or tailnet.
- **What leaves your machines.** Terminal contents an agent reads, and
  command output, go to the agent and its provider.
- **Audit log.** Approvals, refusals, token problems, and every command run
  are logged to `~/.local/state/rex-mcp-bridge/audit.log`.

## Development

```sh
go test ./...
REX_E2E_HOSTS=studio go test -tags e2e -v .   # against real Rex servers
```

The end-to-end test opens and closes an `mcp` session on each host.

## License

MIT
