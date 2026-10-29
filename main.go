// Command rex-mcp-bridge exposes the terminals of chosen Rex hosts to AI
// agents over the Model Context Protocol.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fatwang2/rex-mcp-bridge/internal/config"
	"github.com/fatwang2/rex-mcp-bridge/internal/oauth"
	"github.com/fatwang2/rex-mcp-bridge/internal/rex"
	"github.com/fatwang2/rex-mcp-bridge/internal/tools"
)

var version = "dev"

const usage = `rex-mcp-bridge exposes the terminals of chosen Rex hosts to AI agents over MCP.

Usage:
  rex-mcp-bridge serve [flags]        Serve MCP over HTTPS with OAuth
  rex-mcp-bridge stdio                Serve MCP over stdin/stdout, for local agents
  rex-mcp-bridge pair                 Make a pairing code to approve a sign-in
  rex-mcp-bridge hosts                List the machines in the configuration
  rex-mcp-bridge hosts set NAME MODE  Allow machine NAME at most MODE (read, run, interactive)
  rex-mcp-bridge hosts remove NAME    Take machine NAME out of the configuration
  rex-mcp-bridge clients              List approved clients
  rex-mcp-bridge clients revoke ID    Revoke a client (or --all)
  rex-mcp-bridge version              Print the version

serve joins your tailnet as its own Tailscale node and serves
https://HOSTNAME.<tailnet>.ts.net/mcp, on the public internet through
Tailscale Funnel unless --funnel=false. With --listen it serves plain HTTP
for a reverse proxy you run instead.

The configuration, ~/.config/rex-mcp-bridge/config.json unless --config
says otherwise, lists the machines agents may use and the most each allows.
Machine names are labels from "rex hosts", and this machine's own name
(its host name, or local_name in the configuration), also written "local". Changes
apply without a restart.

Remote agents get only the machines the owner picks on the approval page,
within those limits. With no configuration, serve offers every machine in
"rex hosts" there, and stdio allows only this machine, read only.

State lives in ~/.local/state/rex-mcp-bridge.
`

func main() {
	log.SetFlags(0)
	log.SetPrefix("rex-mcp-bridge: ")
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serveCmd(args)
	case "stdio":
		err = stdioCmd(args)
	case "pair":
		err = pairCmd(args)
	case "hosts":
		err = hostsCmd(args)
	case "clients":
		err = clientsCmd(args)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// flags returns a flag set with the --config flag every command takes.
// rexBin is the rex executable, set by --rex. Agents such as Claude Desktop
// start the bridge without the user's shell PATH, where rex may not be.
var rexBin string

func addRexFlag(fs *flag.FlagSet) {
	fs.StringVar(&rexBin, "rex", "rex", "path to the rex `executable`")
}

func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return fs, fs.String("config", "", "configuration `file`")
}

// parseAnyOrder parses flags that may come before, between, or after the
// positional arguments, and returns the positional arguments.
func parseAnyOrder(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		fs.Parse(args)
		if fs.NArg() == 0 {
			return pos
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func configPath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return config.DefaultPath()
}

// offerAll is the configuration serve uses without a file: every machine
// rex knows, each allowing up to interactive, so the owner decides on the
// approval page.
func offerAll(rc *rex.Client) func() *config.Config {
	return func() *config.Config {
		cfg := &config.Config{Hosts: map[string]config.Host{rex.LocalHost: {Mode: config.ModeInteractive}}}
		hosts, err := rc.Hosts(context.Background())
		if err != nil {
			log.Printf("listing rex hosts: %v", err)
		}
		for name := range hosts {
			cfg.Hosts[name] = config.Host{Mode: config.ModeInteractive}
		}
		return cfg
	}
}

func stateDir() (string, error) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".local", "state")
	}
	dir = filepath.Join(dir, "rex-mcp-bridge")
	return dir, os.MkdirAll(dir, 0o700)
}

func oauthStore() (*oauth.Store, error) {
	dir, err := stateDir()
	if err != nil {
		return nil, err
	}
	return &oauth.Store{Dir: filepath.Join(dir, "oauth")}, nil
}

func newMCPServer(cfg func() *config.Config, audit *log.Logger) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:       "rex-mcp-bridge",
		Title:      "Rex",
		Version:    version,
		WebsiteURL: "https://github.com/fatwang2/rex-mcp-bridge",
	}, nil)
	bridge := &tools.Bridge{
		Config: cfg,
		Rex:    &rex.Client{Bin: rexBin, ConnectTimeout: 40 * time.Second},
		Audit:  audit,
	}
	bridge.Register(server)
	return server
}

func stdioCmd(args []string) error {
	fs, cfgFlag := flags("stdio")
	addRexFlag(fs)
	fs.Parse(args)
	path, err := configPath(*cfgFlag)
	if err != nil {
		return err
	}
	if _, err := config.Load(path); err != nil {
		return err
	}
	src := &config.Source{Path: path, Fallback: config.Default}
	dir, err := stateDir()
	if err != nil {
		return err
	}
	audit, closeAudit, err := openAudit(filepath.Join(dir, "audit.log"))
	if err != nil {
		return err
	}
	defer closeAudit()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return newMCPServer(src.Get, audit).Run(ctx, &mcp.StdioTransport{})
}

func pairCmd(args []string) error {
	fs, _ := flags("pair")
	fs.Parse(args)
	store, err := oauthStore()
	if err != nil {
		return err
	}
	code, err := store.NewPairingCode()
	if err != nil {
		return err
	}
	fmt.Printf("Pairing code: %s\n", code)
	fmt.Printf("Enter it on the sign-in page within %v. It works once.\n", oauth.PairingCodeTTL)
	return nil
}

func clientsCmd(args []string) error {
	store, err := oauthStore()
	if err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "revoke" {
		fs, _ := flags("clients revoke")
		all := fs.Bool("all", false, "revoke every client")
		pos := parseAnyOrder(fs, args[1:])
		switch {
		case *all:
			n, err := store.RevokeAll()
			if err != nil {
				return err
			}
			fmt.Printf("Revoked %d clients.\n", n)
		case len(pos) == 1:
			g, err := store.Revoke(pos[0])
			if err != nil {
				return err
			}
			fmt.Printf("Revoked %s (%s).\n", g.ClientName, g.ID[:8])
		default:
			return fmt.Errorf("usage: rex-mcp-bridge clients revoke ID | --all")
		}
		return nil
	}
	if len(args) > 0 {
		return fmt.Errorf("unknown clients command %q", args[0])
	}
	grants, err := store.Grants()
	if err != nil {
		return err
	}
	if len(grants) == 0 {
		fmt.Println("No approved clients.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCLIENT\tSENDS TO\tMACHINES\tAPPROVED\tEXPIRES")
	for _, g := range grants {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", g.ID[:8], g.ClientName, g.RedirectHost, oauth.FormatHosts(g.HostModes()),
			g.CreatedAt.Local().Format("2006-01-02 15:04"), g.ExpiresAt.Local().Format("2006-01-02"))
	}
	return tw.Flush()
}

func hostsCmd(args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs, cfgFlag := flags("hosts " + sub)
	addRexFlag(fs)
	pos := parseAnyOrder(fs, args)
	path, err := configPath(*cfgFlag)
	if err != nil {
		return err
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		if len(cfg.Hosts) == 0 {
			fmt.Printf("No machines in %s.\n", path)
			fmt.Println("serve offers every machine in \"rex hosts\" on the approval page; stdio allows only local, read only.")
			fmt.Println("Add one with: rex-mcp-bridge hosts set NAME MODE")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "MACHINE\tAT MOST")
		named := cfg.Named()
		for _, name := range named.Names() {
			label := name
			if named.IsThisMachine(name) {
				label += " (this machine)"
			}
			fmt.Fprintf(tw, "%s\t%s\n", label, named.Hosts[name].Mode)
		}
		return tw.Flush()

	case "set":
		if len(pos) != 2 {
			return errors.New("usage: rex-mcp-bridge hosts set NAME MODE")
		}
		name, mode := pos[0], config.Mode(pos[1])
		if name == cfg.ThisMachine() {
			name = rex.LocalHost // stored as local, so the file can move between machines
		}
		if name != rex.LocalHost {
			known, err := (&rex.Client{Bin: rexBin}).Hosts(context.Background())
			if err != nil {
				return err
			}
			if _, ok := known[name]; !ok {
				return fmt.Errorf("%q is not in \"rex hosts\"; use local for this machine, or add it with rex hosts add", name)
			}
		}
		cfg.Hosts[name] = config.Host{Mode: mode}
		if err := cfg.Save(path); err != nil {
			return err
		}
		fmt.Printf("%s: at most %s.\n", name, mode)

	case "remove":
		if len(pos) != 1 {
			return errors.New("usage: rex-mcp-bridge hosts remove NAME")
		}
		name := pos[0]
		if name == cfg.ThisMachine() {
			name = rex.LocalHost
		}
		if _, ok := cfg.Hosts[name]; !ok {
			return fmt.Errorf("%q is not in %s", name, path)
		}
		delete(cfg.Hosts, name)
		if err := cfg.Save(path); err != nil {
			return err
		}
		fmt.Printf("Removed %s.\n", name)
		if len(cfg.Hosts) == 0 {
			fmt.Println("No machines are left: agents over stdio and new approvals get none.")
		}

	default:
		return fmt.Errorf("unknown hosts command %q", sub)
	}
	return nil
}
