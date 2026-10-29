package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"

	"github.com/fatwang2/rex-mcp-bridge/internal/config"
	"github.com/fatwang2/rex-mcp-bridge/internal/oauth"
	"github.com/fatwang2/rex-mcp-bridge/internal/rex"
)

const mcpPath = "/mcp"

func serveCmd(args []string) error {
	fs, cfgFlag := flags("serve")
	addRexFlag(fs)
	hostname := fs.String("hostname", "rex-mcp", "Tailscale node `name`")
	funnel := fs.Bool("funnel", true, "serve on the public internet through Tailscale Funnel, so hosted agents such as claude.ai can connect")
	listen := fs.String("listen", "", "serve plain HTTP on `addr` instead of Tailscale, behind your own HTTPS proxy")
	publicURL := fs.String("public-url", "", "the public https `URL` of your proxy (with --listen)")
	fs.Parse(args)

	path, err := configPath(*cfgFlag)
	if err != nil {
		return err
	}
	if _, err := config.Load(path); err != nil {
		return err
	}
	src := &config.Source{Path: path, Fallback: offerAll(&rex.Client{Bin: rexBin})}
	dir, err := stateDir()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		ln       net.Listener
		issuer   string
		identify func(*http.Request) *oauth.Identity
	)
	if *listen != "" {
		if *publicURL == "" {
			return errors.New("--listen needs --public-url, the https address your proxy serves")
		}
		issuer, err = checkPublicURL(*publicURL)
		if err != nil {
			return err
		}
		if ln, err = net.Listen("tcp", *listen); err != nil {
			return err
		}
	} else {
		ts := &tsnet.Server{
			Dir:      filepath.Join(dir, "tsnet"),
			Hostname: *hostname,
			Logf:     func(string, ...any) {},
			UserLogf: log.Printf,
		}
		defer ts.Close()
		log.Printf("starting Tailscale node %q (the first run prints a sign-in link)", *hostname)
		st, err := ts.Up(ctx)
		if err != nil {
			return err
		}
		lc, err := ts.LocalClient()
		if err != nil {
			return err
		}
		identify = tailscaleOwner(lc, st.Self.UserID)
		domains := ts.CertDomains()
		if len(domains) == 0 {
			return errors.New("this tailnet has no HTTPS certificates; turn on MagicDNS and HTTPS in the Tailscale admin console")
		}
		issuer = "https://" + domains[0]
		if *funnel {
			ln, err = ts.ListenFunnel("tcp", ":443")
			if err != nil {
				return fmt.Errorf("%w\nFunnel must be allowed for this node in your tailnet policy (nodeAttrs \"funnel\"), or run with --funnel=false", err)
			}
		} else if ln, err = ts.ListenTLS("tcp", ":443"); err != nil {
			return err
		}
	}

	audit, closeAudit, err := openAudit(filepath.Join(dir, "audit.log"))
	if err != nil {
		return err
	}
	defer closeAudit()
	store, err := oauthStore()
	if err != nil {
		return err
	}
	as := &oauth.Server{Issuer: issuer, MCPPath: mcpPath, Store: store, Candidates: candidates(src.Get), Audit: audit, Identify: identify}

	srv := &http.Server{
		Handler:           accessLog(newHandler(src.Get, as, audit)),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
		IdleTimeout: 2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()

	log.Printf("serving %s", as.Resource())
	if src.Exists() {
		log.Printf("machines, at most: %s (from %s)", describeHosts(src.Get()), path)
	} else {
		log.Printf("no %s: the approval page offers every machine in rex hosts: %s", path, describeHosts(src.Get()))
	}
	if *listen == "" && !*funnel {
		log.Printf("tailnet only: hosted agents such as claude.ai cannot reach this address")
	}
	audit.Printf("start resource=%s hosts=%q", as.Resource(), describeHosts(src.Get()))
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type connKey struct{}

// tailscaleOwner recognizes requests from devices of the user who owns this
// Tailscale node. Requests through Funnel come from the internet and are
// never recognized, nor are tagged devices, which belong to no user.
func tailscaleOwner(lc *local.Client, owner tailcfg.UserID) func(*http.Request) *oauth.Identity {
	return func(r *http.Request) *oauth.Identity {
		c, _ := r.Context().Value(connKey{}).(net.Conn)
		if tc, ok := c.(*tls.Conn); ok {
			c = tc.NetConn()
		}
		if c == nil {
			return nil
		}
		if _, funnel := c.(*ipn.FunnelConn); funnel {
			return nil
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		who, err := lc.WhoIs(ctx, r.RemoteAddr)
		if err != nil || who.Node == nil || who.UserProfile == nil || who.Node.IsTagged() || who.Node.User != owner {
			return nil
		}
		device := who.Node.ComputedName
		if device == "" {
			device = who.Node.Name
		}
		return &oauth.Identity{Login: who.UserProfile.LoginName, Device: device}
	}
}

// candidates offers the configured machines on the approval page.
func candidates(cfg func() *config.Config) func(context.Context) []oauth.Candidate {
	return func(context.Context) []oauth.Candidate {
		c := cfg()
		var out []oauth.Candidate
		for _, name := range c.Names() {
			out = append(out, oauth.Candidate{Name: name, Max: c.Hosts[name].Mode, This: c.IsThisMachine(name)})
		}
		return out
	}
}

func newHandler(cfg func() *config.Config, as *oauth.Server, audit *log.Logger) http.Handler {
	server := newMCPServer(cfg, audit)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	mux := http.NewServeMux()
	as.Routes(mux)
	mux.Handle(mcpPath, auth.RequireBearerToken(as.Verify, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: as.ResourceMetadataURL(),
	})(mcpHandler))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "rex-mcp-bridge: point your agent at %s\n", as.Resource())
	})
	return mux
}

// accessLog prints one line per request to standard error. It leaves out
// query strings, which carry OAuth codes and state.
func accessLog(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s %q", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond), r.UserAgent())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush lets streamed MCP responses through.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func checkPublicURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid --public-url %q", raw)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLocal(u.Hostname())) {
		return "", fmt.Errorf("--public-url must be https (http only on localhost)")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("--public-url must not have a path")
	}
	return u.Scheme + "://" + u.Host, nil
}

func isLocal(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func describeHosts(cfg *config.Config) string {
	var parts []string
	for _, name := range cfg.Names() {
		parts = append(parts, name+"="+string(cfg.Hosts[name].Mode))
	}
	return strings.Join(parts, " ")
}

func openAudit(path string) (*log.Logger, func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return log.New(f, "", log.LstdFlags|log.LUTC), func() { f.Close() }, nil
}
