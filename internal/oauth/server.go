// Package oauth is a small OAuth 2.1 authorization server for one owner.
//
// Clients identify themselves with a Client ID Metadata Document, or
// register through Dynamic Client Registration (RFC 7591) for older
// clients, and send the owner to an approval page. The owner approves with
// a pairing code made on the host by "rex-mcp-bridge pair", or without one
// when Identify recognizes them, and chooses which machines the client may
// use, and how. Codes need PKCE with S256, and
// refresh tokens rotate.
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/fatwang2/rex-mcp-bridge/internal/config"
)

const (
	pendingTTL  = 10 * time.Minute
	codeTTL     = time.Minute
	maxPending  = 1000
	maxBodySize = 64 << 10

	// Failed pairing codes allowed per request, and across all requests in
	// failureWindow, before approvals are refused.
	maxRequestFailures = 5
	maxFailures        = 10
	failureWindow      = 10 * time.Minute
)

// Paths served by the authorization server.
const (
	pathAuthorize = "/oauth/authorize"
	pathToken     = "/oauth/token"
	pathRegister  = "/oauth/register"
)

// Server is the authorization server and the token verifier for the MCP
// endpoint.
type Server struct {
	// Issuer is the public base URL, such as https://rex-mcp.example.ts.net.
	Issuer string
	// MCPPath is the path of the protected MCP endpoint.
	MCPPath string
	Store   *Store
	// Candidates returns the machines the owner can offer a client, each
	// with the most it may be allowed.
	Candidates func(context.Context) []Candidate
	// Audit receives one line per security-relevant event.
	Audit *log.Logger
	// Identify, if set, recognizes the owner from how a request arrived,
	// such as from one of their own Tailscale devices. The owner then
	// approves without a pairing code. It returns nil for anyone else.
	Identify func(*http.Request) *Identity
	// HTTPClient fetches Client ID Metadata Documents. Nil means a client
	// that reaches only public internet addresses.
	HTTPClient *http.Client

	cimd     cimdCache
	mu       sync.Mutex
	pending  map[string]*pendingAuth
	codes    map[string]*authCode
	failures []time.Time
}

type pendingAuth struct {
	client      *clientInfo
	redirectURI string
	state       string
	challenge   string
	created     time.Time
	failures    int
	// browser is the hash of a cookie set on the browser that opened the
	// page. Only that browser can submit it, so another site cannot make
	// the owner's browser approve a sign-in in the background.
	browser string
}

// Identity is the owner, recognized without a pairing code.
type Identity struct {
	Login  string // such as alice@example.com
	Device string // the device they approve from
}

type authCode struct {
	clientID    string
	clientName  string
	redirectURI string
	challenge   string
	hosts       map[string]config.Mode
	expires     time.Time
}

// Candidate is a machine the owner can offer a client.
type Candidate struct {
	Name string
	Max  config.Mode
	// This is set for the machine the bridge runs on.
	This bool
}

// Resource is the URL of the protected MCP endpoint.
func (s *Server) Resource() string { return s.Issuer + s.MCPPath }

// ResourceMetadataURL is where clients find the protected resource metadata.
func (s *Server) ResourceMetadataURL() string {
	return s.Issuer + "/.well-known/oauth-protected-resource" + s.MCPPath
}

// Routes registers the metadata and OAuth endpoints on mux.
func (s *Server) Routes(mux *http.ServeMux) {
	prm := auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               s.Resource(),
		AuthorizationServers:   []string{s.Issuer},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Rex MCP Bridge",
	})
	mux.Handle("/.well-known/oauth-protected-resource", prm)
	mux.Handle("/.well-known/oauth-protected-resource"+s.MCPPath, prm)
	mux.HandleFunc("/.well-known/oauth-authorization-server", cors(s.handleMetadata))
	mux.HandleFunc(pathRegister, cors(s.handleRegister))
	mux.HandleFunc(pathAuthorize, s.handleAuthorize)
	mux.HandleFunc(pathToken, cors(s.handleToken))
}

// Verify checks an access token for the MCP endpoint.
func (s *Server) Verify(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	g, err := s.Store.Verify(token)
	if errors.Is(err, ErrInvalidGrant) {
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}
	if err != nil {
		return nil, err
	}
	return &auth.TokenInfo{
		Expiration: g.AccessExpiresAt,
		UserID:     g.ID,
		Extra:      map[string]any{ExtraHosts: g.HostModes(), ExtraClient: g.ClientName},
	}, nil
}

// Keys in auth.TokenInfo.Extra.
const (
	ExtraHosts  = "hosts"
	ExtraClient = "client"
)

// GrantedMode returns what a token allows on host: nothing ("") unless the
// owner chose that machine when approving the client.
func GrantedMode(ti *auth.TokenInfo, host string) config.Mode {
	if ti == nil {
		return ""
	}
	hosts, _ := ti.Extra[ExtraHosts].(map[string]config.Mode)
	if m, ok := hosts[host]; ok {
		return m
	}
	return hosts[AnyHost]
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.Issuer,
		"authorization_endpoint":                         s.Issuer + pathAuthorize,
		"token_endpoint":                                 s.Issuer + pathToken,
		"registration_endpoint":                          s.Issuer + pathRegister,
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          authMethods,
		"authorization_response_iss_parameter_supported": true,
		"client_id_metadata_document_supported":          true,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize)).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "body must be JSON")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "give 1 to 10 redirect_uris")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := checkRedirectURI(u); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}
	if req.AuthMethod == "" {
		// RFC 7591 says client_secret_basic, but MCP clients that omit it,
		// like those that set it, expect to be public.
		req.AuthMethod = "none"
	}
	if !slices.Contains(authMethods, req.AuthMethod) {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "token_endpoint_auth_method must be one of "+strings.Join(authMethods, ", "))
		return
	}
	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		name = "Unnamed client"
	}
	name = truncate(name, 100)
	c, secret, err := s.Store.RegisterClient(name, req.RedirectURIs, req.AuthMethod)
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", err.Error())
		return
	}
	s.Audit.Printf("register client=%s name=%q auth=%s redirect=%v", c.ID, c.Name, c.AuthMethod, c.RedirectURIs)
	resp := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        c.CreatedAt.Unix(),
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"token_endpoint_auth_method": c.AuthMethod,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	}
	if secret != "" {
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	writeJSON(w, http.StatusCreated, resp)
}

// authMethods are the supported token_endpoint_auth_method values. MCP
// clients, including claude.ai, are public ("none"); the secret methods are
// for DCR clients that ask for one.
var authMethods = []string{"none", "client_secret_basic", "client_secret_post"}

// authenticateClient identifies the client calling the token endpoint and
// checks its secret, if it was registered with one.
func (s *Server) authenticateClient(r *http.Request) (string, error) {
	id, secret, basic := r.BasicAuth()
	if basic {
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		secret, err2 = url.QueryUnescape(secret)
		if err1 != nil || err2 != nil {
			return "", errors.New("bad basic credentials")
		}
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	c, err := s.resolveClient(r.Context(), id)
	if err != nil {
		return "", err
	}
	if c.SecretHash == "" {
		return c.ID, nil
	}
	if secret == "" || !equal(hashSecret(secret), c.SecretHash) {
		return "", errors.New("wrong client secret")
	}
	return c.ID, nil
}

// checkRedirectURI allows https anywhere, and http only on loopback, for
// agents that receive the code on the user's own machine.
func checkRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" {
		return fmt.Errorf("invalid redirect_uri %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("redirect_uri %q must use https, or http on localhost", raw)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.startAuthorize(w, r)
	case http.MethodPost:
		s.finishAuthorize(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) startAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, err := s.resolveClient(r.Context(), q.Get("client_id"))
	if err != nil {
		s.Audit.Printf("authorize-unknown-client client=%q err=%q", q.Get("client_id"), err)
		s.renderError(w, http.StatusBadRequest, "This sign-in link names a client that could not be verified. Start the sign-in again from your agent.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	if !redirectAllowed(client.RedirectURIs, redirectURI) {
		s.renderError(w, http.StatusBadRequest, "This sign-in link has a redirect address the client did not register.")
		return
	}
	// From here on, errors go back to the client.
	fail := func(code, desc string) {
		redirectError(w, r, redirectURI, q.Get("state"), s.Issuer, code, desc)
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only code is supported")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		fail("invalid_request", "PKCE with S256 is required")
		return
	}
	if res := q.Get("resource"); res != "" && !s.knownResource(res) {
		fail("invalid_target", "unknown resource")
		return
	}

	p := &pendingAuth{
		client:      client,
		redirectURI: redirectURI,
		state:       q.Get("state"),
		challenge:   q.Get("code_challenge"),
		created:     time.Now(),
	}
	id := randomSecret()
	cookie := randomSecret()
	p.browser = hashSecret(cookie)
	s.mu.Lock()
	s.prune()
	if len(s.pending) >= maxPending {
		s.mu.Unlock()
		fail("temporarily_unavailable", "too many sign-ins in progress")
		return
	}
	if s.pending == nil {
		s.pending = map[string]*pendingAuth{}
	}
	s.pending[id] = p
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     browserCookie(id),
		Value:    cookie,
		Path:     pathAuthorize,
		MaxAge:   int(pendingTTL.Seconds()),
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.Issuer, "https://"),
		SameSite: http.SameSiteStrictMode,
	})
	s.renderApprove(w, r, id, p, nil, "")
}

func browserCookie(request string) string { return "rmb_" + request[:16] }

// sameBrowser reports whether r comes from the page the server rendered for
// p: same origin, and carrying the cookie set with it.
func (s *Server) sameBrowser(r *http.Request, id string, p *pendingAuth) bool {
	if o := r.Header.Get("Origin"); o != "" && o != s.Issuer {
		return false
	}
	c, err := r.Cookie(browserCookie(id))
	return err == nil && equal(hashSecret(c.Value), p.browser)
}

// identify returns the owner if Identify recognizes them.
func (s *Server) identify(r *http.Request) *Identity {
	if s.Identify == nil {
		return nil
	}
	return s.Identify(r)
}

func (s *Server) finishAuthorize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		s.renderError(w, http.StatusBadRequest, "Bad form.")
		return
	}
	id := r.PostForm.Get("request")
	s.mu.Lock()
	s.prune()
	p := s.pending[id]
	s.mu.Unlock()
	if p == nil {
		s.renderError(w, http.StatusBadRequest, "This sign-in expired. Start it again from your agent.")
		return
	}
	if !s.sameBrowser(r, id, p) {
		s.Audit.Printf("authorize-wrong-browser client=%s name=%q origin=%q", p.client.ID, p.client.Name, r.Header.Get("Origin"))
		s.renderError(w, http.StatusForbidden, "This sign-in page must be submitted from the browser that opened it. Start the sign-in again from your agent.")
		return
	}

	if r.PostForm.Get("action") != "approve" {
		s.dropPending(id)
		s.Audit.Printf("deny client=%s name=%q", p.client.ID, p.client.Name)
		redirectError(w, r, p.redirectURI, p.state, s.Issuer, "access_denied", "the owner denied access")
		return
	}

	hosts, problem := s.chosenHosts(r)
	if problem != "" {
		s.renderApprove(w, r, id, p, r.PostForm, problem)
		return
	}

	via := "pairing-code"
	if who := s.identify(r); who != nil {
		via = fmt.Sprintf("tailscale login=%s device=%q", who.Login, who.Device)
	} else if !s.checkPairingCode(w, r, id, p) {
		return
	}

	s.dropPending(id)
	http.SetCookie(w, &http.Cookie{Name: browserCookie(id), Path: pathAuthorize, MaxAge: -1})
	code := randomSecret()
	s.mu.Lock()
	if s.codes == nil {
		s.codes = map[string]*authCode{}
	}
	s.codes[hashSecret(code)] = &authCode{
		clientID:    p.client.ID,
		clientName:  p.client.Name,
		redirectURI: p.redirectURI,
		challenge:   p.challenge,
		hosts:       hosts,
		expires:     time.Now().Add(codeTTL),
	}
	s.mu.Unlock()
	s.Audit.Printf("approve client=%s name=%q hosts=%q redirect=%s via=%s", p.client.ID, p.client.Name, FormatHosts(hosts), p.redirectURI, via)

	u, _ := url.Parse(p.redirectURI)
	v := u.Query()
	v.Set("code", code)
	if p.state != "" {
		v.Set("state", p.state)
	}
	v.Set("iss", s.Issuer)
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// checkPairingCode consumes the pairing code in the form. When it is wrong,
// it shows the owner why and returns false.
func (s *Server) checkPairingCode(w http.ResponseWriter, r *http.Request, id string, p *pendingAuth) bool {
	if s.tooManyFailures() {
		s.renderError(w, http.StatusTooManyRequests, "Too many wrong pairing codes. Wait ten minutes, make a new code, and start the sign-in again.")
		return false
	}
	ok, err := s.Store.UsePairingCode(r.PostForm.Get("code"))
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Could not check the pairing code.")
		return false
	}
	if ok {
		return true
	}
	failures := s.recordFailure(p)
	s.Audit.Printf("bad-pairing-code client=%s name=%q", p.client.ID, p.client.Name)
	if failures >= maxRequestFailures {
		s.dropPending(id)
		s.renderError(w, http.StatusForbidden, "Too many wrong pairing codes for this sign-in. Start it again from your agent.")
		return false
	}
	s.renderApprove(w, r, id, p, r.PostForm, "That pairing code is wrong or expired. Make a new one with: rex-mcp-bridge pair")
	return false
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	f := r.PostForm
	clientID, err := s.authenticateClient(r)
	if err != nil {
		s.Audit.Printf("token-client-rejected err=%q", err)
		w.Header().Set("WWW-Authenticate", `Basic realm="rex-mcp-bridge"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	switch f.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, clientID, f)
	case "refresh_token":
		g, t, err := s.Store.Refresh(clientID, f.Get("refresh_token"))
		if err != nil {
			if errors.Is(err, ErrInvalidGrant) {
				s.Audit.Printf("refresh-rejected client=%s err=%q", clientID, err)
				oauthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
				return
			}
			oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		writeTokens(w, g, t)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, clientID string, f url.Values) {
	s.mu.Lock()
	key := hashSecret(f.Get("code"))
	c := s.codes[key]
	delete(s.codes, key) // single use, even when the exchange fails
	s.mu.Unlock()
	if c == nil || time.Now().After(c.expires) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired code")
		return
	}
	if clientID != c.clientID || f.Get("redirect_uri") != c.redirectURI {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "client_id or redirect_uri does not match the code")
		return
	}
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if !equal(base64.RawURLEncoding.EncodeToString(sum[:]), c.challenge) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match")
		return
	}
	if res := f.Get("resource"); res != "" && !s.knownResource(res) {
		oauthError(w, http.StatusBadRequest, "invalid_target", "unknown resource")
		return
	}
	redirect, _ := url.Parse(c.redirectURI)
	g := &Grant{ClientID: c.clientID, ClientName: c.clientName, RedirectHost: redirect.Host, Hosts: c.hosts}
	t, err := s.Store.CreateGrant(g)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	s.Audit.Printf("grant id=%s client=%s name=%q hosts=%q", g.ID, g.ClientID, g.ClientName, FormatHosts(g.Hosts))
	writeTokens(w, g, t)
}

// chosenHosts reads the machines and levels picked on the approval page and
// checks them against the candidates. It returns a problem to show the
// owner if the choice is not allowed.
func (s *Server) chosenHosts(r *http.Request) (map[string]config.Mode, string) {
	max := map[string]config.Mode{}
	for _, c := range s.Candidates(r.Context()) {
		max[c.Name] = c.Max
	}
	hosts := map[string]config.Mode{}
	for _, name := range r.PostForm["host"] {
		m := config.Mode(r.PostForm.Get("mode." + name))
		limit, ok := max[name]
		if !ok || !slices.Contains(config.Modes(limit), m) {
			return nil, fmt.Sprintf("%s can't be given %q access.", name, m)
		}
		hosts[name] = m
	}
	if len(hosts) == 0 {
		return nil, "Choose at least one machine."
	}
	return hosts, ""
}

// FormatHosts writes host modes as "a=run b=read", sorted by host.
func FormatHosts(hosts map[string]config.Mode) string {
	names := make([]string, 0, len(hosts))
	for h := range hosts {
		names = append(names, h)
	}
	slices.Sort(names)
	var b strings.Builder
	for i, h := range names {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%s", h, hosts[h])
	}
	return b.String()
}

// knownResource reports whether res names this server, comparing scheme and
// host without case and ignoring a trailing slash.
func (s *Server) knownResource(res string) bool {
	u, err := url.Parse(res)
	if err != nil {
		return false
	}
	norm := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimSuffix(u.Path, "/")
	return norm == strings.ToLower(s.Issuer)+s.MCPPath || norm == strings.ToLower(s.Issuer)
}

func writeTokens(w http.ResponseWriter, g *Grant, t *Tokens) {
	refreshIn := time.Until(g.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":             t.Access,
		"token_type":               "Bearer",
		"expires_in":               int(AccessTokenTTL.Seconds()),
		"refresh_token":            t.Refresh,
		"refresh_token_expires_in": int(refreshIn.Seconds()),
		"scope":                    "rex",
	})
}

// prune drops expired sign-ins and codes. The caller holds s.mu.
func (s *Server) prune() {
	now := time.Now()
	for id, p := range s.pending {
		if now.Sub(p.created) > pendingTTL {
			delete(s.pending, id)
		}
	}
	for k, c := range s.codes {
		if now.After(c.expires) {
			delete(s.codes, k)
		}
	}
}

func (s *Server) dropPending(id string) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

// recordFailure counts a wrong pairing code and returns how many this
// sign-in has had.
func (s *Server) recordFailure(p *pendingAuth) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.failures++
	s.failures = append(s.failures, time.Now())
	return p.failures
}

func (s *Server) tooManyFailures() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-failureWindow)
	kept := s.failures[:0]
	for _, t := range s.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.failures = kept
	return len(kept) >= maxFailures
}

func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, issuer, code, desc string) {
	u, _ := url.Parse(redirectURI)
	v := u.Query()
	v.Set("error", code)
	v.Set("error_description", desc)
	if state != "" {
		v.Set("state", state)
	}
	v.Set("iss", issuer)
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// cors lets browser-based agents call an endpoint. The endpoints it wraps
// use no cookies, so any origin is safe.
func cors(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
