package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fatwang2/rex-mcp-bridge/internal/config"
	"github.com/fatwang2/rex-mcp-bridge/internal/oauth"
)

const redirect = "https://agent.example/callback"

type testEnv struct {
	t     *testing.T
	ts    *httptest.Server
	as    *oauth.Server
	store *oauth.Store
	http  *http.Client
}

func newTestEnv(t *testing.T) *testEnv {
	cfg := &config.Config{Hosts: map[string]config.Host{
		"local":  {Mode: config.ModeRun},
		"studio": {Mode: config.ModeRead},
	}}
	store := &oauth.Store{Dir: t.TempDir()}
	cfg.LocalName = "local" // keep the name the tests use
	named := cfg.Named()
	get := func() *config.Config { return named }
	as := &oauth.Server{MCPPath: mcpPath, Store: store, Candidates: candidates(get), Audit: log.New(io.Discard, "", 0)}
	ts := httptest.NewServer(nil)
	as.Issuer = ts.URL
	ts.Config.Handler = newHandler(get, as, nil)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	noRedirect := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &testEnv{t: t, ts: ts, as: as, store: store, http: noRedirect}
}

func (e *testEnv) postJSON(path string, body any) (*http.Response, map[string]any) {
	b, _ := json.Marshal(body)
	resp, err := e.http.Post(e.ts.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, decode(e.t, resp)
}

func (e *testEnv) postForm(path string, v url.Values) *http.Response {
	resp, err := e.http.PostForm(e.ts.URL+path, v)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func decode(t *testing.T, resp *http.Response) map[string]any {
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return m
}

func (e *testEnv) register() string {
	resp, m := e.postJSON("/oauth/register", map[string]any{"client_name": "Test Agent", "redirect_uris": []string{redirect}})
	if resp.StatusCode != http.StatusCreated {
		e.t.Fatalf("register: %d %v", resp.StatusCode, m)
	}
	return m["client_id"].(string)
}

var requestField = regexp.MustCompile(`name="request" value="([^"]+)"`)

// startSignIn opens the approval page and returns its request ID.
func (e *testEnv) startSignIn(clientID, verifier string) string {
	return e.startSignInTo(clientID, redirect, verifier)
}

func (e *testEnv) startSignInTo(clientID, redirectURI, verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {"xyz"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"resource":              {e.ts.URL + mcpPath},
	}
	resp, err := e.http.Get(e.ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := requestField.FindSubmatch(body)
	if m == nil {
		e.t.Fatalf("approval page has no request field:\n%s", body)
	}
	if u, _ := url.Parse(redirectURI); !bytes.Contains(body, []byte(u.Host)) {
		e.t.Error("approval page does not name where access goes")
	}
	return string(m[1])
}

// signIn runs the whole flow and returns the token response.
func (e *testEnv) signIn(mode config.Mode) map[string]any {
	clientID := e.register()
	verifier := "a-long-enough-code-verifier-for-pkce-0123456789"
	req := e.startSignIn(clientID, verifier)
	code, err := e.store.NewPairingCode()
	if err != nil {
		e.t.Fatal(err)
	}
	resp := e.postForm("/oauth/authorize", url.Values{"request": {req}, "action": {"approve"}, "host": {"local"}, "mode.local": {string(mode)}, "code": {strings.ToLower(code)}})
	if resp.StatusCode != http.StatusFound {
		e.t.Fatalf("approve: status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("state") != "xyz" || loc.Query().Get("iss") != e.ts.URL {
		e.t.Errorf("redirect %s lacks state or iss", loc)
	}
	resp = e.postForm("/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier},
	})
	tok := decode(e.t, resp)
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}
	tok["client_id"] = clientID
	return tok
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func (e *testEnv) connect(token string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	return client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   e.ts.URL + mcpPath,
		HTTPClient: &http.Client{Transport: bearer{token}},
	}, nil)
}

func TestMCPNeedsToken(t *testing.T) {
	e := newTestEnv(t)
	resp, err := http.Post(e.ts.URL+mcpPath, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
	if h := resp.Header.Get("WWW-Authenticate"); !strings.Contains(h, "/.well-known/oauth-protected-resource/mcp") {
		t.Errorf("WWW-Authenticate = %q", h)
	}
	if _, err := e.connect("0123456789abcdef0123456789abcdef.nope"); err == nil {
		t.Error("connected with a made-up token")
	}
}

func TestMetadata(t *testing.T) {
	e := newTestEnv(t)
	resp, err := http.Get(e.ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, resp)
	if m["issuer"] != e.ts.URL || m["registration_endpoint"] != e.ts.URL+"/oauth/register" {
		t.Errorf("metadata = %v", m)
	}
	resp, err = http.Get(e.ts.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if m := decode(t, resp); m["resource"] != e.ts.URL+mcpPath {
		t.Errorf("resource metadata = %v", m)
	}
}

func TestSignInAndUseMCP(t *testing.T) {
	e := newTestEnv(t)
	tok := e.signIn(config.ModeRead)
	session, err := e.connect(tok["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) == 0 {
		t.Error("no tools")
	}
}

func TestRefreshRotatesAndDetectsReuse(t *testing.T) {
	e := newTestEnv(t)
	tok := e.signIn(config.ModeRead)
	refresh := func(rt string) (*http.Response, map[string]any) {
		resp := e.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {tok["client_id"].(string)}})
		return resp, decode(t, resp)
	}
	first := tok["refresh_token"].(string)
	resp, next := refresh(first)
	if resp.StatusCode != http.StatusOK || next["refresh_token"] == first {
		t.Fatalf("refresh: %d %v", resp.StatusCode, next)
	}
	if _, err := e.store.Verify(tok["access_token"].(string)); err == nil {
		t.Error("old access token still works after refresh")
	}
	// Reusing the rotated-out token revokes the grant.
	if resp, _ := refresh(first); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reused refresh token: status %d", resp.StatusCode)
	}
	if _, err := e.store.Verify(next["access_token"].(string)); err == nil {
		t.Error("grant survived refresh token reuse")
	}
}

func TestWrongPairingCode(t *testing.T) {
	e := newTestEnv(t)
	req := e.startSignIn(e.register(), "verifier-verifier-verifier-verifier-verifier")
	for i := range 5 {
		resp := e.postForm("/oauth/authorize", url.Values{"request": {req}, "action": {"approve"}, "host": {"local"}, "mode.local": {"read"}, "code": {"AAAA-AAAA"}})
		resp.Body.Close()
		want := http.StatusOK // the page again, with an error
		if i == 4 {
			want = http.StatusForbidden
		}
		if resp.StatusCode != want {
			t.Fatalf("attempt %d: status %d, want %d", i+1, resp.StatusCode, want)
		}
	}
}

func TestModeAboveConfigRefused(t *testing.T) {
	e := newTestEnv(t)
	req := e.startSignIn(e.register(), "verifier-verifier-verifier-verifier-verifier")
	code, _ := e.store.NewPairingCode()
	resp := e.postForm("/oauth/authorize", url.Values{"request": {req}, "action": {"approve"}, "host": {"studio"}, "mode.studio": {"run"}, "code": {code}})
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Fatal("approved interactive although no host allows it")
	}
}

func TestRevoke(t *testing.T) {
	e := newTestEnv(t)
	tok := e.signIn(config.ModeRun)
	grants, _ := e.store.Grants()
	if len(grants) != 1 {
		t.Fatalf("%d grants, want 1", len(grants))
	}
	if _, err := e.store.Revoke(grants[0].ID[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := e.connect(tok["access_token"].(string)); err == nil {
		t.Error("revoked token still connects")
	}
}

func TestRegisterRejectsPlainHTTP(t *testing.T) {
	e := newTestEnv(t)
	resp, _ := e.postJSON("/oauth/register", map[string]any{"redirect_uris": []string{"http://evil.example/cb"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	resp, _ = e.postJSON("/oauth/register", map[string]any{"redirect_uris": []string{"http://127.0.0.1:33418/callback"}})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("loopback redirect: status %d, want 201", resp.StatusCode)
	}
}

// approve approves a pending sign-in and returns the authorization code.
func (e *testEnv) approve(req string, mode config.Mode) string {
	code, err := e.store.NewPairingCode()
	if err != nil {
		e.t.Fatal(err)
	}
	resp := e.postForm("/oauth/authorize", url.Values{"request": {req}, "action": {"approve"}, "host": {"local"}, "mode.local": {string(mode)}, "code": {code}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		e.t.Fatalf("approve: status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return loc.Query().Get("code")
}

func TestClientIDMetadataDocument(t *testing.T) {
	e := newTestEnv(t)
	const callback = "https://claude.example/api/mcp/auth_callback"
	var doc *httptest.Server
	doc = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  doc.URL + "/client.json",
			"client_name":                "Claude",
			"redirect_uris":              []string{callback},
			"token_endpoint_auth_method": "none",
		})
	}))
	defer doc.Close()
	e.as.HTTPClient = doc.Client()
	clientID := doc.URL + "/client.json"

	resp, err := http.Get(e.ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	if m := decode(t, resp); m["client_id_metadata_document_supported"] != true {
		t.Fatalf("metadata does not advertise CIMD: %v", m)
	}

	verifier := "cimd-verifier-cimd-verifier-cimd-verifier-0123"
	code := e.approve(e.startSignInTo(clientID, callback, verifier), config.ModeRead)
	resp = e.postForm("/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {callback}, "code_verifier": {verifier}, "resource": {e.ts.URL + mcpPath},
	})
	if tok := decode(t, resp); resp.StatusCode != http.StatusOK || tok["access_token"] == nil {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}

	// A redirect the document does not list is refused before any page.
	resp, err = e.http.Get(e.ts.URL + "/oauth/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://evil.example/cb"},
		"code_challenge": {"x"}, "code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unlisted redirect: status %d, want 400", resp.StatusCode)
	}
}

func TestCIMDRefusesPrivateAddresses(t *testing.T) {
	e := newTestEnv(t)
	doc := httptest.NewTLSServer(http.NotFoundHandler())
	defer doc.Close()
	// No HTTPClient override: the default refuses loopback addresses.
	resp, err := e.http.Get(e.ts.URL + "/oauth/authorize?client_id=" + url.QueryEscape(doc.URL+"/client.json"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestLoopbackRedirectIgnoresPort(t *testing.T) {
	e := newTestEnv(t)
	resp, m := e.postJSON("/oauth/register", map[string]any{"client_name": "Claude Code", "redirect_uris": []string{"http://localhost/callback"}})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d %v", resp.StatusCode, m)
	}
	e.startSignInTo(m["client_id"].(string), "http://localhost:51234/callback", "loopback-verifier-loopback-verifier-0123456")
}

func TestConfidentialClient(t *testing.T) {
	e := newTestEnv(t)
	resp, m := e.postJSON("/oauth/register", map[string]any{
		"client_name": "Server Agent", "redirect_uris": []string{redirect}, "token_endpoint_auth_method": "client_secret_basic",
	})
	if resp.StatusCode != http.StatusCreated || m["client_secret"] == nil {
		t.Fatalf("register: %d %v", resp.StatusCode, m)
	}
	clientID, secret := m["client_id"].(string), m["client_secret"].(string)
	verifier := "secret-verifier-secret-verifier-secret-0123456"
	code := e.approve(e.startSignIn(clientID, verifier), config.ModeRead)

	exchange := func(user, pass string) int {
		req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/oauth/token", strings.NewReader(url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier},
		}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(user, pass)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := exchange(clientID, "wrong"); got != http.StatusUnauthorized {
		t.Errorf("wrong secret: status %d, want 401", got)
	}
	// The failed attempt was refused before the code was looked up, so it
	// still works with the right secret.
	if got := exchange(clientID, secret); got != http.StatusOK {
		t.Errorf("right secret: status %d, want 200", got)
	}
}

func TestClientGetsOnlyApprovedMachines(t *testing.T) {
	e := newTestEnv(t)
	tok := e.signIn(config.ModeRun) // approves local only
	grants, _ := e.store.Grants()
	if got := oauth.FormatHosts(grants[0].HostModes()); got != "local=run" {
		t.Fatalf("grant hosts = %q, want local=run", got)
	}
	session, err := e.connect(tok["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	// studio is in the configuration, but this client was not given it.
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "capture", Arguments: map[string]any{"host": "studio", "block": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "not approved") {
		t.Errorf("capture on an unapproved machine: %+v", res.Content)
	}
}

func TestApprovalNeedsAMachine(t *testing.T) {
	e := newTestEnv(t)
	req := e.startSignIn(e.register(), "verifier-verifier-verifier-verifier-verifier")
	code, _ := e.store.NewPairingCode()
	resp := e.postForm("/oauth/authorize", url.Values{"request": {req}, "action": {"approve"}, "code": {code}})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound || !bytes.Contains(body, []byte("at least one machine")) {
		t.Errorf("approved with no machine chosen: %d", resp.StatusCode)
	}
}

func TestOldGrantAppliesToEveryMachine(t *testing.T) {
	g := &oauth.Grant{Mode: config.ModeRead}
	if got := oauth.FormatHosts(g.HostModes()); got != "*=read" {
		t.Errorf("HostModes = %q", got)
	}
}

func TestApproveWithoutCodeWhenRecognized(t *testing.T) {
	e := newTestEnv(t)
	e.as.Identify = func(*http.Request) *oauth.Identity {
		return &oauth.Identity{Login: "owner@example.com", Device: "laptop"}
	}
	resp, err := e.http.Get(e.ts.URL + "/oauth/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {e.register()}, "redirect_uri": {redirect},
		"code_challenge": {"x"}, "code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if rp := resp.Header.Get("Referrer-Policy"); rp == "no-referrer" {
		t.Error("Referrer-Policy no-referrer makes browsers submit the form with Origin: null")
	}
	if !bytes.Contains(body, []byte("owner@example.com")) || bytes.Contains(body, []byte(`name="code"`)) {
		t.Errorf("page does not show the recognized owner instead of the code field")
	}
	req := string(requestField.FindSubmatch(body)[1])
	resp = e.postForm("/oauth/authorize", url.Values{"request": {req}, "action": {"approve"}, "host": {"local"}, "mode.local": {"read"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("approve without code: status %d, want 302", resp.StatusCode)
	}
}

func TestApprovalBoundToBrowser(t *testing.T) {
	e := newTestEnv(t)
	req := e.startSignIn(e.register(), "verifier-verifier-verifier-verifier-verifier")
	code, _ := e.store.NewPairingCode()
	form := url.Values{"request": {req}, "action": {"approve"}, "host": {"local"}, "mode.local": {"read"}, "code": {code}}

	// Another browser, without the page's cookie.
	resp, err := http.PostForm(e.ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("other browser: status %d, want 403", resp.StatusCode)
	}

	// The same browser, but posted from another site.
	r, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	resp, err = e.http.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site post: status %d, want 403", resp.StatusCode)
	}

	// The page's own browser still works, and the code was not used up.
	if resp := e.postForm("/oauth/authorize", form); resp.StatusCode != http.StatusFound {
		t.Errorf("same browser: status %d, want 302", resp.StatusCode)
	}
}
