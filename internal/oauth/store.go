package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/fatwang2/rex-mcp-bridge/internal/config"
)

// Lifetimes of what the store hands out.
const (
	PairingCodeTTL = 10 * time.Minute
	GrantTTL       = 30 * 24 * time.Hour
	AccessTokenTTL = time.Hour
)

// maxClients bounds the registrations kept on disk, since anyone who can
// reach the server can register a client.
const maxClients = 500

// unusedClientTTL is how long a registration with no grant is kept.
const unusedClientTTL = 7 * 24 * time.Hour

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Store keeps registered clients, grants, and pairing codes as files, so the
// CLI can create pairing codes and revoke grants while the server runs.
type Store struct {
	Dir string
}

// Client is a registered OAuth client.
type Client struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	AuthMethod   string    `json:"auth_method"`
	SecretHash   string    `json:"secret_hash,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// Grant is an approved client and the tokens issued to it.
type Grant struct {
	ID           string `json:"id"`
	ClientID     string `json:"client_id"`
	ClientName   string `json:"client_name"`
	RedirectHost string `json:"redirect_host"`
	// Hosts maps each machine the owner chose to what the client may do
	// there.
	Hosts map[string]config.Mode `json:"hosts,omitempty"`
	// Mode is from grants made before machines were chosen one by one; it
	// applied to every machine.
	Mode      config.Mode `json:"mode,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`

	AccessHash      string    `json:"access_hash"`
	AccessExpiresAt time.Time `json:"access_expires_at"`
	RefreshHash     string    `json:"refresh_hash"`
	// PrevRefreshHash is the refresh token rotated out last. Presenting it
	// again means the token was copied, so the grant is revoked.
	PrevRefreshHash string `json:"prev_refresh_hash,omitempty"`
}

// AnyHost stands for every machine in HostModes of an old grant.
const AnyHost = "*"

// HostModes returns what the grant allows on each machine.
func (g *Grant) HostModes() map[string]config.Mode {
	if g.Hosts != nil {
		return g.Hosts
	}
	return map[string]config.Mode{AnyHost: g.Mode}
}

// Tokens is a newly issued token pair.
type Tokens struct {
	Access, Refresh string
}

func (s *Store) path(kind, name string) string { return filepath.Join(s.Dir, kind, name+".json") }

// lock serializes changes between the server and CLI commands.
func (s *Store) lock() (unlock func(), err error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

func (s *Store) write(kind, name string, v any) error {
	dir := filepath.Join(s.Dir, kind)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path(kind, name))
}

func (s *Store) read(kind, name string, v any) error {
	data, err := os.ReadFile(s.path(kind, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (s *Store) list(kind string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.Dir, kind))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".json"); ok && !strings.HasPrefix(name, ".") {
			names = append(names, name)
		}
	}
	return names, nil
}

// RegisterClient stores a new client. Unless authMethod is "none", it also
// returns the client's secret, which is not stored.
func (s *Store) RegisterClient(name string, redirectURIs []string, authMethod string) (*Client, string, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, "", err
	}
	defer unlock()
	if err := s.pruneClients(); err != nil {
		return nil, "", err
	}
	c := &Client{ID: randomHex(), Name: name, RedirectURIs: redirectURIs, AuthMethod: authMethod, CreatedAt: time.Now().UTC()}
	var secret string
	if authMethod != "none" {
		secret = randomSecret()
		c.SecretHash = hashSecret(secret)
	}
	return c, secret, s.write("clients", c.ID, c)
}

// pruneClients drops old registrations that never got a grant, and refuses
// new ones when too many remain. The caller holds the lock.
func (s *Store) pruneClients() error {
	ids, err := s.list("clients")
	if err != nil {
		return err
	}
	if len(ids) < maxClients/2 {
		return nil
	}
	granted := map[string]bool{}
	grants, err := s.grants()
	if err != nil {
		return err
	}
	for _, g := range grants {
		granted[g.ClientID] = true
	}
	kept := 0
	for _, id := range ids {
		var c Client
		if err := s.read("clients", id, &c); err == nil && !granted[id] && time.Since(c.CreatedAt) > unusedClientTTL {
			os.Remove(s.path("clients", id))
			continue
		}
		kept++
	}
	if kept >= maxClients {
		return errors.New("too many registered clients")
	}
	return nil
}

// Client returns a registered client.
func (s *Store) Client(id string) (*Client, error) {
	if !idPattern.MatchString(id) {
		return nil, fs.ErrNotExist
	}
	var c Client
	if err := s.read("clients", id, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// NewPairingCode creates a single-use code that approves one sign-in.
func (s *Store) NewPairingCode() (string, error) {
	b := make([]byte, 5)
	rand.Read(b)
	code := base32.StdEncoding.EncodeToString(b) // 8 characters, 40 bits
	unlock, err := s.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	expires := time.Now().Add(PairingCodeTTL).UTC()
	if err := s.write("pairing", hashSecret(normalizeCode(code)), map[string]time.Time{"expires_at": expires}); err != nil {
		return "", err
	}
	return code[:4] + "-" + code[4:], nil
}

// UsePairingCode consumes code and reports whether it was valid.
func (s *Store) UsePairingCode(code string) (bool, error) {
	code = normalizeCode(code)
	if code == "" {
		return false, nil
	}
	unlock, err := s.lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	name := hashSecret(code)
	var p struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := s.read("pairing", name, &p); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := os.Remove(s.path("pairing", name)); err != nil {
		return false, err
	}
	return time.Now().Before(p.ExpiresAt), nil
}

func normalizeCode(code string) string {
	code = strings.ToUpper(code)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, code)
}

// CreateGrant stores a new grant and issues its first tokens.
func (s *Store) CreateGrant(g *Grant) (*Tokens, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	g.ID = randomHex()
	now := time.Now().UTC()
	g.CreatedAt = now
	g.ExpiresAt = now.Add(GrantTTL)
	t := g.issue(now)
	return t, s.write("grants", g.ID, g)
}

func (g *Grant) issue(now time.Time) *Tokens {
	t := &Tokens{Access: g.ID + "." + randomSecret(), Refresh: g.ID + "." + randomSecret()}
	g.AccessHash = hashSecret(t.Access)
	g.AccessExpiresAt = now.Add(AccessTokenTTL)
	g.RefreshHash = hashSecret(t.Refresh)
	return t
}

// ErrInvalidGrant means a token is unknown, expired, or revoked.
var ErrInvalidGrant = errors.New("invalid grant")

// Refresh rotates the tokens of the grant that refresh belongs to.
func (s *Store) Refresh(clientID, refresh string) (*Grant, *Tokens, error) {
	id, ok := grantID(refresh)
	if !ok {
		return nil, nil, ErrInvalidGrant
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, nil, err
	}
	defer unlock()
	var g Grant
	if err := s.read("grants", id, &g); errors.Is(err, fs.ErrNotExist) {
		return nil, nil, ErrInvalidGrant
	} else if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	h := hashSecret(refresh)
	switch {
	case g.ClientID != clientID || now.After(g.ExpiresAt):
		return nil, nil, ErrInvalidGrant
	case g.PrevRefreshHash != "" && equal(h, g.PrevRefreshHash):
		os.Remove(s.path("grants", id))
		return nil, nil, fmt.Errorf("%w: refresh token reused, grant revoked", ErrInvalidGrant)
	case !equal(h, g.RefreshHash):
		return nil, nil, ErrInvalidGrant
	}
	g.PrevRefreshHash = g.RefreshHash
	t := g.issue(now.UTC())
	return &g, t, s.write("grants", id, &g)
}

// Verify returns the grant an access token belongs to.
func (s *Store) Verify(access string) (*Grant, error) {
	id, ok := grantID(access)
	if !ok {
		return nil, ErrInvalidGrant
	}
	var g Grant
	if err := s.read("grants", id, &g); errors.Is(err, fs.ErrNotExist) {
		return nil, ErrInvalidGrant
	} else if err != nil {
		return nil, err
	}
	now := time.Now()
	if !equal(hashSecret(access), g.AccessHash) || now.After(g.AccessExpiresAt) || now.After(g.ExpiresAt) {
		return nil, ErrInvalidGrant
	}
	return &g, nil
}

// Grants returns every grant, oldest first.
func (s *Store) Grants() ([]*Grant, error) {
	return s.grants()
}

func (s *Store) grants() ([]*Grant, error) {
	ids, err := s.list("grants")
	if err != nil {
		return nil, err
	}
	var gs []*Grant
	for _, id := range ids {
		var g Grant
		if err := s.read("grants", id, &g); err == nil {
			gs = append(gs, &g)
		}
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].CreatedAt.Before(gs[j].CreatedAt) })
	return gs, nil
}

// Revoke deletes a grant. A unique prefix of its ID is enough.
func (s *Store) Revoke(prefix string) (*Grant, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	gs, err := s.grants()
	if err != nil {
		return nil, err
	}
	var match *Grant
	for _, g := range gs {
		if prefix != "" && strings.HasPrefix(g.ID, prefix) {
			if match != nil {
				return nil, fmt.Errorf("%q matches more than one grant", prefix)
			}
			match = g
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no grant matches %q", prefix)
	}
	return match, os.Remove(s.path("grants", match.ID))
}

// RevokeAll deletes every grant and reports how many there were.
func (s *Store) RevokeAll() (int, error) {
	unlock, err := s.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	ids, err := s.list("grants")
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err := os.Remove(s.path("grants", id)); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

func grantID(token string) (string, bool) {
	id, _, ok := strings.Cut(token, ".")
	return id, ok && idPattern.MatchString(id)
}

func randomHex() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randomSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
