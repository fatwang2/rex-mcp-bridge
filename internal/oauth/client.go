package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// clientInfo is what the server knows about a client, however it was
// registered.
type clientInfo struct {
	ID   string
	Name string
	// Domain is the host of a Client ID Metadata Document URL. Unlike the
	// name, which the client chooses, it shows who really runs the client.
	Domain       string
	RedirectURIs []string
	// SecretHash is set for confidential clients registered through DCR.
	SecretHash string
}

// resolveClient finds a client by ID. An https URL is a Client ID Metadata
// Document; anything else must have been registered through DCR.
func (s *Server) resolveClient(ctx context.Context, id string) (*clientInfo, error) {
	if strings.HasPrefix(id, "https://") {
		return s.cimd.get(ctx, s.HTTPClient, id)
	}
	c, err := s.Store.Client(id)
	if err != nil {
		return nil, errors.New("unknown client")
	}
	return &clientInfo{ID: c.ID, Name: c.Name, RedirectURIs: c.RedirectURIs, SecretHash: c.SecretHash}, nil
}

const (
	cimdMaxSize    = 16 << 10
	cimdTimeout    = 5 * time.Second
	cimdDefaultTTL = 10 * time.Minute
	cimdMaxTTL     = 24 * time.Hour
	cimdMaxEntries = 100
)

// cimdCache fetches and caches Client ID Metadata Documents.
type cimdCache struct {
	mu      sync.Mutex
	entries map[string]cimdEntry
}

type cimdEntry struct {
	info    *clientInfo
	expires time.Time
}

func (c *cimdCache) get(ctx context.Context, hc *http.Client, id string) (*clientInfo, error) {
	c.mu.Lock()
	e, ok := c.entries[id]
	c.mu.Unlock()
	if ok && time.Now().Before(e.expires) {
		return e.info, nil
	}
	info, ttl, err := fetchCIMD(ctx, hc, id)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.entries == nil || len(c.entries) >= cimdMaxEntries {
		c.entries = map[string]cimdEntry{}
	}
	c.entries[id] = cimdEntry{info: info, expires: time.Now().Add(ttl)}
	c.mu.Unlock()
	return info, nil
}

func fetchCIMD(ctx context.Context, hc *http.Client, id string) (*clientInfo, time.Duration, error) {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" || u.Path == "/" || u.Fragment != "" || u.User != nil {
		return nil, 0, fmt.Errorf("client_id %q is not a valid metadata document URL", id)
	}
	if hc == nil {
		hc = publicHTTPClient
	}
	ctx, cancel := context.WithTimeout(ctx, cimdTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetching client metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("fetching client metadata: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxSize+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > cimdMaxSize {
		return nil, 0, errors.New("client metadata document is too large")
	}
	var doc struct {
		ClientID     string   `json:"client_id"`
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, fmt.Errorf("client metadata is not valid JSON: %w", err)
	}
	if doc.ClientID != id {
		return nil, 0, errors.New("client metadata client_id does not match its URL")
	}
	if doc.AuthMethod != "" && doc.AuthMethod != "none" {
		return nil, 0, fmt.Errorf("client metadata asks for %s, and only none is supported", doc.AuthMethod)
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, 0, errors.New("client metadata has no redirect_uris")
	}
	for _, r := range doc.RedirectURIs {
		if err := checkRedirectURI(r); err != nil {
			return nil, 0, err
		}
	}
	name := strings.TrimSpace(doc.ClientName)
	if name == "" {
		name = u.Host
	}
	info := &clientInfo{ID: id, Name: truncate(name, 100), Domain: u.Hostname(), RedirectURIs: doc.RedirectURIs}
	return info, cacheTTL(resp.Header.Get("Cache-Control")), nil
}

// cacheTTL reads max-age from a Cache-Control header, within bounds.
func cacheTTL(cc string) time.Duration {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "no-store" || part == "no-cache" {
			return 0
		}
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				return min(time.Duration(n)*time.Second, cimdMaxTTL)
			}
		}
	}
	return cimdDefaultTTL
}

// publicHTTPClient fetches metadata documents from the public internet
// only. Refusing private, loopback, and tailnet addresses keeps a client_id
// URL from probing the host's own network.
var publicHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: cimdTimeout,
			Control: func(_, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				if ip := net.ParseIP(host); ip == nil || !isPublicIP(ip) {
					return fmt.Errorf("refusing to fetch client metadata from %s", host)
				}
				return nil
			},
		}).DialContext,
		TLSHandshakeTimeout:   cimdTimeout,
		ResponseHeaderTimeout: cimdTimeout,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("client metadata must not redirect")
	},
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isPublicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || cgnat.Contains(ip))
}

// redirectAllowed reports whether redirect matches one of registered. A
// loopback redirect matches whatever its port, since native agents such as
// Claude Code listen on a port that changes each time (RFC 8252 §7.3).
func redirectAllowed(registered []string, redirect string) bool {
	got, err := url.Parse(redirect)
	if err != nil {
		return false
	}
	for _, r := range registered {
		if r == redirect {
			return true
		}
		want, err := url.Parse(r)
		if err != nil {
			continue
		}
		if got.Scheme == "http" && want.Scheme == "http" &&
			isLoopback(got.Hostname()) && got.Hostname() == want.Hostname() &&
			got.Path == want.Path && got.RawQuery == want.RawQuery {
			return true
		}
	}
	return false
}
