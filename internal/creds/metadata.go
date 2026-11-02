package creds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ezgamehost/ezgh-fleets-agent/internal/config"
)

const (
	defaultMetadataEndpoint = "http://169.254.169.254"
	// An IPv6-only guest has no route to the IPv4 address.
	defaultMetadataFallback = "http://[fd65:7a67:6800::254]"
	defaultProductNamePath  = "/sys/class/dmi/id/product_name"
	instanceProductName     = "EZGH Compute"
	instanceRefreshMargin   = 5 * time.Minute
	metadataTokenTTL        = 6 * time.Hour
	metadataRetryAfter      = 5 * time.Second
)

// NoBotRetry is how long the agent waits before asking again when the instance has no Bot, so
// attaching one later is enough.
const NoBotRetry = 3 * time.Minute

// ErrNoProjectID means the instance document names the project only by its prj_ ID, from a host
// that doesn't send projectId yet: fleets-api's paths need the UUID.
var ErrNoProjectID = errors.New("fleets-api needs the project's UUID, and the instance metadata gives only its prj_ ID (no projectId yet): set project in the config, or wait for the host to send projectId")

// ErrNoBot means the instance has no Bot attached.
var ErrNoBot = errors.New("this instance has no Bot attached")

// Metadata fetches the temporary `ezgh_` key of the Bot attached to this compute instance,
// from the metadata service. The key is used until 5 minutes before it expires. Ported from
// ezgh-cli's instance provider.
type Metadata struct {
	Endpoint        string // default http://169.254.169.254
	Fallback        string // tried when Endpoint is unreachable; default http://[fd65:7a67:6800::254]
	ProductNamePath string // default /sys/class/dmi/id/product_name
	HTTP            *http.Client
	Now             func() time.Time

	mu        sync.Mutex
	token     string
	tokenExp  time.Time
	key, bot  string
	expiresAt time.Time
	nextTry   time.Time
	lastErr   error
	retry     time.Duration // the metadata service's Retry-After (503, 429) on the last answer
	project   string
}

// Available reports whether this machine is an EZGH compute instance. No network is touched.
func (p *Metadata) Available() bool {
	path := p.ProductNamePath
	if path == "" {
		path = defaultProductNamePath
	}
	b, err := os.ReadFile(path)
	return err == nil && strings.TrimSpace(string(b)) == instanceProductName
}

func (p *Metadata) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Key returns the current key.
func (p *Metadata) Key(ctx context.Context) (string, error) {
	key, _, err := p.Credentials(ctx)
	return key, err
}

// Credentials returns the current key and the Bot it acts as.
func (p *Metadata) Credentials(ctx context.Context) (key, bot string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.key != "" && now.Add(instanceRefreshMargin).Before(p.expiresAt) {
		return p.key, p.bot, nil
	}
	if !now.Before(p.nextTry) {
		if err = p.fetch(ctx); err == nil {
			return p.key, p.bot, nil
		}
		p.lastErr = err
		p.nextTry = now.Add(max(metadataRetryAfter, p.retry))
		if errors.Is(err, ErrNoBot) {
			p.key = ""
			p.nextTry = now.Add(NoBotRetry)
		}
	}
	// A failed fetch keeps the old key until it actually expires.
	if p.key != "" && now.Before(p.expiresAt) {
		return p.key, p.bot, nil
	}
	if err == nil {
		// Backing off: report the failure that started it, without asking again.
		if err = p.lastErr; err == nil {
			err = errors.New("instance credentials expired and the metadata service is not answering")
		}
	}
	return "", "", err
}

// Project is the instance's project UUID from GET /ezgh/v1/instance: projectId, else project
// when that's a UUID (older definitions), else ErrNoProjectID. Kept once read: it can't change.
func (p *Metadata) Project(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.project != "" {
		return p.project, nil
	}
	status, body, err := p.do(ctx, http.MethodGet, "/ezgh/v1/instance", nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("instance metadata answered %d", status)
	}
	var doc struct {
		Project   string `json:"project"`
		ProjectID string `json:"projectId"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Project == "" && doc.ProjectID == "" || doc.ProjectID != "" && !config.IsUUID(doc.ProjectID) {
		return "", errors.New("instance metadata sent an unreadable answer")
	}
	switch {
	case doc.ProjectID != "":
		p.project = doc.ProjectID
	case config.IsUUID(doc.Project):
		p.project = doc.Project
	default:
		return "", fmt.Errorf("%w (project %s)", ErrNoProjectID, doc.Project)
	}
	return p.project, nil
}

// Invalidate drops the cached key if it is the one an API refused, so the next Key refetches.
func (p *Metadata) Invalidate(refused string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == refused {
		p.key, p.expiresAt, p.nextTry = "", time.Time{}, time.Time{}
	}
}

func (p *Metadata) fetch(ctx context.Context) error {
	for attempt := 0; ; attempt++ {
		if p.token == "" || !p.now().Before(p.tokenExp) {
			if err := p.newToken(ctx); err != nil {
				return err
			}
		}
		status, body, err := p.do(ctx, http.MethodGet, "/ezgh/v1/credentials", nil)
		if err != nil {
			return err
		}
		switch {
		case status == http.StatusOK:
			var c struct {
				APIKey    string    `json:"apiKey"`
				ExpiresAt time.Time `json:"expiresAt"`
				Bot       string    `json:"bot"`
			}
			if err := json.Unmarshal(body, &c); err != nil || c.APIKey == "" || c.ExpiresAt.IsZero() {
				return errors.New("instance metadata sent an unreadable answer")
			}
			p.key, p.bot, p.expiresAt = c.APIKey, c.Bot, c.ExpiresAt
			return nil
		case status == http.StatusUnauthorized && attempt == 0:
			p.token = "" // the token is gone (after a migration or a host restart): get a new one
		case status == http.StatusNotFound && errorCode(body) == "no_bot":
			return ErrNoBot
		default:
			return fmt.Errorf("instance metadata answered %d", status)
		}
	}
}

func (p *Metadata) newToken(ctx context.Context) error {
	status, body, err := p.do(ctx, http.MethodPut, "/ezgh/v1/token", http.Header{"Ezgh-Metadata-Token-Ttl-Seconds": {strconv.Itoa(int(metadataTokenTTL.Seconds()))}})
	if err != nil {
		return err
	}
	if status != http.StatusOK || len(body) == 0 {
		return fmt.Errorf("instance metadata answered %d to the token request", status)
	}
	p.token = strings.TrimSpace(string(body))
	p.tokenExp = p.now().Add(metadataTokenTTL - instanceRefreshMargin)
	return nil
}

// metadataClient is shared, so connections are reused. No proxy: the service is link-local.
var metadataClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
	DialContext:     (&net.Dialer{Timeout: time.Second}).DialContext,
	MaxIdleConns:    2,
	IdleConnTimeout: time.Minute,
}}

// endpoints is the address to ask and the one to try if it's unreachable. The config fills in the
// IPv4 default, so that value gets the fallback too; a metadataUrl of your own doesn't.
func (p *Metadata) endpoints() (string, string) {
	if p.Endpoint == "" || p.Endpoint == defaultMetadataEndpoint {
		return defaultMetadataEndpoint, defaultMetadataFallback
	}
	return p.Endpoint, p.Fallback
}

func (p *Metadata) do(ctx context.Context, method, path string, h http.Header) (int, []byte, error) {
	endpoint, fallback := p.endpoints()
	status, body, err := p.call(ctx, endpoint, method, path, h)
	if err != nil && fallback != "" {
		return p.call(ctx, fallback, method, path, h)
	}
	return status, body, err
}

func (p *Metadata) call(ctx context.Context, endpoint, method, path string, h http.Header) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range h {
		req.Header[k] = v
	}
	req.Header.Set("EZGH-Metadata", "true")
	if p.token != "" && method == http.MethodGet {
		req.Header.Set("EZGH-Metadata-Token", p.token)
	}
	c := p.HTTP
	if c == nil {
		c = metadataClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("instance metadata unreachable: %w", err)
	}
	defer resp.Body.Close()
	p.retry = 0
	if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 {
		p.retry = time.Duration(n) * time.Second
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, b, nil
}
