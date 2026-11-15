package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/http01"
	"imuslab.com/zoraxy/mod/info/logger"
)

var _ challenge.Provider = (*http01Provider)(nil)

type httpChallengeEntry struct {
	domain  string
	keyAuth string
}

// http01Provider multiplexes ACME HTTP-01 challenge tokens over a single
// ref-counted listener so concurrent certificate operations never collide with
// bind: address already in use, and tears down cleanly once all challenges finish.
type http01Provider struct {
	mu         sync.Mutex
	port       string
	logger     *logger.Logger
	listener   net.Listener
	serveDone  chan struct{}
	challenges map[string]httpChallengeEntry
}

func newHTTP01Provider(port string, logger *logger.Logger) *http01Provider {
	return &http01Provider{
		port:       port,
		logger:     logger,
		challenges: make(map[string]httpChallengeEntry),
	}
}

func (p *http01Provider) logf(message string, err error) {
	if p.logger != nil {
		p.logger.PrintAndLog("ACME", message, err)
	}
}

// Port returns the currently configured or actively bound HTTP-01 challenge port.
func (p *http01Provider) Port() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.port
}

// Present registers an HTTP-01 challenge token and starts the shared challenge
// HTTP server if it is not already listening.
func (p *http01Provider) Present(ctx context.Context, domain, token, keyAuth string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	p.mu.Lock()
	if p.challenges == nil {
		p.challenges = make(map[string]httpChallengeEntry)
	}
	p.challenges[token] = httpChallengeEntry{
		domain:  domain,
		keyAuth: keyAuth,
	}

	if p.listener == nil {
		ln, boundPort, err := p.listenWithFallbackLocked(ctx)
		if err != nil {
			delete(p.challenges, token)
			p.mu.Unlock()
			return fmt.Errorf("could not start HTTP server for challenge: %w", err)
		}

		srv := &http.Server{
			Handler:           http.HandlerFunc(p.serveHTTP),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		srv.SetKeepAlivesEnabled(false)

		done := make(chan struct{})
		p.port = boundPort
		p.listener = ln
		p.serveDone = done

		go func() {
			defer close(done)
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				p.logf("HTTP-01 challenge server stopped unexpectedly", err)
			}
		}()
	}

	p.mu.Unlock()
	return nil
}

// CleanUp unregisters the challenge token and closes the listener once no
// active HTTP-01 challenges remain.
func (p *http01Provider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	p.mu.Lock()
	delete(p.challenges, token)

	var done chan struct{}
	if len(p.challenges) == 0 && p.listener != nil {
		ln := p.listener
		done = p.serveDone
		p.listener = nil
		p.serveDone = nil
		_ = ln.Close()
	}
	p.mu.Unlock()

	if done != nil {
		<-done
	}
	return nil
}

// Close forcefully shuts down any active HTTP-01 listener and clears tokens.
func (p *http01Provider) Close() error {
	p.mu.Lock()
	clear(p.challenges)
	ln := p.listener
	done := p.serveDone
	p.listener = nil
	p.serveDone = nil
	if ln != nil {
		_ = ln.Close()
	}
	p.mu.Unlock()

	if done != nil {
		<-done
	}
	return nil
}

func (p *http01Provider) listenWithFallbackLocked(ctx context.Context) (net.Listener, string, error) {
	var lc net.ListenConfig
	configuredPort := strings.TrimSpace(p.port)

	if configuredPort != "" && configuredPort != "0" {
		ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort("", configuredPort))
		if err == nil {
			return ln, extractListenerPort(ln, configuredPort), nil
		}
		if ctx.Err() != nil {
			return nil, "", err
		}

		// If the startup port was claimed externally or is temporarily busy,
		// allocate an ephemeral loopback-reachable port and update p.port so the
		// special ACME routing rule picks it up immediately.
		fallbackLn, fallbackErr := lc.Listen(ctx, "tcp", ":0")
		if fallbackErr != nil {
			return nil, "", err
		}
		boundPort := extractListenerPort(fallbackLn, configuredPort)
		p.logf(fmt.Sprintf("Configured HTTP-01 challenge port %s unavailable (%v); switched to port %s", configuredPort, err, boundPort), nil)
		return fallbackLn, boundPort, nil
	}

	ln, err := lc.Listen(ctx, "tcp", ":0")
	if err != nil {
		return nil, "", err
	}
	return ln, extractListenerPort(ln, configuredPort), nil
}

func extractListenerPort(ln net.Listener, fallback string) string {
	if addr, ok := ln.Addr().(*net.TCPAddr); ok && addr.Port > 0 {
		return strconv.Itoa(addr.Port)
	}
	return fallback
}

func (p *http01Provider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, http01.PathPrefix) {
		http.NotFound(w, r)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, http01.PathPrefix)
	if token == "" {
		http.NotFound(w, r)
		return
	}

	p.mu.Lock()
	entry, ok := p.challenges[token]
	p.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodGet && matchChallengeHost(r.Host, entry.domain) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(entry.keyAuth))
		return
	}

	// Preserve lego ProviderServer behavior: avoid leaking keyAuth when Host or
	// HTTP method does not match the expected authorization domain.
	_, _ = w.Write([]byte("TEST"))
}

func matchChallengeHost(requestHost, domain string) bool {
	h := normalizeChallengeHost(requestHost)
	d := normalizeChallengeHost(domain)
	return h != "" && d != "" && strings.EqualFold(h, d)
}

func normalizeChallengeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = raw[1 : len(raw)-1]
	}
	return strings.TrimSuffix(raw, ".")
}
