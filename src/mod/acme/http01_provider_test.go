package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/info/logger"
)

func TestHTTP01Provider_SharedListenerAndFallback(t *testing.T) {
	ctx := context.Background()

	t.Run("shared listener across concurrent tokens", func(t *testing.T) {
		p := newHTTP01Provider("0", nil)
		defer p.Close()

		if err := p.Present(ctx, "alpha.example.com", "tok-a", "key-a"); err != nil {
			t.Fatalf("present alpha: %v", err)
		}
		port := p.Port()
		if port == "" || port == "0" {
			t.Fatalf("expected active ephemeral port, got %q", port)
		}
		if err := p.Present(ctx, "beta.example.com:80", "tok-b", "key-b"); err != nil {
			t.Fatalf("present beta: %v", err)
		}
		if p.Port() != port {
			t.Fatalf("expected reused port %s, got %s", port, p.Port())
		}

		assertChallengeHTTP(t, port, "alpha.example.com", "tok-a", http.StatusOK, "key-a")
		assertChallengeHTTP(t, port, "beta.example.com:80", "tok-b", http.StatusOK, "key-b")
		assertChallengeHTTP(t, port, "other.example.com", "tok-a", http.StatusOK, "TEST")

		_ = p.CleanUp(ctx, "alpha.example.com", "tok-a", "key-a")
		assertChallengeHTTP(t, port, "alpha.example.com", "tok-a", http.StatusNotFound, "")
		assertChallengeHTTP(t, port, "beta.example.com", "tok-b", http.StatusOK, "key-b")

		_ = p.CleanUp(ctx, "beta.example.com:80", "tok-b", "key-b")
		assertPortClosed(t, port)
	})

	t.Run("fallback to ephemeral port when configured port busy", func(t *testing.T) {
		occupied, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatalf("listen occupied socket: %v", err)
		}
		defer occupied.Close()

		busyPort := fmt.Sprintf("%d", occupied.Addr().(*net.TCPAddr).Port)
		p := newHTTP01Provider(busyPort, nil)
		defer p.Close()

		if err := p.Present(ctx, "fallback.example.com", "tok-fb", "key-fb"); err != nil {
			t.Fatalf("present with busy port %s: %v", busyPort, err)
		}
		defer p.CleanUp(ctx, "fallback.example.com", "tok-fb", "key-fb")

		if got := p.Port(); got == "" || got == "0" || got == busyPort {
			t.Fatalf("expected fallback port distinct from %s, got %q", busyPort, got)
		}
		assertChallengeHTTP(t, p.Port(), "fallback.example.com", "tok-fb", http.StatusOK, "key-fb")
	})
}

func TestHTTP01Provider_MatchChallengeHostAndTimeouts(t *testing.T) {
	hostCases := []struct {
		host, domain string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"EXAMPLE.COM:80", "example.com", true},
		{"[::1]:56563", "::1", true},
		{"sub.example.com", "example.com", false},
		{"", "example.com", false},
	}
	for _, tc := range hostCases {
		if got := matchChallengeHost(tc.host, tc.domain); got != tc.want {
			t.Fatalf("matchChallengeHost(%q, %q) = %v, want %v", tc.host, tc.domain, got, tc.want)
		}
	}

	if got := certObtainTimeout(false, 0, 1); got != defaultHTTP01Timeout {
		t.Fatalf("http-01 single timeout = %v, want %v", got, defaultHTTP01Timeout)
	}
	if got := certObtainTimeout(false, 0, 10); got != maxHTTP01Timeout {
		t.Fatalf("http-01 capped timeout = %v, want %v", got, maxHTTP01Timeout)
	}
	if got := certObtainTimeout(true, 60, 1); got != time.Duration(minDNS01PropTimeoutSecs)*time.Second+dns01TimeoutHeadroom {
		t.Fatalf("dns-01 minimum propagation timeout mismatch: %v", got)
	}
	if got := certObtainTimeout(true, 5000, 1); got != maxDNS01Timeout {
		t.Fatalf("dns-01 capped timeout = %v, want %v", got, maxDNS01Timeout)
	}
}

func TestObtainCertContext_TimeoutAndConcurrentHTTP01(t *testing.T) {
	t.Run("cancels permanently pending CA and closes listener", func(t *testing.T) {
		h, cleanup := newIsolatedACMEHandler(t, "0")
		defer cleanup()

		ca := newTestACMEServer(t, true, nil)
		defer ca.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
		defer cancel()

		start := time.Now()
		ok, err := h.ObtainCertContext(ctx, []string{"slow.example.com"}, "slow.example.com", "a@example.com", "Custom", ca.URL+"/dir", true, false, 0, "", false, false)
		if ok || err == nil {
			t.Fatalf("expected timeout failure, got ok=%v err=%v", ok, err)
		}
		if time.Since(start) > 3*time.Second {
			t.Fatalf("cancellation took too long: %v", time.Since(start))
		}
		if got := h.Getport(); got == "" || got == "0" {
			t.Fatalf("expected active listener port before cancellation, got %q", got)
		}
		assertPortClosed(t, h.Getport())
	})

	t.Run("concurrent HTTP-01 authorizations share listener and DB", func(t *testing.T) {
		h, cleanup := newIsolatedACMEHandler(t, "0")
		defer cleanup()

		var arrived atomic.Int32
		bothReady := make(chan struct{})
		var probeMu sync.Mutex
		var probeErr error

		ca := newTestACMEServer(t, false, func(domain, token string) {
			if arrived.Add(1) == 2 {
				close(bothReady)
			}
			select {
			case <-bothReady:
			case <-time.After(3 * time.Second):
				probeMu.Lock()
				probeErr = fmt.Errorf("timed out waiting for concurrent challenges (%s)", domain)
				probeMu.Unlock()
				return
			}
			if err := assertChallengeReachable(h.Getport(), domain, token); err != nil {
				probeMu.Lock()
				probeErr = err
				probeMu.Unlock()
			}
		})
		defer ca.Close()

		domains := []string{"first.example.com", "second.example.com"}
		errs := make([]error, len(domains))
		var wg sync.WaitGroup
		for i, d := range domains {
			wg.Add(1)
			go func(idx int, domain string) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				ok, err := h.ObtainCertContext(ctx, []string{domain}, domain, "a@example.com", "Custom", ca.URL+"/dir", true, false, 0, "", false, false)
				if !ok && err == nil {
					err = errors.New("ObtainCertContext returned ok=false with nil error")
				}
				errs[idx] = err
			}(i, d)
		}
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("concurrent ObtainCertContext(%s): %v", domains[i], err)
			}
			for _, ext := range []string{".pem", ".key", ".json"} {
				if _, err := os.Stat(filepath.Join("conf", "certs", domains[i]+ext)); err != nil {
					t.Fatalf("missing %s%s: %v", domains[i], ext, err)
				}
			}
		}
		probeMu.Lock()
		defer probeMu.Unlock()
		if probeErr != nil {
			t.Fatalf("concurrent challenge probe failed: %v", probeErr)
		}
		assertPortClosed(t, h.Getport())
	})
}

func TestAutoRenewer_OverlapAndLifecycle(t *testing.T) {
	h, cleanup := newIsolatedACMEHandler(t, "0")
	defer cleanup()

	cfgPath := filepath.Join(t.TempDir(), "autorenew.json")
	renewer, err := NewAutoRenewer(cfgPath, filepath.Join("conf", "certs"), 3600, 30, h, newTestLogger(t))
	if err != nil {
		t.Fatalf("NewAutoRenewer: %v", err)
	}
	defer renewer.Close()
	renewer.RenewerConfig.Enabled = true
	renewer.RenewerConfig.Email = "a@example.com"

	renewer.renewMu.Lock()
	var overlapErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, overlapErr = renewer.CheckAndRenewCertificates()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		renewer.renewMu.Unlock()
		t.Fatal("overlapping CheckAndRenewCertificates blocked")
	}
	renewer.renewMu.Unlock()

	if !errors.Is(overlapErr, ErrAutoRenewInProgress) {
		t.Fatalf("expected ErrAutoRenewInProgress, got %v", overlapErr)
	}
	if renewed, err := renewer.CheckAndRenewCertificates(); err != nil || len(renewed) != 0 {
		t.Fatalf("unexpected empty-folder renewal result: renewed=%v err=%v", renewed, err)
	}

	// Safe before StartAutoRenewTicker and across repeated Close calls.
	renewer.RenewerConfig.Enabled = false
	renewer.Close()
	renewer.RunStartupCheck()
	renewer.StartAutoRenewTicker()
	renewer.StartAutoRenewTicker()
	renewer.Close()
	renewer.Close()
}

func newTestLogger(t *testing.T) *logger.Logger {
	t.Helper()
	l, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatalf("create test logger: %v", err)
	}
	return l
}

func newIsolatedACMEHandler(t *testing.T, port string) (*ACMEHandler, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	if err := os.MkdirAll(filepath.Join("conf", "certs"), 0o755); err != nil {
		t.Fatalf("create conf/certs dir: %v", err)
	}
	db, err := database.NewDatabase(filepath.Join(tmpDir, "acme.db"), dbinc.BackendBoltDB)
	if err != nil {
		t.Fatalf("create test database: %v", err)
	}
	h := NewACME(port, db, newTestLogger(t), true, 0o600, 0o644)
	return h, func() {
		_ = h.Close()
		db.Close()
	}
}

func assertChallengeHTTP(t *testing.T, port, host, token string, wantStatus int, wantBody string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%s/.well-known/acme-challenge/%s", port, token), nil)
	req.Host = host
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET token %s: %v", token, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus || (wantBody != "" && string(body) != wantBody) {
		t.Fatalf("GET %s = %d %q, want %d %q", token, resp.StatusCode, string(body), wantStatus, wantBody)
	}
}

func assertChallengeReachable(port, domain, token string) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%s/.well-known/acme-challenge/%s", port, token), nil)
	if err != nil {
		return err
	}
	req.Host = domain
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected challenge status %d", resp.StatusCode)
	}
	return nil
}

func assertPortClosed(t *testing.T, port string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 100*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("expected HTTP-01 listener on port %s to close", port)
}

func newTestACMEServer(t *testing.T, stall bool, onChallenge func(domain, token string)) *httptest.Server {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test ACME CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	type orderState struct {
		order legoacme.Order
		chain []byte
	}
	type authzState struct {
		domain, token string
		authz         legoacme.Authorization
	}

	var (
		seq    atomic.Int64
		mu     sync.Mutex
		orders = map[string]*orderState{}
		authzs = map[string]*authzState{}
		srv    *httptest.Server
	)

	decodeJWS := func(r *http.Request, dst any) bool {
		var env struct{ Payload string }
		if json.NewDecoder(r.Body).Decode(&env) != nil {
			return false
		}
		raw, err := base64.RawURLEncoding.DecodeString(env.Payload)
		return err == nil && json.Unmarshal(raw, dst) == nil
	}
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", seq.Add(1)))
		switch p := r.URL.Path; {
		case p == "/dir":
			writeJSON(w, http.StatusOK, legoacme.Directory{
				NewNonceURL: srv.URL + "/newNonce", NewAccountURL: srv.URL + "/newAccount",
				NewOrderURL: srv.URL + "/newOrder", RevokeCertURL: srv.URL + "/revokeCert", KeyChangeURL: srv.URL + "/keyChange",
			})
		case p == "/newNonce":
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusOK)
		case p == "/newAccount":
			w.Header().Set("Location", srv.URL+"/acct/1")
			writeJSON(w, http.StatusCreated, legoacme.Account{Status: legoacme.StatusValid})
		case p == "/newOrder":
			var req legoacme.Order
			if !decodeJWS(r, &req) {
				http.Error(w, "bad order", http.StatusBadRequest)
				return
			}
			oid := fmt.Sprintf("o%d", seq.Add(1))
			var urls []string
			mu.Lock()
			for _, id := range req.Identifiers {
				aid := fmt.Sprintf("a%d", seq.Add(1))
				tok := fmt.Sprintf("t%d", seq.Add(1))
				urls = append(urls, srv.URL+"/authz/"+aid)
				authzs[aid] = &authzState{
					domain: id.Value, token: tok,
					authz: legoacme.Authorization{
						Status: legoacme.StatusPending, Expires: time.Now().Add(time.Hour).UTC(), Identifier: id,
						Challenges: []legoacme.Challenge{{Type: "http-01", URL: srv.URL + "/chall/" + aid, Status: legoacme.StatusPending, Token: tok}},
					},
				}
			}
			ord := legoacme.Order{Status: legoacme.StatusPending, Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Identifiers: req.Identifiers, Authorizations: urls, Finalize: srv.URL + "/finalize/" + oid}
			orders[oid] = &orderState{order: ord}
			mu.Unlock()
			w.Header().Set("Location", srv.URL+"/order/"+oid)
			writeJSON(w, http.StatusCreated, ord)
		case strings.HasPrefix(p, "/order/"):
			mu.Lock()
			st := orders[strings.TrimPrefix(p, "/order/")]
			var ord legoacme.Order
			if st != nil {
				ord = st.order
			}
			mu.Unlock()
			if st == nil {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, http.StatusOK, ord)
		case strings.HasPrefix(p, "/authz/"):
			mu.Lock()
			st := authzs[strings.TrimPrefix(p, "/authz/")]
			var a legoacme.Authorization
			if st != nil {
				a = st.authz
			}
			mu.Unlock()
			if st == nil {
				http.NotFound(w, r)
				return
			}
			if stall {
				w.Header().Set("Retry-After", "1")
			}
			writeJSON(w, http.StatusOK, a)
		case strings.HasPrefix(p, "/chall/"):
			aid := strings.TrimPrefix(p, "/chall/")
			mu.Lock()
			st := authzs[aid]
			mu.Unlock()
			if st == nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s/authz/%s>;rel="up"`, srv.URL, aid))
			if stall {
				w.Header().Set("Retry-After", "1")
				mu.Lock()
				c := st.authz.Challenges[0]
				mu.Unlock()
				writeJSON(w, http.StatusOK, c)
				return
			}
			if onChallenge != nil {
				onChallenge(st.domain, st.token)
			}
			mu.Lock()
			st.authz.Status = legoacme.StatusValid
			st.authz.Challenges[0].Status = legoacme.StatusValid
			st.authz.Challenges[0].Validated = time.Now().UTC()
			c := st.authz.Challenges[0]
			mu.Unlock()
			writeJSON(w, http.StatusOK, c)
		case strings.HasPrefix(p, "/finalize/"):
			oid := strings.TrimPrefix(p, "/finalize/")
			var csrReq struct{ CSR string }
			if !decodeJWS(r, &csrReq) {
				http.Error(w, "bad finalize", http.StatusBadRequest)
				return
			}
			der, _ := base64.RawURLEncoding.DecodeString(csrReq.CSR)
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
				SerialNumber: big.NewInt(seq.Add(1) + 10), Subject: csr.Subject, DNSNames: csr.DNSNames,
				NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}, caCert, csr.PublicKey, caKey)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			mu.Lock()
			st := orders[oid]
			st.chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), caPEM...)
			st.order.Status = legoacme.StatusValid
			st.order.Certificate = srv.URL + "/cert/" + oid
			ord := st.order
			mu.Unlock()
			w.Header().Set("Location", srv.URL+"/order/"+oid)
			writeJSON(w, http.StatusOK, ord)
		case strings.HasPrefix(p, "/cert/"):
			mu.Lock()
			st := orders[strings.TrimPrefix(p, "/cert/")]
			var chain []byte
			if st != nil {
				chain = st.chain
			}
			mu.Unlock()
			if st == nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write(chain)
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}
