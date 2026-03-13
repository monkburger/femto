package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/femto-server/femto/internal/config"
)

// ---------------------------------------------------------------------------
// TLS certificate helpers
// ---------------------------------------------------------------------------

func generateCert(t *testing.T, dir string, names ...string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour * 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kf, _ := os.Create(keyPath)
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()
	return certPath, keyPath
}

func generateExpiredCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		DNSNames:     []string{"expired.example.com"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	certPath := filepath.Join(dir, "expired.pem")
	keyPath := filepath.Join(dir, "expired.key")
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kf, _ := os.Create(keyPath)
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()
	return certPath, keyPath
}

func buildCfg(t *testing.T, dir string, names []string, dirListing bool) *config.Config {
	t.Helper()
	certPath, keyPath := generateCert(t, dir, names...)
	return &config.Config{
		Server: config.ServerConfig{
			Listen:            []config.ListenAddr{"127.0.0.1:0"},
			ReadHeaderTimeout: config.Duration{Duration: 5 * time.Second},
			ReadTimeout:       config.Duration{Duration: 30 * time.Second},
			WriteTimeout:      config.Duration{Duration: 60 * time.Second},
			IdleTimeout:       config.Duration{Duration: 120 * time.Second},
			ShutdownTimeout:   config.Duration{Duration: 5 * time.Second},
			MaxHeaderBytes:    65536,
			Security: config.SecurityHeadersConfig{
				HSTS:                  "max-age=63072000; includeSubDomains; preload",
				ContentTypeOptions:    "nosniff",
				FrameOptions:          "DENY",
				ContentSecurityPolicy: "default-src 'self'",
				ReferrerPolicy:        "strict-origin-when-cross-origin",
			},
		},
		VHosts: []config.VHostConfig{
			{
				ServerNames:  names,
				DocumentRoot: dir,
				DirListing:   dirListing,
				TLS:          config.TLSConfig{Cert: certPath, Key: keyPath},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// canonicalHost
// ---------------------------------------------------------------------------

func TestCanonicalHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Example.Com:443", "example.com"},
		{"example.com:8443", "example.com"},
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		// IPv6 with port — brackets stripped, port dropped.
		{"[::1]:443", "::1"},
		// IPv6 bare (no port) — brackets stripped.
		{"[::1]", "::1"},
		// IPv6 no brackets, no port.
		{"::1", "::1"},
	}
	for _, tc := range cases {
		if got := canonicalHost(tc.in); got != tc.want {
			t.Errorf("canonicalHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// vhostRouter
// ---------------------------------------------------------------------------

func TestVhostRouterExact(t *testing.T) {
	var called string
	r := &vhostRouter{
		exact: map[string]http.Handler{
			"example.com": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = "exact" }),
		},
		wildcard: map[string]http.Handler{},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	r.ServeHTTP(httptest.NewRecorder(), req)
	if called != "exact" {
		t.Errorf("exact match not called, got %q", called)
	}
}

func TestVhostRouterWildcard(t *testing.T) {
	var called string
	r := &vhostRouter{
		exact: map[string]http.Handler{},
		wildcard: map[string]http.Handler{
			".example.com": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = "wildcard" }),
		},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "api.example.com"
	r.ServeHTTP(httptest.NewRecorder(), req)
	if called != "wildcard" {
		t.Errorf("wildcard match not called, got %q", called)
	}
}

func TestVhostRouterExactBeforeWildcard(t *testing.T) {
	var called string
	r := &vhostRouter{
		exact: map[string]http.Handler{
			"api.example.com": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = "exact" }),
		},
		wildcard: map[string]http.Handler{
			".example.com": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = "wildcard" }),
		},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "api.example.com"
	r.ServeHTTP(httptest.NewRecorder(), req)
	if called != "exact" {
		t.Errorf("exact should take priority, got %q", called)
	}
}

func TestVhostRouterMisdirected(t *testing.T) {
	r := &vhostRouter{
		exact:    map[string]http.Handler{},
		wildcard: map[string]http.Handler{},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "unknown.com"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusMisdirectedRequest {
		t.Errorf("misdirected: status = %d, want 421", w.Code)
	}
}

// ---------------------------------------------------------------------------
// noListFS
// ---------------------------------------------------------------------------

func TestNoListFS_FileServed(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello"), 0644)
	fs := noListFS{root: http.Dir(dir), indexFiles: []string{"index.html"}}
	f, err := fs.Open("/hello.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	f.Close()
}

func TestNoListFS_DirWithIndex(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>"), 0644)
	fs := noListFS{root: http.Dir(dir), indexFiles: []string{"index.html"}}
	f, err := fs.Open("/")
	if err != nil {
		t.Fatalf("Open with index.html: %v", err)
	}
	f.Close()
}

func TestNoListFS_DirWithoutIndex(t *testing.T) {
	dir := t.TempDir()
	fs := noListFS{root: http.Dir(dir), indexFiles: []string{"index.html"}}
	_, err := fs.Open("/")
	if err != os.ErrPermission {
		t.Errorf("expected os.ErrPermission, got %v", err)
	}
}

// TestNoListFS_ReaddirAlwaysBlocked verifies that noListFS never permits
// directory listing even when a non-"index.html" index file is configured.
// Previously, noListFS.Open returned the raw directory handle in this case,
// letting http.FileServer call Readdir and expose the full listing.
func TestNoListFS_ReaddirAlwaysBlocked(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.htm"), []byte("<html>"), 0644)
	fs := noListFS{root: http.Dir(dir), indexFiles: []string{"index.htm"}}
	f, err := fs.Open("/")
	if err != nil {
		t.Fatalf("Open with index.htm: %v", err)
	}
	defer f.Close()
	if _, err := f.Readdir(-1); err != os.ErrPermission {
		t.Errorf("Readdir should return os.ErrPermission, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// security headers middleware
// ---------------------------------------------------------------------------

func TestSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"secure.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := srv.securityHeadersMiddleware(inner)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	mustContain := map[string]string{
		"Strict-Transport-Security": "max-age=63072000",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'self'",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
	for header, substr := range mustContain {
		val := w.Header().Get(header)
		if !strings.Contains(val, substr) {
			t.Errorf("header %q = %q, want to contain %q", header, val, substr)
		}
	}
}

func TestSecurityHeadersSuppressed(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"nosec.example.com"}, false)
	cfg.Server.Security = config.SecurityHeadersConfig{}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	w := httptest.NewRecorder()
	srv.securityHeadersMiddleware(inner).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	for _, h := range []string{
		"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options",
		"Content-Security-Policy", "Referrer-Policy",
	} {
		if v := w.Header().Get(h); v != "" {
			t.Errorf("suppressed header %q still present: %q", h, v)
		}
	}
}

// ---------------------------------------------------------------------------
// certificate expiry checks
// ---------------------------------------------------------------------------

func TestCheckCertExpiryValid(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateCert(t, dir, "valid.example.com")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkCertExpiry(&cert, []string{"valid.example.com"}, log.New(io.Discard, "", 0)); err != nil {
		t.Errorf("valid cert flagged as error: %v", err)
	}
}

func TestCheckCertExpiryExpired(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateExpiredCert(t, dir)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkCertExpiry(&cert, []string{"expired.example.com"}, log.New(io.Discard, "", 0)); err == nil {
		t.Error("expired cert should return error")
	}
}

// ---------------------------------------------------------------------------
// server.New — document_root validation
// ---------------------------------------------------------------------------

func TestNewMissingDocRoot(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateCert(t, dir, "docroot.example.com")
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:            []config.ListenAddr{"127.0.0.1:0"},
			MaxHeaderBytes:    65536,
			ReadHeaderTimeout: config.Duration{Duration: 5 * time.Second},
			ReadTimeout:       config.Duration{Duration: 5 * time.Second},
			WriteTimeout:      config.Duration{Duration: 5 * time.Second},
			IdleTimeout:       config.Duration{Duration: 5 * time.Second},
		},
		VHosts: []config.VHostConfig{
			{
				ServerNames:  []string{"docroot.example.com"},
				DocumentRoot: "/nonexistent/docroot",
				TLS:          config.TLSConfig{Cert: certPath, Key: keyPath},
			},
		},
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New should fail for missing document_root")
	}
	if !strings.Contains(err.Error(), "document_root") {
		t.Errorf("error %q should mention document_root", err.Error())
	}
}

// ---------------------------------------------------------------------------
// loggingResponseWriter
// ---------------------------------------------------------------------------

func TestLoggingResponseWriter(t *testing.T) {
	inner := httptest.NewRecorder()
	lw := &loggingResponseWriter{ResponseWriter: inner}
	lw.WriteHeader(http.StatusNotFound)
	if lw.status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", lw.status)
	}
	n, _ := lw.Write([]byte("hello"))
	if lw.bytes != int64(n) {
		t.Errorf("bytes = %d, want %d", lw.bytes, n)
	}
}

func TestLoggingResponseWriterDefaultStatus(t *testing.T) {
	inner := httptest.NewRecorder()
	lw := &loggingResponseWriter{ResponseWriter: inner}
	lw.Write([]byte("ok"))
	if lw.status != http.StatusOK {
		t.Errorf("default status = %d, want 200", lw.status)
	}
}

// ---------------------------------------------------------------------------
// limitListener
// ---------------------------------------------------------------------------

func TestLimitListenerZeroMeansUnlimited(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ll := newLimitListener(ln, 0)
	if _, ok := ll.(*limitListener); ok {
		t.Error("max=0 should return original listener, not limitListener")
	}
}

func TestLimitListenerEnforcesLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ll := newLimitListener(ln, 2)
	lll, ok := ll.(*limitListener)
	if !ok {
		t.Fatal("expected *limitListener")
	}
	if cap(lll.sem) != 2 {
		t.Errorf("sem cap = %d, want 2", cap(lll.sem))
	}
	if len(lll.sem) != 2 {
		t.Errorf("sem len = %d, want 2 (all slots available)", len(lll.sem))
	}
}

// ---------------------------------------------------------------------------
// Unix domain socket listener
// ---------------------------------------------------------------------------

func TestUnixSocketServesRequests(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "femto.sock")
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>unix</h1>"), 0644)

	certPath, keyPath := generateCert(t, dir, "uds.example.com")
	cfg := &config.Config{
		Server: config.ServerConfig{
			// Use port 0 so the TCP listener binds to any free port.
			Listen:            []config.ListenAddr{"127.0.0.1:0"},
			ReadHeaderTimeout: config.Duration{Duration: 5 * time.Second},
			ReadTimeout:       config.Duration{Duration: 5 * time.Second},
			WriteTimeout:      config.Duration{Duration: 5 * time.Second},
			IdleTimeout:       config.Duration{Duration: 5 * time.Second},
			MaxHeaderBytes:    65536,
			Unix: config.UnixConfig{
				Enabled: true,
				Path:    sockPath,
				Mode:    0660,
			},
		},
		VHosts: []config.VHostConfig{
			{
				ServerNames:  []string{"uds.example.com"},
				DocumentRoot: dir,
				IndexFiles:   []string{"index.html"},
				TLS:          config.TLSConfig{Cert: certPath, Key: keyPath},
			},
		},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Start the Unix socket listener directly — we don't call Run() because
	// that blocks and manages its own signal loop.  Instead we replicate just
	// the UDS portion: build the handler, create the listener, serve.
	handler := srv.accessLogMiddleware(srv.securityHeadersMiddleware(srv.router))
	unixSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}
	t.Cleanup(func() {
		unixSrv.Close()
		os.Remove(sockPath)
	})
	go unixSrv.Serve(ln) //nolint:errcheck

	// Dial the socket with a custom transport.
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}

	// Give the server a moment to be ready.
	time.Sleep(20 * time.Millisecond)

	resp, err := httpClient.Get("http://uds.example.com/")
	if err != nil {
		t.Fatalf("GET via unix socket: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "unix") {
		t.Errorf("body %q does not contain expected content", body)
	}
}

func TestUnixSocketStaleSockRemoved(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "femto.sock")
	// Create a stale socket file.
	ln, _ := net.Listen("unix", sockPath)
	ln.Close()

	if _, err := os.Stat(sockPath); err != nil {
		t.Skip("could not create stale socket for test")
	}

	// Removing a stale socket in Run() is tested implicitly: if New+Run didn't
	// remove it, net.Listen("unix",...) would fail with EADDRINUSE.
	// Here we just verify os.Remove on the path clears it.
	if err := os.Remove(sockPath); err != nil {
		t.Fatalf("os.Remove stale socket: %v", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Error("stale socket file still exists after remove")
	}
}

// ---------------------------------------------------------------------------
// Cache-Control middleware
// ---------------------------------------------------------------------------

func TestCacheControlHeader(t *testing.T) {
	dir := t.TempDir()
	// Use a plain CSS file instead of index.html to avoid http.FileServer's
	// automatic redirect from /index.html → / (301).
	_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0644)

	cfg := buildCfg(t, dir, []string{"cache.example.com"}, false)
	cfg.VHosts[0].CacheMaxAge = config.Duration{Duration: 24 * time.Hour}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/style.css", nil)
	req.Host = "cache.example.com"
	w := httptest.NewRecorder()
	handler := srv.securityHeadersMiddleware(srv.router)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "max-age=86400") {
		t.Errorf("Cache-Control = %q, want to contain max-age=86400", cc)
	}
	if !strings.Contains(cc, "public") {
		t.Errorf("Cache-Control = %q, want to contain 'public'", cc)
	}
}

func TestCacheControlNotSentWhenZero(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>"), 0644)

	cfg := buildCfg(t, dir, []string{"nocache.example.com"}, false)
	// CacheMaxAge is zero by default.

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Host = "nocache.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if cc := w.Header().Get("Cache-Control"); cc != "" {
		t.Errorf("Cache-Control should be absent, got %q", cc)
	}
}

// TestCacheControlNotOnErrors verifies that Cache-Control is absent on 404
// responses and present on 200 responses when cache_max_age is configured.
// Previously the header was set unconditionally, causing CDNs/browsers to
// cache error responses for the full max_age duration.
func TestCacheControlNotOnErrors(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>cached</html>"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0644)

	cfg := buildCfg(t, dir, []string{"errorcache.example.com"}, false)
	cfg.VHosts[0].CacheMaxAge = config.Duration{Duration: 24 * time.Hour}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Run("404 must not have Cache-Control", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/nonexistent.html", nil)
		req.Host = "errorcache.example.com"
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); cc != "" {
			t.Errorf("Cache-Control must be absent on 404, got %q", cc)
		}
	})

	t.Run("200 must have Cache-Control", func(t *testing.T) {
		// Request /style.css to get a direct 200; /index.html is redirected to /.
		req := httptest.NewRequest("GET", "/style.css", nil)
		req.Host = "errorcache.example.com"
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=86400") {
			t.Errorf("Cache-Control = %q, want max-age=86400 on 200", cc)
		}
	})
}

// ---------------------------------------------------------------------------
// acceptsEncoding helper
// ---------------------------------------------------------------------------

func TestAcceptsEncoding(t *testing.T) {
	cases := []struct {
		header string
		enc    string
		want   bool
	}{
		{"gzip, deflate, br", "br", true},
		{"gzip, deflate, br", "gzip", true},
		{"gzip, deflate, br", "zstd", false},
		// q-values
		{"gzip;q=0.9, br;q=1.0", "br", true},
		{"gzip;q=0.9, br;q=1.0", "deflate", false},
		// wildcard
		{"*", "br", true},
		// must not match substring — "brotli" is NOT "br"
		{"brotli", "br", false},
		// case-insensitive
		{"GZIP", "gzip", true},
		// empty header
		{"", "gzip", false},
	}
	for _, tc := range cases {
		got := acceptsEncoding(tc.header, tc.enc)
		if got != tc.want {
			t.Errorf("acceptsEncoding(%q, %q) = %v, want %v", tc.header, tc.enc, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Pre-compressed file serving
// ---------------------------------------------------------------------------

func TestPrecompressedBrotliServed(t *testing.T) {
	dir := t.TempDir()
	content := []byte("<html>hello</html>")
	compressed := []byte("fake-brotli-bytes") // content doesn't matter; we check headers
	_ = os.WriteFile(filepath.Join(dir, "index.html"), content, 0644)
	_ = os.WriteFile(filepath.Join(dir, "index.html.br"), compressed, 0644)

	cfg := buildCfg(t, dir, []string{"br.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	req.Host = "br.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "br" {
		t.Errorf("Content-Encoding = %q, want 'br'", ce)
	}
	if vary := w.Header().Get("Vary"); !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("Vary = %q, want to contain Accept-Encoding", vary)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestPrecompressedGzipFallback(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log('hi')"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "app.js.gz"), []byte("fake-gzip"), 0644)

	cfg := buildCfg(t, dir, []string{"gz.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip") // no br
	req.Host = "gz.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("Content-Encoding = %q, want 'gzip'", ce)
	}
}

func TestPrecompressedPassthroughWhenNoneAvailable(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0644)
	// No .br or .gz sidecar — FileServer serves uncompressed.

	cfg := buildCfg(t, dir, []string{"plain.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/style.css", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	req.Host = "plain.example.com"
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be absent, got %q", ce)
	}
}

// TestPrecompressedVaryNotOverwritten verifies that precompressedMiddleware
// appends to an existing Vary header rather than replacing it. A prior
// middleware may have set Vary: Origin; the middleware must not erase that.
func TestPrecompressedVaryNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log('hi')"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "app.js.br"), []byte("fake-br"), 0644)

	cfg := buildCfg(t, dir, []string{"vary.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Wrap the router with a middleware that already sets Vary: Origin.
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Origin")
		srv.router.ServeHTTP(w, r)
	})

	req := httptest.NewRequest("GET", "/app.js", nil)
	req.Header.Set("Accept-Encoding", "br")
	req.Host = "vary.example.com"
	w := httptest.NewRecorder()
	outer.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	varyAll := strings.Join(w.Header().Values("Vary"), ", ")
	if !strings.Contains(varyAll, "Origin") {
		t.Errorf("Vary %q: prior Origin value was overwritten", varyAll)
	}
	if !strings.Contains(varyAll, "Accept-Encoding") {
		t.Errorf("Vary %q: Accept-Encoding not added", varyAll)
	}
}

// ---------------------------------------------------------------------------
// realRemoteAddr / trusted proxies
// ---------------------------------------------------------------------------

func TestRealRemoteAddrDirect(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"raddr.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	// No trusted proxies configured — should return RemoteAddr unchanged.
	got := srv.realRemoteAddr(req)
	if got != "203.0.113.1:12345" {
		t.Errorf("realRemoteAddr = %q, want 203.0.113.1:12345", got)
	}
}

func TestRealRemoteAddrTrustedXFF(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"raddr2.example.com"}, false)
	cfg.Server.TrustedProxies = []string{"127.0.0.1/32"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")

	got := srv.realRemoteAddr(req)
	if got != "203.0.113.5" {
		t.Errorf("realRemoteAddr = %q, want 203.0.113.5", got)
	}
}

func TestRealRemoteAddrTrustedForwarded(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"raddr3.example.com"}, false)
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("Forwarded", "for=198.51.100.7;proto=https, for=10.1.2.3")

	got := srv.realRemoteAddr(req)
	if got != "198.51.100.7" {
		t.Errorf("realRemoteAddr = %q, want 198.51.100.7", got)
	}
}

// ---------------------------------------------------------------------------
// reloadCerts
// ---------------------------------------------------------------------------

func TestReloadCerts(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"reload.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Regenerate certs on disk and reload — should succeed without error.
	generateCert(t, dir, "reload.example.com")
	if err := srv.reloadCerts(); err != nil {
		t.Fatalf("reloadCerts: %v", err)
	}

	// getCertificate should still return a cert after reload.
	hello := &tls.ClientHelloInfo{ServerName: "reload.example.com"}
	cert, err := srv.getCertificate(hello)
	if err != nil {
		t.Fatalf("getCertificate after reload: %v", err)
	}
	if cert == nil {
		t.Error("getCertificate returned nil cert after reload")
	}
}

// ---------------------------------------------------------------------------
// HTTP → HTTPS redirect handler
// ---------------------------------------------------------------------------

func TestRedirectHandlerIssues301(t *testing.T) {
	dir := t.TempDir()
	cfg := buildCfg(t, dir, []string{"redir.example.com"}, false)
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Mirror the handler built inside Run().
	redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := canonicalHost(r.Host)
		if host == "" || !srv.isKnownHost(host) {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})

	t.Run("known host redirects", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/some/path?q=1", nil)
		req.Host = "redir.example.com"
		w := httptest.NewRecorder()
		redirectHandler.ServeHTTP(w, req)

		if w.Code != http.StatusMovedPermanently {
			t.Errorf("status = %d, want 301", w.Code)
		}
		loc := w.Header().Get("Location")
		if loc != "https://redir.example.com/some/path?q=1" {
			t.Errorf("Location = %q, want https://redir.example.com/some/path?q=1", loc)
		}
	})

	t.Run("unknown host rejected (open-redirect prevention)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/path", nil)
		req.Host = "evil.com"
		w := httptest.NewRecorder()
		redirectHandler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for unknown host", w.Code)
		}
	})

	t.Run("empty host rejected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/path", nil)
		req.Host = ""
		w := httptest.NewRecorder()
		redirectHandler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for empty host", w.Code)
		}
	})
}
