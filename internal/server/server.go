package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/femto-server/femto/internal/config"
)

// noListFS wraps http.Dir and blocks directory listing.
// When a directory is requested, it tries each name in indexFiles in order.
// If none exist it returns os.ErrPermission (→ 403).
type noListFS struct {
	root       http.Dir
	indexFiles []string
}

// noListDir wraps an http.File for a directory and overrides Readdir so that
// http.FileServer can never fall through to directory listing, even when the
// configured index file is not "index.html" and http.FileServer's own
// built-in index.html search fails.
type noListDir struct{ http.File }

func (noListDir) Readdir(int) ([]os.FileInfo, error) { return nil, os.ErrPermission }

func (fs noListFS) Open(name string) (http.File, error) {
	f, err := fs.root.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if fi.IsDir() {
		base := strings.TrimRight(name, "/")
		for _, idxName := range fs.indexFiles {
			idx, err := fs.root.Open(base + "/" + idxName)
			if err == nil {
				idx.Close()
				// Wrap the directory so Readdir is always blocked.
				// http.FileServer will still open "index.html" via a
				// separate fs.Open call; that succeeds for the standard
				// case.  For non-"index.html" index files the configured
				// file is never served via FileServer, but we guarantee
				// that no directory listing escapes.
				return noListDir{f}, nil
			}
		}
		f.Close()
		return nil, os.ErrPermission
	}
	return f, nil
}

// loggingResponseWriter captures the status code and bytes written for access
// logging. Unwrap() exposes the underlying writer so that http.ResponseController
// can still reach optional interfaces (e.g. http.Flusher, http3.ResponseWriter).
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *loggingResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *loggingResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// limitListener wraps a net.Listener and enforces a cap on concurrent open
// connections. When max <= 0 the original listener is returned unmodified.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(l net.Listener, max int) net.Listener {
	if max <= 0 {
		return l
	}
	ll := &limitListener{Listener: l, sem: make(chan struct{}, max)}
	for i := 0; i < max; i++ {
		ll.sem <- struct{}{}
	}
	return ll
}

func (l *limitListener) Accept() (net.Conn, error) {
	<-l.sem
	c, err := l.Listener.Accept()
	if err != nil {
		l.sem <- struct{}{}
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { l.sem <- struct{}{} }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// vhostRouter dispatches requests to per-virtual-host handlers based on the
// Host header. Exact names take priority over wildcard entries.
type vhostRouter struct {
	exact    map[string]http.Handler // "example.com"  -> handler
	wildcard map[string]http.Handler // ".example.com" -> handler (from *.example.com)
}

func (r *vhostRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := canonicalHost(req.Host)

	if h, ok := r.exact[host]; ok {
		h.ServeHTTP(w, req)
		return
	}

	if dot := strings.Index(host, "."); dot >= 0 {
		if h, ok := r.wildcard[host[dot:]]; ok {
			h.ServeHTTP(w, req)
			return
		}
	}

	http.Error(w, "421 Misdirected Request", http.StatusMisdirectedRequest)
}

// canonicalHost returns the lowercase hostname from a host[:port] string,
// correctly handling IPv6 addresses in either bracketed form ("[::1]:443")
// or bare form ("[::1]").
func canonicalHost(hostport string) string {
	lower := strings.ToLower(hostport)
	host, _, err := net.SplitHostPort(lower)
	if err != nil {
		// No port present.  Strip brackets around a bare IPv6 address,
		// e.g. "[::1]" → "::1".
		host = lower
		if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
			host = host[1 : len(host)-1]
		}
	}
	return host
}

// acceptsEncoding reports whether the Accept-Encoding header value includes
// enc as an exact token.  It parses comma-separated tokens, strips optional
// q-values ("gzip;q=0.9"), and treats "*" as matching any encoding.
func acceptsEncoding(header, enc string) bool {
	for _, token := range strings.Split(header, ",") {
		token = strings.TrimSpace(token)
		if i := strings.IndexByte(token, ';'); i >= 0 {
			token = strings.TrimSpace(token[:i])
		}
		if strings.EqualFold(token, enc) || token == "*" {
			return true
		}
	}
	return false
}

// Server is the Femto HTTP/3-first TLS-only server.
type Server struct {
	cfg            *config.Config
	certsMu        sync.RWMutex
	certs          map[string]*tls.Certificate
	router         *vhostRouter
	errorLog       *log.Logger
	accessLog      *log.Logger
	logFiles       []*os.File // closed on shutdown
	trustedProxies []*net.IPNet
}

// New builds a Server from cfg, loading and validating all TLS certificates
// and verifying that every document_root directory exists.
func New(cfg *config.Config) (*Server, error) {
	errorLog, accessLog, logFiles, err := openLoggers(cfg.Server.ErrorLog, cfg.Server.AccessLog)
	if err != nil {
		return nil, err
	}
	trustedProxies, err := parseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		for _, f := range logFiles {
			f.Close()
		}
		return nil, fmt.Errorf("server: %w", err)
	}
	s := &Server{
		cfg:   cfg,
		certs: make(map[string]*tls.Certificate),
		router: &vhostRouter{
			exact:    make(map[string]http.Handler),
			wildcard: make(map[string]http.Handler),
		},
		errorLog:       errorLog,
		accessLog:      accessLog,
		logFiles:       logFiles,
		trustedProxies: trustedProxies,
	}
	if err := s.loadCerts(); err != nil {
		s.closeLogFiles()
		return nil, err
	}
	if err := s.checkDocRoots(); err != nil {
		s.closeLogFiles()
		return nil, err
	}
	s.buildRouter()
	return s, nil
}

// openLoggers opens the access and error log destinations.
// path == ""  → os.Stderr
// path == "off" → io.Discard
// otherwise   → the named file (created/appended, 0640)
func openLoggers(errorPath, accessPath string) (errorLog, accessLog *log.Logger, files []*os.File, err error) {
	open := func(path string) (io.Writer, *os.File, error) {
		switch path {
		case "", "stderr":
			return os.Stderr, nil, nil
		case "off":
			return io.Discard, nil, nil
		default:
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
			if err != nil {
				return nil, nil, fmt.Errorf("opening log file %q: %w", path, err)
			}
			return f, f, nil
		}
	}
	errW, errFile, e := open(errorPath)
	if e != nil {
		return nil, nil, nil, e
	}
	accW, accFile, e := open(accessPath)
	if e != nil {
		if errFile != nil {
			errFile.Close()
		}
		return nil, nil, nil, e
	}
	for _, f := range []*os.File{errFile, accFile} {
		if f != nil {
			files = append(files, f)
		}
	}
	return log.New(errW, "", log.LstdFlags), log.New(accW, "", 0), files, nil
}

func (s *Server) closeLogFiles() {
	for _, f := range s.logFiles {
		f.Close()
	}
}

func (s *Server) loadCerts() error {
	newCerts := make(map[string]*tls.Certificate)
	for _, vh := range s.cfg.VHosts {
		cert, err := tls.LoadX509KeyPair(vh.TLS.Cert, vh.TLS.Key)
		if err != nil {
			return fmt.Errorf("server: loading cert for %v: %w", vh.ServerNames, err)
		}
		// Append a separate intermediate chain file if configured.
		// If the cert file is already a full-chain bundle this is a no-op.
		if vh.TLS.Chain != "" {
			if err := appendChain(&cert, vh.TLS.Chain, vh.ServerNames, s.errorLog); err != nil {
				return err
			}
		}
		if err := checkCertExpiry(&cert, vh.ServerNames, s.errorLog); err != nil {
			return err
		}
		for _, name := range vh.ServerNames {
			c := cert
			newCerts[strings.ToLower(name)] = &c
		}
	}
	s.certsMu.Lock()
	s.certs = newCerts
	s.certsMu.Unlock()
	return nil
}

// reloadCerts re-reads all TLS certificates from disk without dropping
// existing connections.  Intended to be triggered by SIGHUP so that cert
// renewals (e.g. Let's Encrypt) take effect without a full restart.
func (s *Server) reloadCerts() error {
	return s.loadCerts()
}

// appendChain reads a PEM file of intermediate certificates and appends their
// raw DER bytes to cert.Certificate (after the leaf).  The root CA should NOT
// be included in the chain file — clients already have it in their trust store
// and including it only wastes bytes on every TLS handshake.
func appendChain(cert *tls.Certificate, chainPath string, names []string, logger *log.Logger) error {
	data, err := os.ReadFile(chainPath)
	if err != nil {
		return fmt.Errorf("server: reading chain for %v: %w", names, err)
	}
	var count int
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		// Validate it is a parseable X.509 certificate before trusting it.
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("server: invalid certificate in chain for %v: %w", names, err)
		}
		cert.Certificate = append(cert.Certificate, block.Bytes)
		count++
	}
	if count == 0 {
		return fmt.Errorf("server: chain file %q for %v contains no CERTIFICATE blocks", chainPath, names)
	}
	return nil
}

// checkCertExpiry returns an error if the leaf certificate has already expired,
// logs a warning if it expires within 30 days, and logs the full chain depth so
// the operator can confirm intermediates are present at startup.
func checkCertExpiry(cert *tls.Certificate, names []string, logger *log.Logger) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("server: certificate for %v contains no data", names)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("server: parsing certificate for %v: %w", names, err)
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("server: certificate for %v expired on %s",
			names, leaf.NotAfter.Format(time.DateOnly))
	}
	if days := leaf.NotAfter.Sub(now).Hours() / 24; days < 30 {
		logger.Printf("femto: WARNING certificate for %v expires in %.0f days (%s)",
			names, days, leaf.NotAfter.Format(time.DateOnly))
	}
	// Log chain depth so the operator can confirm intermediates are present.
	// depth 1 = leaf only (no intermediates — may cause handshake failures on
	// clients that do not cache the intermediate from a prior connection).
	depth := len(cert.Certificate)
	if depth < 2 {
		logger.Printf("femto: WARNING certificate chain for %v has depth %d (leaf only) — "+
			"consider including intermediate CA(s) via tls.cert bundle or tls.chain",
			names, depth)
	} else {
		logger.Printf("femto: certificate for %v OK (expires %s, chain depth %d)",
			names, leaf.NotAfter.Format(time.DateOnly), depth)
	}
	return nil
}

// checkDocRoots verifies that every vhost document_root exists and is a
// directory, failing fast at startup before any port is opened.
func (s *Server) checkDocRoots() error {
	for _, vh := range s.cfg.VHosts {
		fi, err := os.Stat(vh.DocumentRoot)
		if err != nil {
			return fmt.Errorf("server: vhost %v: document_root %q: %w",
				vh.ServerNames, vh.DocumentRoot, err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("server: vhost %v: document_root %q is not a directory",
				vh.ServerNames, vh.DocumentRoot)
		}
	}
	return nil
}

// getCertificate implements tls.Config.GetCertificate, selecting the right
// certificate by SNI name with single-level wildcard fallback.
// When no SNI is present (e.g. the client connected via IP address), the first
// loaded certificate is returned so the TLS handshake can still complete.
func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.certsMu.RLock()
	defer s.certsMu.RUnlock()
	name := strings.ToLower(hello.ServerName)
	if name == "" {
		// No SNI — IP-direct connection. Return the first cert we have.
		for _, cert := range s.certs {
			return cert, nil
		}
		return nil, fmt.Errorf("server: no certificates loaded")
	}
	if cert, ok := s.certs[name]; ok {
		return cert, nil
	}
	if dot := strings.Index(name, "."); dot >= 0 {
		if cert, ok := s.certs["*"+name[dot:]]; ok {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("server: no certificate for %q", name)
}

// isKnownHost reports whether host (canonical form: lowercase, no port, no
// brackets) is served by a configured vhost.  Used to validate the redirect
// target and prevent open-redirect attacks via a crafted Host header.
func (s *Server) isKnownHost(host string) bool {
	if _, ok := s.router.exact[host]; ok {
		return true
	}
	if dot := strings.Index(host, "."); dot >= 0 {
		if _, ok := s.router.wildcard[host[dot:]]; ok {
			return true
		}
	}
	return false
}

func (s *Server) buildRouter() {
	for _, vh := range s.cfg.VHosts {
		var fs http.FileSystem
		if vh.DirListing {
			fs = http.Dir(vh.DocumentRoot)
		} else {
			fs = noListFS{root: http.Dir(vh.DocumentRoot), indexFiles: vh.IndexFiles}
		}
		var handler http.Handler = http.FileServer(fs)
		handler = precompressedMiddleware(fs, handler)
		if vh.CacheMaxAge.Duration > 0 {
			handler = cacheControlMiddleware(vh.CacheMaxAge.Duration, handler)
		}
		for _, name := range vh.ServerNames {
			key := strings.ToLower(name)
			if strings.HasPrefix(key, "*.") {
				s.router.wildcard[key[1:]] = handler
			} else {
				s.router.exact[key] = handler
			}
		}
	}
}

// precompressedMiddleware transparently serves pre-compressed variants of
// static files.  For each request it checks whether a brotli (.br) or gzip
// (.gz) sidecar exists alongside the original file.  If the client advertises
// support via Accept-Encoding and the sidecar is present, the compressed file
// is served with the correct Content-Encoding, Content-Type (of the original),
// and Vary headers.  Range requests are stripped because ranges on a
// content-encoded body are not meaningful to clients expecting the original.
func precompressedMiddleware(fs http.FileSystem, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		urlPath := r.URL.Path
		if urlPath == "" {
			urlPath = "/"
		}
		ae := r.Header.Get("Accept-Encoding")
		for _, enc := range []struct{ name, ext string }{
			{"br", ".br"},
			{"gzip", ".gz"},
		} {
			if !acceptsEncoding(ae, enc.name) {
				continue
			}
			f, err := fs.Open(urlPath + enc.ext)
			if err != nil {
				continue
			}
			fi, err := f.Stat()
			if err != nil || fi.IsDir() {
				f.Close()
				continue
			}
			h := w.Header()
			h.Set("Content-Encoding", enc.name)
			h.Add("Vary", "Accept-Encoding")
			if ct := mime.TypeByExtension(path.Ext(urlPath)); ct != "" {
				h.Set("Content-Type", ct)
			}
			// Strip Range so ServeContent serves the full compressed body.
			r2 := r.Clone(r.Context())
			r2.Header.Del("Range")
			http.ServeContent(w, r2, urlPath+enc.ext, fi.ModTime(), f)
			f.Close()
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cacheWriter intercepts WriteHeader so that Cache-Control is only applied to
// successful (2xx) and revalidation (304) responses. Error responses such as
// 403 and 404 must never be cached as "public" for the configured max-age.
type cacheWriter struct {
	http.ResponseWriter
	cacheControl string
	wroteHeader  bool
}

func (cw *cacheWriter) WriteHeader(status int) {
	if !cw.wroteHeader {
		cw.wroteHeader = true
		if status/100 == 2 || status == http.StatusNotModified {
			cw.ResponseWriter.Header().Set("Cache-Control", cw.cacheControl)
		}
	}
	cw.ResponseWriter.WriteHeader(status)
}

func (cw *cacheWriter) Write(b []byte) (int, error) {
	if !cw.wroteHeader {
		// Implicit 200 OK — safe to cache.
		cw.wroteHeader = true
		cw.ResponseWriter.Header().Set("Cache-Control", cw.cacheControl)
	}
	return cw.ResponseWriter.Write(b)
}

func (cw *cacheWriter) Unwrap() http.ResponseWriter { return cw.ResponseWriter }

// cacheControlMiddleware injects a Cache-Control header on 2xx and 304
// responses only. Error responses (4xx, 5xx) are left without Cache-Control
// so that clients and CDNs do not cache them for the max-age duration.
func cacheControlMiddleware(maxAge time.Duration, next http.Handler) http.Handler {
	v := fmt.Sprintf("public, max-age=%d", int64(maxAge.Seconds()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&cacheWriter{ResponseWriter: w, cacheControl: v}, r)
	})
}

func (s *Server) tcpTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: s.getCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

func (s *Server) quicTLSConfig() *tls.Config {
	return http3.ConfigureTLSConfig(&tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: s.getCertificate,
	})
}

// securityHeadersMiddleware injects the configured security response headers.
// Any header whose configured value is an empty string is not sent.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	sec := s.cfg.Server.Security
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if sec.HSTS != "" {
			h.Set("Strict-Transport-Security", sec.HSTS)
		}
		if sec.ContentTypeOptions != "" {
			h.Set("X-Content-Type-Options", sec.ContentTypeOptions)
		}
		if sec.FrameOptions != "" {
			h.Set("X-Frame-Options", sec.FrameOptions)
		}
		if sec.ContentSecurityPolicy != "" {
			h.Set("Content-Security-Policy", sec.ContentSecurityPolicy)
		}
		if sec.ReferrerPolicy != "" {
			h.Set("Referrer-Policy", sec.ReferrerPolicy)
		}
		if sec.PermissionsPolicy != "" {
			h.Set("Permissions-Policy", sec.PermissionsPolicy)
		}
		next.ServeHTTP(w, r)
	})
}

// accessLogMiddleware logs one structured line per completed request.
// Format: <remote> <proto> <method> <uri> <status> <bytes> <duration> <ua>
func (s *Server) accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(lw, r)
		status := lw.status
		if status == 0 {
			status = http.StatusOK
		}
		s.accessLog.Printf("%s %s %s %s %d %d %s %q",
			s.realRemoteAddr(r),
			r.Proto,
			r.Method,
			r.URL.RequestURI(),
			status,
			lw.bytes,
			time.Since(start).Round(time.Microsecond),
			r.UserAgent(),
		)
	})
}

// realRemoteAddr returns the true client address for logging.  When the
// request arrives from a trusted proxy (or over a Unix socket), the
// RFC 7239 Forwarded header is checked first, then X-Forwarded-For.
func (s *Server) realRemoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// Unix socket connections have an empty or "@" remote addr — always trust.
	isTrusted := host == "" || host == "@"
	if !isTrusted && len(s.trustedProxies) > 0 {
		ip := net.ParseIP(host)
		for _, network := range s.trustedProxies {
			if ip != nil && network.Contains(ip) {
				isTrusted = true
				break
			}
		}
	}
	if !isTrusted {
		return r.RemoteAddr
	}
	// RFC 7239: Forwarded: for=<client> takes precedence over X-Forwarded-For.
	if fwd := r.Header.Get("Forwarded"); fwd != "" {
		for _, part := range strings.Split(fwd, ",") {
			for _, field := range strings.Split(strings.TrimSpace(part), ";") {
				field = strings.TrimSpace(field)
				if strings.HasPrefix(strings.ToLower(field), "for=") {
					return strings.Trim(field[4:], `"`)
				}
			}
		}
	}
	// X-Forwarded-For: leftmost entry is the original client.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return r.RemoteAddr
}

// parseTrustedProxies converts a slice of IP addresses or CIDR strings into
// a slice of *net.IPNet.  Plain IPs are converted to host CIDRs (/32 or /128).
func parseTrustedProxies(specs []string) ([]*net.IPNet, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	nets := make([]*net.IPNet, 0, len(specs))
	for _, s := range specs {
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy address %q", s)
			}
			if ip.To4() != nil {
				s = s + "/32"
			} else {
				s = s + "/128"
			}
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", s, err)
		}
		nets = append(nets, ipnet)
	}
	return nets, nil
}

// Run starts a TCP+QUIC listener pair for each configured listen address and
// blocks until a listener error occurs or SIGINT/SIGTERM is received, at which
// point it performs a graceful shutdown.
func (s *Server) Run() error {
	cfg := s.cfg.Server

	// Middleware stack: access log -> security headers -> vhost router.
	handler := s.accessLogMiddleware(s.securityHeadersMiddleware(s.router))

	h3srv := &http3.Server{Handler: handler}

	// TCP handler adds Alt-Svc to advertise HTTP/3 to the client.
	tcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h3srv.SetQUICHeaders(w.Header()); err != nil {
			s.errorLog.Printf("femto: Alt-Svc: %v", err)
		}
		handler.ServeHTTP(w, r)
	})

	tcpSrv := &http.Server{
		Handler:           tcpHandler,
		TLSConfig:         s.tcpTLSConfig(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout.Duration,
		ReadTimeout:       cfg.ReadTimeout.Duration,
		WriteTimeout:      cfg.WriteTimeout.Duration,
		IdleTimeout:       cfg.IdleTimeout.Duration,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	// Unix domain socket server (plain HTTP — TLS is the caller's job).
	var unixSrv *http.Server
	if cfg.Unix.Enabled {
		unixSrv = &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout.Duration,
			ReadTimeout:       cfg.ReadTimeout.Duration,
			WriteTimeout:      cfg.WriteTimeout.Duration,
			IdleTimeout:       cfg.IdleTimeout.Duration,
			MaxHeaderBytes:    cfg.MaxHeaderBytes,
		}
	}

	n := len(cfg.Listen)
	listenerCount := n * 2 // TCP + QUIC per TLS address
	if cfg.Unix.Enabled {
		listenerCount++
	}
	if cfg.Redirect.Enabled {
		listenerCount += len(cfg.Redirect.Listen)
	}
	errCh := make(chan error, listenerCount)

	for _, rawAddr := range cfg.Listen {
		addr, _ := rawAddr.Resolve()

		quicLn, err := quic.ListenAddrEarly(addr, s.quicTLSConfig(), &quic.Config{})
		if err != nil {
			return fmt.Errorf("server: quic listen %s: %w", addr, err)
		}

		// Apply the connection limit on the raw TCP listener *before* TLS so
		// that tls.NewListener can return a *tls.Conn directly.  Go's http.Server
		// must receive a *tls.Conn from Accept() to detect the negotiated ALPN
		// protocol and dispatch the connection to the HTTP/2 handler.
		rawLn, err := net.Listen("tcp", addr)
		if err != nil {
			_ = quicLn.Close()
			return fmt.Errorf("server: tcp listen %s: %w", addr, err)
		}
		tcpLn := tls.NewListener(newLimitListener(rawLn, cfg.MaxConnections), s.tcpTLSConfig())

		s.errorLog.Printf("femto: listening on %s  [TLS 1.3 | HTTP/2 (TCP) | HTTP/3 (QUIC)]", addr)

		go func(ql *quic.EarlyListener) { errCh <- h3srv.ServeListener(ql) }(quicLn)
		go func(l net.Listener) { errCh <- tcpSrv.Serve(l) }(tcpLn)
	}

	if cfg.Unix.Enabled {
		// Remove a stale socket file left from a previous run.
		if err := os.Remove(cfg.Unix.Path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("server: removing stale unix socket %q: %w", cfg.Unix.Path, err)
		}
		unixLn, err := net.Listen("unix", cfg.Unix.Path)
		if err != nil {
			return fmt.Errorf("server: unix listen %q: %w", cfg.Unix.Path, err)
		}
		if err := os.Chmod(cfg.Unix.Path, os.FileMode(cfg.Unix.Mode)); err != nil {
			_ = unixLn.Close()
			return fmt.Errorf("server: chmod unix socket %q: %w", cfg.Unix.Path, err)
		}
		s.errorLog.Printf("femto: listening on unix:%s  [HTTP/1.1]", cfg.Unix.Path)
		go func() { errCh <- unixSrv.Serve(unixLn) }()
	}

	// HTTP → HTTPS redirect listeners (plain HTTP, no TLS).
	var redirectSrvs []*http.Server
	if cfg.Redirect.Enabled {
		// SECURITY: validate the Host header against configured vhosts before
		// building the Location URL.  An attacker-controlled Host header must
		// not produce a redirect to an arbitrary external domain.
		redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := canonicalHost(r.Host)
			if host == "" || !s.isKnownHost(host) {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
		for _, rawAddr := range cfg.Redirect.Listen {
			addr, _ := rawAddr.Resolve()
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("server: redirect listen %s: %w", addr, err)
			}
			rsrv := &http.Server{
				Handler:           redirectHandler,
				ReadHeaderTimeout: cfg.ReadHeaderTimeout.Duration,
				ReadTimeout:       cfg.ReadTimeout.Duration,
				WriteTimeout:      cfg.WriteTimeout.Duration,
				IdleTimeout:       cfg.IdleTimeout.Duration,
			}
			s.errorLog.Printf("femto: listening on %s  [HTTP/1.1 → HTTPS redirect]", addr)
			redirectSrvs = append(redirectSrvs, rsrv)
			go func(l net.Listener, srv *http.Server) { errCh <- srv.Serve(l) }(ln, rsrv)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		select {
		case err := <-errCh:
			return err
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				// SIGHUP: reload TLS certificates without dropping connections.
				if err := s.reloadCerts(); err != nil {
					s.errorLog.Printf("femto: cert reload failed: %v", err)
				} else {
					s.errorLog.Printf("femto: certificates reloaded")
				}
				continue
			}
			// SIGTERM / SIGINT: graceful shutdown.
			s.errorLog.Printf("femto: received %s, graceful shutdown (timeout: %s)...",
				sig, cfg.ShutdownTimeout.Duration)
			ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout.Duration)
			if err := tcpSrv.Shutdown(ctx); err != nil {
				s.errorLog.Printf("femto: TCP shutdown: %v", err)
			}
			if err := h3srv.Close(); err != nil {
				s.errorLog.Printf("femto: QUIC shutdown: %v", err)
			}
			if unixSrv != nil {
				if err := unixSrv.Shutdown(ctx); err != nil {
					s.errorLog.Printf("femto: Unix shutdown: %v", err)
				}
				_ = os.Remove(cfg.Unix.Path)
			}
			for _, rsrv := range redirectSrvs {
				if err := rsrv.Shutdown(ctx); err != nil {
					s.errorLog.Printf("femto: redirect shutdown: %v", err)
				}
			}
			s.closeLogFiles()
			cancel()
			return nil
		}
	}
}
