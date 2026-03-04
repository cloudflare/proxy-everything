package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// TLSServerFactory wraps a VM-side net.Conn into a TLS server connection,
// presenting a leaf certificate for the client's requested SNI.
type TLSServerFactory interface {
	NewServer(conn net.Conn) (*tls.Conn, error)
}

// tlsInterceptor implements TLSServerFactory using an ephemeral CA.
type tlsInterceptor struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	cache  sync.Map // SNI string to *tls.Certificate
	size   atomic.Int64
}

const maxCACerts = 512

// NewTLSInterceptor creates a TLSServerFactory from PEM-encoded CA cert and key.
func NewTLSInterceptor(caCertPEM, caKeyPEM []byte) (*tlsInterceptor, error) {
	pair, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA keypair: %w", err)
	}

	caCert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	caKey, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is not ECDSA")
	}

	return &tlsInterceptor{caCert: caCert, caKey: caKey}, nil
}

func (t *tlsInterceptor) mintCert(sni string) (*tls.Certificate, error) {
	if cached, ok := t.cache.Load(sni); ok {
		return cached.(*tls.Certificate), nil
	}

	if t.size.Load() > maxCACerts {
		t.cache.Clear()
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		DNSNames:     []string{sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, t.caCert, &leafKey.PublicKey, t.caKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{leafDER, t.caCert.Raw},
		PrivateKey:  leafKey,
	}

	// TODO: Make it LRU. So LRU keys get evicted when we are at capacity.
	_, load := t.cache.LoadOrStore(sni, cert)
	if !load {
		t.size.Add(1)
	}

	return cert, nil
}

// NewServer wraps conn with a TLS server that presents a cert matching
// the client's SNI, signed by the intercept CA.
// The returned *tls.Conn has already completed the handshake.
func (t *tlsInterceptor) NewServer(conn net.Conn) (*tls.Conn, error) {
	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return t.mintCert(hello.ServerName)
		},
	})

	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	return tlsConn, nil
}

// tlsCloseConn wraps *tls.Conn with CloseRead support, so it can be
// used as a half-close-capable connection by the proxy pump.
// CloseWrite() is provided by *tls.Conn (sends TLS close_notify).
type tlsCloseConn struct {
	*tls.Conn
	onCloseRead func() error
}

func (c *tlsCloseConn) CloseRead() error {
	return c.onCloseRead()
}

// createCA generates an ephemeral ECDSA P-256 CA certificate and key pair,
// writing them to certPath and keyPath. Parent directories are created as needed.
func createCA(certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("mkdir for cert: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return fmt.Errorf("mkdir for key: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Cloudflare TLS proxy-everything Intercept CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}

	return nil
}
