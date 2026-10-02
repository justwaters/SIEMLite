package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// EnsureCertificate makes sure certFile/keyFile exist. If both are present
// they are used untouched (bring your own cert). If neither exists, a
// self-signed ECDSA certificate valid for hosts is generated. It returns the
// SHA-256 fingerprint of the certificate so clients can pin it.
func EnsureCertificate(certFile, keyFile string, hosts []string) (fingerprint string, generated bool, err error) {
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	switch {
	case certErr == nil && keyErr == nil:
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return "", false, fmt.Errorf("load TLS certificate: %w", err)
		}
		return fingerprintOf(pair.Certificate[0]), false, nil
	case certErr == nil || keyErr == nil:
		return "", false, errors.New("TLS certificate and key must both exist or both be absent")
	}

	der, keyPEM, err := selfSigned(hosts)
	if err != nil {
		return "", false, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return "", false, fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return "", false, fmt.Errorf("write private key: %w", err)
	}
	return fingerprintOf(der), true, nil
}

func selfSigned(hosts []string) (der, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "SIEMLite", Organization: []string{"SIEMLite"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed: usable directly as a trust anchor (curl --cacert)
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
