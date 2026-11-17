package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadRSAPrivateKey loads an RSA private key from a PEM file.
// Both PKCS#8 and PKCS#1 are tried.
func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key: no PEM block found")
	}

	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 key: %w", err)
		}
		rk, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA (EC/Ed25519 are not supported)")
		}
		key = rk
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}

	if key.N.BitLen() < 2048 {
		return nil, errors.New("RSA key must be at least 2048 bits")
	}
	return key, nil
}
