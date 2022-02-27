/*
BetterPEM

A more ergonomic way to extract PEM data.

See the ParsePEM example for how to use it with strings and []bytes.
*/
package betterpem

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var ErrPemUnderlyingFormatError = errors.New("pem passed was not a string or []byte")
var ErrPemIsUnsupportedType = errors.New("pem is an unsupported type")

func intoBytes(pemInt interface{}) ([]byte, error) {
	var pemBytes []byte = nil
	if b, ok := pemInt.([]byte); ok {
		pemBytes = b
	}
	if s, ok := pemInt.(string); ok {
		pemBytes = []byte(s)
	}
	if pemBytes == nil {
		return nil, ErrPemUnderlyingFormatError
	}
	return pemBytes, nil
}

// Parsing a PEM results in a ParsedPEM object being returned
type ParsedPEM struct {
	obj interface{}
}

// Give the object back in its typeless form
func (p ParsedPEM) Interface() interface{} {
	return p.obj
}

// Return the ParsedPEM's object as a *x509.Certificate.
//
// Panics if the object wasn't an x.509 certificate
func (p ParsedPEM) MustCertificate() *x509.Certificate {
	r, ok := p.obj.(*x509.Certificate)
	if !ok {
		panic(fmt.Sprintf("%#v is not an *x509.Certificate", p.obj))
	}
	return r
}

// Returns the ParsedPEM's object as a *rsa.PrivateKey
//
// Panics if the object wasn't an RSA private key
func (p ParsedPEM) MustRSAPrivateKey() *rsa.PrivateKey {
	r, ok := p.obj.(*rsa.PrivateKey)
	if !ok {
		panic(fmt.Sprintf("%#v is not an rsa.PrivateKey", p.obj))
	}
	return r
}

// Returns the ParsedPEM's object as a *ecdsa.PrivateKey
//
// Panics if the object wasn't an ECDSA private key
func (p ParsedPEM) MustECPrivateKey() *ecdsa.PrivateKey {
	r, ok := p.obj.(*ecdsa.PrivateKey)
	if !ok {
		panic(fmt.Sprintf("%#v is not an ecdsa.PrivateKey", p.obj))
	}
	return r
}

// Parse PEM data into a slice of ParsedPEM objects
//
// This function will parse all discovered PEM blocks
// and return them in the order discovered after parsing
// them into their appropriate types.
//
// See ParsedPEM for details on extracting the object.
//
// Produces an error if there is no PEM data found.
//
func ParsePEM(pemInt interface{}) ([]ParsedPEM, error) {
	objs := []ParsedPEM{}
	pemBytes, err := intoBytes(pemInt)
	if err != nil {
		return nil, err
	}
	var der *pem.Block
	var rest []byte = pemBytes
	for {
		der, rest = pem.Decode(rest)
		if der == nil {
			break
		}
		switch der.Type {
		case "CERTIFICATE":
			r, err := x509.ParseCertificate(der.Bytes)
			if err != nil {
				return nil, err
			}
			objs = append(objs, ParsedPEM{r})
		case "RSA PRIVATE KEY":
			r, err := x509.ParsePKCS1PrivateKey(der.Bytes)
			if err != nil {
				return nil, err
			}
			objs = append(objs, ParsedPEM{r})
		case "EC PRIVATE KEY":
			r, err := x509.ParseECPrivateKey(der.Bytes)
			if err != nil {
				return nil, err
			}
			objs = append(objs, ParsedPEM{r})
		case "PRIVATE KEY":
			r, err := x509.ParsePKCS8PrivateKey(der.Bytes)
			if err != nil {
				return nil, err
			}
			objs = append(objs, ParsedPEM{r})
		default:
		}
	}
	if len(objs) > 0 {
		return objs, nil
	}
	return nil, ErrPemIsUnsupportedType
}
