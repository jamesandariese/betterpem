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
	"io"
)

var ErrPemUnderlyingFormatError = errors.New("pem passed was not a string, []byte, or io.Reader")
var ErrPemIsUnsupportedType = errors.New("pem is an unsupported type")

func intoBytes(pemInt interface{}) ([]byte, error) {
	switch v := pemInt.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	case io.Reader:
		pemBytes, err := io.ReadAll(v)
		if err != nil {
			return nil, err
		}
		return pemBytes, nil
	default:
		return nil, ErrPemUnderlyingFormatError
	}
	panic("unreachable")
}

// Parsing a PEM results in a ParsedPEM object being returned
type ParsedPEMs struct {
	objs []interface{}
}

// Return the number of parsed PEMs remaining to be consumed
func (p *ParsedPEMs) Length() int {
	return len(p.objs)
}

// Give the object back in its typeless form
func (p *ParsedPEMs) Interface() interface{} {
	ret := p.objs[0]
	p.objs = p.objs[1:]
	return ret
}

// Return the ParsedPEM's object as a *x509.Certificate.
//
// Panics if the object wasn't an x.509 certificate
func (p *ParsedPEMs) MustCertificate() *x509.Certificate {
	r, ok := p.objs[0].(*x509.Certificate)
	if !ok {
		panic(fmt.Sprintf("%#v is not an *x509.Certificate", p.objs[0]))
	}
	p.objs = p.objs[1:]
	return r
}

// Returns the ParsedPEM's object as a *rsa.PrivateKey
//
// Panics if the object wasn't an RSA private key
func (p *ParsedPEMs) MustRSAPrivateKey() *rsa.PrivateKey {
	r, ok := p.objs[0].(*rsa.PrivateKey)
	if !ok {
		panic(fmt.Sprintf("%#v is not an rsa.PrivateKey", p.objs[0]))
	}
	p.objs = p.objs[1:]
	return r
}

// Returns the ParsedPEM's object as a *ecdsa.PrivateKey
//
// Panics if the object wasn't an ECDSA private key
func (p *ParsedPEMs) MustECPrivateKey() *ecdsa.PrivateKey {
	r, ok := p.objs[0].(*ecdsa.PrivateKey)
	if !ok {
		panic(fmt.Sprintf("%#v is not an ecdsa.PrivateKey", p.objs[0]))
	}
	p.objs = p.objs[1:]
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
func ParsePEMs(pemInt interface{}) (ParsedPEMs, error) {
	objs := []interface{}{}
	pemBytes, err := intoBytes(pemInt)
	if err != nil {
		return ParsedPEMs{}, err
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
				return ParsedPEMs{}, err
			}
			objs = append(objs, r)
		case "RSA PRIVATE KEY":
			r, err := x509.ParsePKCS1PrivateKey(der.Bytes)
			if err != nil {
				return ParsedPEMs{}, err
			}
			objs = append(objs, r)
		case "EC PRIVATE KEY":
			r, err := x509.ParseECPrivateKey(der.Bytes)
			if err != nil {
				return ParsedPEMs{}, err
			}
			objs = append(objs, r)
		case "PRIVATE KEY":
			r, err := x509.ParsePKCS8PrivateKey(der.Bytes)
			if err != nil {
				return ParsedPEMs{}, err
			}
			objs = append(objs, r)
		default:
		}
	}
	if len(objs) > 0 {
		return ParsedPEMs{objs}, nil
	}
	return ParsedPEMs{}, ErrPemIsUnsupportedType
}
