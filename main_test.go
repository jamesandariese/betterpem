package betterpem

import (
	"bytes"
	"crypto/ecdsa"
	"embed"
	"fmt"
	"io"
	"testing"
)

//go:embed testfiles/rsa_512.key
var test_rsakey []byte

//go:embed testfiles/rsa_512.csr
var test_rsareq []byte

//go:embed testfiles/rsa_512.crt
var test_rsacert []byte

//go:embed testfiles/ca/ca.crt
var test_ca []byte

//go:embed testfiles/ca/ca.key
var test_cakey []byte

//go:embed testfiles/ec_P-521.crt
var test_eccert []byte

//go:embed testfiles/ec_P-521.key
var test_eckey []byte

//go:embed testfiles/*.crt testfiles/*.key testfiles/*.csr
var test_fs embed.FS

func ExampleParsePEMs() {
	f, err := test_fs.Open("testfiles/ec_P-256.key")
	if err != nil {
		fmt.Printf("Failed to open ec_P-256.key: %v", err)
		return
	}
	bytes, err := io.ReadAll(f)
	if err != nil {
		fmt.Printf("Failed to read ec_P-256.key: %v", err)
		return
	}
	var becpriv *ecdsa.PrivateKey
	var secpriv *ecdsa.PrivateKey
	var fecpriv *ecdsa.PrivateKey

	{ // it works with []byte.
		pemObjs, err := ParsePEMs(bytes)
		if err != nil || pemObjs.Length() != 1 {
			fmt.Printf("failed to parse PEM: %v", err)
			return
		}
		becpriv = pemObjs.MustECPrivateKey()
	}

	{ // it also works with string.  magic!
		pemObjs, err := ParsePEMs(string(bytes))
		if err != nil || pemObjs.Length() != 1 {
			fmt.Printf("failed to parse PEM: %v", err)
			return
		}
		secpriv = pemObjs.MustECPrivateKey()
	}

	{ // but wait!  there's more!  it also works with io.Reader!
		// we could have skipped the whole io.ReadAll after all!
		// this block is all we needed.
		f, err := test_fs.Open("testfiles/ec_P-256.key")
		if err != nil {
			fmt.Printf("Failed to open ec_P-256.key: %v", err)
			return
		}
		pemObjs, err := ParsePEMs(f)
		if err != nil || pemObjs.Length() != 1 {
			fmt.Printf("failed to parse ec_P-256.key: %v", err)
			return
		}
		fecpriv = pemObjs.MustECPrivateKey()
	}

	// the three should be the same.  let's just check to be sure.
	if secpriv.Equal(becpriv) && fecpriv.Equal(becpriv) {
		fmt.Println("string, byte, and io.Reader versions are equal")
	}
	//Output: string, byte, and io.Reader versions are equal
}

func TestLoadPem(t *testing.T) {
	objs, err := ParsePEMs(test_eckey)
	if err != nil {
		t.Errorf("unexpected error parsing pem %#v", err)
	}
	t.Logf("parsedObj: %#v", objs.Interface())
}

func TestLoadManyPem(t *testing.T) {
	pembyteblocks := [][]byte{
		test_rsacert,
		test_rsakey,
		test_ca,
		test_cakey,
		test_rsareq,
		test_eccert,
		test_eckey,
	}
	pems := bytes.Join(pembyteblocks, []byte{'\n'})
	objs, err := ParsePEMs(pems)
	if err != nil {
		t.Errorf("error while reading PEMs %#v", err)
	}
	if objs.Length() != len(pembyteblocks)-1 {
		// except for the csr which we don't parse and _should_ be missing
		t.Error("ParsePEM did not parse all the expected blocks properly")
	}
	rsacert := objs.MustCertificate()
	rsakey := objs.MustRSAPrivateKey()
	cacert := objs.MustCertificate()
	cakey := objs.MustRSAPrivateKey()
	eccert := objs.MustCertificate()
	eckey := objs.MustECPrivateKey()
	if !rsakey.PublicKey.Equal(rsacert.PublicKey) {
		t.Error("okay...")
	}
	if !cakey.PublicKey.Equal(cacert.PublicKey) {
		t.Error("wait what?")
	}
	if !eckey.PublicKey.Equal(eccert.PublicKey) {
		t.Errorf("%#v != %#v", eckey.PublicKey, eccert.PublicKey)
	}
}

func TestLoadPemUnderrun(t *testing.T) {
	objs, err := ParsePEMs(test_eckey)
	if err != nil {
		t.Errorf("unexpected error parsing pem %#v", err)
	}
	failedAsExpected := false
	func() {
		defer func() {
			if recover() != nil {
				failedAsExpected = true
			}
		}()
		objs.Interface()
		objs.Interface()
	}()
	if !failedAsExpected {
		t.Error("Expected an error from object underrun but there was no panic")
	}
}
func TestLoadPemWrongType(t *testing.T) {
	objs, err := ParsePEMs(test_eckey)
	if err != nil {
		t.Errorf("unexpected error parsing pem %#v", err)
	}
	failedAsExpected := false
	func() {
		defer func() {
			if recover() != nil {
				failedAsExpected = true
			}
		}()
		t.Logf("parsedObj: %#v", objs.MustRSAPrivateKey())
	}()
	if !failedAsExpected {
		t.Error("Expected an error from trying to coerce an EC to RSA but there was no panic")
	}
}
