package betterpem

import (
	"bytes"
	"crypto/ecdsa"
	"embed"
	"fmt"
	"io"
	"testing"
)

//go:embed testfiles/rsakey.pem
var test_rsakey []byte

//go:embed testfiles/rsareq.pem
var test_rsareq []byte

//go:embed testfiles/rsacert.pem
var test_rsacert []byte

//go:embed testfiles/ca/ca.pem
var test_ca []byte

//go:embed testfiles/ca/cakey.pem
var test_cakey []byte

//go:embed testfiles/eccert.pem
var test_eccert []byte

//go:embed testfiles/eckey.pem
var test_eckey []byte

//go:embed testfiles/*
var test_fs embed.FS

func ExampleParsePEM() {
	f, err := test_fs.Open("testfiles/eckey.pem")
	if err != nil {
		fmt.Printf("Failed to open eckey.pem: %v", err)
		return
	}
	bytes, err := io.ReadAll(f)
	if err != nil {
		fmt.Printf("Failed to read eckey.pem: %v", err)
		return
	}

	var becpriv *ecdsa.PrivateKey
	var secpriv *ecdsa.PrivateKey

	{ // it works with []byte.
		pemObjs, err := ParsePEM(bytes)
		if err != nil || len(pemObjs) != 1 {
			fmt.Printf("failed to parse PEM: %v", err)
			return
		}
		becpriv = pemObjs[0].MustECPrivateKey()
	}

	{ // it also works with string.  magic!
		pemObjs, err := ParsePEM(string(bytes))
		if err != nil || len(pemObjs) != 1 {
			fmt.Printf("failed to parse PEM: %v", err)
			return
		}
		secpriv = pemObjs[0].MustECPrivateKey()
	}

	// the two should be the same.
	if secpriv.Equal(becpriv) {
		fmt.Println("string and byte versions are equal")
	}
	//Output: string and byte versions are equal
}

func TestLoadPem(t *testing.T) {
	obj, err := ParsePEM(test_eckey)
	if err != nil {
		t.Errorf("unexpected error parsing pem %#v", err)
	}
	t.Logf("parsedObj: %#v", obj[0])
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
	objs, err := ParsePEM(pems)
	if err != nil {
		t.Errorf("error while reading PEMs %#v", err)
	}
	for _, obj := range objs {
		t.Logf("%#v", obj)
	}
	if len(objs) != len(pembyteblocks)-1 {
		// except for the csr which we don't parse and _should_ be missing
		t.Error("ParsePEM did not parse all the expected blocks properly")
	}
	rsacert := objs[0].MustCertificate()
	rsakey := objs[1].MustRSAPrivateKey()
	cacert := objs[2].MustCertificate()
	cakey := objs[3].MustRSAPrivateKey()
	eccert := objs[4].MustCertificate()
	eckey := objs[5].MustECPrivateKey()
	if !rsakey.PublicKey.Equal(rsacert.PublicKey) {
		t.Error("okay...")
	}
	if !cakey.PublicKey.Equal(cacert.PublicKey) {
		t.Error("wait what?")
	}
	if !eckey.PublicKey.Equal(eccert.PublicKey) {
		t.Errorf("%#v != %#v", eckey.PublicKey, eccert.PublicKey)
	}
	failedAsExpected := false
	func() {
		defer func() {
			if recover() != nil {
				failedAsExpected = true
			}
		}()
		objs[5].MustCertificate()
	}()
	if !failedAsExpected {
		t.Error("Expected MustCertificate to fail for EC private key but it did not")
	}
}
