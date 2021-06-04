package pkcs7

import (
	"bytes"
	"crypto/dsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"testing"
)

func TestSign(t *testing.T) {
	t.Parallel()
	content := []byte("Hello World")
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for _, sigalgroot := range sigalgs {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
		}
		truststore := x509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, sigalginter := range sigalgs {
			interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, sigalginter, true)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", sigalgroot, sigalginter, err)
			}
			var parents []*x509.Certificate
			parents = append(parents, interCert.Certificate)
			for _, sigalgsigner := range sigalgs {
				signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalgsigner, false)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				for _, testDetach := range []bool{false, true} {
					log.Printf("test %s/%s/%s detached %t\n", sigalgroot, sigalginter, sigalgsigner, testDetach)
					toBeSigned, err := NewSignedData(content)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot initialize signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}

					// Set the digest to match the end entity cert
					signerDigest, _ := getDigestOIDForSignatureAlgorithm(signerCert.Certificate.SignatureAlgorithm)
					toBeSigned.SetDigestAlgorithm(signerDigest)

					if err := toBeSigned.AddSignerChain(signerCert.Certificate, *signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
						t.Fatalf("test %s/%s/%s: cannot add signer: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						toBeSigned.Detach()
					}
					signed, err := toBeSigned.Finish()
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot finish signing data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
					p7, err := Parse(signed)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot parse signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						p7.Content = content
					}
					if !bytes.Equal(content, p7.Content) {
						t.Errorf("test %s/%s/%s: content was not found in the parsed data:\n\tExpected: %s\n\tActual: %s", sigalgroot, sigalginter, sigalgsigner, content, p7.Content)
					}
					if err := p7.VerifyWithChain(truststore); err != nil {
						t.Errorf("test %s/%s/%s: cannot verify signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if !signerDigest.Equal(p7.Signers[0].DigestAlgorithm.Algorithm) {
						t.Errorf("test %s/%s/%s: expected digest algorithm %q but got %q",
							sigalgroot, sigalginter, sigalgsigner, signerDigest, p7.Signers[0].DigestAlgorithm.Algorithm)
					}
				}
			}
		}
	}
}

func TestSignAndVerifyWithOpenSSL(t *testing.T) {
	t.Parallel()
	content := []byte("Hello World")
	// write the content to a temp file
	tmpContentFile, err := ioutil.TempFile("", "TestDSASignAndVerifyWithOpenSSL_content")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpContentFile.Name(), content, 0755)

	block, _ := pem.Decode([]byte(dsaPublicCert))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}
	signerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("failed to parse certificate: " + err.Error())
	}

	// write the signer cert to a temp file
	tmpSignerCertFile, err := ioutil.TempFile("", "TestDSASignAndVerifyWithOpenSSL_signer")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpSignerCertFile.Name(), dsaPublicCert, 0755)

	priv := dsa.PrivateKey{
		PublicKey: dsa.PublicKey{Parameters: dsa.Parameters{P: fromHex("fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7"),
			Q: fromHex("9760508F15230BCCB292B982A2EB840BF0581CF5"),
			G: fromHex("F7E1A085D69B3DDECBBCAB5C36B857B97994AFBBFA3AEA82F9574C0B3D0782675159578EBAD4594FE67107108180B449167123E84C281613B7CF09328CC8A6E13C167A8B547C8D28E0A3AE1E2BB3A675916EA37F0BFA213562F1FB627A01243BCCA4F1BEA8519089A883DFE15AE59F06928B665E807B552564014C3BFECF492A"),
		},
		},
		X: fromHex("7D6E1A3DD4019FD809669D8AB8DA73807CEF7EC1"),
	}
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("test case: cannot initialize signed data: %s", err)
	}
	if err := toBeSigned.SignWithoutAttr(signerCert, &priv, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	toBeSigned.Detach()
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("test case: cannot finish signing data: %s", err)
	}

	// write the signature to a temp file
	tmpSignatureFile, err := ioutil.TempFile("", "TestDSASignAndVerifyWithOpenSSL_signature")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpSignatureFile.Name(), pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: signed}), 0755)

	// call openssl to verify the signature on the content using the root
	opensslCMD := exec.Command("openssl", "smime", "-verify", "-noverify",
		"-in", tmpSignatureFile.Name(), "-inform", "PEM",
		"-content", tmpContentFile.Name())
	out, err := opensslCMD.CombinedOutput()
	if err != nil {
		t.Fatalf("test case: openssl command failed with %s: %s", err, out)
	}
	os.Remove(tmpSignatureFile.Name())  // clean up
	os.Remove(tmpContentFile.Name())    // clean up
	os.Remove(tmpSignerCertFile.Name()) // clean up
}

func ExampleSignedData(t *testing.T) {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatalf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedData([]byte("Example data to be signed"))
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

func TestSignedDataWithContentType(t *testing.T) {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate(x509.SHA1WithRSA)
	if err != nil {
		t.Fatalf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedDataWithContentType(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}, []byte("Example data to be signed"))
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSignerNoChain(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		fmt.Printf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

func TestUnmarshalSignedAttribute(t *testing.T) {
	t.Parallel()
	cert, err := createTestCertificate(x509.SHA512WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
	testValue := "TestValue"
	if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{Attribute{Type: oidTest, Value: testValue}},
	}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	var actual string
	err = p7.UnmarshalSignedAttribute(oidTest, &actual)
	if err != nil {
		t.Fatalf("Cannot unmarshal test value: %s", err)
	}
	if testValue != actual {
		t.Errorf("Attribute does not match test value\n\tExpected: %s\n\tActual: %s", testValue, actual)
	}
}

func TestDegenerateCertificate(t *testing.T) {
	t.Parallel()
	cert, err := createTestCertificate(x509.SHA1WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	deg, err := DegenerateCertificate(cert.Certificate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	testOpenSSLParse(t, deg)
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: deg})
}

// writes the cert to a temporary file and tests that openssl can read it.
func testOpenSSLParse(t *testing.T, certBytes []byte) {
	tmpCertFile, err := ioutil.TempFile("", "testCertificate")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCertFile.Name()) // clean up

	if _, err := tmpCertFile.Write(certBytes); err != nil {
		t.Fatal(err)
	}

	opensslCMD := exec.Command("openssl", "pkcs7", "-inform", "der", "-in", tmpCertFile.Name())
	_, err = opensslCMD.Output()
	if err != nil {
		t.Fatal(err)
	}

	if err := tmpCertFile.Close(); err != nil {
		t.Fatal(err)
	}

}
func fromHex(s string) *big.Int {
	result, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return result
}

func TestUnmarshal(t *testing.T) {
	testSignature := `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`
	b, err := base64.StdEncoding.DecodeString(testSignature)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	var content contentInfo
	_, err = asn1.Unmarshal(b, &content)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(content.ContentType)

	var inner signedData
	_, err = asn1.Unmarshal(content.Content.Bytes, &inner)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log("signers", len(inner.SignerInfos))
	if len(inner.SignerInfos) > 0 {
		si := inner.SignerInfos[0]
		t.Logf("version: %d", si.Version)
		t.Logf("issuer Name: %v", string(si.IssuerAndSerialNumber.IssuerName.Bytes))
		t.Logf("serial Number: %v", si.IssuerAndSerialNumber.SerialNumber)
		t.Logf("digest alg: %v", si.DigestAlgorithm)

		t.Log("authentication attributes:")
		for _, attr := range si.AuthenticatedAttributes {
			t.Log("oid", attr.Type)

			var test string
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &test); err == nil {
				t.Log("value string:", test)
			} else {
				t.Log("value", string(attr.Value.Bytes))
			}
		}

		t.Log("unauthentication attributes:")
		for _, attr := range si.UnauthenticatedAttributes {
			t.Log("oid", attr.Type)
		}

		t.Logf("digest algo: %v", si.DigestAlgorithm)
		t.Logf("encrypt algo: %v", si.DigestEncryptionAlgorithm)
		// t.Logf("unauth: %v", si.UnauthenticatedAttributes)
	}

	t.Log("algorithm")
	for _, di := range inner.DigestAlgorithmIdentifiers {
		t.Logf("di: %v", di.Algorithm)
	}

	// t.Log("certificates", string(inner.Certificates.Raw))
	// t.Logf("crls: %d", len(inner.CRLs))
}
