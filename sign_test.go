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
	t.Log("itext")
	testUnmarshal(t, `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`)

	t.Log("unipdf")
	testUnmarshal(t, `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`)

	t.Log("unipdf PRD")
	testUnmarshal(t, `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`)
}

func testUnmarshal(t *testing.T, sig string) {
	b, err := base64.StdEncoding.DecodeString(sig)
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

	t.Log("content")
	t.Logf("version: %d", inner.Version)
	t.Log("digest algorithm")
	for _, di := range inner.DigestAlgorithmIdentifiers {
		t.Logf("\t %v: %v", di.Algorithm, di.Parameters)
	}
	t.Logf("content info: %v", inner.ContentInfo)
	t.Log("certificates:")
	certs, err := inner.Certificates.Parse()
	if err == nil {
		for _, cert := range certs {
			t.Logf("\tissuer: %v", cert.Issuer)
			t.Logf("\tserialNumber: %v", cert.SerialNumber)
		}
	}
	t.Log("crl:")
	for _, crl := range inner.CRLs {
		t.Logf("\talgorithm: %v", crl.SignatureAlgorithm)
		t.Logf("\tvalue: %v", crl.SignatureValue)
		t.Logf("\ttbs: %v", crl.TBSCertList)
	}

	t.Log("signers", len(inner.SignerInfos))
	if len(inner.SignerInfos) > 0 {
		si := inner.SignerInfos[0]
		t.Logf("version: %d", si.Version)
		t.Log("issuer:")
		t.Logf("\tissuer Name: %v", string(si.IssuerAndSerialNumber.IssuerName.Bytes))
		t.Logf("\tserial Number: %v", si.IssuerAndSerialNumber.SerialNumber)
		t.Logf("digest alg: %v", si.DigestAlgorithm)

		t.Log("authentication attributes:")
		for _, attr := range si.AuthenticatedAttributes {
			t.Log("\toid", attr.Type)

			var test string
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &test); err == nil {
				t.Log("\tvalue string:", test)
			} else {
				t.Log("\tvalue", base64.StdEncoding.EncodeToString(attr.Value.Bytes))
			}
		}

		t.Logf("encrypt algo: %v", si.DigestEncryptionAlgorithm)

		t.Log("unauthentication attributes:")
		for _, attr := range si.UnauthenticatedAttributes {
			t.Log("\toid", attr.Type)

			var test string
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &test); err == nil {
				t.Log("\tvalue string:", test)
			} else {
				t.Log("\tvalue", base64.StdEncoding.EncodeToString(attr.Value.Bytes))
			}
		}
	}

}
