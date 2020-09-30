package era

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/edgelesssys/ertgolib/ert"
	"github.com/stretchr/testify/assert"
)

func TestGetCertificate(t *testing.T) {
	config := []byte(`
{
	"securityVersion": 2,
	"productID": 3,
	"signerID": "ABCD"
}
`)

	assert := assert.New(t)
	quote := []byte{2, 3, 4}

	server, addr, expectedCert := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/quote", r.RequestURI)
		w.Write(quote)
	}))
	defer server.Close()

	hash := sha256.Sum256(server.Certificate().Raw)

	// get certificate without quote validation
	actualCert, err := getCertificate(addr, nil, nil)
	assert.Nil(err)
	assert.Equal(expectedCert, actualCert)

	// get certificate with quote validation
	actualCert, err = getCertificate(addr, config,
		func(reportBytes []byte) (ert.Report, error) {
			assert.Equal(quote, reportBytes)
			return ert.Report{
				Data:            hash[:],
				SecurityVersion: 2,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			}, nil
		})
	assert.Nil(err)
	assert.Equal(expectedCert, actualCert)

	// verify fails
	actualCert, err = getCertificate(addr, config,
		func(reportBytes []byte) (ert.Report, error) {
			assert.Equal(quote, reportBytes)
			return ert.Report{}, errors.New("")
		})
	assert.NotNil(err)

	// invalid addr
	actualCert, err = getCertificate("", nil, nil)
	assert.NotNil(err)

	// invalid hash
	actualCert, err = getCertificate(addr, config,
		func(reportBytes []byte) (ert.Report, error) {
			assert.Equal(quote, reportBytes)
			hashCopy := hash
			hashCopy[2] ^= 0xFF
			r := ert.Report{
				Data:            hashCopy[:],
				SecurityVersion: 2,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			}
			return r, nil
		})
	assert.NotNil(err)

	// invalid security version
	actualCert, err = getCertificate(addr, config,
		func(reportBytes []byte) (ert.Report, error) {
			assert.Equal(quote, reportBytes)
			return ert.Report{
				Data:            hash[:],
				SecurityVersion: 1,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			}, nil
		})
	assert.NotNil(err)

	// newer security version
	actualCert, err = getCertificate(addr, config,
		func(reportBytes []byte) (ert.Report, error) {
			assert.Equal(quote, reportBytes)
			return ert.Report{
				Data:            hash[:],
				SecurityVersion: 3,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			}, nil
		})
	assert.Nil(err)
	assert.Equal(expectedCert, actualCert)

	// invalid product
	actualCert, err = getCertificate(addr, config,
		func(reportBytes []byte) (ert.Report, error) {
			assert.Equal(quote, reportBytes)
			return ert.Report{
				Data:            hash[:],
				SecurityVersion: 2,
				ProductID:       []byte{0x04, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			}, nil
		})
	assert.NotNil(err)

	// invalid signer
	actualCert, err = getCertificate(addr, config,
		func(reportBytes []byte) (ert.Report, error) {
			assert.Equal(quote, reportBytes)
			return ert.Report{
				Data:            hash[:],
				SecurityVersion: 2,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCE},
			}, nil
		})
	assert.NotNil(err)
}

func TestGetManifestSignature(t *testing.T) {
	assert := assert.New(t)
	const expectedSig = "foo"

	server, addr, cert := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/signature", r.RequestURI)
		io.WriteString(w, expectedSig)
	}))
	defer server.Close()

	// get signature with valid addr and cert
	sig, err := GetManifestSignature(addr, cert)
	assert.Nil(err)
	assert.Equal(expectedSig, sig)

	// invalid addr
	_, err = GetManifestSignature("", cert)
	assert.NotNil(err)

	// invalid certificate
	_, err = GetManifestSignature(addr, "")
	assert.NotNil(err)

	// wrong certificate
	_, err = GetManifestSignature(addr, createCertificate())
	assert.NotNil(err)
}

func newServer(handler http.Handler) (server *httptest.Server, addr string, cert string) {
	s := httptest.NewTLSServer(handler)
	return s, s.Listener.Addr().String(), toPEM(s.Certificate().Raw)
}

func toPEM(certificate []byte) string {
	result := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if len(result) <= 0 {
		panic("EncodeToMemory failed")
	}
	return string(result)
}

func createCertificate() string {
	template := &x509.Certificate{
		SerialNumber: &big.Int{},
		Subject:      pkix.Name{CommonName: "localhost"},
		NotAfter:     time.Now().Add(time.Hour),
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	return toPEM(cert)
}
