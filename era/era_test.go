package era

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/edgelesssys/ertgolib/ert"
	"github.com/stretchr/testify/assert"
)

type generalResponse struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"` // only used when status = "error"
}

func TestGetCertificate(t *testing.T) {
	config := []byte(`
{
	"securityVersion": 2,
	"productID": 3,
	"signerID": "ABCD"
}
`)

	assert := assert.New(t)
	var quote []byte
	var cert string

	server, addr, expectedCert := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/quote", r.RequestURI)
		jsn, err := json.Marshal(certQuoteResp{cert, quote})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		w.Write(jsn)
	}))
	cert = expectedCert
	block, _ := pem.Decode([]byte(cert))
	certRaw := block.Bytes
	hash := sha256.Sum256([]byte(certRaw))
	quote = hash[:]

	defer server.Close()

	// get certificate without quote validation
	actualCerts, err := getCertificate(addr, nil, nil)
	assert.Nil(err)
	assert.EqualValues(expectedCert, pem.EncodeToMemory(actualCerts[0]))

	// get certificate with quote validation
	actualCerts, err = getCertificate(addr, config,
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
	assert.EqualValues(expectedCert, pem.EncodeToMemory(actualCerts[0]))

	// verify fails
	actualCerts, err = getCertificate(addr, config,
		func(reportBytes []byte) (ert.Report, error) {
			assert.Equal(quote, reportBytes)
			return ert.Report{}, errors.New("")
		})
	assert.NotNil(err)

	// invalid addr
	actualCerts, err = getCertificate("", nil, nil)
	assert.NotNil(err)

	// invalid hash
	actualCerts, err = getCertificate(addr, config,
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
	actualCerts, err = getCertificate(addr, config,
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
	actualCerts, err = getCertificate(addr, config,
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
	assert.EqualValues(expectedCert, pem.EncodeToMemory(actualCerts[0]))

	// invalid product
	actualCerts, err = getCertificate(addr, config,
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
	actualCerts, err = getCertificate(addr, config,
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

func TestGetCertificateNewFormat(t *testing.T) {
	config := []byte(`
{
	"securityVersion": 2,
	"productID": 3,
	"signerID": "ABCD"
}
`)

	assert := assert.New(t)
	var quote []byte
	var cert string

	server, addr, expectedCert := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/quote", r.RequestURI)
		writeJSON(w, certQuoteResp{cert, quote})
	}))

	cert = expectedCert
	block, _ := pem.Decode([]byte(cert))
	certRaw := block.Bytes
	hash := sha256.Sum256([]byte(certRaw))
	quote = hash[:]

	defer server.Close()

	// get certificate without quote validation
	actualCerts, err := getCertificate(addr, nil, nil)
	assert.Nil(err)
	assert.EqualValues(expectedCert, pem.EncodeToMemory(actualCerts[0]))

	// get certificate with quote validation
	actualCerts, err = getCertificate(addr, config,
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
	assert.EqualValues(expectedCert, pem.EncodeToMemory(actualCerts[0]))
}

func TestGetMultipleCertificates(t *testing.T) {
	config := []byte(`
	{
		"securityVersion": 2,
		"productID": 3,
		"signerID": "ABCD"
	}
	`)

	assert := assert.New(t)
	var quote []byte
	var certs string

	server, addr, expectedCerts := newServerMultipleCertificates(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/quote", r.RequestURI)
		jsn, err := json.Marshal(certQuoteResp{certs, quote})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		w.Write(jsn)
	}))
	certs = expectedCerts[0] + expectedCerts[1]
	block, _ := pem.Decode([]byte(expectedCerts[1])) // last one is supposed to be root CA, which we use for quoting
	certRaw := block.Bytes
	hash := sha256.Sum256([]byte(certRaw))
	quote = hash[:]

	defer server.Close()

	// get certificates without quote validation
	actualCerts, err := getCertificate(addr, nil, nil)
	assert.Nil(err)
	assert.EqualValues(expectedCerts[0], pem.EncodeToMemory(actualCerts[0]))
	assert.EqualValues(expectedCerts[1], pem.EncodeToMemory(actualCerts[1]))

	// get certificates with quote validation
	actualCerts, err = getCertificate(addr, config,
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
	assert.EqualValues(expectedCerts[0], pem.EncodeToMemory(actualCerts[0]))
	assert.EqualValues(expectedCerts[1], pem.EncodeToMemory(actualCerts[1]))
}

func newServer(handler http.Handler) (server *httptest.Server, addr string, cert string) {
	s := httptest.NewTLSServer(handler)
	return s, s.Listener.Addr().String(), toPEM(s.Certificate().Raw)
}

func newServerMultipleCertificates(handler http.Handler) (server *httptest.Server, addr string, certs []string) {
	// Create a second test certificate
	key, err := rsa.GenerateKey(rand.Reader, 3096)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		IsCA:         false,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}

	testCertRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	s := httptest.NewTLSServer(handler)
	expectedCerts := []string{toPEM(testCertRaw), toPEM(s.Certificate().Raw)}
	return s, s.Listener.Addr().String(), expectedCerts
}

func toPEM(certificate []byte) string {
	result := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if len(result) <= 0 {
		panic("EncodeToMemory failed")
	}
	return string(result)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	dataToReturn := generalResponse{Status: "success", Data: v}
	if err := json.NewEncoder(w).Encode(dataToReturn); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
