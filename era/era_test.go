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

	"github.com/edgelesssys/ego/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type generalResponse struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"` // only used when status = "error"
}

func TestGetCertificate(t *testing.T) {
	signerConfig := `
{
	"securityVersion": 2,
	"productID": 3,
	"signerID": "ABCD"
}`
	signerReport := &attestation.Report{
		SecurityVersion: 2,
		ProductID:       []byte{0x03, 0x00},
		SignerID:        []byte{0xAB, 0xCD},
	}

	testCases := map[string]struct {
		config    string
		report    *attestation.Report
		verifyErr error
		expectErr bool
	}{
		"get certificate without quote validation": {},
		"get certificate with quote validation": {
			config: signerConfig,
			report: signerReport,
		},
		"verify fails": {
			config:    signerConfig,
			report:    signerReport,
			verifyErr: errors.New("failed"),
			expectErr: true,
		},
		"invalid hash": {
			config: signerConfig,
			report: &attestation.Report{
				Data:            make([]byte, 64),
				SecurityVersion: 2,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			},
			expectErr: true,
		},
		"invalid security version": {
			config: signerConfig,
			report: &attestation.Report{
				SecurityVersion: 1,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			},
			expectErr: true,
		},
		"newer security version": {
			config: signerConfig,
			report: &attestation.Report{
				SecurityVersion: 3,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			},
		},
		"invalid product": {
			config: signerConfig,
			report: &attestation.Report{
				SecurityVersion: 2,
				ProductID:       []byte{0x04, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			},
			expectErr: true,
		},
		"invalid signer": {
			config: signerConfig,
			report: &attestation.Report{
				SecurityVersion: 2,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCE},
			},
			expectErr: true,
		},
		"missing productID": {
			config:    `{"securityVersion":2, "signerID":"ABCD"}`,
			report:    signerReport,
			expectErr: true,
		},
		"missing securityVersion": {
			config:    `{"productID":3, "signerID":"ABCD"}`,
			report:    signerReport,
			expectErr: true,
		},
		"uniqeID": {
			config: `{"uniqueID":"ABCD"}`,
			report: &attestation.Report{
				UniqueID: []byte{0xAB, 0xCD},
			},
		},
		"invalid uniqeID": {
			config: `{"uniqueID":"ABCD"}`,
			report: &attestation.Report{
				UniqueID: []byte{0xAB, 0xCE},
			},
			expectErr: true,
		},
		"debug enclave not allowed": {
			config: `{"uniqueID":"ABCD"}`,
			report: &attestation.Report{
				UniqueID: []byte{0xAB, 0xCD},
				Debug:    true,
			},
			expectErr: true,
		},
		"debug enclave allowed": {
			config: `{"uniqueID":"ABCD", "debug":true}`,
			report: &attestation.Report{
				UniqueID: []byte{0xAB, 0xCD},
				Debug:    true,
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

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
			defer server.Close()

			cert = expectedCert
			block, _ := pem.Decode([]byte(cert))
			certRaw := block.Bytes
			hash := sha256.Sum256([]byte(certRaw))
			quote = hash[:]

			var verify verifyFunc
			if tc.report != nil {
				verify = func(reportBytes []byte) (attestation.Report, error) {
					assert.Equal(quote, reportBytes)
					report := *tc.report
					if report.Data == nil {
						report.Data = hash[:]
					}
					return report, tc.verifyErr
				}
			}

			actualCerts, err := getCertificate(addr, []byte(tc.config), verify)
			if tc.expectErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.EqualValues(expectedCert, pem.EncodeToMemory(actualCerts[0]))
		})
	}
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
		func(reportBytes []byte) (attestation.Report, error) {
			assert.Equal(quote, reportBytes)
			return attestation.Report{
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
		func(reportBytes []byte) (attestation.Report, error) {
			assert.Equal(quote, reportBytes)
			return attestation.Report{
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
