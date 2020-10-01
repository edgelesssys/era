package era

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
