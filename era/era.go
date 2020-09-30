package era

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/edgelesssys/ertgolib/ert"
	"github.com/edgelesssys/ertgolib/erthost"
)

type certQuoteResp struct {
	Cert  string
	Quote []byte
}

// GetCertificate gets the TLS certificate from the server in PEM format. It performs remote attestation
// to verify the certificate. A config file must be provided that contains the attestation metadata.
func GetCertificate(host, configFilename string) (string, error) {
	config, err := ioutil.ReadFile(configFilename)
	if err != nil {
		return "", err
	}
	return getCertificate(host, config, erthost.VerifyRemoteReport)
}

// InsecureGetCertificate gets the TLS certificate from the server in PEM format, but does not perform remote attestation.
func InsecureGetCertificate(host string) (string, error) {
	return getCertificate(host, nil, nil)
}

func getCertificate(host string, config []byte, verifyRemoteReport func([]byte) (ert.Report, error)) (string, error) {
	cert, quote, err := httpGetCertQuote(&tls.Config{InsecureSkipVerify: true}, host, "quote")
	if err != nil {
		return "", err
	}

	if verifyRemoteReport != nil {

		report, err := verifyRemoteReport(quote)
		if err != nil {
			return "", err
		}
		//todo how to convert cert in PEM(string) to raw

		block, _ := pem.Decode([]byte(cert))
		certRaw := block.Bytes

		if err := verifyReport(report, certRaw, config); err != nil {
			return "", err
		}
	}

	return cert, nil
}

func verifyReport(report ert.Report, cert []byte, config []byte) error {
	hash := sha256.Sum256(cert)
	if !bytes.Equal(report.Data[:len(hash)], hash[:]) {
		return errors.New("report data does not match the certificate's hash")
	}

	var cfg struct {
		SecurityVersion uint
		UniqueID        string
		SignerID        string
		ProductID       uint16
	}
	if err := json.Unmarshal(config, &cfg); err != nil {
		return err
	}
	if cfg.SecurityVersion == 0 {
		return errors.New("missing securityVersion in config")
	}
	if cfg.ProductID == 0 {
		return errors.New("missing productID in config")
	}

	if report.SecurityVersion < cfg.SecurityVersion {
		return errors.New("invalid security version")
	}
	if binary.LittleEndian.Uint16(report.ProductID) != cfg.ProductID {
		return errors.New("invalid product")
	}
	if err := verifyID(cfg.UniqueID, report.UniqueID, "unqiueID"); err != nil {
		return err
	}
	if err := verifyID(cfg.SignerID, report.SignerID, "signerID"); err != nil {
		return err
	}
	if cfg.UniqueID == "" && cfg.SignerID == "" {
		fmt.Println("Warning: Configuration contains neither uniqueID nor signerID!")
	}

	return nil
}

func verifyID(expected string, actual []byte, name string) error {
	if expected == "" {
		return nil
	}
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedBytes, actual) {
		return errors.New("invalid " + name)
	}
	return nil
}

func httpGetCertQuote(tlsConfig *tls.Config, host, path string) (string, []byte, error) {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	url := url.URL{Scheme: "https", Host: host, Path: path}
	resp, err := client.Get(url.String())
	if err != nil {
		return "", nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	var certquote certQuoteResp
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, errors.New(resp.Status + ": " + string(body))
	}
	err = json.Unmarshal(body, &certquote)
	if err != nil {
		return "", nil, err
	}
	resp.Body.Close()
	return certquote.Cert, certquote.Quote, nil
}
