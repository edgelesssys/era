package edbra

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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

// GetCertificate gets the TLS certificate from the EDB server in PEM format. It performs remote attestation
// to verify the certificate. A config file must be provided that contains the attestation metadata.
func GetCertificate(host, configFilename string) (string, error) {
	config, err := ioutil.ReadFile(configFilename)
	if err != nil {
		return "", err
	}
	return getCertificate(host, config, erthost.VerifyRemoteReport)
}

// InsecureGetCertificate gets the TLS certificate from the EDB server in PEM format, but does not perform remote attestation.
func InsecureGetCertificate(host string) (string, error) {
	return getCertificate(host, nil, nil)
}

// GetManifestSignature gets the manifest signature from the EDB server. The required certificate can be obtained by GetCertificate.
func GetManifestSignature(host, certificate string) (string, error) {
	tlsCfg := tls.Config{RootCAs: x509.NewCertPool()}
	if !tlsCfg.RootCAs.AppendCertsFromPEM([]byte(certificate)) {
		return "", errors.New("Failed to parse certificate")
	}
	resp, err := httpGet(&tlsCfg, host, "signature")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := httpRead(resp)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func getCertificate(host string, config []byte, verifyRemoteReport func([]byte) (ert.Report, error)) (string, error) {
	// Using root as ServerName lets EDB use the root certificate for this connection.
	resp, err := httpGet(&tls.Config{ServerName: "root", InsecureSkipVerify: true}, host, "quote")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	certRaw := resp.TLS.PeerCertificates[0].Raw

	if verifyRemoteReport != nil {
		reportBytes, err := httpRead(resp)
		if err != nil {
			return "", err
		}
		report, err := verifyRemoteReport(reportBytes)
		if err != nil {
			return "", err
		}
		if err := verifyReport(report, certRaw, config); err != nil {
			return "", err
		}
	}

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certRaw})
	if len(cert) <= 0 {
		return "", errors.New("pem encode failed")
	}

	return string(cert), nil
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

func httpGet(tlsConfig *tls.Config, host, path string) (*http.Response, error) {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	url := url.URL{Scheme: "https", Host: host, Path: path}
	return client.Get(url.String())
}

func httpRead(resp *http.Response) ([]byte, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status + ": " + string(body))
	}
	return body, nil
}
