package main

import "C"
import "github.com/edgelesssys/edb/edbra"

func main() {}

//export edbGetCertificate
func edbGetCertificate(host, configFilename *C.char, certificate **C.char) *C.char {
	cert, err := edbra.GetCertificate(C.GoString(host), C.GoString(configFilename))
	if err != nil {
		return C.CString(err.Error())
	}
	*certificate = C.CString(cert)
	return nil
}

//export edbInsecureGetCertificate
func edbInsecureGetCertificate(host *C.char, certificate **C.char) *C.char {
	cert, err := edbra.InsecureGetCertificate(C.GoString(host))
	if err != nil {
		return C.CString(err.Error())
	}
	*certificate = C.CString(cert)
	return nil
}

//export edbGetManifestSignature
func edbGetManifestSignature(host, certificate *C.char, signature **C.char) *C.char {
	sig, err := edbra.GetManifestSignature(C.GoString(host), C.GoString(certificate))
	if err != nil {
		return C.CString(err.Error())
	}
	*signature = C.CString(sig)
	return nil
}
