package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/edgelesssys/edb/edbra"
)

func main() {
	host := flag.String("h", "", "host address, required")
	configFilename := flag.String("c", "", "config file, required")
	out := flag.String("o", "", "output file, required")
	skipQuote := flag.Bool("skip-quote", false, "skip quote verification")
	flag.Parse()
	if *host == "" || *configFilename == "" || *out == "" {
		flag.Usage()
		return
	}

	var cert string
	var err error
	if *skipQuote {
		fmt.Println("Warning: skipping quote verification")
		cert, err = edbra.InsecureGetCertificate(*host)
	} else {
		cert, err = edbra.GetCertificate(*host, *configFilename)
	}

	if err != nil {
		panic(err)
	}

	sig, err := edbra.GetManifestSignature(*host, cert)
	if err != nil {
		fmt.Println("GetManifestSignature failed:", err)
	} else if len(sig) > 0 {
		fmt.Printf("Manifest signature: %v\n", sig)
	}

	if err := ioutil.WriteFile(*out, []byte(cert), 0644); err != nil {
		panic(err)
	}
}
