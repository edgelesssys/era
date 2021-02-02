package main

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/edgelesssys/era/era"
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
		cert, err = era.InsecureGetCertificate(*host)
	} else {
		cert, err = era.GetCertificate(*host, *configFilename)
	}

	if err != nil {
		if err == era.ErrEmptyQuote {
			fmt.Println("ERROR: Received an empty quote from host. Is it running in OE Simulation mode?")
			fmt.Println("For testing purposes, you can pass the parameter '-skip-quote' to skip remote attestation.")
		}
		panic(err)
	}

	if err := ioutil.WriteFile(*out, []byte(cert), 0644); err != nil {
		panic(err)
	}
	fmt.Println("SUCCESS, certificate writen to", *out)
}
