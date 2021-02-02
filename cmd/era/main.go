package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/edgelesssys/era/era"
)

func main() {
	host := flag.String("h", "", "host address, required")
	configFilename := flag.String("c", "", "config file, required")
	outputRoot := flag.String("output-root", "", "output file for root certificate")
	outputIntermediate := flag.String("output-intermediate", "", "output file for intermediate certificate")
	outputChain := flag.String("output-chain", "", "output file for certificate chain")
	skipQuote := flag.Bool("skip-quote", false, "skip quote verification")
	flag.Parse()

	var noOutputGiven bool
	if *outputRoot == "" && *outputIntermediate == "" && *outputChain == "" {
		noOutputGiven = true
		fmt.Println("ERROR: You need to provide at least one type of output. Check usage for more information.")
	}

	if *host == "" || *configFilename == "" || noOutputGiven {
		flag.Usage()
		return
	}

	var certs []string
	var err error
	if *skipQuote {
		fmt.Println("WARNING: Skipping quote verification")
		certs, err = era.InsecureGetCertificate(*host)
	} else {
		certs, err = era.GetCertificate(*host, *configFilename)
	}

	if err != nil {
		if err == era.ErrEmptyQuote {
			fmt.Println("ERROR: Received an empty quote from host. Is it running in OE Simulation mode?")
			fmt.Println("For testing purposes, you can pass the parameter '-skip-quote' to skip remote attestation.")
		}
		panic(err)
	}

	if len(certs) == 0 {
		panic(errors.New("no certificate retrieved from host"))
	}

	// Write root certificate as PEM to disk
	if *outputRoot != "" {
		if err := ioutil.WriteFile(*outputRoot, []byte(certs[len(certs)-1]), 0644); err != nil {
			panic(err)
		}
		fmt.Println("Root certificate writen to", *outputRoot)
	}

	// Write intermediate certificate as PEM to disk
	if *outputIntermediate != "" {
		if len(certs) > 1 {
			if err := ioutil.WriteFile(*outputIntermediate, []byte(certs[0]), 0644); err != nil {
				panic(err)
			}
			fmt.Println("Intermediate certificate writen to", *outputIntermediate)
		} else {
			fmt.Println("WARNING: No intermediate certificate received.")
		}
	}

	// Write certificate chain as PEM to disk
	if *outputChain != "" {
		if len(certs) > 1 {
			var chain string
			for _, cert := range certs {
				chain += cert
			}

			if err := ioutil.WriteFile(*outputChain, []byte(chain), 0644); err != nil {
				panic(err)
			}

			fmt.Println("Certificate chain writen to", *outputChain)
		} else {
			fmt.Println("WARNING: Only received root certificate from host.")
			fmt.Println("No chain will be saved on disk. Use '-output-root' for products using only a root CA as trust anchor")
		}
	}
}
