package main

import (
	"edglesssys/era/era"
	"flag"
	"fmt"
	"io/ioutil"
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
		panic(err)
	}

	if err := ioutil.WriteFile(*out, []byte(cert), 0644); err != nil {
		panic(err)
	}
}
