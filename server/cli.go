package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

func ImportClientCert(args []string) {
	if len(args) != 1 || (len(args) >= 1 && args[0] == "help") {
		fmt.Printf("Usage: %s importCert <certname.crt>\n", os.Args[0])
		os.Exit(1)
	}

	certBytes, err := ioutil.ReadFile(args[0])
	if err != nil {
		log.Fatalf("Error reading certificate file: %s", err)
	}
	pemBlock, _ := pem.Decode(certBytes)
	if pemBlock == nil {
		log.Fatalf("Unable to parse PEM block from certificate file.")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		log.Fatalf("Error parsing certificate file: %s", err)
	}

	db := DbOpen()
	db.AddClientCert(cert.Subject.CommonName, cert)
}

func RunServer(args []string) {
	if (len(args) > 3) || (len(args) >= 1 && args[0] == "help") {
		fmt.Printf("Usage: %s server [certRefreshInterval [certLifetime [pollInterval]]] \n", os.Args[0])
		os.Exit(1)
	}

	var certs []tls.Certificate
	certDir, err := os.Open("./server_certs")
	if err != nil {
		log.Fatalf("Could not read server certificates directory: %s", err)
	}
	files, err := certDir.Readdir(0)
	if err != nil {
		log.Fatalf("Could not read server certificates files.")
	}
	for _, fileinfo := range files {
		if fileinfo.IsDir() {
			continue
		}
		if !strings.HasSuffix(fileinfo.Name(), ".crt") {
			continue
		}
		certFname := fmt.Sprintf("./server_certs/%s", fileinfo.Name())
		pemFname := fmt.Sprintf("./server_certs/%s.pem", fileinfo.Name()[:len(fileinfo.Name())-4])
		_, err = os.Stat(pemFname)
		if err != nil {
			continue
		}

		log.Printf("Reading server certificate files: %s %s\n", certFname, pemFname)

		certBytes, err := ioutil.ReadFile(certFname)
		if err != nil {
			log.Fatalf("Could not read file: %s", err)
		}
		pemBlock, _ := pem.Decode(certBytes)
		if pemBlock == nil {
			log.Fatalf("Unable to parse PEM block from certificate file.")
		}
		publicCert, err := x509.ParseCertificates(pemBlock.Bytes)
		if err != nil {
			log.Fatalf("Could not decode certificate.")
		}
		if time.Now().After(publicCert[0].NotAfter) {
			continue
		}

		privBytes, err := ioutil.ReadFile(pemFname)
		if err != nil {
			log.Fatalf("Could not read file: %s", err)
		}

		tlsCert, err := tls.X509KeyPair(certBytes, privBytes)
		if err != nil {
			log.Fatalf("Unable to build TLS certificate: %s", err)
		}
		certs = append(certs, tlsCert)
	}

	if len(certs) == 0 {
		log.Fatalf("No current certificates found.")
	}

	var certRefreshInterval time.Duration = 0
	if len(args) > 0 {
		certRefreshInterval, err = time.ParseDuration(args[0])
		if err != nil {
			log.Fatalf("Could not parse duration argument: %s", err)
		}
	}
	var certLifetime time.Duration = 0
	if len(args) > 1 {
		certLifetime, err = time.ParseDuration(args[1])
		if err != nil {
			log.Fatalf("Could not parse lifetime argument: %s", err)
		}
	}
	var pollInterval time.Duration = 0
	if len(args) > 2 {
		pollInterval, err = time.ParseDuration(args[2])
		if err != nil {
			log.Fatalf("Could not parse poll interval argument: %s", err)
		}
	}

	Start(certs, certRefreshInterval, certLifetime, pollInterval)
}
