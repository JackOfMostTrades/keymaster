package client

import (
	"crypto/tls"
	"log"
	"os"
	"time"
)

func AddSecret(args []string) {
	if len(args) != 6 || (len(args) >= 1 && args[0] == "help") {
		log.Fatalf("Usage: %s addSecret <client.crt> <client.pem> <secretKey> <secretValue> <validFrom> <validUntil>", os.Args[0])
	}
	tlsCert, err := tls.LoadX509KeyPair(args[0], args[1])
	if err != nil {
		log.Fatalf("Could not read certificate/key files: %s", err)
	}
	client := createClient("localhost", 12345, &tlsCert)

	validFrom, err := time.Parse(time.RFC3339, args[4])
	if err != nil {
		log.Fatalf("Could not parse validFrom: %s", err)
	}
	validUntil, err := time.Parse(time.RFC3339, args[5])
	if err != nil {
		log.Fatalf("Could not parse validUntil: %s", err)
	}
	response := client.addSecret(args[2], args[3], validFrom, validUntil)
	log.Printf("Response: %s", response)
}

func GetSecret(args []string) {
	if len(args) != 3 || (len(args) >= 1 && args[0] == "help") {
		log.Fatalf("Usage: %s addSecret <client.crt> <client.pem> <secretKey>", os.Args[0])
	}
	tlsCert, err := tls.LoadX509KeyPair(args[0], args[1])
	if err != nil {
		log.Fatalf("Could not read certificate/key files: %s", err)
	}
	client := createClient("localhost", 12345, &tlsCert)
	secrets := client.getSecret(args[2])

	for _, secret := range secrets {
		log.Printf("Secret: `%s` valid from %s until %s", secret.Secret, secret.ValidFrom, secret.ValidUntil)
	}
}

func GetServerCertificates(args []string) {
	if len(args) != 0 || (len(args) == 1 && args[0] == "help") {
		log.Fatalf("Usage: %s getServerCerts", os.Args[0])
	}
	client := createNoClientAuth("localhost", 12345)
	response := client.getServerCertificates()
	log.Printf("Got a response of length: %d", len(response))
	for _, cert := range response {
		log.Printf("  %s", cert)
	}
}
