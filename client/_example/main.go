package main

import (
	"log"
	"time"

	"github.com/JackOfMostTrades/keymaster/client"
)

func main() {
	client, err := client.Init("localhost", 12345, "applejack.crt", "applejack.pem", []string{
		"root_database_password"})
	if err != nil {
		log.Fatalf("Could not create client: %s", err)
	}
	client.ClientCertLifetime = 2 * time.Minute
	client.ClientRotatePeriod = 2 * time.Minute
	client.PollInterval = 1 * time.Minute
	client.Poll()

	for {
		log.Printf("root_database_password: %s", client.GetSecret("root_database_password"))
		time.Sleep(10 * time.Second)
	}
}
