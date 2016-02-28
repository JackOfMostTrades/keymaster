package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/JackOfMostTrades/keymaster/client"
	"github.com/JackOfMostTrades/keymaster/server"
	"github.com/JackOfMostTrades/keymaster/util"
)

func usage() {
	fmt.Printf("Usage: %s <command> <command_arg1> ...\n", os.Args[0])
	fmt.Printf("    Commands: genCert importClientCert server addSecret getSecret getServerCerts help\n")
	fmt.Printf("Use %s <command> help for more information about that command.\n", os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "genCert":
		genCert(os.Args[2:])
	case "importClientCert":
		server.ImportClientCert(os.Args[2:])
	case "server":
		server.RunServer(os.Args[2:])
	case "addSecret":
		client.AddSecret(os.Args[2:])
	case "getSecret":
		client.GetSecret(os.Args[2:])
	case "getServerCerts":
		client.GetServerCertificates(os.Args[2:])
	case "help":
		usage()
	default:
		usage()
	}
}

func genCert(args []string) {
	if len(args) != 4 || (len(args) >= 1 && args[0] == "help") {
		fmt.Printf("Usage: %s genCert <hostname> <lifetime> <output.crt> <output.pem>\n", os.Args[0])
		os.Exit(1)
	}
	lifetime, err := time.ParseDuration(args[1])
	if err != nil {
		log.Fatalf("Unable to parse lifetime argument: %s", err)
	}

	cert, priv := util.GenCert(args[0], lifetime)
	err = ioutil.WriteFile(args[2], cert, 0644)
	if err != nil {
		log.Fatalf("Error writing file: %s", err)
	}
	err = ioutil.WriteFile(args[3], priv, 0600)
	if err != nil {
		log.Fatalf("Error writing file: %s", err)
	}
}
