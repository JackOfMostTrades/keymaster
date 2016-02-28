package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/JackOfMostTrades/keymaster/common"
)

type Server struct {
	listener  net.Listener
	tlsConfig *tls.Config
	db        *DbConn

	ServerRotatePeriod time.Duration
	ServerCertLifetime time.Duration
	ServerPollInterval time.Duration
}

func getNewServerCertIndex() int {
	index := 1
	for {
		certFname := fmt.Sprintf("./server_certs/%.4d.crt", index)
		_, err := os.Stat(certFname)
		if err != nil {
			break
		}
		index += 1
	}
	return index
}

func Start(serverCerts []tls.Certificate,
	rotatePeriod time.Duration,
	certLifetime time.Duration,
	pollInterval time.Duration) *Server {
	db := DbOpen()

	tlsConfig := &tls.Config{
		Certificates: serverCerts,
		ClientAuth:   tls.RequestClientCert,
	}

	listener, err := tls.Listen("tcp", ":12345", tlsConfig)
	if err != nil {
		log.Fatalf("Unable to start server: %s", err)
	}

	if rotatePeriod == 0 {
		rotatePeriod = 4 * time.Hour
	}
	if certLifetime == 0 {
		certLifetime = 24 * time.Hour
	}
	if pollInterval == 0 {
		pollInterval = 1 * time.Hour
	}

	server := &Server{
		listener:           listener,
		tlsConfig:          tlsConfig,
		db:                 db,
		ServerRotatePeriod: rotatePeriod,
		ServerCertLifetime: certLifetime,
		ServerPollInterval: pollInterval,
	}

	listenerChan := make(chan int)
	go func() {
		log.Printf("Starting server routine.")
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Server acceptor goroutine is shutting down.")
				return
			}
			go server.handleConnection(conn)
		}
		log.Printf("Server routine exiting.")
		listenerChan <- 0
	}()

	updateServerCertChan := make(chan int)
	go func() {
		log.Printf("Starting server cert refresh routine.")
		for {
			var newCerts []tls.Certificate
			lastExpiration := time.Now()
			for _, cert := range serverCerts {
				xCert, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					log.Fatalf("Could not parse loaded x509 certificate.")
				}
				if time.Now().Before(xCert.NotAfter) {
					newCerts = append(newCerts, cert)
					if xCert.NotAfter.After(lastExpiration) {
						lastExpiration = xCert.NotAfter
					}
				}
			}

			if len(newCerts) == 0 || lastExpiration.Before(time.Now().Add(server.ServerRotatePeriod)) {
				xCert, err := x509.ParseCertificate(serverCerts[0].Certificate[0])
				if err != nil {
					log.Fatalf("Unable to parse loaded x509 certificate.")
				}
				certBytes, privBytes := common.GenCert(xCert.Subject.CommonName, server.ServerCertLifetime)
				// Save the certificate to the server_certs dir
				certIndex := getNewServerCertIndex()
				ioutil.WriteFile(fmt.Sprintf("./server_certs/%.4d.crt", certIndex), certBytes, 0644)
				ioutil.WriteFile(fmt.Sprintf("./server_certs/%.4d.pem", certIndex), privBytes, 0600)

				tlsCert, err := tls.X509KeyPair(certBytes, privBytes)
				if err != nil {
					log.Fatalf("Could not parse bytes of generated certificate.")
				}
				newCerts = append(newCerts, tlsCert)

				newCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
				if err != nil {
					log.Fatalf("Unable to parse generated certificate.")
				}
				log.Printf("Generating new server certificate (%s; %.4d.crt).", hex.EncodeToString(newCert.Signature)[:10], certIndex)
			}

			if len(newCerts) > 0 {
				serverCerts = newCerts
				tlsConfig.Certificates = serverCerts
			}

			time.Sleep(server.ServerPollInterval)
		}
		log.Printf("Server refresh routine shutdown.")
		updateServerCertChan <- 0
	}()

	// Block returning until gorountines return
	<-listenerChan
	<-updateServerCertChan

	return server
}

func (server *Server) Close() {
	server.db.Close()
	server.listener.Close()
}

func (server *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	tconn := conn.(*tls.Conn)
	err := tconn.Handshake()
	if err != nil {
		log.Printf("Error performing TLS handshake: %s", err)
		return
	}

	decoder := json.NewDecoder(conn)
	var commandName common.CommandName
	decoder.Decode(&commandName)

	if commandName.Command == "GetServerCertificates" {
		var response []string
		for _, cert := range server.tlsConfig.Certificates {
			xCert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				log.Fatal("Could not parse loaded x509 certificate.")
			}
			response = append(response, hex.EncodeToString(xCert.Signature))
		}
		json.NewEncoder(conn).Encode(response)
		return
	}

	if len(tconn.ConnectionState().PeerCertificates) < 1 {
		log.Printf("Error: no peer certificates included in connection state.")
		return
	}
	clientCert := tconn.ConnectionState().PeerCertificates[0]
	clientId := clientCert.Subject.CommonName
	signature := hex.EncodeToString(clientCert.Signature)
	dbCertId := server.db.GetClientCertIdBySignature(signature)
	if dbCertId < 0 {
		log.Printf("Unable to find database certificate for client.")
		return
	}
	if time.Now().After(clientCert.NotAfter) {
		log.Printf("Client using expired certificate.")
		return
	}

	var response interface{}
	switch commandName.Command {
	case "GetPublicKeys":
		c := common.GetPublicKeysCommand{}
		decoder.Decode(&c)
		response = server.getPublicKeys(clientId, c)
	case "AddSecrets":
		c := common.AddSecretsCommand{}
		decoder.Decode(&c)
		response = server.addSecrets(clientId, c)
	case "GetSecrets":
		c := common.GetSecretsCommand{}
		decoder.Decode(&c)
		response = server.getSecrets(clientId, dbCertId, c)
	case "GetAllSecrets":
		response = server.getAllSecrets(clientId, dbCertId)
	case "AddClientCert":
		c := common.AddClientCertCommand{}
		decoder.Decode(&c)
		response = server.addClientCert(clientId, c)
	default:
		log.Printf("Unsupported command: %s", commandName.Command)
		return
	}

	json.NewEncoder(conn).Encode(response)
}

func (server *Server) getPublicKeys(clientId string, command common.GetPublicKeysCommand) []common.DbCert {
	return server.db.GetPublicKeys(clientId, command.SecretKey)
}
func (server *Server) getSecrets(clientId string, dbCertId int64, command common.GetSecretsCommand) []common.Secret {
	return server.db.GetSecrets(clientId, dbCertId, command.SecretKey)
}
func (server *Server) addSecrets(clientId string, command common.AddSecretsCommand) string {
	server.db.AddSecrets(clientId, command.SecretKey, command.Secrets)
	return "OK"
}
func (server *Server) addClientCert(clientId string, command common.AddClientCertCommand) int64 {
	publicCert, err := x509.ParseCertificates(command.DerBytes)
	if err != nil {
		log.Printf("ERROR: Unable to parse certificate: %s", err)
		return -1
	}
	return server.db.AddClientCert(clientId, publicCert[0])
}
func (server *Server) getAllSecrets(clientId string, dbCertId int64) map[string][]common.Secret {
	return server.db.GetAllSecretsForClient(clientId, dbCertId)
}
