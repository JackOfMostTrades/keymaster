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
	"sync"
	"time"

	"github.com/JackOfMostTrades/keymaster/common"
)

type Server struct {
	listener     net.Listener
	tlsConfig    *tls.Config
	db           dao
	waitGroup    sync.WaitGroup
	shuttingDown bool

	pollChan    chan int
	pollWaiters []chan int
	pollMutex   sync.Mutex

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

func NewServer(serverCerts []tls.Certificate) *Server {
	return newServerWithDb(serverCerts, NewSqlDao())
}
func newServerWithDb(serverCerts []tls.Certificate, db dao) *Server {

	tlsConfig := &tls.Config{
		Certificates: serverCerts,
		ClientAuth:   tls.RequestClientCert,
	}

	listener, err := tls.Listen("tcp", ":12345", tlsConfig)
	if err != nil {
		log.Fatalf("Unable to start server: %s", err)
	}

	server := &Server{
		listener:     listener,
		tlsConfig:    tlsConfig,
		db:           db,
		waitGroup:    sync.WaitGroup{},
		shuttingDown: false,

		pollChan:    make(chan int),
		pollWaiters: nil,
		pollMutex:   sync.Mutex{},

		ServerRotatePeriod: 4 * time.Hour,
		ServerCertLifetime: 24 * time.Hour,
		ServerPollInterval: 1 * time.Hour,
	}

	server.waitGroup.Add(1)
	go func() {
		log.Printf("Starting server routine.")
		for {
			conn, err := listener.Accept()
			if err == nil {
				go server.handleConnection(conn)
			}
			if server.shuttingDown {
				break
			}
		}
		log.Printf("Server routine exiting.")
		server.waitGroup.Done()
	}()

	server.waitGroup.Add(1)
	go func() {
		log.Printf("Starting server cert refresh routine.")
		for {
			poller := time.NewTimer(server.ServerPollInterval)
			select {
			case <-poller.C:
			case <-server.pollChan:
			}
			poller.Stop()

			var newCerts []tls.Certificate
			lastExpiration := time.Now()
			for _, cert := range serverCerts {
				xCert, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					log.Fatalf("Could not parse loaded x509 certificate.")
				}
				if time.Now().Add(server.ServerPollInterval).Before(xCert.NotAfter) {
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

			server.pollMutex.Lock()
			for i := range server.pollWaiters {
				close(server.pollWaiters[i])
			}
			server.pollWaiters = nil
			server.pollMutex.Unlock()

			if server.shuttingDown {
				break
			}
		}

		log.Printf("Server refresh routine shutdown.")
		server.waitGroup.Done()
	}()

	return server
}

// Wait until the server shuts down. This will generally never happen by itself
// so it will either block forever or wait until some other thread causes it
// to close.
func (server *Server) WaitFor() {
	server.waitGroup.Wait()
}

func (server *Server) Poll() {
	mychan := make(chan int)
	server.pollMutex.Lock()
	server.pollWaiters = append(server.pollWaiters, mychan)
	server.pollMutex.Unlock()

	server.pollChan <- 0
	<-mychan
}

func (server *Server) Close() {
	server.shuttingDown = true
	server.Poll()
	server.db.Close()
	server.listener.Close()
	server.WaitFor()
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
		response := server.getServerCertificates()
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

func (server *Server) getServerCertificates() []string {
	var response []string
	for _, cert := range server.tlsConfig.Certificates {
		xCert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Fatal("Could not parse loaded x509 certificate.")
		}
		response = append(response, hex.EncodeToString(xCert.Signature))
	}
	return response
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
