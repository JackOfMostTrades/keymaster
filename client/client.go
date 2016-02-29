package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log"
	"strconv"
	"time"

	"github.com/JackOfMostTrades/keymaster/common"
)

type remoteClient struct {
	hostname    string
	port        int
	tlsCert     *tls.Certificate
	serverCerts []string
}

func createClient(hostname string, port int, tlsCert *tls.Certificate) *remoteClient {
	client := remoteClient{hostname: hostname, port: port, tlsCert: tlsCert}
	client.bootstrap()
	return &client
}
func createNoClientAuth(hostname string, port int) *remoteClient {
	client := remoteClient{hostname: hostname, port: port}
	client.bootstrap()
	return &client
}

func (client *remoteClient) bootstrap() {
	var response []string
	client.doCommand("GetServerCertificates", nil, &response, false)
	client.serverCerts = response
}

func (client *remoteClient) doCommand(commandName string, command interface{}, response interface{}, verifyServer bool) {

	certs := make([]tls.Certificate, 0, 1)
	if client.tlsCert != nil {
		certs = append(certs, *client.tlsCert)
	}

	conn, err := tls.Dial("tcp", client.hostname+":"+strconv.Itoa(client.port), &tls.Config{
		Certificates:       certs,
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("ERROR: Could not connect to server.")
		return
	}
	if verifyServer {
		conn.Handshake()
		if conn.ConnectionState().PeerCertificates[0].NotAfter.Before(time.Now()) {
			log.Printf("ERROR: Server presented expired certificate.")
			conn.Close()
			return
		}
		signature := hex.EncodeToString(conn.ConnectionState().PeerCertificates[0].Signature)
		found := false
		for _, sig := range client.serverCerts {
			if sig == signature {
				found = true
				break
			}
		}
		if !found {
			log.Printf("ERROR: Unable to verify server certificate.")
			conn.Close()
			return
		}
	}

	encoder := json.NewEncoder(conn)
	encoder.Encode(common.CommandName{commandName})
	if command != nil {
		encoder.Encode(command)
	}
	json.NewDecoder(conn).Decode(response)
	conn.Close()
}

func (client *remoteClient) getServerCertificates() []string {
	var response []string
	client.doCommand("GetServerCertificates", nil, &response, true)
	return response
}

func (client *remoteClient) getSecret(secretKey string) []common.Secret {
	var response []common.Secret
	client.doCommand("GetSecrets", common.GetSecretsCommand{secretKey}, &response, true)
	rsaPrivateKey := client.tlsCert.PrivateKey.(*rsa.PrivateKey)
	for i := range response {
		plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, response[i].Secret, nil)
		if err != nil {
			log.Printf("Error decrypting secret: %s", err)
		}
		response[i].Secret = plaintext
	}
	return response
}

func (client *remoteClient) addSecret(secretKey string, secretValue string, validFrom time.Time, validUntil time.Time) string {
	var dbCerts []common.DbCert
	client.doCommand("GetPublicKeys", common.GetPublicKeysCommand{secretKey}, &dbCerts, true)

	var newSecrets []common.Secret
	for _, dbCert := range dbCerts {
		publicCert, err := x509.ParseCertificates(dbCert.Cert)
		if err != nil {
			log.Printf("Unable to parse received certificate.")
			continue
		}
		rsaPublicKey := publicCert[0].PublicKey.(*rsa.PublicKey)
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, []byte(secretValue), nil)
		if err != nil {
			log.Fatalf("Encryption failure.")
		}

		secret := common.Secret{
			CertId:     dbCert.Id,
			Secret:     ciphertext,
			ValidFrom:  validFrom,
			ValidUntil: validUntil,
		}
		newSecrets = append(newSecrets, secret)
	}

	var response string
	client.doCommand("AddSecrets", common.AddSecretsCommand{
		SecretKey: secretKey,
		Secrets:   newSecrets,
	}, &response, true)

	return response
}

func (client *remoteClient) updateClientCert(newCert *tls.Certificate) {
	var newCertId int64
	client.doCommand("AddClientCert", common.AddClientCertCommand{newCert.Certificate[0]}, &newCertId, true)

	oldPrivateKey := client.tlsCert.PrivateKey.(*rsa.PrivateKey)
	publicCert, err := x509.ParseCertificates(newCert.Certificate[0])
	if err != nil {
		log.Printf("Unable to parse certificate.")
		return
	}
	newPublicKey := publicCert[0].PublicKey.(*rsa.PublicKey)

	var oldSecrets map[string][]common.Secret
	client.doCommand("GetAllSecrets", nil, &oldSecrets, true)
	for key, secrets := range oldSecrets {
		for i := range secrets {
			plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, oldPrivateKey, secrets[i].Secret, nil)
			if err != nil {
				log.Printf("Error decrypting secret: %s", err)
				continue
			}
			ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, newPublicKey, plaintext, nil)
			if err != nil {
				log.Printf("Error encrypting secret: %s", err)
				continue
			}
			secrets[i].CertId = newCertId
			secrets[i].Secret = ciphertext
		}

		var response string
		client.doCommand("AddSecrets", common.AddSecretsCommand{
			SecretKey: key,
			Secrets:   secrets,
		}, &response, true)

		if response != "OK" {
			log.Printf("Error setting new secret values: %s", response)
		}
	}

	client.tlsCert = newCert
}
