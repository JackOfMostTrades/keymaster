package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/JackOfMostTrades/keymaster/common"
)

type stubServer struct {
	listener  net.Listener
	tlsConfig *tls.Config
	waitGroup sync.WaitGroup

	requestLog  [][]interface{}
	secrets     map[string][]common.Secret
	clientCerts map[int64]*x509.Certificate
}

func NewStubServer() *stubServer {
	certBytes, privBytes := common.GenCert("keymaster.local", time.Hour)
	serverCert, _ := tls.X509KeyPair(certBytes, privBytes)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
	}

	listener, err := tls.Listen("tcp", ":12345", tlsConfig)
	if err != nil {
		return nil
	}

	server := &stubServer{
		listener:  listener,
		tlsConfig: tlsConfig,
		waitGroup: sync.WaitGroup{},

		requestLog:  nil,
		secrets:     make(map[string][]common.Secret),
		clientCerts: make(map[int64]*x509.Certificate),
	}

	server.waitGroup.Add(1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				break
			}
			go server.handleStubRequest(conn)
		}
		server.waitGroup.Done()
	}()

	return server
}

func (server *stubServer) handleStubRequest(conn net.Conn) {
	reader := json.NewDecoder(conn)
	writer := json.NewEncoder(conn)

	var clientCertId int64 = -1
	tlsConn := conn.(*tls.Conn)
	tlsConn.Handshake()
	clientSig := tlsConn.ConnectionState().PeerCertificates[0].Signature
	for key, cert := range server.clientCerts {
		if bytes.Equal(cert.Signature, clientSig) {
			clientCertId = key
			break
		}
	}

	var commandName common.CommandName
	reader.Decode(&commandName)

	var commandObj interface{}
	var response interface{}

	switch commandName.Command {
	case "GetServerCertificates":
		activeCert, _ := x509.ParseCertificate(server.tlsConfig.Certificates[0].Certificate[0])
		response = []string{hex.EncodeToString(activeCert.Signature)}
	case "GetSecrets":
		var c common.GetSecretsCommand
		reader.Decode(&c)
		commandObj = c
		var secretsOut []common.Secret = nil
		secrets, ok := server.secrets[c.SecretKey]
		if ok {
			for _, secret := range secrets {
				if secret.CertId == clientCertId {
					secretsOut = append(secretsOut, secret)
				}
			}
		}
		response = secretsOut
	case "GetAllSecrets":
		secrets := make(map[string][]common.Secret)
		for key, secretList := range server.secrets {
			secrets[key] = nil
			for _, secret := range secretList {
				if secret.CertId == clientCertId {
					secrets[key] = append(secrets[key], secret)
				}
			}
		}
		response = secrets
	case "AddSecrets":
		var c common.AddSecretsCommand
		reader.Decode(&c)
		commandObj = c
		for _, secret := range c.Secrets {
			server.secrets[c.SecretKey] = append(server.secrets[c.SecretKey], secret)
		}
		response = "OK"
	case "AddClientCertificate":
		var c common.AddClientCertCommand
		reader.Decode(&c)
		commandObj = c
		certId := int64(len(server.clientCerts) + 1)
		server.clientCerts[certId], _ = x509.ParseCertificate(c.DerBytes)
		response = certId
	}

	server.requestLog = append(server.requestLog, []interface{}{
		commandName.Command, commandObj,
	})
	writer.Encode(response)
	conn.Close()
}
func (server *stubServer) close() {
	server.listener.Close()
	server.waitGroup.Wait()
}

func TestClientCertRotation(t *testing.T) {
	server := NewStubServer()
	defer server.close()

	certBytes, privBytes := common.GenCert("client.local", time.Hour)
	ioutil.WriteFile("test.crt", certBytes, 0644)
	ioutil.WriteFile("test.pem", privBytes, 0600)
	defer os.Remove("test.crt")
	defer os.Remove("test.pem")

	pemBytes, _ := pem.Decode(certBytes)
	xCert, _ := x509.ParseCertificate(pemBytes.Bytes)
	server.clientCerts[1] = xCert

	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, xCert.PublicKey.(*rsa.PublicKey), []byte("value1"), nil)
	server.secrets["secret1"] = []common.Secret{common.Secret{1, ciphertext, time.Now(), time.Now().Add(time.Hour)}}
	ciphertext, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, xCert.PublicKey.(*rsa.PublicKey), []byte("value3"), nil)
	server.secrets["secret3"] = []common.Secret{common.Secret{1, ciphertext, time.Now(), time.Now().Add(time.Hour)}}

	client, _ := Init("localhost", 12345, "test.crt", "test.pem", []string{"secret1", "secret2"})
	defer client.Close()
	if !bytes.Equal(client.client.tlsCert.Certificate[0], pemBytes.Bytes) {
		t.Error("Active client certificate doesn't match expected bytes.")
	}
	if string(client.GetSecret("secret1")) != "value1" {
		t.Error("Unable to get initial secret1")
	}

	client.ClientRotatePeriod = time.Hour
	client.Poll()
	if bytes.Equal(client.client.tlsCert.Certificate[0], pemBytes.Bytes) {
		t.Error("Expected client to rotate active certificate.")
	}
	certBytes, _ = ioutil.ReadFile("test.crt")
	pemBytes, _ = pem.Decode(certBytes)
	if !bytes.Equal(client.client.tlsCert.Certificate[0], pemBytes.Bytes) {
		t.Error("Active certificate doesn't match filesystem certificate.")
	}

	privBytes, _ = ioutil.ReadFile("test.pem")
	tlsCert, _ := tls.X509KeyPair(certBytes, privBytes)
	plaintext, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, tlsCert.PrivateKey.(*rsa.PrivateKey), server.secrets["secret1"][1].Secret, nil)
	if string(plaintext) != "value1" {
		t.Error("Secret not updated to use new client certificate.")
	}
	plaintext, _ = rsa.DecryptOAEP(sha256.New(), rand.Reader, tlsCert.PrivateKey.(*rsa.PrivateKey), server.secrets["secret3"][1].Secret, nil)
	if string(plaintext) != "value3" {
		t.Error("Secret not updated to use new client certificate.")
	}
}
func TestClientSecretRefresh(t *testing.T) {
	server := NewStubServer()
	defer server.close()

	certBytes, privBytes := common.GenCert("client.local", 100*time.Hour)
	ioutil.WriteFile("test.crt", certBytes, 0644)
	ioutil.WriteFile("test.pem", privBytes, 0600)
	defer os.Remove("test.crt")
	defer os.Remove("test.pem")

	pemBytes, _ := pem.Decode(certBytes)
	xCert, _ := x509.ParseCertificate(pemBytes.Bytes)
	server.clientCerts[1] = xCert

	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, xCert.PublicKey.(*rsa.PublicKey), []byte("value1"), nil)
	server.secrets["secret1"] = []common.Secret{common.Secret{1, ciphertext, time.Now(), time.Now().Add(time.Hour)}}
	ciphertext, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, xCert.PublicKey.(*rsa.PublicKey), []byte("value2"), nil)
	server.secrets["secret2"] = []common.Secret{common.Secret{1, ciphertext, time.Now(), time.Now().Add(time.Hour)}}

	client, _ := Init("localhost", 12345, "test.crt", "test.pem", []string{"secret1", "secret2"})
	defer client.Close()

	client.Poll()
	if string(client.GetSecret("secret1")) != "value1" {
		t.Error("Got incorrect initial value for secret1")
	}
	if string(client.GetSecret("secret2")) != "value2" {
		t.Error("Got incorrect initial value for secret2")
	}

	ciphertext, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, xCert.PublicKey.(*rsa.PublicKey), []byte("value3"), nil)
	server.secrets["secret2"] = append(server.secrets["secret2"], common.Secret{1, ciphertext, time.Now(), time.Now().Add(time.Hour)})

	client.Poll()
	if string(client.GetSecret("secret1")) != "value1" {
		t.Error("Got incorrect new value for secret1")
	}
	if string(client.GetSecret("secret2")) != "value3" {
		t.Error("Got incorrect new value for secret2")
	}
}
func TestClientSecretRotation(t *testing.T) {
	server := NewStubServer()
	defer server.close()

	certBytes, privBytes := common.GenCert("client.local", 100*time.Hour)
	ioutil.WriteFile("test.crt", certBytes, 0644)
	ioutil.WriteFile("test.pem", privBytes, 0600)
	defer os.Remove("test.crt")
	defer os.Remove("test.pem")

	pemBytes, _ := pem.Decode(certBytes)
	xCert, _ := x509.ParseCertificate(pemBytes.Bytes)
	server.clientCerts[1] = xCert

	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, xCert.PublicKey.(*rsa.PublicKey), []byte("value1"), nil)
	server.secrets["secret1"] = []common.Secret{common.Secret{1, ciphertext, time.Now(), time.Now().Add(time.Hour)}}

	client, _ := Init("localhost", 12345, "test.crt", "test.pem", []string{"secret1"})
	defer client.Close()

	client.Poll()
	if string(client.GetSecret("secret1")) != "value1" {
		t.Error("Got incorrect initial value for secret1")
	}

	ciphertext, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, xCert.PublicKey.(*rsa.PublicKey), []byte("value2"), nil)
	server.secrets["secret1"] = append(server.secrets["secret1"], common.Secret{1, ciphertext, time.Now().Add(2 * time.Second), time.Now().Add(time.Hour)})

	client.Poll()
	if string(client.GetSecret("secret1")) != "value1" {
		t.Error("Got incorrect new value for secret1")
	}
	// The new value should be seen after the sleep even though there won't be a new poll
	time.Sleep(2 * time.Second)
	if string(client.GetSecret("secret1")) != "value2" {
		t.Error("Got incorrect new value for secret1")
	}
}
