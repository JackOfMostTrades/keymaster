package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/JackOfMostTrades/keymaster/common"
)

func createServer(t *testing.T) *Server {
	certBytes, pemBytes := common.GenCert("keymaster.local", 2*time.Second)
	tlsCert, err := tls.X509KeyPair(certBytes, pemBytes)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	db := NewTestDao()
	server := newServerWithDb([]tls.Certificate{tlsCert}, db)
	server.ServerCertLifetime = 60 * time.Second
	server.ServerPollInterval = 1 * time.Hour
	server.ServerRotatePeriod = 60 * time.Second

	return server
}

func getCertSig(cert []byte) string {
	xCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(xCert.Signature)
}

func TestGetCertificatesAndRotation(t *testing.T) {
	server := createServer(t)
	defer server.Close()

	serverSig := getCertSig(server.tlsConfig.Certificates[0].Certificate[0])
	certs := server.getServerCertificates()
	if len(certs) != 1 {
		t.Errorf("Server should have 1 certificate, but has %d", len(certs))
	}
	if certs[0] != serverSig {
		t.Errorf("Got unexpected certificate from server.")
	}

	server.Poll() // This will cause a new certificate to get generated
	certs = server.getServerCertificates()
	if len(certs) != 2 {
		t.Errorf("Server should have 2 certificates, but has %d", len(certs))
	}
	if certs[0] != serverSig {
		t.Errorf("Got unexpected certificate from server.")
	}
	if certs[1] == serverSig {
		t.Errorf("Got unexpected certificate from server.")
	}

	time.Sleep(2 * time.Second) // The original cert was a 2-second lifetime, so this should cause it to expire
	server.Poll()               // The server will now expire the first cert, activate the second, and generate a third
	newCerts := server.getServerCertificates()
	if len(newCerts) != 2 {
		t.Errorf("Server should have 2 certificates, but has %d", len(newCerts))
	}
	if newCerts[0] != certs[1] {
		t.Errorf("Got unexpected certificate from server.")
	}
	if getCertSig(server.tlsConfig.Certificates[0].Certificate[0]) != certs[1] {
		t.Error("Server did not switch current certificate after the original expired.")
	}
}

func doClientCommand(tlsCert *tls.Certificate, commandName string, command interface{}, result interface{}) {
	var certs []tls.Certificate
	if tlsCert != nil {
		certs = append(certs, *tlsCert)
	}
	conn, err := tls.Dial("tcp", "localhost:12345", &tls.Config{
		Certificates:       certs,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer conn.Close()

	writer := json.NewEncoder(conn)
	reader := json.NewDecoder(conn)
	writer.Encode(common.CommandName{commandName})
	if command != nil {
		writer.Encode(command)
	}
	reader.Decode(result)
}

func TestVerifyClientCert(t *testing.T) {
	server := createServer(t)
	defer server.Close()

	server.db.(*TestDao).clients = map[int64]string{1: "foo.bar"}
	server.db.(*TestDao).clientPerms = map[int64]map[string][]bool{1: map[string][]bool{"mysecret": []bool{true, true}}}

	// Verify we can get server certs without client-side cert
	var serverCerts []string = nil
	doClientCommand(nil, "GetServerCertificates", nil, &serverCerts)
	if len(serverCerts) != 1 {
		t.Errorf("Incorrect number of server certificates returned: %d", len(serverCerts))
	}
	if serverCerts[0] != getCertSig(server.tlsConfig.Certificates[0].Certificate[0]) {
		t.Error("Returned server signature doesn't match server's current signature.")
	}

	// Generate initial client cert
	certBytes, pemBytes := common.GenCert("foo.bar", 2*time.Second)
	clientCert, _ := tls.X509KeyPair(certBytes, pemBytes)

	// Verify we can get server certs with an invalid client-side cert
	serverCerts = nil
	doClientCommand(&clientCert, "GetServerCertificates", nil, &serverCerts)
	if len(serverCerts) != 1 {
		t.Errorf("Incorrect number of server certificates returned: %d", len(serverCerts))
	}
	if serverCerts[0] != getCertSig(server.tlsConfig.Certificates[0].Certificate[0]) {
		t.Error("Returned server signature doesn't match server's current signature.")
	}

	// Add client cert
	certBlock, _ := pem.Decode(certBytes)
	server.addClientCert("foo.bar", common.AddClientCertCommand{certBlock.Bytes})

	// Add a secret the client will try to retrieve
	server.addSecrets("foo.bar", common.AddSecretsCommand{"mysecret", []common.Secret{
		common.Secret{1, []byte("foobar"), time.Now(), time.Now().Add(time.Hour)}}})

	var secrets []common.Secret = nil
	doClientCommand(&clientCert, "GetSecrets", common.GetSecretsCommand{"mysecret"}, &secrets)
	if len(secrets) != 1 {
		t.Errorf("Should have received secret: %d", len(secrets))
	}
	if string(secrets[0].Secret) != "foobar" {
		t.Errorf("Received bad secret: %s", secrets[0].Secret)
	}

	// Try to retrieve secret with bad cert
	certBytes, pemBytes = common.GenCert("foo.bar", 2*time.Second)
	badCert, _ := tls.X509KeyPair(certBytes, pemBytes)
	secrets = nil
	doClientCommand(&badCert, "GetSecrets", common.GetSecretsCommand{"mysecret"}, &secrets)
	if len(secrets) != 0 {
		t.Errorf("Should have received no secrets: %d", len(secrets))
	}

	// Wait for good certificate to expire
	time.Sleep(2 * time.Second)
	secrets = nil
	doClientCommand(&clientCert, "GetSecrets", common.GetSecretsCommand{"mysecret"}, &secrets)
	if len(secrets) != 0 {
		t.Errorf("Should have received no secrets: %d", len(secrets))
	}
}

func TestAddClientCert(t *testing.T) {
	server := createServer(t)
	defer server.Close()

	server.db.(*TestDao).clients = map[int64]string{1: "foo.bar", 2: "host.bar"}

	if len(server.db.(*TestDao).clientCerts) != 0 {
		t.Error("Unexpected number of certificates in the database.")
	}

	certBytes, _ := common.GenCert("foo.bar", time.Hour)
	pemBlock, _ := pem.Decode(certBytes)
	result := server.addClientCert("foo.bar", common.AddClientCertCommand{pemBlock.Bytes})
	if result < 0 {
		t.Errorf("Got negative result from adding a certificate (%d).", result)
	}
	count := len(server.db.(*TestDao).clientCerts)
	if count != 1 {
		t.Errorf("Unexpected number of certificates in the database (%d).", count)
	}
	var id int64 = 0
	for id, _ = range server.db.(*TestDao).clientCerts {
		break
	}
	if id != result {
		t.Errorf("Unpected id for certificate in database (%d).", id)
	}

	certBytes, _ = common.GenCert("host.bar", time.Hour)
	pemBlock, _ = pem.Decode(certBytes)
	result = server.addClientCert("foo.bar", common.AddClientCertCommand{pemBlock.Bytes})
	if result != -1 {
		t.Errorf("Expected negative result from adding a certificate (%d).", result)
	}
	count = len(server.db.(*TestDao).clientCerts)
	if count != 1 {
		t.Errorf("Unexpected number of certificates in the database (%d).", count)
	}
}

func TestGetPublicKeys(t *testing.T) {
	// TODO: Implement test
}
func TestAddSecrets(t *testing.T) {
	// TODO: Implement test
}
func TestGetSecrets(t *testing.T) {
	// TODO: Implement test
}
func TestGetAllSecrets(t *testing.T) {
	// TODO: Implement test
}
