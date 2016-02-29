package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/JackOfMostTrades/keymaster/common"
)

func TestRejectInvalidCert(t *testing.T) {
	server := NewStubServer()
	defer server.close()

	certBytes, privBytes := common.GenCert("client.local", 100*time.Hour)
	pemBytes, _ := pem.Decode(certBytes)
	xCert, _ := x509.ParseCertificate(pemBytes.Bytes)
	server.clientCerts[1] = xCert

	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, xCert.PublicKey.(*rsa.PublicKey), []byte("value1"), nil)
	server.secrets["secret1"] = []common.Secret{common.Secret{1, ciphertext, time.Now(), time.Now().Add(time.Hour)}}

	tlsCert, _ := tls.X509KeyPair(certBytes, privBytes)
	rClient := createClient("localhost", 12345, &tlsCert)
	secrets := rClient.getSecret("secret1")
	if len(secrets) != 1 || string(secrets[0].Secret) != "value1" {
		t.Error("Unable to get initial secret value.")
	}

	badBytes, badPriv := common.GenCert("keymaster.local", time.Hour)
	badTls, _ := tls.X509KeyPair(badBytes, badPriv)
	server.tlsConfig.Certificates[0] = badTls
	secrets = rClient.getSecret("secret1")
	if len(secrets) != 0 {
		t.Error("Client should have returned no results with bad server certificate.")
	}

	certBytes, privBytes = common.GenCert("keymaster.local", 10*time.Second)
	serverTls, _ := tls.X509KeyPair(certBytes, privBytes)
	server.tlsConfig.Certificates[0] = serverTls
	rClient = createClient("localhost", 12345, &tlsCert)
	secrets = rClient.getSecret("secret1")
	if len(secrets) != 1 || string(secrets[0].Secret) != "value1" {
		t.Error("Unable to get initial secret value (stage 2).")
	}

	time.Sleep(10 * time.Second)
	secrets = rClient.getSecret("secret1")
	if len(secrets) != 0 {
		t.Error("Client should have returned no results with expired server certificate.")
	}

}
