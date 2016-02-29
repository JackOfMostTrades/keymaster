package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/JackOfMostTrades/keymaster/common"
	"github.com/JackOfMostTrades/keymaster/server"
)

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test.")
	}

	con, err := sql.Open("mysql", "dev:password@/keymaster")
	if err != nil {
		t.Errorf("Unable to connect to database: %s", err)
		t.FailNow()
	}
	defer con.Close()
	con.Exec("DELETE FROM secret")
	con.Exec("DELETE FROM client_perm")
	con.Exec("DELETE FROM client_cert")
	con.Exec("DELETE FROM audit_log")
	con.Exec("DELETE FROM client")
	con.Exec("INSERT INTO client (id,external_id) VALUES (1,'client.local'),(2,'master.local')")
	con.Exec("INSERT INTO client_perm (client_id,secret_key,can_read,can_write) VALUES (1,'mysecret',1,0),(2,'mysecret',1,1)")

	_, err = os.Stat("./server_certs")
	if err != nil {
		os.Mkdir("./server_certs", 0755)
	}

	serverCert, serverPriv := common.GenCert("keymaster.local", 10*time.Second)
	serverTls, _ := tls.X509KeyPair(serverCert, serverPriv)
	srvr := server.NewServer([]tls.Certificate{serverTls})
	defer srvr.Close()

	srvr.ServerCertLifetime = 10 * time.Second
	srvr.ServerPollInterval = time.Second
	srvr.ServerRotatePeriod = 5 * time.Second
	srvr.Poll()

	clientCert, clientPriv := common.GenCert("client.local", 10*time.Second)
	ioutil.WriteFile("client.crt", clientCert, 0644)
	ioutil.WriteFile("client.pem", clientPriv, 0600)
	defer os.Remove("client.crt")
	defer os.Remove("client.pem")
	server.ImportClientCert([]string{"client.crt"})

	masterCert, masterPriv := common.GenCert("master.local", 24*time.Hour)
	ioutil.WriteFile("master.crt", masterCert, 0644)
	ioutil.WriteFile("master.pem", masterPriv, 0600)
	defer os.Remove("master.crt")
	defer os.Remove("master.pem")
	server.ImportClientCert([]string{"master.crt"})
	AddSecret([]string{"master.crt", "master.pem", "mysecret", "secret1",
		time.Now().Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339)})

	client, _ := Init("localhost", 12345, "client.crt", "client.pem", []string{"mysecret"})
	defer client.Close()

	client.ClientCertLifetime = 10 * time.Second
	client.PollInterval = time.Second
	client.ClientRotatePeriod = 5 * time.Second
	client.Poll()

	if string(client.GetSecret("mysecret")) != "secret1" {
		t.Error("Got invalid initial secret value.")
	}

	t.Log("Waiting 10 seconds for client/server to rotate certificates...")
	time.Sleep(10 * time.Second)
	clientPem, _ := pem.Decode(clientCert)
	origClientCert, _ := x509.ParseCertificate(clientPem.Bytes)
	clientCert, _ = ioutil.ReadFile("client.crt")
	clientPem, _ = pem.Decode(clientCert)
	newClientCert, _ := x509.ParseCertificate(clientPem.Bytes)

	if bytes.Equal(newClientCert.Signature, origClientCert.Signature) {
		t.Error("Client did not rotate certificate")
		t.FailNow()
	}
	if !bytes.Equal(client.client.tlsCert.Certificate[0], newClientCert.Raw) {
		t.Error("Client does not have new certificate as active.")
		t.FailNow()
	}

	origServerCert, _ := x509.ParseCertificate(serverTls.Certificate[0])
	serverCerts := client.client.getServerCertificates()
	for _, serverCert := range serverCerts {
		if serverCert == hex.EncodeToString(origServerCert.Signature) {
			t.Error("Server still using original certificate after it should have rotated.")
			t.FailNow()
		}
	}

	AddSecret([]string{"master.crt", "master.pem", "mysecret", "secret2",
		time.Now().Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339)})
	time.Sleep(10 * time.Second)
	if string(client.GetSecret("mysecret")) != "secret2" {
		t.Error("Client did not receive new secret value.")
		t.FailNow()
	}

	client.ClientCertLifetime = 24 * time.Hour
	client.ClientRotatePeriod = 4 * time.Hour
	client.PollInterval = 1 * time.Hour
	AddSecret([]string{"master.crt", "master.pem", "mysecret", "secret3",
		time.Now().Add(10 * time.Second).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339)})
	client.Poll()

	if string(client.GetSecret("mysecret")) != "secret2" {
		t.Error("Client received new value early.")
		t.FailNow()
	}
	t.Log("Sleeping 10 seconds to wait for new secret value to become active.")
	time.Sleep(10 * time.Second)
	if string(client.GetSecret("mysecret")) != "secret3" {
		t.Error("Client does not show new secret value.")
		t.FailNow()
	}

}
