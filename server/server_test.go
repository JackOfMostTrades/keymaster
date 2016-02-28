package server

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/JackOfMostTrades/keymaster/common"
	_ "github.com/mattn/go-sqlite3"
)

func createServer(t *testing.T) *Server {
	certBytes, pemBytes := common.GenCert("keymaster.local", 2*time.Second)
	tlsCert, err := tls.X509KeyPair(certBytes, pemBytes)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	_, err = os.Stat("/tmp/keymaster.db")
	if err == nil {
		os.Remove("/tmp/keymaster.db")
	}

	sqlConn, err := sql.Open("sqlite3", "/tmp/keymaster.db")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	sqlInit, err := ioutil.ReadFile("./server_test.sql")
	if err != nil {
		t.Log(err)
		sqlConn.Close()
		t.FailNow()
	}
	tx, err := sqlConn.Begin()
	if err != nil {
		t.Log(err)
		sqlConn.Close()
		t.FailNow()
	}
	sqlStmtSlice := strings.Split(string(sqlInit), ";\n")
	for _, q := range sqlStmtSlice {
		_, err := tx.Exec(q)
		if err != nil {
			t.Logf("Error running SQL command (%s): %s", q, err)
			tx.Rollback()
			sqlConn.Close()
			t.FailNow()
		}
	}
	err = tx.Commit()
	if err != nil {
		t.Log(err)
		sqlConn.Close()
		t.FailNow()
	}

	db := &DbConn{sqlConn}
	server := newServerWithDb([]tls.Certificate{tlsCert}, db)
	server.ServerCertLifetime = 60 * time.Second
	server.ServerPollInterval = 1 * time.Hour
	server.ServerRotatePeriod = 60 * time.Second

	return server
}

func TestGetCertificatesAndRotation(t *testing.T) {
	server := createServer(t)
	defer server.Close()

	xCert, err := x509.ParseCertificate(server.tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Log("Could not parse certificate.")
		t.FailNow()
	}

	certs := server.getServerCertificates()
	if len(certs) != 1 {
		t.Errorf("Server should have 1 certificate, but has %d", len(certs))
	}
	if certs[0] != hex.EncodeToString(xCert.Signature) {
		t.Errorf("Got unexpected certificate from server.")
	}

	server.Poll() // This will cause a new certificate to get generated
	certs = server.getServerCertificates()
	if len(certs) != 2 {
		t.Errorf("Server should have 2 certificates, but has %d", len(certs))
	}
	if certs[0] != hex.EncodeToString(xCert.Signature) {
		t.Errorf("Got unexpected certificate from server.")
	}
	if certs[1] == hex.EncodeToString(xCert.Signature) {
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
	currentCert, err := x509.ParseCertificate(server.tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Error("Could not parse current certificate.")
	} else {
		if hex.EncodeToString(currentCert.Signature) != certs[1] {
			t.Error("Server did not switch current certificate after the original expired.")
		}
	}
}

func getQueryResult(server *Server, query string, args ...interface{}) int64 {
	row := server.db.conn.QueryRow(query, args...)
	if row == nil {
		panic("Test query requires a result.")
	}
	var result int64
	err := row.Scan(&result)
	if err != nil {
		panic(err)
	}
	return result
}

func TestAddClientCert(t *testing.T) {
	server := createServer(t)
	defer server.Close()

	server.db.conn.Exec("INSERT INTO client (external_id) VALUES('foo.bar'),('host.bar')")

	if getQueryResult(server, "SELECT COUNT(*) FROM client_cert") != 0 {
		t.Error("Unexpected number of certificates in the database.")
	}

	certBytes, _ := common.GenCert("foo.bar", time.Hour)
	pemBlock, _ := pem.Decode(certBytes)
	result := server.addClientCert("foo.bar", common.AddClientCertCommand{pemBlock.Bytes})
	if result < 0 {
		t.Errorf("Got negative result from adding a certificate (%d).", result)
	}
	count := getQueryResult(server, "SELECT COUNT(*) FROM client_cert")
	if count != 1 {
		t.Errorf("Unexpected number of certificates in the database (%d).", count)
	}
	id := getQueryResult(server, "SELECT id FROM client_cert")
	if id != result {
		t.Errorf("Unpected id for certificate in database (%d).", id)
	}

	certBytes, _ = common.GenCert("host.bar", time.Hour)
	pemBlock, _ = pem.Decode(certBytes)
	result = server.addClientCert("foo.bar", common.AddClientCertCommand{pemBlock.Bytes})
	if result != -1 {
		t.Errorf("Expected negative result from adding a certificate (%d).", result)
	}
	count = getQueryResult(server, "SELECT COUNT(*) FROM client_cert")
	if count != 1 {
		t.Errorf("Unexpected number of certificates in the database (%d).", count)
	}
}
