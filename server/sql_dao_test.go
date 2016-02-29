package server

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/JackOfMostTrades/keymaster/common"

	"gopkg.in/DATA-DOG/go-sqlmock.v1"
)

func TestSqlDaoAddSecrets(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	mySqlDao := sqlDao{db}
	defer mySqlDao.Close()

	validFrom := time.Now()
	validUntil := time.Now().Add(time.Hour)
	secretsToAdd := []common.Secret{common.Secret{200, []byte("secretValue"), validFrom, validUntil}}

	tests := []struct {
		canRead      bool
		canWrite     bool
		certClientId int64
		isAdded      bool
	}{
		// Without any permissions, inserting should fail
		{false, false, 100, false},
		// With read permission, fail to insert for another client
		{true, false, 101, false},
		// With read permission, succeed to instert for self
		{true, false, 100, true},
		// With write permission, succeed to instert for another client
		{true, true, 101, true},
		// With write permission, succeed to insert for self
		{true, true, 100, true},
	}

	for _, test := range tests {
		mock.ExpectQuery("SELECT id FROM client WHERE external_id=\\?").WithArgs("foo.local").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(100))
		mock.ExpectExec("INSERT INTO audit_log").WithArgs(100, "Client requesting public keys for secret 'mysecret'.")
		mock.ExpectQuery("SELECT can_read,can_write FROM client_perm WHERE client_id=\\? AND secret_key=\\?").WithArgs(100, "mysecret").WillReturnRows(
			sqlmock.NewRows([]string{"can_read", "can_write"}).AddRow(test.canRead, test.canWrite))

		if test.canRead || test.canWrite {
			instStmt := mock.ExpectPrepare("INSERT INTO secret")
			selectStmt := mock.ExpectPrepare("SELECT client_id FROM client_cert")
			if !test.canWrite {
				selectStmt.ExpectQuery().WithArgs(200).WillReturnRows(sqlmock.NewRows([]string{"client_id"}).AddRow(test.certClientId))
			}
			if test.isAdded {
				instStmt.ExpectExec().WithArgs(200, "mysecret", validFrom, validUntil, []byte("secretValue"))
			}
		}

		mySqlDao.AddSecrets("foo.local", "mysecret", secretsToAdd)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("There were unfulfilled expections: %s", err)
		}
	}
}
func TestSqlDaoGetPublicKeys(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	mySqlDao := sqlDao{db}
	defer mySqlDao.Close()

	tests := []struct {
		canWrite    bool
		returnsKeys bool
	}{
		{false, false},
		{true, true},
	}

	for _, test := range tests {
		permCount := 0
		if test.canWrite {
			permCount = 1
		}
		mock.ExpectQuery("SELECT id FROM client WHERE external_id=\\?").WithArgs("foo.local").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(100))
		mock.ExpectExec("INSERT INTO audit_log").WithArgs(100, "Client requesting public keys for secret 'mysecret'.")
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM client_perm WHERE client_id=\\? AND secret_key=\\? AND can_write=1").WithArgs(100, "mysecret").WillReturnRows(
			sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(permCount))

		if test.canWrite {
			mock.ExpectQuery("SELECT C.id,C.certificate FROM client_cert").WillReturnRows(
				sqlmock.NewRows([]string{"id", "certificate"}).AddRow(200, []byte("derBytesHere")))
		}

		publicKeys := mySqlDao.GetPublicKeys("foo.local", "mysecret")

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("There were unfulfilled expections: %s", err)
		}

		if test.returnsKeys {
			if len(publicKeys) != 1 || publicKeys[0].Id != 200 || !bytes.Equal(publicKeys[0].Cert, []byte("derBytesHere")) {
				t.Error("Incorrect keys returned for test case.")
			}
		} else {
			if len(publicKeys) != 0 {
				t.Error("Incorrect keys returned for test case.")
			}
		}
	}
}
func TestSqlDaoAddClientCert(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	mySqlDao := sqlDao{db}
	defer mySqlDao.Close()

	tests := []struct {
		hostname string
		keyAdded bool
	}{
		{"other.local", false},
		{"foo.local", true},
	}

	for _, test := range tests {
		newCertBytes, _ := common.GenCert(test.hostname, time.Hour)
		newCert := toCert(newCertBytes)

		if test.hostname == "foo.local" {
			mock.ExpectQuery("SELECT id FROM client WHERE external_id=\\?").WithArgs("foo.local").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(100))
		}
		if test.keyAdded {
			mock.ExpectExec("INSERT INTO client_cert").WithArgs(
				100, newCert.Raw, hex.EncodeToString(newCert.Signature), newCert.NotBefore, newCert.NotAfter).WillReturnResult(
				sqlmock.NewResult(200, 1))
		}

		newId := mySqlDao.AddClientCert("foo.local", newCert)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("There were unfulfilled expections: %s", err)
		}

		if test.keyAdded {
			if newId != 200 {
				t.Error("Incorrect id returned].")
			}
		} else {
			if newId != -1 {
				t.Error("Incorrect id returned].")
			}
		}
	}
}
