package server

import (
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"log"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/JackOfMostTrades/keymaster/common"
)

type sqlDao struct {
	conn *sql.DB
}

func NewSqlDao() dao {
	con, err := sql.Open("mysql", "dev:password@/keymaster")
	if err != nil {
		log.Fatalf("Unable to connect to database.")
	}
	return &sqlDao{con}
}

func (db *sqlDao) Close() {
	db.conn.Close()
}

func (db *sqlDao) getInternalClientId(clientId string) int64 {
	row := db.conn.QueryRow("SELECT id FROM client WHERE external_id=?", clientId)
	var iid int64
	err := row.Scan(&iid)
	if err != nil {
		log.Printf("Unable to get client id: %s", err)
		return -1
	}
	return iid
}

func (db *sqlDao) GetSecrets(clientId string, dbCertId int64, secretKey string) []common.Secret {
	iid := db.getInternalClientId(clientId)
	if iid < 0 {
		return nil
	}

	db.conn.Exec("INSERT INTO audit_log (client_id,description,log_time) VALUES(?,?,NOW())",
		iid, "Client requesting secret '"+secretKey+"'.")

	rows, err := db.conn.Query(`
		SELECT S.client_cert_id,S.secret,S.valid_from,S.valid_until FROM secret S
			WHERE S.valid_until >= NOW() AND S.client_cert_id=? AND S.secret_key=?`,
		dbCertId, secretKey)
	if err != nil {
		log.Printf("ERROR: Failure to execute query: %s", err)
		return nil
	}

	var secrets []common.Secret
	for rows.Next() {
		var s = common.Secret{}
		var valid_from, valid_until []uint8
		err = rows.Scan(&s.CertId, &s.Secret, &valid_from, &valid_until)
		if err != nil {
			log.Printf("ERROR: Query scan failure: %s", err)
			return nil
		}
		s.ValidFrom, err = time.Parse(time.RFC3339, strings.Replace(string(valid_from), " ", "T", -1)+"Z")
		if err != nil {
			log.Fatalf("Could not parse date returned from SQL: %s", err)
		}
		s.ValidUntil, err = time.Parse(time.RFC3339, strings.Replace(string(valid_until), " ", "T", -1)+"Z")
		if err != nil {
			log.Fatalf("Could not parse date returned from SQL: %s", err)
		}
		secrets = append(secrets, s)
	}
	return secrets
}

func (db *sqlDao) AddSecrets(clientId string, secretKey string, secrets []common.Secret) {
	iid := db.getInternalClientId(clientId)
	if iid < 0 {
		return
	}

	db.conn.Exec("INSERT INTO audit_log (client_id,description,log_time) VALUES(?,?,NOW())",
		iid, "Client requesting public keys for secret '"+secretKey+"'.")

	// Verify that this client has permission
	canRead := false
	canWrite := false
	row := db.conn.QueryRow("SELECT can_read,can_write FROM client_perm WHERE client_id=? AND secret_key=?",
		iid, secretKey)
	if row != nil {
		row.Scan(&canRead, &canWrite)
	}
	if !canRead && !canWrite {
		log.Printf("WARN: Client tried to update a secret to which they have neither read nor write permission.")
		return
	}

	instStmt, err := db.conn.Prepare("INSERT INTO secret (client_cert_id, secret_key, valid_from, valid_until, secret) VALUES(?,?,?,?,?)")
	if err != nil {
		log.Printf("ERROR: Unable to prepare statement: %s", err)
		return
	}
	defer instStmt.Close()

	verifyPermStmt, err := db.conn.Prepare(`SELECT client_id FROM client_cert WHERE id=?`)
	if err != nil {
		log.Printf("ERROR: Unable to prepare statement: %s", err)
		return
	}
	defer verifyPermStmt.Close()

	for _, v := range secrets {
		if !canWrite {
			var certClientId int64
			row := verifyPermStmt.QueryRow(v.CertId)
			row.Scan(&certClientId)
			if certClientId != iid {
				log.Printf("WARN: Client tried to update a secret for another client but they do not have write access.")
				continue
			}
		}

		instStmt.Exec(v.CertId, secretKey, v.ValidFrom, v.ValidUntil, v.Secret)
	}
}

func (db *sqlDao) GetPublicKeys(clientId string, secretKey string) []common.DbCert {
	iid := db.getInternalClientId(clientId)
	if iid < 0 {
		return nil
	}

	db.conn.Exec("INSERT INTO audit_log (client_id,description,log_time) VALUES(?,?,NOW())",
		iid, "Client requesting public keys for secret '"+secretKey+"'.")

	// Verify that this client has permission
	row := db.conn.QueryRow("SELECT COUNT(*) FROM client_perm WHERE client_id=? AND secret_key=? AND can_write=1",
		iid, secretKey)
	var count int
	row.Scan(&count)
	if count == 0 {
		return nil
	}

	rows, err := db.conn.Query(`SELECT C.id,C.certificate FROM client_cert C
		INNER JOIN client_perm P ON P.client_id = C.client_id
		WHERE P.secret_key=? AND P.can_read=1 AND C.valid_until >= NOW()`,
		secretKey)
	if err != nil {
		log.Printf("Unable to execute query: %s", err)
		return nil
	}

	var result []common.DbCert
	for rows.Next() {
		var c = common.DbCert{}
		err = rows.Scan(&c.Id, &c.Cert)
		if err != nil {
			log.Printf("Unable to extract row result: %s", err)
		}
		result = append(result, c)
	}
	return result
}

func (db *sqlDao) AddClientCert(clientId string, cert *x509.Certificate) int64 {
	// Verify the certificate corresponds to the client id
	if clientId != cert.Subject.CommonName {
		log.Printf("ERROR: Client tried adding a certificate for the wrong subject name.")
		return -1
	}

	iid := db.getInternalClientId(clientId)
	if iid < 0 {
		return -1
	}

	result, err := db.conn.Exec(
		"INSERT INTO client_cert (client_id,certificate,signature,valid_from,valid_until) VALUES(?,?,?,?,?)",
		iid, cert.Raw, hex.EncodeToString(cert.Signature), cert.NotBefore, cert.NotAfter)
	if err != nil {
		log.Printf("ERROR: Unable to add certificate: %s", err)
		return -1
	}
	certId, err := result.LastInsertId()
	if err != nil {
		log.Printf("ERROR: Unable to get generated id for certificate: %s", err)
		return -1
	}

	db.conn.Exec("INSERT INTO audit_log (client_id,description,log_time) VALUES(?,?,NOW())",
		iid, "Adding client certificate for client "+strconv.FormatInt(int64(iid), 10)+" with id "+strconv.FormatInt(certId, 10)+".")

	return certId
}

func (db *sqlDao) GetClientCertIdBySignature(signature string) int64 {
	row := db.conn.QueryRow(
		"SELECT id FROM client_cert WHERE signature=?", signature)
	if row == nil {
		return -1
	}
	var id int64
	err := row.Scan(&id)
	if err != nil {
		log.Printf("Unable to extract row result: %s", err)
		return -1
	}
	return id
}

func (db *sqlDao) GetAllSecretsForClient(clientId string, dbCertId int64) map[string][]common.Secret {
	iid := db.getInternalClientId(clientId)
	if iid < 0 {
		return nil
	}

	db.conn.Exec("INSERT INTO audit_log (client_id,description,log_time) VALUES(?,?,NOW())",
		iid, "Client requesting all secrets.")

	rows, err := db.conn.Query(`
		SELECT S.client_cert_id,S.secret_key,S.secret,S.valid_from,S.valid_until FROM secret S
			WHERE S.valid_until >= NOW() AND S.client_cert_id=?`,
		dbCertId)
	if err != nil {
		log.Printf("ERROR: Failure to execute query: %s", err)
		return nil
	}

	result := make(map[string][]common.Secret)
	for rows.Next() {
		var secretKey string
		var s = common.Secret{}
		var valid_from, valid_until []uint8
		err = rows.Scan(&s.CertId, &secretKey, &s.Secret, &valid_from, &valid_until)
		if err != nil {
			log.Printf("ERROR: Query scan failure: %s", err)
			return nil
		}
		s.ValidFrom, err = time.Parse(time.RFC3339, strings.Replace(string(valid_from), " ", "T", -1)+"Z")
		if err != nil {
			log.Fatalf("Could not parse date returned from SQL: %s", err)
		}
		s.ValidUntil, err = time.Parse(time.RFC3339, strings.Replace(string(valid_until), " ", "T", -1)+"Z")
		if err != nil {
			log.Fatalf("Could not parse date returned from SQL: %s", err)
		}

		secrets, ok := result[secretKey]
		if !ok {
			secrets = nil
		}
		secrets = append(secrets, s)
		result[secretKey] = secrets
	}
	return result
}
