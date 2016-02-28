package server

import (
	"testing"
)

func TestSqlDaoAddSecrets(t *testing.T) {
	// TODO: Test that a client can only add secrets they can write or that they
	// can read and are updating their own secret
}
func TestSqlDaoGetPublicKeys(t *testing.T) {
	// TODO: Test that a client can only get all public keys if they can write the secretKey
}
func TestSqlDaoAddClientCert(t *testing.T) {
	// TODO: Test that a client can only add a cert matching their client name
}
