package server

import (
	"crypto/x509"

	"github.com/JackOfMostTrades/keymaster/common"
)

// Functions providing a DAO-like interface to DB data

type dao interface {
	Close()
	GetSecrets(clientId string, dbCertId int64, secretKey string) []common.Secret
	AddSecrets(clientId string, secretKey string, secrets []common.Secret)
	GetPublicKeys(clientId string, secretKey string) []common.DbCert
	AddClientCert(clientId string, cert *x509.Certificate) int64
	GetClientCertIdBySignature(signature string) int64
	GetAllSecretsForClient(clientId string, dbCertId int64) map[string][]common.Secret
}
