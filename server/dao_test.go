package server

import (
	"crypto/x509"
	"encoding/hex"

	"github.com/JackOfMostTrades/keymaster/common"
)

type certRow struct {
	clientId int64
	cert     *x509.Certificate
}

type TestDao struct {
	clients     map[int64]string
	clientCerts map[int64]certRow
	secrets     map[string][]common.Secret
	clientPerms map[int64]map[string][]bool
}

func NewTestDao() dao {
	testDao := TestDao{
		make(map[int64]string),
		make(map[int64]certRow),
		make(map[string][]common.Secret),
		make(map[int64]map[string][]bool),
	}
	return &testDao
}

func (this *TestDao) Close() {
	// Nothing to clean up
}

func (this *TestDao) GetSecrets(clientId string, dbCertId int64, secretKey string) []common.Secret {
	var result []common.Secret
	for _, secret := range this.secrets[secretKey] {
		if dbCertId == secret.CertId {
			result = append(result, secret)
		}
	}
	return result
}
func (this *TestDao) AddSecrets(clientId string, secretKey string, secrets []common.Secret) {
	for _, secret := range secrets {
		this.secrets[secretKey] = append(this.secrets[secretKey], secret)
	}
}
func (this *TestDao) GetPublicKeys(clientId string, secretKey string) []common.DbCert {
	var certs []common.DbCert
	for iid, permsByKey := range this.clientPerms {
		perm := permsByKey[secretKey]
		if perm[0] {
			// Get certs for this client
			for certId, cert := range this.clientCerts {
				if cert.clientId == iid {
					certs = append(certs, common.DbCert{certId, cert.cert.Raw})
				}
			}
		}
	}
	return certs
}
func (this *TestDao) AddClientCert(clientId string, cert *x509.Certificate) int64 {
	if clientId != cert.Subject.CommonName {
		return -1
	}

	var actualIid int64 = -1
	for iid, clientName := range this.clients {
		if clientName == clientId {
			actualIid = iid
			break
		}
	}
	if actualIid != -1 {
		certId := int64(len(this.clientCerts) + 1)
		this.clientCerts[certId] = certRow{actualIid, cert}
		return certId
	}
	return -1
}
func (this *TestDao) GetClientCertIdBySignature(signature string) int64 {
	for certId, cert := range this.clientCerts {
		if hex.EncodeToString(cert.cert.Signature) == signature {
			return certId
		}
	}
	return -1
}
func (this *TestDao) GetAllSecretsForClient(clientId string, dbCertId int64) map[string][]common.Secret {
	var result map[string][]common.Secret
	for secretKey, secrets := range this.secrets {
		for _, secret := range secrets {
			if secret.CertId == dbCertId {
				result[secretKey] = append(result[secretKey], secret)
			}
		}
	}
	return result
}
