package common

type CommandName struct {
	Command string
}

type GetSecretsCommand struct {
	SecretKey string
}
type GetPublicKeysCommand struct {
	SecretKey string
}
type AddSecretsCommand struct {
	SecretKey string
	Secrets   []Secret
}
type AddClientCertCommand struct {
	DerBytes []byte
}
