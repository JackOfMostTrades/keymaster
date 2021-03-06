package client

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"sync"
	"time"

	"github.com/JackOfMostTrades/keymaster/common"
)

type Service struct {
	client       *remoteClient
	crtFile      string
	pemFile      string
	secretKeys   []string
	cacheMutex   sync.Mutex
	secretCache  map[string][]common.Secret
	shuttingDown bool
	waitGroup    sync.WaitGroup

	pollChannel chan int
	pollWaiters []chan int
	pollMutex   sync.Mutex

	PollInterval       time.Duration
	ClientRotatePeriod time.Duration
	ClientCertLifetime time.Duration
}

func Init(hostname string, port int, crtFile string, pemFile string, secretKeys []string) (*Service, error) {
	tlsCert, err := tls.LoadX509KeyPair(crtFile, pemFile)
	if err != nil {
		return nil, err
	}
	client := createClient(hostname, port, &tlsCert)
	service := &Service{
		client:       client,
		crtFile:      crtFile,
		pemFile:      pemFile,
		secretKeys:   secretKeys,
		cacheMutex:   sync.Mutex{},
		secretCache:  make(map[string][]common.Secret),
		shuttingDown: false,
		waitGroup:    sync.WaitGroup{},

		pollChannel: make(chan int),
		pollMutex:   sync.Mutex{},
		pollWaiters: nil,

		PollInterval:       1 * time.Hour,
		ClientRotatePeriod: 4 * time.Hour,
		ClientCertLifetime: 24 * time.Hour,
	}

	service.waitGroup.Add(1)

	go func() {
		for {
			poller := time.NewTimer(service.PollInterval)
			select {
			case <-poller.C:
			case <-service.pollChannel:
			}
			poller.Stop()

			service.rotateClientCert()
			service.rotateServerCert()
			service.refreshSecrets()

			service.pollMutex.Lock()
			for i := range service.pollWaiters {
				close(service.pollWaiters[i])
			}
			service.pollWaiters = nil
			service.pollMutex.Unlock()

			if service.shuttingDown {
				break
			}
		}
		service.waitGroup.Done()
	}()

	return service, nil
}

func (service *Service) Poll() {
	mychan := make(chan int)
	service.pollMutex.Lock()
	service.pollWaiters = append(service.pollWaiters, mychan)
	service.pollMutex.Unlock()

	service.pollChannel <- 0
	<-mychan
}

func (service *Service) Close() {
	service.shuttingDown = true
	service.Poll()
	service.waitGroup.Wait()
}

func (service *Service) rotateClientCert() {
	clientCert, err := x509.ParseCertificate(service.client.tlsCert.Certificate[0])
	if err != nil {
		log.Fatalf("Could not parse loaded x509 certificate.")
	}
	if clientCert.NotAfter.Before(time.Now().Add(service.ClientRotatePeriod)) {
		log.Printf("Rotating client certificate.")

		certBytes, pemBytes := common.GenCert(clientCert.Subject.CommonName, service.ClientCertLifetime)
		tlsCert, err := tls.X509KeyPair(certBytes, pemBytes)
		if err != nil {
			log.Fatalf("Could not load x509 certificate as TLS cert: %s", err)
		}
		service.client.updateClientCert(&tlsCert)

		err = ioutil.WriteFile(service.crtFile, certBytes, 0644)
		if err != nil {
			log.Fatalf("Could not save new certificate file.")
		}
		err = ioutil.WriteFile(service.pemFile, pemBytes, 0600)
		if err != nil {
			log.Fatalf("Could not save new certificate private key.")
		}
	}
}
func (service *Service) rotateServerCert() {
	serverCerts := service.client.getServerCertificates()
	service.client.serverCerts = serverCerts
}

func (service *Service) refreshSecrets() {
	for _, secretKey := range service.secretKeys {
		secrets := service.client.getSecret(secretKey)
		service.cacheMutex.Lock()
		service.secretCache[secretKey] = secrets
		service.cacheMutex.Unlock()
	}
}

func (service *Service) GetSecret(secretKey string) []byte {
	secrets, ok := service.secretCache[secretKey]
	if !ok {
		service.refreshSecrets()
		secrets = service.secretCache[secretKey]
	}

	var bestSecret *common.Secret = nil
	for i := range secrets {
		secret := &secrets[i]
		if secret.ValidFrom.After(time.Now()) || secret.ValidUntil.Before(time.Now()) {
			continue
		}
		if bestSecret == nil || secret.ValidFrom.After(bestSecret.ValidFrom) {
			bestSecret = secret
		}
	}
	if bestSecret == nil {
		return nil
	}
	return bestSecret.Secret
}
