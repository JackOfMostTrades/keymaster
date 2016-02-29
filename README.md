**Disclaimer**

This is a project I completed over the course of a weekend, with the goal of learning Go. Since it is the first thing I've written in Go, it most likely doesn't represent many best practices. Since I completed it over the course of just a few days, I wouldn't suggest sticking it in production out-of-the-box.

KeyMaster
=========

KeyMaster is a server and client-side API for storing and distributing secrets. It has a number of features, each of which aim to achieve different goals. The primary feature is that KeyMaster works as a secret distribution hub. It's features include

* Secret distribution to clients. Secrets had a valid-from date, so secrets can be distributed in advance of a switch-over time.
* Mutual authentication. Both client and server use TLS certificates. KeyMaster uses pinned signatures and doesn't rely on any PKI.
* Client-side asymmetric encryption. The KeyMaster server never receives the plaintext secrets.
 * When a secret is added, the client which is adding the secret receives all the public keys of relevant clients, encrypts the secret with those keys, and then the ciphertext is stored on the KeyMaster server.
 * Although a compromised KeyMaster server would be able to hijack new secrets by inserting its own public key, it will not have access to any prior secrets.
* Continuous, automated certificate rotation. Both clients and the server rotate their certificates on a configurable interval.
 * Although not perfect (a compromised key can be used to authenticate additional key rotations), this provides some reduction of impact of a compromised key. In particular, already expired keys will generally be useless.
* Client-side caching. Although KeyMaster is a single point of failure for dependent applications, clients cache secrets and suffer no impact for servers which are down for a period less than the certificate rotation period.

Example Usage
-------------

```
func main() {
	client, err := client.Init("localhost", 12345, "applejack.crt", "applejack.pem",
                []string{"root_database_password"})
	if err != nil {
		log.Fatalf("Could not create client: %s", err)
	}
        // Optionally, you can change the key rotation durations
	client.ClientCertLifetime = 2 * time.Minute
	client.ClientRotatePeriod = 2 * time.Minute
	client.PollInterval = 1 * time.Minute
        // You can also manually trigger polling; useful for testing
	client.Poll()

	// This loop just prints out the current password
	for {
		log.Printf("root_database_password: %s", client.GetSecret("root_database_password"))
		time.Sleep(10 * time.Second)
	}
}
```

KeyMaster has a command line interface for some operations. You can add/change a secret with a command such as

    bin/keymaster addSecret client.crt client.pem root_database_password new_secret_value `date -u +%Y-%m-%dT%H:%M:%SZ` '2100-01-01T00:00:00Z'



