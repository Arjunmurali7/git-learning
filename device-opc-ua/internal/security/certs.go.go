package security

import (
	"fmt"
	"log"
	"os"
)

const (
	ClientCertFile = "/run/edgex/secrets/device-opcua/certs/opc-client-cert.pem"
	ClientKeyFile  = "/run/edgex/secrets/device-opcua/certs/opc-client-key.pem"
	ServerTrustDir = "/run/edgex/secrets/device-opcua/truststore/"
)

// EnsureClientCertificate
// checks that cert & key exist.

func EnsureClientCertificate() error {
	if _, err := os.Stat(ClientCertFile); err != nil {
		return fmt.Errorf("OPC UA client certificate missing at %s: %w", ClientCertFile, err)
	}
	if _, err := os.Stat(ClientKeyFile); err != nil {
		return fmt.Errorf("OPC UA client private key missing at %s: %w", ClientKeyFile, err)
	}

	log.Println("[SECURITY] Using existing OPC UA client certificate:", ClientCertFile)
	return nil
}

// SaveServerCertificate is unchanged: just saves trusted server certs.
func SaveServerCertificate(certDER []byte, name string) {
	_ = os.MkdirAll(ServerTrustDir, 0o700)
	path := ServerTrustDir + name + ".der"
	_ = os.WriteFile(path, certDER, 0o644)
	log.Println("[SECURITY] Server certificate trusted:", path)
}
