package handshake

import (
	"crypto/dsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

// parse privaty key in PCKS doesnt work for dsa :) `AGL suggested that nobody uses DSA anymore, so this can be closed.` https://github.com/golang/go/issues/6868
func parseDSAPrivateKeyPCKS8(der []byte) (*dsa.PrivateKey, error) {

	type Params struct {
		P, Q, G *big.Int
	}

	type Algorithm struct {
		Algorithm any
		Structt   Params
	}

	var k struct {
		Version    int
		Algorithm  Algorithm
		PrivateKey []byte
	}

	_, err := asn1.Unmarshal(der, &k)

	if err != nil {
		return nil, fmt.Errorf("\n error unmarshaling cert object, err:%v", err)
	}
	var value *big.Int

	// Unmarshal the ASN.1-encoded data
	_, err = asn1.Unmarshal(k.PrivateKey, &value)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling ASN.1: %v", err)
	}

	// Compute the public key (Y = G^X mod P)
	publicKey := new(big.Int).Exp(k.Algorithm.Structt.G, value, k.Algorithm.Structt.P)

	dsaKey := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: k.Algorithm.Structt.P,
				Q: k.Algorithm.Structt.Q,
				G: k.Algorithm.Structt.G,
			},
			Y: publicKey,
		},
		X: value,
	}

	return dsaKey, nil
}

func parseDSAPrivateKey(der []byte) (*dsa.PrivateKey, error) {

	privkey, err := parseDSAPrivateKeyPCKS8(der)
	if err == nil {
		return privkey, nil
	}

	var k struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Pub     *big.Int
		Priv    *big.Int
	}

	rest, err := asn1.Unmarshal(der, &k)

	if err != nil {
		return nil, fmt.Errorf("failed to parse DSA key: " + err.Error())
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("leftover after parsing: %v", rest)
	}

	dsaKey := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: k.P,
				Q: k.Q,
				G: k.G,
			},
			Y: k.Pub,
		},
		X: k.Priv,
	}

	return dsaKey, nil
}

func (serverData *ServerData) parseCertificate(certFile, keyFile string) ([]byte, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	keyBlockBytes := keyBlock.Bytes

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	if cert.PublicKeyAlgorithm == x509.DSA {
		dsaPrivate, err := parseDSAPrivateKey(keyBlockBytes)

		if err != nil {
		} else {
			serverData.CipherDef.Dsa.PrivateKey = dsaPrivate
		}
	} else if cert.PublicKeyAlgorithm == x509.RSA {
		privateKey, err := x509.ParsePKCS8PrivateKey(keyBlockBytes)
		if err != nil {
			privateKey, err = x509.ParsePKCS1PrivateKey(keyBlockBytes)
			if err != nil {
				privateKey, err = x509.ParseECPrivateKey(keyBlockBytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse private key: %v", err)
				}
			}
		}

		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if ok {
			serverData.CipherDef.Rsa.PrivateKey = rsaKey
		} else {
			return nil, fmt.Errorf("can't convert to rsa private key")
		}
		if binary.BigEndian.Uint16(serverData.Version) > uint16(SSL30Version) {
			serverData.CipherDef.Rsa.LengthRecord = true
		}
	} else {
		return nil, fmt.Errorf("\n unkown certificate with pub cert algorithm: %v", cert.PublicKeyAlgorithm)
	}

	rawBytes := cert.Raw
	return rawBytes, nil
}

func (serverData *ServerData) loadCert(certPath, keyPath string) error {

	certBytes, err := serverData.parseCertificate(certPath, keyPath)

	if err != nil {
		return fmt.Errorf("problem passing certificate, err:%v", err)
	}

	serverData.cert = certBytes

	return nil

}
