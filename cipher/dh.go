package cipher

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"handshakeServer/helpers"
	"math/big"
)

// anonmouys cipher we need to send server key exchange message all are dh
// 		enum { rsa, diffie_hellman, fortezza_kea }
// 		KeyExchangeAlgorithm;

//  struct {
// 	 opaque rsa_modulus<1..2^16-1>;
// 	 opaque rsa_exponent<1..2^16-1>;
//  } ServerRSAParams;
// struct {
// 	opaque dh_p<1..2^16-1>;
// 	opaque dh_g<1..2^16-1>;
// 	opaque dh_Ys<1..2^16-1>;
// } ServerDHParams;     /* Ephemeral DH parameters */

// struct {
// 	opaque r_s [128];
// } ServerFortezzaParams;
// enum { anonymous, rsa, dsa } SignatureAlgorithm;

// digitally-signed struct {
// 	select(SignatureAlgorithm) {
// 		case anonymous: struct { };
// 		case rsa:
// 			opaque md5_hash[16];
// 			opaque sha_hash[20];
// 		case dsa:
// 			opaque sha_hash[20];
// 	};
// } Signature;
// struct {
// 	select (KeyExchangeAlgorithm) {
// 		case diffie_hellman:
// 			ServerDHParams params;
// 			Signature signed_params;
// 		case rsa:
// 			ServerRSAParams params;
// 			Signature signed_params;
// 		case fortezza_kea:
// 			ServerFortezzaParams params;
// 	};
// } ServerKeyExchange;

// Ideally for static dh this should be store on the disk, but just for sake of implementing it, lets story it in ram
type DhComponent struct {
	prime   *big.Int
	g       *big.Int
	private *big.Int
	public  *big.Int
}

var staticDh *DhComponent
var staticDhWeak *DhComponent

func generatePrivateKey(p *big.Int) (*big.Int, error) {
	privateKey, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, fmt.Errorf("problem generating private key: %v", err)
	}
	privateKey.Add(privateKey, big.NewInt(1))
	return privateKey, nil
}

// Compute the public key
func computePublicKey(g, privateKey, p *big.Int) *big.Int {
	publicKey := new(big.Int).Exp(g, privateKey, p)
	return publicKey
}

func generateDhComponents(weakKey bool) (*DhComponent, error) {
	keyLength := 2048

	if weakKey {
		keyLength = 512
	}
	p, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return nil, fmt.Errorf("problem generating p: %v", err)
	}
	pPrime := p.Primes[0]

	gGenerator := big.NewInt(2)
	serverPrivateVal, err := generatePrivateKey(pPrime)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	serverPublicKey := computePublicKey(gGenerator, serverPrivateVal, pPrime)

	return &DhComponent{
		prime:   pPrime,
		g:       gGenerator,
		private: serverPrivateVal,
		public:  serverPublicKey,
	}, nil
	// return &DhComponent{
	// 	prime:   big.NewInt(7),
	// 	g:       big.NewInt(3),
	// 	private: big.NewInt(2),
	// 	public:  big.NewInt(2),
	// }, nil
}

func (dh *DhParams) GenerateDhParams(weakKey bool, ephemeral bool) ([]byte, error) {
	//Ephemeral Diffie-Hellman (DHE in the context of TLS) differs from the static Diffie-Hellman (DH) in the way that static Diffie-Hellman key exchanges always use the same Diffie-Hellman private keys. So, each time the same parties do a DH key exchange, they end up with the same shared secret.
	// https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/ephemeral-diffie-hellman/
	var dhComponent *DhComponent
	var err error

	if weakKey {
		if staticDhWeak != nil && !ephemeral {
			dhComponent = staticDhWeak
		} else {
			dhComponent, err = generateDhComponents(true)
			staticDhWeak = dhComponent
		}
	} else {
		if staticDh != nil && !ephemeral {
			dhComponent = staticDh
		} else {
			dhComponent, err = generateDhComponents(weakKey)
			staticDh = dhComponent
		}

	}

	if err != nil {
		return nil, err
	}

	dh.P = dhComponent.prime
	dh.Q = dhComponent.g
	dh.Private = dhComponent.private

	prime := dhComponent.prime.Bytes() // p a large prime nmber
	generator := dhComponent.g.Bytes() // g a base used for generic public values
	// p and g are public paramters, both parties need to know these paramters to perform the key exchange

	publicKey := dhComponent.public.Bytes() // Ys the server public key
	// the server public key is essential for the client t ocompue the shared secre, the clients needs this value to compute its own private value

	// to calcualte shared secret i need to clientPublic^serverPriavte mod p (pprime)

	primeLen := helpers.Int32ToBigEndian(len(prime))
	genLen := helpers.Int32ToBigEndian(len(generator))
	serverPubKeyLength := helpers.Int32ToBigEndian(len(publicKey))

	resp := []byte{}
	resp = append(resp, primeLen...)
	resp = append(resp, prime...)
	resp = append(resp, genLen...)
	resp = append(resp, generator...)
	resp = append(resp, serverPubKeyLength...)
	resp = append(resp, publicKey...)

	return resp, nil
}

// Compute the shared secret
// client public key, server private key, prime number  client public key^server private mod p
func (dh *DhParams) ComputePreMasterSecret() *big.Int {
	return new(big.Int).Exp(dh.ClientPublic, dh.Private, dh.P)
}
