package cipher

import (
	"errors"
	"fmt"
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

func generatePrivateKey(p *big.Int) (*big.Int, error) {
	// privateKey, ok := rand.Int(rand.Reader, p)
	privateKey, ok := new(big.Int).SetString("3", 16)
	if !ok {
		return nil, errors.New("")
	}
	return privateKey, nil
}

// Compute the public key
func computePublicKey(g, privateKey, p *big.Int) *big.Int {
	publicKey := new(big.Int).Exp(g, privateKey, p)
	return publicKey
}

func (dh *DhParams) GenerateDhParams() []byte {

	pPrime, ok := new(big.Int).SetString("3", 16)
	if !ok {
		fmt.Println("Error generating private key:")
		return []byte{}
	}
	gGenerator := big.NewInt(2)
	serverPrivateVal, err := generatePrivateKey(pPrime)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return []byte{}
	}
	serverPublicKey := computePublicKey(gGenerator, serverPrivateVal, pPrime)

	dh.P = pPrime
	dh.Q = gGenerator
	dh.Private = serverPrivateVal

	prime := pPrime.Bytes()         // p a large prime nmber
	generator := gGenerator.Bytes() // g a base used for generic public values
	// p and g are public paramters, both parties need to know these paramters to perform the key exchange

	publicKey := serverPublicKey.Bytes() // Ys the server public key
	// the server public key is essential for the client t ocompue the shared secre, the clients needs this value to compute its own private value

	// to calcualte shared secret i need to clientPublic^serverPriavte mod p (pprime)

	resp := []byte{}
	resp = append(resp, []byte{0, byte(len(prime))}...)
	resp = append(resp, prime...)
	resp = append(resp, []byte{0, byte(len(generator))}...)
	resp = append(resp, generator...)
	resp = append(resp, []byte{0, byte(len(publicKey))}...)
	resp = append(resp, publicKey...)

	return resp
}

// Compute the shared secret
// client public key, server private key, prime number  client public key^server private mod p
func (dh *DhParams) ComputePreMasterSecret() *big.Int {
	fmt.Println("clientPublic")
	fmt.Println("clientPublic")
	fmt.Println("clientPublic")
	fmt.Println("clientPublic")
	fmt.Println("clientPublic")
	fmt.Println("clientPublic")
	fmt.Println("clientPublic")
	fmt.Println("clientPublic")
	fmt.Println("clientPublic")
	fmt.Println("clientPublic")
	fmt.Println("clientPublic")
	fmt.Println(dh.ClientPublic.Bytes())
	fmt.Println("private")
	fmt.Println(dh.Private.Bytes())
	fmt.Println("p")
	fmt.Println(dh.P)
	fmt.Println("result ")
	fmt.Println(new(big.Int).Exp(dh.ClientPublic, dh.Private, dh.P).Bytes())
	return new(big.Int).Exp(dh.ClientPublic, dh.Private, dh.P)
}
