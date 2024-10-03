package handshake

import (
	"crypto/dsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net"
	"os"
	"reflect"
	"time"
	s3_cipher "webserver/cipher"
	"webserver/global"
	"webserver/helpers"
)

// SSL 3.0

// 1. Fragmentation, block goes int o sslplaintext
// struct {
// 		ContentType type;
// 		ProtocolVersion version;
// 		uint16 length;
// 		opaque fragment[SSLPlaintext.length];
// } SSLPlaintext;
// } GenericBlockCipher;

// 2. Compression and decompression
//  struct {
// 		ContentType type;       /* same as SSLPlaintext.type */
// 		ProtocolVersion version;/* same as SSLPlaintext.version */
// 		uint16 length;
// 		opaque fragment[SSLCompressed.length];
// } SSLCompressed;

// 3. Integrity of data (mac), intially record is set SSL_NULL_WITH_NULL_NULL, which does not provide any security., but once the handshake is complete, the two partied have shared secrets that are used to encrypt record and compute mac
// Transform SSLCompressed structure into an SSLCiphertext.
// struct {
// 		ContentType type;
// 		ProtocolVersion version;
// 		uint16 length;
// 		select (CipherSpec.cipher_type) {
// 			case stream: GenericStreamCipher;
// 			case block: GenericBlockCipher;
// 		} fragment;
// 	} SSLCiphertext;

//  stream-ciphered struct {
// 		opaque content[SSLCompressed.length];
// 		opaque MAC[CipherSpec.hash_size];
// } GenericStreamCipher;

// block-ciphered struct {
// 		opaque content[SSLCompressed.length];
// 		opaque MAC[CipherSpec.hash_size];
// 		uint8 padding[GenericBlockCipher.padding_length];
// 		uint8 padding_length;
// } GenericBlockCipher;
// Block cipher required padding to fill the gap e.g we have 1000 bytes and we add 24 bytes to have 1024 bytes block.

//  block ciphers: des, 3des, rc2
// stream ciphers: rc2
// We have two StreamCipher and BlockCipher for backward comapbility and flexibility

// Handshake

// Client                                                Server
//       ClientHello                   -------->
//                                                        ServerHello
//                                                       Certificate*
//                                                 ServerKeyExchange*
//                                                CertificateRequest*
//                                     <--------      ServerHelloDone
//       Certificate*
//       ClientKeyExchange
//       CertificateVerify*
//       [ChangeCipherSpec]
//       Finished                      -------->
//                                                 [ChangeCipherSpec]
//                                     <--------             Finished
//       Application Data              <------->     Application Data

// First ssl client and server agree on protocol version, select cryptographic algorithms, optionally authenticate each other (sometime client send certificate too), add use public key encryption techniquies to generate  shared secrets.
// Client send a hello message to which server must respond with server hello or fatal error will occure when connection will fail.
// Client and server establishes following attribute: Procotol version, sessio id, cipher suite, compression method and additonal two random values are generatd and exchanged, clientHello.random and serverHello.random
// Following the hello message, server will send its certificatem Additonally, a server key excvhange massage may be sent, if it is required( e.g if their server has no certificate or if its cerificate is for singing only, for certian algorithms like diffie-hellman server maay need provide additional parameters):
// Signin certificate: oftren used in senceration like code singin, document or digital signatures, where primarly requirement is to verify the identity of signer and the integiry of the signed content, but not really for secure connection, there is not encryption of data nor a pulibc key
// Then sometime sever may request client cerificate if that is appropriate to the cipher suite selected.
// Now server send hello message done
// Client then can send certificate or send notify there is no certificate, then send client key exchange, content of the message will depend on pblic key algorithm selected. IF theclient has sent a certificate with signing ability, a digitally signed cerificate verify message is sent to explicity verify the cerifiacte (client encrypts message with private key, send to the server, server decrypts and cofirms it)
// client send cofirmation that it will used cipher spect and copy key to current state and start using them
// Client send finished message under cuureny ciper spec, so handshake its pretty complete

// Resume session

// Client                                       Server
// ClientHello                   -------->
// 												ServerHello
// 												[change cipher spec]
// 							  	<--------       Finished
// change cipher spec
// Finished                      -------->
// Application Data              <------->     Application Data

// clients send a hello, using session id, server checks its session cache for a match if it found server is willing to re esatblished connection under the specified ssession state, it will send server hello with same sesion id. At this point client and sever need to change cipher spec.
// If session if is not found, sever generated a new session id and the ssl client and server perform a full handskae.

type TlSContentType byte

const (
	TLSContentTypeApplicationData  TlSContentType = 23
	TLSContentTypeHandshake        TlSContentType = 22
	TLSContentTypeAlert            TlSContentType = 21
	TLSContentTypeChangeCipherSpec TlSContentType = 20
	// to help avoid pipeline stalls, changeciperspec is independet ssl protocol type
	// The CCS message being independent allows it to be processed out of sync with the strict sequence of handshake messages. While the rest of the handshake is being processed, the system can already signal readiness to switch to the new cipher suite, avoiding unnecessary wait times.
)

type SSLVersion uint16

const (
	SSL30Version SSLVersion = 0x0300
)

type TLSAlertDescription byte

const (
	TLSAlertDescriptionCloseNotify            TLSAlertDescription = 0
	TLSAlertDescriptionUnexpectedMessage      TLSAlertDescription = 10
	TLSAlertDescriptionBadRecordMac           TLSAlertDescription = 20
	TLSAlertDescriptionDecompressionFailure   TLSAlertDescription = 30
	TLSAlertDescriptionHandshakeFailure       TLSAlertDescription = 40
	TLSAlertDescriptionNoCertificate          TLSAlertDescription = 41
	TLSAlertDescriptionBadCertificate         TLSAlertDescription = 42
	TLSAlertDescriptionUnsupportedCertificate TLSAlertDescription = 43
	TLSAlertDescriptionCertificateRevoked     TLSAlertDescription = 44
	TLSAlertDescriptionCertificateExpired     TLSAlertDescription = 45
	TLSAlertDescriptionCertificateUnknown     TLSAlertDescription = 46
	TLSAlertDescriptionIllegalParameter       TLSAlertDescription = 47
)

const MASTER_SECRET_LENGTH = 48
const RANDOM_BYTES_LENGTH = 32

type TlSAlertLevel byte

const (
	TLSAlertLevelwarning TlSAlertLevel = 1
	TLSAlertLevelfatal   TlSAlertLevel = 2
)

type TLSHandshakeMessageType byte

const (
	TLSHandshakeMessageHelloRequest TLSHandshakeMessageType = 0
	// server send a request to start new handshake process, allowing session renewals and paramters update
	TLSHandshakeMessageClientHello       TLSHandshakeMessageType = 1
	TLSHandshakeMessageServerHello       TLSHandshakeMessageType = 2
	TLSHandshakeMessageCertificate       TLSHandshakeMessageType = 11
	TLSHandshakeMessageServerKeyExchange TLSHandshakeMessageType = 12
	TLSHandshakeMessageCerificateRequest TLSHandshakeMessageType = 13
	TLSHandshakeMessageServerHelloDone   TLSHandshakeMessageType = 14
	TLSHandshakeMessageCertificateVerify TLSHandshakeMessageType = 15
	TLSHandshakeMessageClientKeyExchange TLSHandshakeMessageType = 16
	TLSHandshakeMessageFinished          TLSHandshakeMessageType = 20
)

type TLSCipherSpec byte

const (
	TLSCipherSpecDefault TLSCipherSpec = 1
)

type Sender uint64

const (
	ClientSender Sender = 0x434C4E54
	serverSender Sender = 0x53525652
)

var pad1 = []byte{
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}

// for sha
var pad2 = []byte{
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}

// DES -Data encryption standard, block encryption, symmetric key, not secure anymore, succedor is 3des, and then aes replaced them

// AES advanced encryption standard, block cipher, symmetric key, aes is faster

type ServerData struct {
	IsClientEncrypted bool
	IsServerEncrypted bool
	PreMasterSecret   []byte
	ClientRandom      []byte
	ServerRandom      []byte
	SSLVersion        []byte
	HandshakeMessages [][]byte
	MasterKey         []byte
	CipherDef         s3_cipher.CipherDef
	ServerSeqNum      []byte
	ClientSeqNum      []byte
	conn              net.Conn
	wBuff             []byte
	cert              []byte
	session           []byte
	reuseSession      bool
}

var sessions = make(map[string]*ServerData)

func (serverData *ServerData) loadCert(certPath, keyPath string) error {

	certBytes, err := serverData.ParseCertificate(certPath, keyPath)

	if err != nil {
		return fmt.Errorf("problem passing certificate, err:%v", err)
	}

	serverData.cert = certBytes

	return nil

}

// parse privaty key in PCKS doesnt work for dsa :) `AGL suggested that nobody uses DSA anymore, so this can be closed.` https://github.com/golang/go/issues/6868
func ParseDSAPrivateKeyPCKS8(der []byte) (*dsa.PrivateKey, error) {

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
		fmt.Printf("\n error parsing, err:%v", err)
		return nil, fmt.Errorf("cant parse it")
	}

	var value *big.Int

	// Unmarshal the ASN.1-encoded data
	_, err = asn1.Unmarshal(k.PrivateKey, &value)
	if err != nil {
		fmt.Println("Error unmarshaling ASN.1:", err)
		return nil, fmt.Errorf("cant parse it")
	}

	// Compute the public key (Y = G^X mod P)
	publicKey := new(big.Int).Exp(k.Algorithm.Structt.G, value, k.Algorithm.Structt.P)

	if err != nil {
		fmt.Printf("error parsing k11, err: %v", err)
		os.Exit(1)
	}

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

func ParseDSAPrivateKey(der []byte) (*dsa.PrivateKey, error) {

	privkey, err := ParseDSAPrivateKeyPCKS8(der)
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
	fmt.Println("lets display k")
	fmt.Printf("/n %+v", k)
	fmt.Println("bytes")
	fmt.Println(k.Priv.Bytes())
	if err != nil {
		return nil, errors.New("ssh: failed to parse DSA key: " + err.Error())
	}
	if len(rest) > 0 {
		return nil, errors.New("ssh: garbage after DSA key")
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

	fmt.Printf("\n private key:%+v", dsaKey)

	return dsaKey, nil
}

func (serverData *ServerData) ParseCertificate(certFile, keyFile string) ([]byte, error) {
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
		dsaPrivate, err := ParseDSAPrivateKey(keyBlockBytes)

		if err != nil {
		} else {
			serverData.CipherDef.Dsa.PrivateKey = *dsaPrivate
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
			serverData.CipherDef.Rsa.PrivateKey = *rsaKey
		} else {
			fmt.Println("can't convert to rsa private key")
			os.Exit(1)
		}
	} else {
		return nil, fmt.Errorf("\n unkown certificate with pub cert algorithm: %v", cert.PublicKeyAlgorithm)
	}

	rawBytes := cert.Raw
	return rawBytes, nil
}

func StartHttpServer(params *global.Params, server *global.Server) {

	listener, err := net.Listen("tcp", "127.0.0.1:4221")

	if err != nil {
		fmt.Println("errr has occured trying while trying to connect")
		fmt.Println(err)
	}
	server.Wg.Done()
	server.Conn = listener
	for {
		sslVersionBinary := make([]byte, 2)
		binary.BigEndian.PutUint16(sslVersionBinary, uint16(SSL30Version))
		fmt.Println("hello version")
		fmt.Println(sslVersionBinary)
		serverData := ServerData{ServerSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0}, SSLVersion: sslVersionBinary, ClientSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0}, CipherDef: s3_cipher.CipherDef{}}

		if (params) != nil {

			err := serverData.loadCert(params.CertPath, params.KeyPath)

			if err != nil {
				fmt.Printf("\n problem loading certificate, err :%v", err)
				os.Exit(1)
			}
		}
		conn, err := listener.Accept()

		if err != nil {
			fmt.Println("errr has occured trying while trying to connect")
			fmt.Println(err)
			break
		}

		serverData.conn = conn

		HandleConnection(conn, &serverData)
	}
}

func HandleConnection(conn net.Conn, serverData *ServerData) {
	defer conn.Close()

	bufInit := []byte{}
	for {

		buff := make([]byte, 1024)
		n, err := conn.Read(buff)
		if err != nil {
			fmt.Println("Error reading Client Hello:", err)
			return
		}

		clientHello := buff[:n]
		fmt.Println("New message came in")
		fmt.Println("client hello")
		fmt.Printf("\n len:%v\n", len(clientHello))
		fmt.Println(clientHello)
		for _, v := range clientHello {
			fmt.Printf(" %02X", v)
		}

		input := append(bufInit, clientHello...)
		msgs, partial, err := serverData.Parser(input)
		bufInit = partial

		if err != nil {
			fmt.Printf("\n parser error: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)

		}

		for _, msg := range msgs {
			handleMessage(msg, conn, serverData)
		}
	}

}

func (serverData *ServerData) sendAlertMsg(level TlSAlertLevel, description TLSAlertDescription) {
	msg := []byte{byte(TLSContentTypeAlert)}
	msg = append(msg, serverData.SSLVersion...)
	msg = append(msg, []byte{0, 2}...)
	msg = append(msg, byte(level))
	msg = append(msg, byte(description))

	_, err := serverData.conn.Write(msg)

	if err != nil {
		fmt.Println("Problem senidng alert")
		os.Exit(1)
	}

	handleAlert(msg, serverData.conn)

}

func generate_finished_handshake_mac(hashingAlgorithm hash.Hash, masterSecret, sender []byte, handshakeMessages [][]byte) []byte {
	n := hashingAlgorithm.Size()
	// Legacy thing with fixed number of 48 bytes
	npad := (48 / n) * n

	pad1Arr := pad1[:npad]
	pad2Arr := pad2[:npad]

	allHandskaedMessageCombined := []byte{}

	for _, v := range handshakeMessages {
		allHandskaedMessageCombined = append(allHandskaedMessageCombined, v...)
	}

	hashingAlgorithm.Write(allHandskaedMessageCombined)
	hashingAlgorithm.Write(sender)
	hashingAlgorithm.Write(masterSecret)
	hashingAlgorithm.Write(pad1Arr)

	tmp := hashingAlgorithm.Sum(nil)
	hashingAlgorithm.Reset()

	hashingAlgorithm.Write(masterSecret)
	hashingAlgorithm.Write(pad2Arr)
	hashingAlgorithm.Write(tmp)

	return hashingAlgorithm.Sum(nil)
}

func ssl_prf(secret, seed []byte, req_len int) []byte {
	hashSHA1 := sha1.New()
	hashMD5 := md5.New()
	result := []byte{}

	rounds := (req_len + hashMD5.Size() - 1) / hashMD5.Size()

	labelArr := [][]byte{{'A'}, {'B', 'B'}, {'C', 'C', 'C'}, {'D', 'D', 'D', 'D'}, {'E', 'E', 'E', 'E', 'E'}, {'F', 'F', 'F', 'F', 'F', 'F'}, {'G', 'G', 'G', 'G', 'G', 'G', 'G'}}

	for i := 0; i < rounds; i++ {
		label := labelArr[i]

		hashSHA1.Reset()
		hashSHA1.Write(label)
		hashSHA1.Write(secret)
		hashSHA1.Write(seed)
		digest := hashSHA1.Sum(nil)

		hashMD5.Reset()
		hashMD5.Write(secret)
		hashMD5.Write(digest)
		md5Digest := hashMD5.Sum(nil)

		result = append(result, md5Digest...)
	}

	return result
}

func (serverData *ServerData) generateStreamCipher(dataCompressedType, sslCompressData []byte, seqNum, mac []byte) []byte {

	// 	stream-ciphered struct {
	// 		opaque content[SSLCompressed.length];
	// 		opaque MAC[CipherSpec.hash_size];
	// 	} GenericStreamCipher;

	// The MAC is generated as:

	// 	hash(MAC_write_secret + pad_2 +
	// 		 hash(MAC_write_secret + pad_1 + seq_num +
	// 			  SSLCompressed.type + SSLCompressed.length +
	// 			  SSLCompressed.fragment));
	var nPad int
	var hashFunc hash.Hash

	switch serverData.CipherDef.Spec.HashAlgorithm {
	case s3_cipher.HashAlgorithmMD5:
		nPad = 48
		hashFunc = md5.New()
	case s3_cipher.HashAlgorithmSHA:
		nPad = 40
		hashFunc = sha1.New()
	default:
		panic("wrong algorithm used can't use: " + serverData.CipherDef.Spec.HashAlgorithm)
	}

	ssl3Pad1Sha := pad1[:nPad]
	ssl3Pad2Sha := pad2[:nPad]

	sslCompressLength := helpers.Int32ToBigEndian(len(sslCompressData))

	hashFunc.Write(mac)
	hashFunc.Write(ssl3Pad1Sha)
	hashFunc.Write(seqNum)
	hashFunc.Write(dataCompressedType)
	hashFunc.Write(sslCompressLength)
	hashFunc.Write(sslCompressData)

	tmp := hashFunc.Sum(nil)
	hashFunc.Reset()

	hashFunc.Write(mac)
	hashFunc.Write(ssl3Pad2Sha)
	hashFunc.Write(tmp)

	return hashFunc.Sum(nil)
}

func handleMessage(clientData []byte, conn net.Conn, serverData *ServerData) {
	contentType := clientData[0]
	dataContent := clientData[5:]
	if serverData.IsClientEncrypted {
		decryptedClientData := serverData.CipherDef.DecryptMessage(clientData[5:], serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient)
		serverData.verifyMac(contentType, decryptedClientData)

		dataContent = decryptedClientData

	}

	if contentType == byte(TLSContentTypeHandshake) {

		handshakeLength := int32(dataContent[1])<<16 | int32(dataContent[2])<<8 | int32(dataContent[3])
		serverData.HandshakeMessages = append(serverData.HandshakeMessages, dataContent[:handshakeLength+4])
		serverData.handleHandshake(dataContent)

	} else if contentType == byte(TLSContentTypeAlert) {
		handleAlert(dataContent, conn)
	} else if contentType == byte(TLSContentTypeChangeCipherSpec) {
		serverData.handleHandshakeChangeCipherSpec(dataContent)
	} else {
		fmt.Println("Unknown record layer type:" + string(contentType))
		serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
	}

}

func (serverData *ServerData) verifyMac(contentType byte, contentData []byte) {
	var clientDataWithHeader int32
	if contentType == 22 {
		clientDataLength := int32(contentData[1])<<16 | int32(contentData[2])<<8 | int32(contentData[3])
		clientDataWithHeader = 4 + clientDataLength
	} else if contentType == 21 {
		clientDataWithHeader = 2
		// return
	}

	dataSent := contentData[:clientDataWithHeader]

	streamCipher := serverData.generateStreamCipher([]byte{byte(contentType)}, dataSent, serverData.ClientSeqNum, serverData.CipherDef.Keys.MacClient)

	if !reflect.DeepEqual(streamCipher, contentData[clientDataWithHeader:]) {
		fmt.Printf("\n macs are diffrent, expected: %v, got: %v", streamCipher, contentData[clientDataWithHeader:])
		serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionBadRecordMac)

		return
	}

	for i := 7; i >= 0; i-- {
		serverData.ClientSeqNum[i] += 1
		if serverData.ClientSeqNum[i] != 0 {
			break
		}
	}
}

func handleAlert(contentData []byte, conn net.Conn) {
	// majorVersion := clientHello[1]
	// minorVersion := clientHello[2]
	// length := clientHello[3:4]
	alertLevel := TlSAlertLevel(contentData[0])

	if alertLevel == TLSAlertLevelfatal {
		conn.Close()
		return
	}

	alertDescription := TLSAlertDescription(contentData[1])

	switch alertDescription {
	case TLSAlertDescriptionCloseNotify:
		// The connection is closing or has been closed gracefully, no action needed
		fmt.Println("Closing connection")
		conn.Close()
	case TLSAlertDescriptionUnexpectedMessage:
		// Do Retry, bad message recive, long term problem can indicate protocol mismatch(client expecting e.g tls 1.2 and server sending 1.3), incorrect squence or error in
		fmt.Print("Unexpected message, Retry connectin again, if problem persist, check configuration")

	case TLSAlertDescriptionBadRecordMac:
		// A message auhentication code (MAC) check failed, check your connection, can indicate server problem or an attack
		// Always fatal
		fmt.Print("MAC failed, check your connection")
	case TLSAlertDescriptionDecompressionFailure:
		// The compression function recived wrong input, mostly indicated corrupted message, decompression methods such as lz77, works by sling a window over the input data to idientify repeted sequences. It replaces these sequences with references to earlier occurances of the same sequence.
		// Lookahed bufer is a smaller buffer within the window that scans for the longer match of the current input string.
		// Match an literal: if match is found it is encoded a tuple (distance, length)
		//
		// Window	Lookahead	Output
		// a		bracadabra	Literal a
		// ab		racadabra	Literal b
		// abr		acadabra	Literal r
		// abra		cadabra		Literal a
		// abrac	adabra		(4, 1) (back 4, length 1)
		// abracad	abra		(7, 4) (back 7, length 4)
		fmt.Print("Can't decompress data, check for input corupteness")
	case TLSAlertDescriptionHandshakeFailure:
		// Handshake process failed, ensure that server and browser supports required protocol and ciphers, may indicate problem with server configuration
		// Always fatal
		fmt.Print("Handshake failure, make sure choose procol and ciphers are supported by both parties")
	case TLSAlertDescriptionNoCertificate:
		// No certificate was provided by the peer
		// Optional field
		fmt.Print("No certificate provided")
	case TLSAlertDescriptionBadCertificate:
		// Bad certificate
		fmt.Print("Make sure that provided cerificate is valid")
	case TLSAlertDescriptionUnsupportedCertificate:
		// The certificate is unsported:
		// 1. Invalid certificate type, e.g server can only accept x5.09 certificated
		// 2. Unrecgonized cerificate authority
		// 3. Certificate algorithm issue, its not supported by peers
		// 4. Certificate version its not supported
		fmt.Print("Unsported certificated, make sure both parties support the type, issuer, version and both known authority")
	case TLSAlertDescriptionCertificateRevoked:
		// Cerificate was revoke
		fmt.Print("Certificate revoked")
	case TLSAlertDescriptionCertificateExpired:
		// Cerificated expired
		fmt.Print("Certificate expiered")
	case TLSAlertDescriptionCertificateUnknown:
		// 1. Unknown certificate
		// 2. Untrusted CA
		// 3. Incomplete Certificate chain, presented certifiacted does not include a complate chain to trsuted root CA
		// 4. Revoked or expired
		// 5. Malformed or corrupted
		// 6. Mimstached purpose, doesnt have appropriate extention
		// 7. Expired trust store
		fmt.Print("Unknown certificate, check CA authority, trust store, extenstion compability or maybe its coruppted data")
	case TLSAlertDescriptionIllegalParameter:
		// Paramters not allowed or recognized:
		// 1. Invalid cipher suite, not implmented by one of the parties
		// 2. Not supported tls version
		// 3. Incorrected exntesion
		// 4. Invalid message structure
		fmt.Print("Illegal paramters, check tls version, supported protcol, extenstion or message structure")

	default:
		fmt.Printf("Unregonized alert occured: %v", alertDescription)
	}

}

func (serverData *ServerData) loadCertificate() error {

	handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(len(serverData.cert) + 3 + 3)
	if err != nil {
		return errors.New("problem converting record layer length to big endina")
	}

	certLengthByte, err := helpers.IntTo3BytesBigEndian(len(serverData.cert) + 3)
	if err != nil {
		return errors.New("problem converting certs length to big endina")
	}

	certLengthByteSingle, err := helpers.IntTo3BytesBigEndian(len(serverData.cert))
	if err != nil {
		return errors.New("problem converting cert length to big endina")
	}

	serverCertificate := []byte{}

	serverCertificate = append(serverCertificate, byte(TLSContentTypeHandshake))

	// 4 are bytes for handshake message type + record length, 3 are bytes for crts' length, 3 bytes are for cert(single);s len
	recordLengthByte := helpers.Int32ToBigEndian(len(serverData.cert) + 4 + 3 + 3)

	serverCertificate = append(serverCertificate, serverData.SSLVersion...)
	serverCertificate = append(serverCertificate, recordLengthByte...)
	serverCertificate = append(serverCertificate, byte(TLSHandshakeMessageCertificate))
	serverCertificate = append(serverCertificate, handshakeLengthByte...)
	serverCertificate = append(serverCertificate, certLengthByte...)
	serverCertificate = append(serverCertificate, certLengthByteSingle...)
	serverCertificate = append(serverCertificate, serverData.cert...)

	err = serverData.BuffSendData(serverCertificate)

	return err

}

func (serverData *ServerData) sendData(data []byte) (n int, err error) {

	if serverData.IsServerEncrypted && (data[0] == byte(TLSContentTypeHandshake) || data[0] == byte(TLSContentTypeApplicationData)) {
		for i := 7; i >= 0; i-- {
			serverData.ServerSeqNum[i] += 1
			if serverData.ServerSeqNum[i] != 0 {
				break
			}
		}
	}

	n, err = serverData.conn.Write(data)
	if err != nil {
		fmt.Println("Error reading Client Hello:", err)
		os.Exit(1)
	}
	serverData.wBuff = []byte{}

	return n, err
}

func (serverData *ServerData) BuffSendData(data []byte) error {

	if len(data) < 5 {
		return fmt.Errorf("message you're sending should be more than 5 chars")
	}

	serverData.wBuff = append(serverData.wBuff, data...)
	if data[0] == byte(TLSContentTypeHandshake) {
		// Collect only handshake content message without record layer, its used in server key exchange
		serverData.HandshakeMessages = append(serverData.HandshakeMessages, data[5:])
	}

	return nil
}

func (serverData *ServerData) handleHandshake(contentData []byte) {

	handshakeMessageType := TLSHandshakeMessageType(contentData[0])

	if handshakeMessageType == TLSHandshakeMessageClientHello {
		err := serverData.handleHandshakeClientHello(contentData)
		if err != nil {
			fmt.Printf("\n Problem handling client hello: %V", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

		fmt.Println("hello server data")
		fmt.Printf("\n %+v", serverData)

		err = serverData.serverHello()
		if err != nil {
			fmt.Printf("\n problem with serverHello msg : %V", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

		if serverData.reuseSession {
			serverData.changeCipher()
			serverData.calculateKeyBlock(serverData.MasterKey)
			err := serverData.serverFinished()

			fmt.Println("after server finished")
			if err != nil {
				fmt.Printf("\n problem with serverFinish msg, err: %v", err)
				serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
			}
			_, err = serverData.sendData(serverData.wBuff)
			return
		}

		if serverData.CipherDef.Spec.SignatureAlgorithm != s3_cipher.SignatureAlgorithmAnonymous {
			err := serverData.loadCertificate()
			if err != nil {
				fmt.Printf("\n problem loading certificate: %V", err)
				serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
			}
		}

		// The server key exchange message is sent by the server if it has no cetificate, has a certificate used for siging (e.g. dss certificate, signing-only rsa)
		// if serverData.CipherDef.Spec.SignatureAlgorithm == s3_cipher.SignatureAlgorithmAnonymous || // No certificate
		// 	serverData.CipherDef.Spec.SignatureAlgorithm == s3_cipher.SignatureAlgorithmDSA || // das certificate
		// 	(serverData.CipherDef.Spec.SignatureAlgorithm == s3_cipher.SignatureAlgorithmRSA && // signin only
		// 		(serverData.CipherDef.Spec.KeyExchange == s3_cipher.KeyExchangeMethodDH))
		// I think can simply if to just if the key exchange method is DH
		if serverData.CipherDef.Spec.KeyExchange == s3_cipher.KeyExchangeMethodDH {
			err = serverData.serverKeyExchange()
			if err != nil {
				fmt.Printf("\n problem with serverkeyexchange message: %V", err)
				serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
			}
		}

		err = serverData.serverHelloDone()
		if err != nil {
			fmt.Printf("\n  problem with serverHelloDone message, err: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

		// lets do one write with collected few messages, don't send extra network round trips
		_, err = serverData.sendData(serverData.wBuff)
		if err != nil {
			fmt.Printf("\n problem sending server hello data, err: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

	} else if handshakeMessageType == TLSHandshakeMessageClientKeyExchange {
		// computes ivs, writekeys, macs, don't need to send any message after this
		serverData.handleHandshakeClientKeyExchange(contentData)

	} else if handshakeMessageType == TLSHandshakeMessageFinished {
		if serverData.reuseSession {
			return
		}
		serverData.handleHandshakeClientFinished(contentData)

		serverData.changeCipher()

		// We don't combine message here to single route trip as change cipher msg is separate content type, in order to not be stalling
		_, err := serverData.sendData(serverData.wBuff)
		if err != nil {
			fmt.Printf("\n problem sending change cipher msg: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

		err = serverData.serverFinished()
		if err != nil {
			fmt.Printf("\n problem with serverFinish msg, err: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}
		_, err = serverData.sendData(serverData.wBuff)

		if err != nil {
			fmt.Printf("\n problem sending server finished msgs: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

		sessions[string(serverData.session)] = serverData

	}
}

func (serverData *ServerData) loadSession(sessionId string) {
	if sessions[sessionId] != nil {
		session := sessions[sessionId]
		serverData.IsClientEncrypted = false
		serverData.reuseSession = true

		serverData.PreMasterSecret = session.PreMasterSecret
		serverData.MasterKey = session.MasterKey
		serverData.CipherDef = session.CipherDef
		serverData.cert = session.cert
		serverData.session = session.session
	}
}

func (serverData *ServerData) handleHandshakeClientHello(contentData []byte) error {
	contentLength := int(contentData[1])<<16 | int(contentData[2])<<8 | int(contentData[3])
	dataContentExpectedLen := contentLength + 4 // 4: 1 bytefor content type, 3 bytes for length
	if dataContentExpectedLen != len(contentData) {
		return fmt.Errorf("conent length does not fit data passed, expected to have length of: %v, got: %v", dataContentExpectedLen, len(contentData))
	}

	clientVersion := contentData[4:6] // backward compability, used to dicated which version to use, now we have version in protocol header.

	if !reflect.DeepEqual(clientVersion, serverData.SSLVersion) {
		return fmt.Errorf("ssl version not matches, expected: %v, got: %v", serverData.SSLVersion, clientVersion)
	}
	radnomBytesTime := int64(binary.BigEndian.Uint32(contentData[6:10]))
	currentTime := time.Now().UnixMilli()

	if currentTime < radnomBytesTime {
		return fmt.Errorf("time: %v should be less than is currently: %v", radnomBytesTime, currentTime)
	}

	sessionLength := int(contentData[38])
	if sessionLength > 32 {
		return fmt.Errorf("session length should be between 0-32")
	}
	sessionIndexEnd := uint16(39 + sessionLength)
	session := contentData[39:sessionIndexEnd]

	cipherSuitesLength := binary.BigEndian.Uint16(contentData[sessionIndexEnd : sessionIndexEnd+2])

	cipherSuites := contentData[sessionIndexEnd+2 : sessionIndexEnd+2+cipherSuitesLength]
	compressionsLength := contentData[sessionIndexEnd+2+cipherSuitesLength]
	compressionMethodList := contentData[sessionIndexEnd+2+cipherSuitesLength+1:]

	if len(compressionMethodList) != int(compressionsLength) {
		return fmt.Errorf("\n got length:%v, expected :%v", len(compressionMethodList), int(compressionsLength))
	}

	serverData.loadSession(string(session))

	serverData.ClientRandom = contentData[6:38]
	err := serverData.CipherDef.SelectCipherSuite(cipherSuites)
	if err != nil {
		return err
	}
	serverData.CipherDef.GetCipherSpecInfo()
	err = serverData.CipherDef.SelectCompressionMethod(compressionMethodList)

	return err
}

func signatureHash(algorithm hash.Hash, clientRandom, serverRandom, serverParams []byte) []byte {
	algorithm.Reset()
	algorithm.Write(clientRandom)
	algorithm.Write(serverRandom)
	algorithm.Write(serverParams)

	return algorithm.Sum(nil)

}

func (serverData *ServerData) serverKeyExchange() error {
	fmt.Println("server key exchange")
	serverKeyExchange := []byte{}

	keyExchangeParams := serverData.CipherDef.GenerateServerKeyExchange()
	hash := []byte{}

	switch serverData.CipherDef.Spec.SignatureAlgorithm {
	case s3_cipher.SignatureAlgorithmAnonymous:
	case s3_cipher.SignatureAlgorithmRSA:
		md5Hash := signatureHash(md5.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		shaHash := signatureHash(sha1.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		hash = append(hash, md5Hash...)
		hash = append(hash, shaHash...)

	case s3_cipher.SignatureAlgorithmDSA:

		shaHash := signatureHash(sha1.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		hash = append(hash, shaHash...)
	default:
		return fmt.Errorf("unsupported Algorithm: %v", serverData.CipherDef.Spec.SignatureAlgorithm)
	}

	signedParams, err := serverData.CipherDef.SignData(hash)
	signatureLength := helpers.Int32ToBigEndian(len(signedParams))

	if err != nil {
		return err
	}

	keyExchangeData := []byte{}
	keyExchangeData = append(keyExchangeData, keyExchangeParams...)
	if len(signedParams) > 0 {
		keyExchangeData = append(keyExchangeData, signatureLength...)
		keyExchangeData = append(keyExchangeData, signedParams...)
	}

	handshakeLengthh := len(keyExchangeData)
	handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(handshakeLengthh)
	if err != nil {
		return fmt.Errorf("err while converting to big endina, err: %v", err)
	}
	recordLengthByte := helpers.Int32ToBigEndian(handshakeLengthh + 4)

	serverKeyExchange = append(serverKeyExchange, byte(TLSContentTypeHandshake))

	serverKeyExchange = append(serverKeyExchange, serverData.SSLVersion...)
	serverKeyExchange = append(serverKeyExchange, recordLengthByte...)
	serverKeyExchange = append(serverKeyExchange, byte(TLSHandshakeMessageServerKeyExchange))
	serverKeyExchange = append(serverKeyExchange, handshakeLengthByte...)
	serverKeyExchange = append(serverKeyExchange, keyExchangeData...)

	err = serverData.BuffSendData(serverKeyExchange)

	return err
}

func (serverData *ServerData) serverHello() error {

	currentTime := time.Now()
	unixTime := currentTime.Unix()

	unitTimeBytes := helpers.Int64ToBIgEndian(unixTime)
	randomBytes := make([]byte, RANDOM_BYTES_LENGTH-len(unitTimeBytes))

	_, err := rand.Read(randomBytes)

	if err != nil {
		fmt.Print("problem generating random bytes")
	}

	cipherSuite := helpers.Int32ToBigEndian(int(serverData.CipherDef.CipherSuite))
	compressionMethod := []byte{byte(serverData.CipherDef.Spec.CompressionMethod)}
	protocolVersion := serverData.SSLVersion

	session := []byte{}
	sessionLength := []byte{0}

	if len(serverData.session) != 0 {
		session = serverData.session
		sessionLength = []byte{byte(len(session))}
	} else {
		session = GenerateSession()
		sessionLength = []byte{byte(len(session))}
		serverData.session = session
	}

	handshakeLength := len(unitTimeBytes) + len(randomBytes) + len(sessionLength) + len(session) + len(cipherSuite) + len(compressionMethod) + len(protocolVersion)
	handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(handshakeLength)

	if err != nil {
		return fmt.Errorf("error converting int to big endian: %v", err)
	}

	recordLengthByte := helpers.Int32ToBigEndian(handshakeLength + 4)

	serverHello := []byte{byte(TLSContentTypeHandshake)}
	serverHello = append(serverHello, serverData.SSLVersion...)
	serverHello = append(serverHello, recordLengthByte...)
	serverHello = append(serverHello, byte(TLSHandshakeMessageServerHello))
	serverHello = append(serverHello, handshakeLengthByte...)
	serverHello = append(serverHello, protocolVersion...)
	serverHello = append(serverHello, unitTimeBytes...)
	serverHello = append(serverHello, randomBytes...)
	serverHello = append(serverHello, sessionLength...)
	serverHello = append(serverHello, session...)
	serverHello = append(serverHello, cipherSuite...)
	serverHello = append(serverHello, compressionMethod...)

	serverData.ServerRandom = unitTimeBytes
	serverData.ServerRandom = append(serverData.ServerRandom, randomBytes...)

	err = serverData.BuffSendData(serverHello)

	return err
}

func (serverData *ServerData) serverHelloDone() error {
	serverHelloDone := []byte{byte(TLSContentTypeHandshake)}
	serverHelloDone = append(serverHelloDone, serverData.SSLVersion...)
	serverHelloDone = append(serverHelloDone, []byte{0, 4}...) // hardcoded as it is always 4 bytes, 1 byte messageType 3 bytes length
	serverHelloDone = append(serverHelloDone, byte(TLSHandshakeMessageServerHelloDone))
	serverHelloDone = append(serverHelloDone, []byte{0, 0, 0}...) // Always 0 length

	err := serverData.BuffSendData(serverHelloDone)

	return err
}

func (serverData *ServerData) handleHandshakeClientKeyExchange(contentData []byte) {

	preMasterSecret := serverData.CipherDef.ComputerMasterSecret(contentData[4:])

	masterKeySeed := []byte{}
	masterKeySeed = append(masterKeySeed, serverData.ClientRandom...)
	masterKeySeed = append(masterKeySeed, serverData.ServerRandom...)

	masterKey := ssl_prf(preMasterSecret, masterKeySeed, MASTER_SECRET_LENGTH)

	serverData.calculateKeyBlock(masterKey)

	serverData.MasterKey = masterKey
	serverData.PreMasterSecret = preMasterSecret
}

func (serverData *ServerData) calculateKeyBlock(masterKey []byte) {
	keyBlockSeed := []byte{}
	keyBlockSeed = append(keyBlockSeed, serverData.ServerRandom...)
	keyBlockSeed = append(keyBlockSeed, serverData.ClientRandom...)

	keyBlockLen := serverData.CipherDef.Spec.HashSize*2 + serverData.CipherDef.Spec.KeyMaterial*2 + serverData.CipherDef.Spec.IvSize*2
	keyBlock := ssl_prf(masterKey, keyBlockSeed, keyBlockLen)

	macEndIndex := serverData.CipherDef.Spec.HashSize * 2
	writeKeyEndIndex := macEndIndex + serverData.CipherDef.Spec.KeyMaterial*2

	cipherDefKeys := s3_cipher.CipherKeys{
		MacClient:      keyBlock[:serverData.CipherDef.Spec.HashSize],
		MacServer:      keyBlock[serverData.CipherDef.Spec.HashSize:macEndIndex],
		WriteKeyClient: keyBlock[macEndIndex : macEndIndex+serverData.CipherDef.Spec.KeyMaterial],
		WriteKeyServer: keyBlock[serverData.CipherDef.Spec.HashSize*2+serverData.CipherDef.Spec.KeyMaterial : writeKeyEndIndex],
		IVClient:       keyBlock[writeKeyEndIndex : writeKeyEndIndex+serverData.CipherDef.Spec.IvSize],
		IVServer:       keyBlock[writeKeyEndIndex+serverData.CipherDef.Spec.IvSize : writeKeyEndIndex+serverData.CipherDef.Spec.IvSize*2],
	}

	serverData.CipherDef.Keys = cipherDefKeys
}

func (serverData *ServerData) changeCipher() {
	serverData.ServerSeqNum = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	serverData.IsServerEncrypted = true

	changeCipherSpecContent := []byte{byte(TLSCipherSpecDefault)}
	changeCiperSpecLength := helpers.Int32ToBigEndian(len(changeCipherSpecContent))

	changeCipherSpecMsg := []byte{byte(TLSContentTypeChangeCipherSpec)}
	changeCipherSpecMsg = append(changeCipherSpecMsg, serverData.SSLVersion...)
	changeCipherSpecMsg = append(changeCipherSpecMsg, changeCiperSpecLength...)
	changeCipherSpecMsg = append(changeCipherSpecMsg, changeCipherSpecContent...)

	serverData.BuffSendData(changeCipherSpecMsg)
}

func (serverData *ServerData) serverFinished() error {
	serverBytes := helpers.Int64ToBIgEndian(int64(serverSender))

	verifyHashMac := []byte{}
	md5Hash := generate_finished_handshake_mac(md5.New(), serverData.MasterKey, serverBytes, serverData.HandshakeMessages)
	shaHash := generate_finished_handshake_mac(sha1.New(), serverData.MasterKey, serverBytes, serverData.HandshakeMessages)

	hashLen := len(md5Hash) + len(shaHash)
	msgLenEndian, err := helpers.IntTo3BytesBigEndian(hashLen)

	if err != nil {
		return fmt.Errorf("problem converting hash len into endian format")
	}

	verifyHashMac = append(verifyHashMac, md5Hash...)
	verifyHashMac = append(verifyHashMac, shaHash...)

	verifyMacWithHeaders := []byte{byte(TLSHandshakeMessageFinished)}
	verifyMacWithHeaders = append(verifyMacWithHeaders, msgLenEndian...)
	verifyMacWithHeaders = append(verifyMacWithHeaders, verifyHashMac...)

	mac := serverData.generateStreamCipher([]byte{byte(TLSContentTypeHandshake)}, verifyMacWithHeaders, serverData.ServerSeqNum, serverData.CipherDef.Keys.MacServer)

	combinedBytes := []byte{}
	combinedBytes = append(combinedBytes, verifyMacWithHeaders...)
	combinedBytes = append(combinedBytes, mac...)

	encryptedMsg := serverData.CipherDef.EncryptMessage(combinedBytes, serverData.CipherDef.Keys.WriteKeyServer, serverData.CipherDef.Keys.IVServer)
	encryptedMsgLength := helpers.Int32ToBigEndian(len(encryptedMsg))

	serverFinished := []byte{byte(TLSContentTypeHandshake)}
	serverFinished = append(serverFinished, serverData.SSLVersion...)
	serverFinished = append(serverFinished, encryptedMsgLength...)
	serverFinished = append(serverFinished, encryptedMsg...)

	serverData.BuffSendData(serverFinished)

	return nil

}

func (serverData *ServerData) handleHandshakeClientFinished(contentData []byte) [][]byte {

	clientBytes := helpers.Int64ToBIgEndian(int64(ClientSender))

	clientHash := []byte{}

	md5Hash := generate_finished_handshake_mac(md5.New(), serverData.MasterKey, clientBytes, serverData.HandshakeMessages[:len(serverData.HandshakeMessages)-1])  // -1 without last message witch is client verify
	shaHash := generate_finished_handshake_mac(sha1.New(), serverData.MasterKey, clientBytes, serverData.HandshakeMessages[:len(serverData.HandshakeMessages)-1]) // -1 without last message witch is client verify

	hashLen := len(md5Hash) + len(shaHash)

	clientHash = append(clientHash, md5Hash...)
	clientHash = append(clientHash, shaHash...)

	// 4 bytes, 1 handshake type, 3 byes length
	inputHash := contentData[4:]

	if !reflect.DeepEqual(clientHash, inputHash[:hashLen]) {
		fmt.Printf("message are different, expected: %v, got: %v", inputHash[:hashLen], clientHash)
		serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionBadRecordMac)
	}

	return [][]byte{}

}

func (serverData *ServerData) handleHandshakeChangeCipherSpec(contentData []byte) {
	serverData.ClientSeqNum = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	message := TLSCipherSpec(contentData[0])
	if message == TLSCipherSpecDefault {
		fmt.Print("Sender is switching to new cipher :)")
	}
	serverData.IsClientEncrypted = true
}
