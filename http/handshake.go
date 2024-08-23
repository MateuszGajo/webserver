package http

import "C"
import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net"
	"time"
	s3_cipher "webserver/cipher"
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
	TLSContentTypeHandshake        TlSContentType = 22
	TLSContentTypeAlert            TlSContentType = 21
	TLSContentTypeChangeCipherSpec TlSContentType = 20
	// to help avoid pipeline stalls, changeciperspec is independet ssl protocl type
	// Treated as its own conten type a not handshake massage it can be proceessed independently of the handshake flow this allow to iimmedietly recognize that
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

type TlSAlertLevel byte

const (
	TLSAlertLevelwarning TlSAlertLevel = 1
	TLSAlertLevelfatal   TlSAlertLevel = 2
)

type TLSHandshakeMessageType byte

const (
	TLSHandshakeMessageHelloRequest TLSHandshakeMessageType = 0
	// server send a request to start new handshake process, allowing session renewls and paramters update
	TLSHandshakeMessageClinetHello       TLSHandshakeMessageType = 1
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

type TLSCompressionAlgorithm byte

const (
	TLSCompressionAlgorithmNull    TLSCompressionAlgorithm = 0
	TLSCompressionAlgorithmDeflate TLSCompressionAlgorithm = 1
	// I found it in seperate rfc, every rfc document ssl 3.0 tls 1.0 etc only contains null as compression algorithm nothing more. In tls 1.3 field is depracted + overall compression algorithm had vulnerability
	// Defalte uses loseless compression, attacker add some data to user's request  and observers if length is changeing, by doing that it can guess what string is in user cookie.
)

type ServerData struct {
	IsEncrypted      bool
	P                *big.Int
	Q                *big.Int
	Private          *big.Int
	Public           *big.Int
	PreMasterSecret  *big.Int
	ClientRandom     []byte
	ServerRandom     []byte
	AllMessagesShort [][]byte
	MasterKey        []byte
	CipherDef        s3_cipher.CipherDef
	SeqNum           int
}

// DES -Data encryption standard, block encryption, symmetric key, not secure anymore, succedor is 3des, and then aes replaced them

// AES advanced encryptio0n standard, block cipher, symmetric key, aes if faster

func intTo3BytesBigEndian(n int) ([]byte, error) {
	// Ensure the integer fits within 3 bytes
	if n < 0 || n > 16777215 {
		return nil, fmt.Errorf("integer out of range for 3 bytes")
	}

	// Create a byte slice of length 3
	bytes := make([]byte, 3)

	// Assign the bytes in big-endian order
	bytes[0] = byte((n >> 16) & 0xFF)
	bytes[1] = byte((n >> 8) & 0xFF)
	bytes[2] = byte(n & 0xFF)

	return bytes, nil
}

func int32ToBIgEndian(val int) []byte {
	bytes := make([]byte, 2)
	unit16value := uint16(val)

	binary.BigEndian.PutUint16(bytes, unit16value)

	return bytes
}

func int64ToBIgEndian(val int64) []byte {
	bytes := make([]byte, 4)
	unit16value := uint32(val)

	binary.BigEndian.PutUint32(bytes, unit16value)

	return bytes
}

func HandleConnection(conn net.Conn) {
	fmt.Print("connection")
	defer conn.Close()
	serverData := ServerData{SeqNum: 0}
	for {

		buff := make([]byte, 1024)
		n, err := conn.Read(buff)
		if err != nil {
			fmt.Println("Error reading Client Hello:", err)
			return
		}

		clientHello := buff[:n]

		for len(clientHello) > 0 {
			fmt.Println("\n loop cipher suite in main")
			fmt.Println("cipher suite in main")
			fmt.Println("cipher suite in main")
			fmt.Println(serverData.CipherDef.CipherSuite)
			fmt.Println("cipher suite in main")
			fmt.Println("cipher suite in main")
			fmt.Println("cipher suite in main")

			clientHello = handleMessage(clientHello, conn, &serverData)
		}
	}

	// clientHello := []byte{22, 3, 0, 0, 69, 1, 0, 0, 65, 3, 0, 102, 238, 138, 0, 43, 72, 173, 88, 26, 125, 182, 44, 4, 213, 158, 0, 30, 230, 195, 164, 44, 133, 177, 179, 138, 219, 68, 93, 157, 71, 88, 163, 127, 0, 0, 14, 0}

}

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

// Compute the shared secret
// client public key, server private key, prime number  client public key^server private mod p
func computeSharedSecret(publicKey, privateKey, p *big.Int) *big.Int {
	sharedSecret := new(big.Int).Exp(publicKey, privateKey, p)
	return sharedSecret
}

func generate_finished_message_md5(masterSecret, sender []byte, handshakeMessages [][]byte, pad1, pad2 byte) []byte {
	n := 16
	npad := (48 / n) * n
	hashMD5 := md5.New()
	pad1Arr := make([]byte, npad)
	for i := range pad1Arr {
		pad1Arr[i] = pad1
	}
	pad2Arr := make([]byte, npad)
	for i := range pad2Arr {
		pad2Arr[i] = pad2
	}

	allHandskaedMessageCombined := []byte{}

	for _, v := range handshakeMessages {
		allHandskaedMessageCombined = append(allHandskaedMessageCombined, v...)
	}

	hashMD5.Write(allHandskaedMessageCombined)
	for _, b := range sender {
		fmt.Printf(" %02X", b)
	}
	hashMD5.Write(sender)
	hashMD5.Write(masterSecret)

	hashMD5.Write(pad1Arr)
	tmp := hashMD5.Sum(nil)
	hashMD5.Reset()
	hashMD5.Write(masterSecret)
	hashMD5.Write(pad2Arr)
	hashMD5.Write(tmp)

	return hashMD5.Sum(nil)
}
func generate_finished_message_sha1(masterSecret, sender []byte, handshakeMessages [][]byte, pad1, pad2 byte) []byte {
	n := 20
	npad := (48 / n) * n
	hashSHA1 := sha1.New()
	pad1Arr := make([]byte, npad)
	for i := range pad1Arr {
		pad1Arr[i] = pad1
	}
	pad2Arr := make([]byte, npad)
	for i := range pad2Arr {
		pad2Arr[i] = pad2
	}

	allHandskaedMessageCombined := []byte{}

	for _, v := range handshakeMessages {
		allHandskaedMessageCombined = append(allHandskaedMessageCombined, v...)
	}

	hashSHA1.Write(allHandskaedMessageCombined)

	hashSHA1.Write(sender)
	hashSHA1.Write(masterSecret)

	hashSHA1.Write(pad1Arr)
	tmp := hashSHA1.Sum(nil)
	hashSHA1.Reset()
	hashSHA1.Write(masterSecret)
	hashSHA1.Write(pad2Arr)
	hashSHA1.Write(tmp)

	return hashSHA1.Sum(nil)
}

func ssl_prf(secret, seed []byte, req_len int) []byte {
	hashSHA1 := sha1.New()
	hashMD5 := md5.New()
	result := []byte{}

	rounds := (req_len + hashMD5.Size() - 1) / hashMD5.Size()

	d := [][]byte{{'A'}, {'B', 'B'}, {'C', 'C', 'C'}, {'D', 'D', 'D', 'D'}, {'E', 'E', 'E', 'E', 'E'}, {'F', 'F', 'F', 'F', 'F', 'F'}, {'G', 'G', 'G', 'G', 'G', 'G', 'G'}}

	for i := 0; i < rounds; i++ {
		label := d[i]

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

var ssl3Pad1 = []byte{
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}

// for sha
var ssl3Pad2 = []byte{
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}

type StreamCipherHash string

const (
	streamCipherHashMD5 = "streamCipherHashMD5"
	streamCipherHashSHA = "streamCipherHashSHA"
)

// TODO: lets think about seq number how to increment it and add it struct here, lets make GC lighweight
func generateStreamCipher(streamCipherHash StreamCipherHash, writeSecret, dataCompressedType, sslCompressData []byte, seqNum []byte) []byte {

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

	switch streamCipherHash {
	case streamCipherHashMD5:
		nPad = 48
		hashFunc = md5.New()
	case streamCipherHashSHA:
		nPad = 40
		hashFunc = sha1.New()
	default:
		panic("wrong algorithm used can't use: " + streamCipherHash)
	}

	ssl3Pad1Sha := ssl3Pad1[:nPad]

	ssl3Pad2Sha := ssl3Pad2[:nPad]

	// seqNum := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	sslCompressLength := []byte{0, 40}

	hashFunc.Write(writeSecret)
	hashFunc.Write(ssl3Pad1Sha)
	hashFunc.Write(seqNum)

	hashFunc.Write(dataCompressedType)

	hashFunc.Write(sslCompressLength)
	hashFunc.Write(sslCompressData)

	tmp := hashFunc.Sum(nil)
	hashFunc.Reset()
	hashFunc.Write(writeSecret)
	hashFunc.Write(ssl3Pad2Sha)
	hashFunc.Write(tmp)

	return hashFunc.Sum(nil)
}

func addCustomPadding(src []byte, blockSize int) []byte {
	paddingLen := blockSize - len(src)%blockSize

	padtext := bytes.Repeat([]byte{0}, paddingLen-1)
	// This how openssl implemented this len -1, https://crypto.stackexchange.com/questions/98917/on-the-correctness-of-the-padding-example-of-rfc-5246
	padtext = append(padtext, byte(paddingLen-1))
	return append(src, padtext...)
}

func handleMessage(clientHello []byte, conn net.Conn, serverData *ServerData) []byte {
	contentType := clientHello[0]

	version := binary.BigEndian.Uint16(clientHello[1:3])
	recordLength := binary.BigEndian.Uint16(clientHello[3:5])
	fmt.Print("lets go handshake content type \n")
	fmt.Println(recordLength)
	switch version {
	case 0x0200:
		fmt.Print("SSL 2.0")
	case 0x0300:
		fmt.Print("SSL 3.0")
	}
	// record length is only 2 bytes while handshake can be 3 bytes, when that happend two request are transmited and reasmbled into one

	if serverData.IsEncrypted {
		fmt.Println("cipher suite111")
		fmt.Println("cipher suite111")
		fmt.Println(serverData.CipherDef.CipherSuite)
		fmt.Println("cipher suite111")
		fmt.Println("cipher suite111")
		decryptedData := s3_cipher.DecryptMessage(clientHello[:5], clientHello[5:], serverData.CipherDef.CipherSuite, serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient)
		fmt.Println("decrypted client hello")
		fmt.Println(decryptedData)
		fmt.Println("decrypted client hex")

		for _, v := range decryptedData {
			fmt.Printf(" %02X", v)
		}

	}

	serverData.AllMessagesShort = append(serverData.AllMessagesShort, clientHello[5:5+recordLength])

	if contentType == byte(TLSContentTypeHandshake) {
		return handleHandshake(clientHello, serverData, conn)
	} else if contentType == byte(TLSContentTypeAlert) {
		alertLevel := TlSAlertLevel(clientHello[5])
		handleAlert(clientHello, conn)
		if alertLevel == TLSAlertLevelfatal {
			conn.Close()
			return []byte{}
		}
	} else if contentType == byte(TLSContentTypeChangeCipherSpec) {
		// The change cipher spec message is sent by both the client and the server to notify the reciing part that subsequent record will be protected under the just-negotiated cipherspec and keys. Copy pending state into currnet.
		// *When resuming a previous sessin, the change cipher spec message is sent after the hello
		// majorVersion := clientHello[1]
		// minorVersion := clientHello[2]
		// length := clientHello[3:4]
		return handleHandshakeChangeCipherSpec(clientHello, serverData, conn)
	}

	return []byte{}
}

func handleAlert(clientHello []byte, conn net.Conn) {
	// majorVersion := clientHello[1]
	// minorVersion := clientHello[2]
	// length := clientHello[3:4]
	// alertLevel := TlSAlertLevel(clientHello[5])
	alertDescription := TLSAlertDescription(clientHello[6])

	switch alertDescription {
	case TLSAlertDescriptionCloseNotify:
		// The connection is closing or has been closed gracefully, no action needed
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
		// Lookahed bufer a samaller buffer within the window that scans for the longer match of the current input string.
		// Match an literal: if match is found it is encoded a tuple (distance, length)
		//
		// Window	Lookahead	Output
		// a		bracadabra	Literal a
		// ab		racadabra	Literal b
		// abr		acadabra	Literal r
		// abra		cadabra		Literal a
		// abrac	adabra		(4, 1) (back 4, length 1)
		// abracad	abra		(7, 4) (back 7, length 4)
		fmt.Print("Can't decompress data, could be corrupted input")
	case TLSAlertDescriptionHandshakeFailure:
		// Handshake process failed, ensure that server and browser supports required protocol and ciphers, may indicate problem with server configuration
		// Always fatal
		fmt.Print("Handshake failure, make sure choose procol and ciphers are supported by both partied")
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
		// 2. Unrecgonized cerrtificate Authority
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

func handleHandshake(clientHello []byte, serverData *ServerData, conn net.Conn) []byte {

	handshakeMessageType := TLSHandshakeMessageType(clientHello[5])

	if handshakeMessageType == TLSHandshakeMessageClinetHello {
		return handleHandshakeClientHello(clientHello, serverData, conn)
	} else if handshakeMessageType == TLSHandshakeMessageClientKeyExchange {

		return handleHandshakeClientKeyExchange(clientHello, serverData, conn)

	} else if handshakeMessageType == TLSHandshakeMessageFinished {
		return handleHandshakeClientFinished(clientHello, serverData, conn)

	}
	return []byte{}
}

func handleHandshakeClientHello(clientHello []byte, serverData *ServerData, conn net.Conn) []byte {

	// client hello
	// handshakeLength := int32(clientHello[6])<<16 | int32(clientHello[7])<<8 | int32(clientHello[8])

	clientVersion := binary.BigEndian.Uint16(clientHello[9:11]) // backward compability, used to dicated which version to use, now there is set in protocol version and newest one is chosen.

	switch clientVersion {
	case 0x0200:
		fmt.Print("CLient version: SSL 2.0")
	case 0x0300:
		fmt.Print("Client version: SSL 3.0")
	}

	//client random
	fmt.Println(clientHello[11:15])
	radnomBytesTime := binary.BigEndian.Uint32(clientHello[11:15])
	radnomBytesData := clientHello[15:43]
	serverData.ClientRandom = clientHello[11:43]

	fmt.Println("Unix time")
	fmt.Println(time.Unix(int64(radnomBytesTime), 0))
	fmt.Println("random bytes")
	fmt.Println(radnomBytesData)
	//session id
	// session := clientHello[43]

	//cipher suites
	// cipherSuiteLength := binary.BigEndian.Uint16(clientHello[44:46])
	// cipherSuites := clientHello[46 : 46+cipherSuiteLength]

	if clientHello[44] == 255 {
		//
		//    Note: All cipher suites whose first byte is 0xFF are considered
		//    private and can be used for defining local/experimental algorithms.
		//    Interoperability of such types is a local matter.
	} else {
		// other encryptions
	}
	// compression mehod
	// compressionMethod := clientHello[46+cipherSuiteLength]

	currentTime := time.Now()
	unixTime := currentTime.Unix()

	unitTimeBytes := int64ToBIgEndian(unixTime)
	randomBytes := make([]byte, 28)

	_, err := rand.Read(randomBytes)

	if err != nil {
		fmt.Print("problem generating random bytes")
	}

	type Resp struct {
		contentType       byte
		version           []byte
		recordLength      []byte
		handshakeType     byte
		handshakeLength   []byte
		protocolVersion   []byte
		gmtUnixTime       []byte
		serverRandom      []byte
		sessionId         byte
		cipherSuite       []byte
		compressionMethod []byte
	}

	cipherSuite := []byte{0, 27}
	serverData.CipherDef.CipherSuite = 0x001B
	fmt.Println("cipher suite")
	fmt.Println("cipher suite")
	fmt.Println("cipher suite")
	fmt.Println(serverData.CipherDef.CipherSuite)
	fmt.Println("cipher suite")
	fmt.Println("cipher suite")
	compressionMethodd := []byte{0}
	protocolVersion := []byte{3, 0}
	sessionIdd := byte(0)
	//                  time				random bytes	 session id cypher suit	  compression methodd
	handshakeLengthh := len(unitTimeBytes) + len(randomBytes) + 1 + len(cipherSuite) + len(compressionMethodd) + len(protocolVersion)
	handshakeLengthhByte, err := intTo3BytesBigEndian(handshakeLengthh)
	recordLengthhByte := int32ToBIgEndian(handshakeLengthh + 4)
	resppp := Resp{
		contentType:       22,
		version:           []byte{3, 0},
		recordLength:      recordLengthhByte, //2 bytes
		handshakeType:     2,
		handshakeLength:   handshakeLengthhByte, //3 bytes,
		protocolVersion:   protocolVersion,
		gmtUnixTime:       unitTimeBytes,
		serverRandom:      randomBytes,
		sessionId:         sessionIdd,
		cipherSuite:       cipherSuite,
		compressionMethod: compressionMethodd,
	}
	serverRandom := []byte{}
	serverRandom = append(serverRandom, resppp.gmtUnixTime...)
	serverRandom = append(serverRandom, resppp.serverRandom...)
	serverData.ServerRandom = serverRandom
	// copy(serverData.serverRandom, serverRandom)

	respEnd := []byte{resppp.contentType}
	respEnd = append(respEnd, resppp.version...)
	respEnd = append(respEnd, resppp.recordLength...)
	respEnd = append(respEnd, resppp.handshakeType)
	respEnd = append(respEnd, resppp.handshakeLength...)
	respEnd = append(respEnd, resppp.protocolVersion...)
	respEnd = append(respEnd, resppp.gmtUnixTime...)
	respEnd = append(respEnd, resppp.serverRandom...)
	respEnd = append(respEnd, resppp.sessionId)
	respEnd = append(respEnd, resppp.cipherSuite...)
	respEnd = append(respEnd, resppp.compressionMethod...)

	_, err = conn.Write(respEnd)
	serverData.AllMessagesShort = append(serverData.AllMessagesShort, respEnd[5:])

	if err != nil {
		fmt.Println("Error reading Client Hello:", err)
		return []byte{}
	}

	// Two bytes should be converted and checked
	if cipherSuite[1] >= 23 && cipherSuite[1] <= 27 {
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

		pPrime, ok := new(big.Int).SetString("3", 16)
		if !ok {
			fmt.Println("Error generating private key:", err)
			return []byte{}
		}
		gGenerator := big.NewInt(2)
		serverPrivateVal, err := generatePrivateKey(pPrime)
		if err != nil {
			fmt.Println("Error generating private key:", err)
			return []byte{}
		}
		serverPublicVal := computePublicKey(gGenerator, serverPrivateVal, pPrime)

		serverData.P = pPrime
		serverData.Q = gGenerator
		serverData.Private = serverPrivateVal

		a1 := pPrime.Bytes()     // p a large prime nmber
		a2 := gGenerator.Bytes() // g a base used for generic public values
		// p and g are public paramters, both parties need to know these paramters to perform the key exchange

		a3 := serverPublicVal.Bytes() // Ys the server public key
		// the server public key is essential for the client t ocompue the shared secre, the clients needs this value to compute its own private value

		// to calcualte shared secret i need to clientPublic^serverPriavte mod p (pprime)

		all := []byte{}
		all = append(all, []byte{0, byte(len(a1))}...)
		all = append(all, a1...)
		all = append(all, []byte{0, byte(len(a2))}...)
		all = append(all, a2...)
		all = append(all, []byte{0, byte(len(a3))}...)
		all = append(all, a3...)

		handshakeLengthh := len(all)
		handshakeLengthhByte, err := intTo3BytesBigEndian(handshakeLengthh)
		if err != nil {
			fmt.Print("err while converting to big endina")
		}
		recordLengthhByte := int32ToBIgEndian(handshakeLengthh + 4)

		resppp := Resp{
			contentType:     22,
			version:         []byte{3, 0},
			recordLength:    recordLengthhByte, //2 bytes
			handshakeType:   12,
			handshakeLength: handshakeLengthhByte, //3 bytes,
		}

		respENd := []byte{resppp.contentType}
		respENd = append(respENd, resppp.version...)
		respENd = append(respENd, resppp.recordLength...)
		respENd = append(respENd, resppp.handshakeType)
		respENd = append(respENd, resppp.handshakeLength...)
		respENd = append(respENd, all...)

		_, err = conn.Write(respENd)
		serverData.AllMessagesShort = append(serverData.AllMessagesShort, respENd[5:])
		if err != nil {
			fmt.Println("Error reading Client Hello:", err)
			return []byte{}
		}

	}

	resp := []byte{22, 3, 0, 0, 4, 14, 0, 0, 0}

	_, err = conn.Write(resp)
	serverData.AllMessagesShort = append(serverData.AllMessagesShort, resp[5:])
	if err != nil {
		fmt.Println("Error reading Client Hello:", err)
		return []byte{}
	}

	getCipherSpecInfo(serverData)

	return []byte{}
}

func handleHandshakeClientKeyExchange(clientHello []byte, serverData *ServerData, conn net.Conn) []byte {
	fmt.Println("handleClientyKeyExchange")
	// handshakeLength := int32(clientHello[6])<<16 | int32(clientHello[7])<<8 | int32(clientHello[8])
	// TODO
	// change cipher spec is zeroing sequence number
	clientPublicKeyLength := binary.BigEndian.Uint16(clientHello[9:11])
	clientPublicKey := clientHello[11 : 11+clientPublicKeyLength]

	for _, v := range serverData.AllMessagesShort {
		fmt.Println(v)
	}

	clinetPublicKeyInt := new(big.Int).SetBytes(clientPublicKey)

	preMasterSecret := computeSharedSecret(clinetPublicKeyInt, serverData.Private, serverData.P)

	masterKeySeed := []byte{}
	keyBlockSeed := []byte{}
	masterKeySeed = append(masterKeySeed, serverData.ClientRandom...)

	masterKeySeed = append(masterKeySeed, serverData.ServerRandom...)

	keyBlockSeed = append(keyBlockSeed, serverData.ServerRandom...)
	keyBlockSeed = append(keyBlockSeed, serverData.ClientRandom...)

	//Hardcoded for testing
	keyBlockLen := serverData.CipherDef.Spec.HashSize*2 + serverData.CipherDef.Spec.KeyMaterial*2 + serverData.CipherDef.Spec.IvSize*2

	masterKey := ssl_prf(preMasterSecret.Bytes(), masterKeySeed, MASTER_SECRET_LENGTH)
	keyBlock := ssl_prf(masterKey, keyBlockSeed, keyBlockLen)

	macEndIndex := serverData.CipherDef.Spec.HashSize * 2
	writeKeyEndIndex := macEndIndex + serverData.CipherDef.Spec.KeyMaterial*2

	fmt.Println("hello")
	fmt.Println("hello")
	fmt.Println(serverData.CipherDef.Spec.HashSize)
	fmt.Println(serverData.CipherDef.Spec.KeyMaterial)
	fmt.Println(serverData.CipherDef.Spec.IvSize)

	// TODO change hardcoded slices
	// TODO make sure we generate keys in right place
	cipherDefKeys := s3_cipher.CipherKeys{
		MacClient:      keyBlock[:serverData.CipherDef.Spec.HashSize],
		MacServer:      keyBlock[serverData.CipherDef.Spec.HashSize:macEndIndex],
		WriteKeyClient: keyBlock[macEndIndex : macEndIndex+serverData.CipherDef.Spec.KeyMaterial],
		WriteKeyServer: keyBlock[serverData.CipherDef.Spec.HashSize*2+serverData.CipherDef.Spec.KeyMaterial : writeKeyEndIndex],
		IVClient:       keyBlock[writeKeyEndIndex : writeKeyEndIndex+serverData.CipherDef.Spec.IvSize],
		IVServer:       keyBlock[writeKeyEndIndex+serverData.CipherDef.Spec.IvSize : writeKeyEndIndex+serverData.CipherDef.Spec.IvSize*2],
	}
	serverData.CipherDef.Keys = cipherDefKeys
	serverData.MasterKey = masterKey
	serverData.PreMasterSecret = preMasterSecret

	return clientHello[11+clientPublicKeyLength:]
}

func handleHandshakeClientFinished(clientHello []byte, serverData *ServerData, conn net.Conn) []byte {
	// pad1 := byte(0x36)
	// pad2 := byte(0x5c)
	// clientBytes := []byte{0x43, 0x4C, 0x4E, 0x54}

	// clientVerifyHash := []byte{}

	// md5Hash := generate_finished_message_md5(serverData.masterKey, clientBytes, serverData.allMessages, serverData.allMessagesShort, pad1, pad2)
	// shaHash := generate_finished_message_sha1(serverData.masterKey, clientBytes, serverData.allMessages, serverData.allMessagesShort, pad1, pad2)

	// clientVerifyHash = append(clientVerifyHash, md5Hash...)
	// clientVerifyHash = append(clientVerifyHash, shaHash...)

	// fmt.Println("\nhash")
	// for _, b := range clientVerifyHash {
	// 	fmt.Printf(" %02X", b)
	// }

	// hashAndHeader := []byte{20, 0, 0, 36}
	// hashAndHeader = append(hashAndHeader, clientVerifyHash...)
	// fmt.Println("hash and header len")
	// fmt.Println(len(hashAndHeader))

	//sha 40 md5 48
	// streamCipher := generateStreamCipher(streamCipherHashSHA, serverData.MacClient, hashAndHeader)
	// fmt.Println("moment of the truth, what is a stream cipher!!!")
	// for _, b := range streamCipher {
	// 	fmt.Printf(" %02X", b)
	// }

	// combinedBytes := []byte{}
	// combinedBytes = append(combinedBytes, hashAndHeader...)
	// combinedBytes = append(combinedBytes, streamCipher...)

	// paddd := addCustomPadding(combinedBytes, 64)
	return []byte{}
}

func getCipherSpecInfo(serverData *ServerData) {
	//TODO  fill all data
	fmt.Println("hello from cipeee1fdffd")
	switch s3_cipher.TLSCipherSuite(serverData.CipherDef.CipherSuite) {
	case s3_cipher.TLS_CIPER_SUITE_SSL_RSA_WITH_NULL_SHA:

	case s3_cipher.TLS_CIPER_SUITE_SSL_RSA_WITH_RC4_128_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_RSA_WITH_IDEA_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_RSA_WITH_DES_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DH_DSS_WITH_DES_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DH_RSA_WITH_DES_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DHE_DSS_WITH_DES_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DHE_RSA_WITH_DES_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
		fmt.Println("hello from cipeee1")
		serverData.CipherDef.Spec.HashSize = 20
		serverData.CipherDef.Spec.KeyMaterial = 24
		serverData.CipherDef.Spec.IvSize = 8
		break
	case s3_cipher.TLS_CIPER_SUITE_SSL_FORTEZZA_KEA_WITH_NULL_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA:
	case s3_cipher.TLS_CIPER_SUITE_SSL_RSA_EXPORT_WITH_RC4_40_MD5:
	case s3_cipher.TLS_CIPER_SUITE_SSL_RSA_WITH_NULL_MD5:
	case s3_cipher.TLS_CIPER_SUITE_SSL_RSA_WITH_RC4_128_MD5:
	case s3_cipher.TLS_CIPER_SUITE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
	case s3_cipher.TLS_CIPER_SUITE_SSL_DH_anon_EXPORT_WITH_RC4_40_MD5:
	case s3_cipher.TLS_CIPHER_SUITE_SSL_NULL_WITH_NULL_NULL:
	default:
		serverData.CipherDef.Spec.HashSize = 0
		serverData.CipherDef.Spec.HashSize = 0
		serverData.CipherDef.Spec.KeyMaterial = 0
	}
}

func handleHandshakeChangeCipherSpec(clientHello []byte, serverData *ServerData, conn net.Conn) []byte {
	fmt.Println("handleClientyCipherspec")
	message := TLSCipherSpec(clientHello[5])
	if message == TLSCipherSpecDefault {
		fmt.Print("Sender is switching to new cipher :)")
	}
	serverData.IsEncrypted = true
	return clientHello[6:]
}
