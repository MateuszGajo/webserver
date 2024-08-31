package http

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"net"
	"os"
	"reflect"
	"time"
	s3_cipher "webserver/cipher"
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
const RANDOM_BYTES_LENGTH = 32

type TlSAlertLevel byte

const (
	TLSAlertLevelwarning TlSAlertLevel = 1
	TLSAlertLevelfatal   TlSAlertLevel = 2
)

type TLSHandshakeMessageType byte

const (
	TLSHandshakeMessageHelloRequest TLSHandshakeMessageType = 0
	// server send a request to start new handshake process, allowing session renewls and paramters update
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

type TLSCompressionAlgorithm byte

const (
	TLSCompressionAlgorithmNull    TLSCompressionAlgorithm = 0
	TLSCompressionAlgorithmDeflate TLSCompressionAlgorithm = 1
	// I found it in seperate rfc, every rfc document ssl 3.0 tls 1.0 etc only contains null as compression algorithm nothing more. In tls 1.3 field is depracted + overall compression algorithm had vulnerability
	// Defalte uses loseless compression, attacker add some data to user's request  and observers if length is changeing, by doing that it can guess what string is in user cookie.
)

type Sender uint64

const (
	ClientSender Sender = 0x434C4E54
	serverSender Sender = 0x53525652
)

type ServerData struct {
	IsEncrypted       bool
	PreMasterSecret   *big.Int
	ClientRandom      []byte
	ServerRandom      []byte
	SSLVersion        []byte
	HandshakeMessages [][]byte
	MasterKey         []byte
	CipherDef         s3_cipher.CipherDef
	SeqNum            []byte
}

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

// AES advanced encryptio0n standard, block cipher, symmetric key, aes is faster

func HandleConnection(conn net.Conn) {
	defer conn.Close()
	// TODO change hardcoded ssl version
	serverData := ServerData{SeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0}, SSLVersion: []byte{3, 0}}
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

		for len(clientHello) > 0 {
			fmt.Println("stpper???")
			fmt.Println("stpper???")

			clientHello = handleMessage(clientHello, conn, &serverData)
		}
	}

	// clientHello := []byte{22, 3, 0, 0, 69, 1, 0, 0, 65, 3, 0, 102, 238, 138, 0, 43, 72, 173, 88, 26, 125, 182, 44, 4, 213, 158, 0, 30, 230, 195, 164, 44, 133, 177, 179, 138, 219, 68, 93, 157, 71, 88, 163, 127, 0, 0, 14, 0}

}

// TODO make this a one function with algorithm passed as argument
func generate_finished_handshake_mac(hashingAlgorithm hash.Hash, masterSecret, sender []byte, handshakeMessages [][]byte) []byte {
	n := hashingAlgorithm.Size()
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

// TODO: lets think about seq number how to increment it and add it struct here, lets make GC lighweight
// Remove StreamCipherHash, we have a time in serverData.cipherDef
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

	// TODO Change hardcoded version when adding support for server
	hashFunc.Write(mac)
	hashFunc.Write(ssl3Pad1Sha)
	hashFunc.Write(seqNum)

	hashFunc.Write(dataCompressedType)

	hashFunc.Write(sslCompressLength)
	hashFunc.Write(sslCompressData)

	tmp := hashFunc.Sum(nil)
	hashFunc.Reset()
	// TODO Change hardcoded version when adding support for server
	hashFunc.Write(mac)
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
	fmt.Println(contentType)
	switch version {
	case 0x0200:
		fmt.Print("SSL 2.0")
	case 0x0300:
		fmt.Print("SSL 3.0")
	}
	// record length is only 2 bytes while handshake can be 3 bytes, when that happend two request are transmited and reasmbled into one

	if serverData.IsEncrypted && contentType != 21 {
		fmt.Println("clienthello before???")

		clientHello = s3_cipher.DecryptMessage(clientHello[:5], clientHello[5:], serverData.CipherDef.CipherSuite, serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient)

	}
	if clientHello[0] != 20 && clientHello[5] != 20 {
		serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientHello[5:5+recordLength])
	}

	if contentType == byte(TLSContentTypeHandshake) {
		resp := handleHandshake(clientHello, serverData, conn)
		return resp
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
	} else {
		fmt.Println("unknown type!!!")
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

	if handshakeMessageType == TLSHandshakeMessageClientHello {
		return handleHandshakeClientHello(clientHello, serverData, conn)
	} else if handshakeMessageType == TLSHandshakeMessageClientKeyExchange {

		return handleHandshakeClientKeyExchange(clientHello, serverData, conn)

	} else if handshakeMessageType == TLSHandshakeMessageFinished {
		return handleHandshakeClientFinished(clientHello, serverData, conn)

	}
	return []byte{}
}

func handleHandshakeClientHello(clientHello []byte, serverData *ServerData, conn net.Conn) []byte {

	// conn.Write([]byte{21, 3, 0, 0, 2, 1, 0})

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

	unitTimeBytes := helpers.Int64ToBIgEndian(unixTime)
	randomBytes := make([]byte, RANDOM_BYTES_LENGTH-len(unitTimeBytes))

	_, err := rand.Read(randomBytes)

	if err != nil {
		fmt.Print("problem generating random bytes")
	}

	cipherSuite := serverData.CipherDef.SelectCipherSuite()
	compressionMethod := serverData.CipherDef.SelectCompressionMethod()
	protocolVersion := serverData.SSLVersion
	// TODO make session work
	sessionId := byte(0)
	//                  time				random bytes	 session id cypher suit	  compression methodd
	handshakeLength := len(unitTimeBytes) + len(randomBytes) + 1 + len(cipherSuite) + len(compressionMethod) + len(protocolVersion)
	handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(handshakeLength)

	if err != nil {
		fmt.Printf("Error converting int to big endian: %v", err)
		os.Exit(1)
	}

	recordLengthByte := helpers.Int32ToBigEndian(handshakeLength + 4)

	serverHelloMsg := []byte{byte(TLSContentTypeHandshake)}
	serverHelloMsg = append(serverHelloMsg, serverData.SSLVersion...)
	serverHelloMsg = append(serverHelloMsg, recordLengthByte...)
	serverHelloMsg = append(serverHelloMsg, byte(TLSHandshakeMessageServerHello))
	serverHelloMsg = append(serverHelloMsg, handshakeLengthByte...) // 3 bytes
	serverHelloMsg = append(serverHelloMsg, protocolVersion...)
	serverHelloMsg = append(serverHelloMsg, unitTimeBytes...)
	serverHelloMsg = append(serverHelloMsg, randomBytes...)
	serverHelloMsg = append(serverHelloMsg, sessionId)
	serverHelloMsg = append(serverHelloMsg, cipherSuite...)
	serverHelloMsg = append(serverHelloMsg, compressionMethod...)

	_, err = conn.Write(serverHelloMsg)
	if err != nil {
		fmt.Println("Error reading Client Hello:", err)
		return []byte{}
	}

	serverData.CipherDef.GetCipherSpecInfo()
	serverData.ServerRandom = append(unitTimeBytes, randomBytes...)
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHelloMsg[5:])

	keyExchangeData := serverData.CipherDef.GenerateServerKeyExchange()
	// Send key exchange message
	if len(keyExchangeData) > 1 {
		handshakeLengthh := len(keyExchangeData)
		handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(handshakeLengthh)
		if err != nil {
			fmt.Print("err while converting to big endina")
		}
		recordLengthByte := helpers.Int32ToBigEndian(handshakeLengthh + 4)

		serverKeyExchangeMsg := []byte{byte(TLSContentTypeHandshake)}
		serverKeyExchangeMsg = append(serverKeyExchangeMsg, serverData.SSLVersion...)
		serverKeyExchangeMsg = append(serverKeyExchangeMsg, recordLengthByte...)
		serverKeyExchangeMsg = append(serverKeyExchangeMsg, byte(TLSHandshakeMessageServerKeyExchange))
		serverKeyExchangeMsg = append(serverKeyExchangeMsg, handshakeLengthByte...)
		serverKeyExchangeMsg = append(serverKeyExchangeMsg, keyExchangeData...)

		_, err = conn.Write(serverKeyExchangeMsg)
		serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverKeyExchangeMsg[5:])
		if err != nil {
			fmt.Println("Error reading Client Hello:", err)
			return []byte{}
		}
	}

	serverHelloDoneMsg := []byte{byte(TLSContentTypeHandshake)}
	serverHelloDoneMsg = append(serverHelloDoneMsg, serverData.SSLVersion...)
	serverHelloDoneMsg = append(serverHelloDoneMsg, []byte{0, 4}...) // hardcoded as it is always 4 bytes, 1 byte messageType 3 bytes length
	serverHelloDoneMsg = append(serverHelloDoneMsg, byte(TLSHandshakeMessageServerHelloDone))
	serverHelloDoneMsg = append(serverHelloDoneMsg, []byte{0, 0, 0}...) // Always 0 length

	_, err = conn.Write(serverHelloDoneMsg)
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHelloDoneMsg[5:])
	if err != nil {
		fmt.Println("Error reading Client Hello:", err)
		return []byte{}
	}

	return []byte{}
}

func handleHandshakeClientKeyExchange(clientHello []byte, serverData *ServerData, conn net.Conn) []byte {
	fmt.Println("handleClientyKeyExchange")
	// handshakeLength := int32(clientHello[6])<<16 | int32(clientHello[7])<<8 | int32(clientHello[8])
	// TODO
	// change cipher spec is zeroing sequence number
	clientPublicKeyLength := binary.BigEndian.Uint16(clientHello[9:11])
	clientPublicKey := clientHello[11 : 11+clientPublicKeyLength]

	clinetPublicKeyInt := new(big.Int).SetBytes(clientPublicKey)
	serverData.CipherDef.DhParams.ClientPublic = clinetPublicKeyInt

	preMasterSecret := serverData.CipherDef.ComputerMasterSecret()

	masterKeySeed := []byte{}
	masterKeySeed = append(masterKeySeed, serverData.ClientRandom...)
	masterKeySeed = append(masterKeySeed, serverData.ServerRandom...)

	keyBlockSeed := []byte{}
	keyBlockSeed = append(keyBlockSeed, serverData.ServerRandom...)
	keyBlockSeed = append(keyBlockSeed, serverData.ClientRandom...)

	keyBlockLen := serverData.CipherDef.Spec.HashSize*2 + serverData.CipherDef.Spec.KeyMaterial*2 + serverData.CipherDef.Spec.IvSize*2

	masterKey := ssl_prf(preMasterSecret.Bytes(), masterKeySeed, MASTER_SECRET_LENGTH)
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
	serverData.MasterKey = masterKey
	serverData.PreMasterSecret = preMasterSecret

	return clientHello[11+clientPublicKeyLength:]
}

func handleHandshakeClientFinished(clientHello []byte, serverData *ServerData, conn net.Conn) []byte {

	clientBytes := helpers.Int64ToBIgEndian(int64(ClientSender))

	clientVerifyHash := []byte{}

	md5Hash := generate_finished_handshake_mac(md5.New(), serverData.MasterKey, clientBytes, serverData.HandshakeMessages)
	shaHash := generate_finished_handshake_mac(sha1.New(), serverData.MasterKey, clientBytes, serverData.HandshakeMessages)

	hashLen := len(md5Hash) + len(shaHash)
	msgLenEndian, err := helpers.IntTo3BytesBigEndian(hashLen)

	if err != nil {
		fmt.Printf("Problem converting hash len into endian format")
		os.Exit(1)
	}

	clientVerifyHash = append(clientVerifyHash, md5Hash...)
	clientVerifyHash = append(clientVerifyHash, shaHash...)

	hashAndHeader := []byte{byte(TLSHandshakeMessageFinished)}
	hashAndHeader = append(hashAndHeader, msgLenEndian...)
	hashAndHeader = append(hashAndHeader, clientVerifyHash...)

	streamCipher := serverData.generateStreamCipher([]byte{byte(TLSContentTypeHandshake)}, hashAndHeader, serverData.SeqNum, serverData.CipherDef.Keys.MacClient)

	combinedBytes := []byte{}
	combinedBytes = append(combinedBytes, hashAndHeader...)
	combinedBytes = append(combinedBytes, streamCipher...)

	clientHelloLength := int(clientHello[8])
	msg := clientHello[5 : 5+clientHelloLength+4]
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, msg)

	if !reflect.DeepEqual(combinedBytes, clientHello[5:]) {
		// TODO Need to throw some error/alert\
		fmt.Println("message are different")
		os.Exit(1)

	}

	_, err = conn.Write([]byte{20, 3, 0, 0, 1, 1})

	serverBytes := helpers.Int64ToBIgEndian(int64(serverSender))

	clientVerifyHash = []byte{}

	md5Hash = generate_finished_handshake_mac(md5.New(), serverData.MasterKey, serverBytes, serverData.HandshakeMessages)
	shaHash = generate_finished_handshake_mac(sha1.New(), serverData.MasterKey, serverBytes, serverData.HandshakeMessages)

	hashLen = len(md5Hash) + len(shaHash)
	msgLenEndian, err = helpers.IntTo3BytesBigEndian(hashLen)

	if err != nil {
		fmt.Printf("Problem converting hash len into endian format")
		os.Exit(1)
	}

	clientVerifyHash = append(clientVerifyHash, md5Hash...)
	clientVerifyHash = append(clientVerifyHash, shaHash...)

	hashAndHeader = []byte{byte(TLSHandshakeMessageFinished)}
	hashAndHeader = append(hashAndHeader, msgLenEndian...)
	hashAndHeader = append(hashAndHeader, clientVerifyHash...)

	streamCipher = serverData.generateStreamCipher([]byte{byte(TLSContentTypeHandshake)}, hashAndHeader, serverData.SeqNum, serverData.CipherDef.Keys.MacServer)

	for i := 7; i >= 0; i-- {
		serverData.SeqNum[i] += 1
		if serverData.SeqNum[i] != 0 {
			break
		}
	}

	combinedBytes = []byte{}
	combinedBytes = append(combinedBytes, hashAndHeader...)
	combinedBytes = append(combinedBytes, streamCipher...)

	combinedBytesPadded := addCustomPadding(combinedBytes, 64)
	for _, v := range serverData.CipherDef.Keys.IVServer {
		fmt.Printf(" %02X", v)
	}
	encryptedMsg, err := s3_cipher.Encrypt3DESCBC(serverData.CipherDef.Keys.WriteKeyServer, serverData.CipherDef.Keys.IVServer, combinedBytesPadded)

	if err != nil {
		fmt.Println("problem encrypting data")
		fmt.Println(err)
	}

	resp := []byte{22, 3, 0, 0, byte(len(encryptedMsg))}
	resp = append(resp, encryptedMsg...)

	for _, v := range resp {
		fmt.Printf(" %02X", v)
	}

	serverData.CipherDef.Keys.IVServer = resp[61:69]
	_, err = conn.Write(resp)

	if err != nil {
		fmt.Print("Couldn't send change cipher spec message")
	}

	tmpCloseAlert(serverData, conn)
	return []byte{}
}

// To removed later
func tmpCloseAlert(serverData *ServerData, conn net.Conn) {
	content := []byte{1, 0}

	streamCipher := serverData.generateStreamCipher([]byte{byte(TLSContentTypeAlert)}, content, serverData.SeqNum, serverData.CipherDef.Keys.MacServer)

	for i := 7; i >= 0; i-- {
		serverData.SeqNum[i] += 1
		if serverData.SeqNum[i] != 0 {
			break
		}
	}

	combinedBytes := []byte{}
	combinedBytes = append(combinedBytes, content...)
	combinedBytes = append(combinedBytes, streamCipher...)

	combinedBytesPadded := addCustomPadding(combinedBytes, 24)
	// the problem is that decoded bytes on openssl are diffrent that ones produces here
	encryptedMsg, err := s3_cipher.Encrypt3DESCBC(serverData.CipherDef.Keys.WriteKeyServer, serverData.CipherDef.Keys.IVServer, combinedBytesPadded)

	if err != nil {
		fmt.Println("problem encrypting data")
		fmt.Println(err)
	}

	resp := []byte{21, 3, 0, 0, byte(len(combinedBytesPadded))}
	resp = append(resp, encryptedMsg...)

	_, err = conn.Write(resp)

	if err != nil {
		fmt.Print("Couldn't send change cipher spec message")
	}

}

func handleHandshakeChangeCipherSpec(clientHello []byte, serverData *ServerData, conn net.Conn) []byte {

	message := TLSCipherSpec(clientHello[5])
	if message == TLSCipherSpecDefault {
		fmt.Print("Sender is switching to new cipher :)")
	}
	serverData.IsEncrypted = true
	return clientHello[6:]
}
