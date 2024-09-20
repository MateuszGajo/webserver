package http

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash"
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

type SSLVersion uint16

const (
	SSL30Version = 0x0300
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
	serverData := ServerData{ServerSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0}, SSLVersion: []byte{3, 0}, ClientSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0}, conn: conn}
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
		msgs, partial, err := Parser(input)
		bufInit = partial

		if err != nil {
			// TODO it should send an alert msg and then close conn
			fmt.Printf("\n parser error: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)

		}

		for _, msg := range msgs {
			handleMessage(msg, conn, &serverData)
		}
	}

}

//TODO: use this alert through code, then lets write some tests

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

func handleMessage(clientData []byte, conn net.Conn, serverData *ServerData) {
	contentType := clientData[0]
	dataContent := clientData[5:]
	if serverData.IsEncrypted {
		decryptedClientData := serverData.CipherDef.DecryptMessage(clientData[5:], serverData.CipherDef.CipherSuite, serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient)

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
		// The change cipher spec message is sent by both the client and the server to notify the reciing part that subsequent record will be protected under the just-negotiated cipherspec and keys. Copy pending state into currnet.
		// *When resuming a previous sessin, the change cipher spec message is sent after the hello
		// majorVersion := clientHello[1]
		// minorVersion := clientHello[2]
		// length := clientHello[3:4]
		serverData.handleHandshakeChangeCipherSpec(dataContent)
	} else {
		fmt.Println("Unknown record layer type:" + string(contentType))
		serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
	}

}

func (serverData *ServerData) verifyMac(contentType byte, contentData []byte) {
	clientDataLength := int32(contentData[1])<<16 | int32(contentData[2])<<8 | int32(contentData[3])
	clientDataWithHeader := 4 + clientDataLength

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

func (serverData *ServerData) loadCertificate() error {
	// TODO: place it better
	cert := flag.String("cert", "", "Server certificate")
	key := flag.String("key", "", "Cert private key")
	flag.Parse()

	pwd, _ := os.Getwd()

	certFileFolder := pwd + *cert
	keyFileFolder := pwd + *key

	// Load the certificate and key
	certBytes, err := serverData.CipherDef.ParseCertificate(certFileFolder, keyFileFolder)

	if err != nil {
		return errors.New("problem passing certificate")
	}

	handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(len(certBytes) + 3 + 3)
	if err != nil {
		return errors.New("problem converting record layer length to big endina")
	}

	certLengthByte, err := helpers.IntTo3BytesBigEndian(len(certBytes) + 3)
	if err != nil {
		return errors.New("problem converting certs length to big endina")
	}

	certLengthByteSingle, err := helpers.IntTo3BytesBigEndian(len(certBytes))
	if err != nil {
		return errors.New("problem converting cert length to big endina")
	}

	serverCertificate := []byte{}

	serverCertificate = append(serverCertificate, byte(TLSContentTypeHandshake))

	// TODO 4  are bytes for handshake message type + record length, 3 are bytes for all cert length, 3 bytes are for singular cer length
	recordLengthByte := helpers.Int32ToBigEndian(len(certBytes) + 4 + 3 + 3)

	serverCertificate = append(serverCertificate, serverData.SSLVersion...)
	serverCertificate = append(serverCertificate, recordLengthByte...)
	serverCertificate = append(serverCertificate, byte(TLSHandshakeMessageCertificate))
	serverCertificate = append(serverCertificate, handshakeLengthByte...)
	serverCertificate = append(serverCertificate, certLengthByte...)
	serverCertificate = append(serverCertificate, certLengthByteSingle...)
	serverCertificate = append(serverCertificate, certBytes...)

	err = serverData.BuffSendData(serverCertificate)

	return err

}

//TODO: universal function to send data

func (serverData *ServerData) sendData(data []byte) (n int, err error) {

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
		return fmt.Errorf("Message you're sending should be more than 5 chars")
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

		err = serverData.serverHello()
		if err != nil {
			fmt.Printf("\n problem with serverHello msg : %V", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

		if serverData.CipherDef.Spec.SignatureAlgorithm != s3_cipher.SignatureAlgorithmAnonymous {
			err := serverData.loadCertificate()
			if err != nil {
				fmt.Printf("\n problem loading certificate: %V", err)
				serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
			}
		}
		// TODO: probably we wanna have conidtion here as one above,
		// this message  is optional
		err = serverData.serverKeyExchange()
		if err != nil {
			fmt.Printf("\n problem with serverkeyexchange message: %V", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

		err = serverData.serverHelloDone()
		if err != nil {
			fmt.Printf("\n  problem with serverHelloDone message, err: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

		// lets do one write with collected few messages, don't create extra network round trips
		_, err = serverData.sendData(serverData.wBuff)
		if err != nil {
			fmt.Printf("\n problem sending server hello data, err: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

	} else if handshakeMessageType == TLSHandshakeMessageClientKeyExchange {
		// computes ivs, writekeys, macs, don't need to send any message after this
		serverData.handleHandshakeClientKeyExchange(contentData)

	} else if handshakeMessageType == TLSHandshakeMessageFinished {
		serverData.handleHandshakeClientFinished(contentData)

		serverData.changeCipher()

		err := serverData.serverFinished()
		if err != nil {
			fmt.Printf("\n problem with serverFinish msg, err: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}
		_, err = serverData.sendData(serverData.wBuff)

		if err != nil {
			fmt.Printf("\n problem sending server finished msgs: %v", err)
			serverData.sendAlertMsg(TLSAlertLevelfatal, TLSAlertDescriptionHandshakeFailure)
		}

	}
}

func (serverData *ServerData) handleHandshakeClientHello(contentData []byte) error {

	clientVersion := binary.BigEndian.Uint16(contentData[4:6]) // backward compability, used to dicated which version to use, now there is set in protocol version and newest one is chosen.

	switch clientVersion {
	case 0x0200:
		fmt.Print("CLient version: SSL 2.0")
	case 0x0300:
		fmt.Print("Client version: SSL 3.0")
	}

	//client random
	fmt.Println(contentData[11:15])
	radnomBytesTime := binary.BigEndian.Uint32(contentData[6:10])
	radnomBytesData := contentData[10:38]
	serverData.ClientRandom = contentData[6:38]

	// sessionId := clientData[38]
	cipherSuitesLength := binary.BigEndian.Uint16(contentData[39:41])

	cipherSuites := contentData[41 : 41+cipherSuitesLength]
	compressionsLength := contentData[41+cipherSuitesLength]

	compressionMethodList := contentData[41+cipherSuitesLength+1:]

	if len(compressionMethodList) != int(compressionsLength) {
		return fmt.Errorf("\n got length:%v, expected :%v", len(compressionMethodList), int(compressionsLength))
	}

	fmt.Println("Unix time")
	fmt.Println(time.Unix(int64(radnomBytesTime), 0))
	fmt.Println("random bytes")
	fmt.Println(radnomBytesData)

	fmt.Println("ciphers")
	fmt.Println(cipherSuites)
	fmt.Println("compression")
	fmt.Println(compressionMethodList)
	serverData.CipherDef.SelectCipherSuite(cipherSuites)
	// compressionMethod := serverData.CipherDef.SelectCompressionMethod()

	if contentData[39] == 255 {
		//
		//    Note: All cipher suites whose first byte is 0xFF are considered
		//    private and can be used for defining local/experimental algorithms.
		//    Interoperability of such types is a local matter.
	} else {
		// other encryptions
	}

	return nil
}

func signatureHash(algorithm hash.Hash, clientRandom, serverRandom, serverParams []byte) []byte {
	algorithm.Reset()
	algorithm.Write(clientRandom)
	algorithm.Write(serverRandom)
	algorithm.Write(serverParams)

	return algorithm.Sum(nil)

}

func (serverData *ServerData) serverKeyExchange() error {

	serverKeyExchange := []byte{}
	// Server key exchange it only used when there is no certificate, has certificate only used for signing (dss, signing-only rsa) or fortezza key exchange

	if serverData.CipherDef.Spec.SignatureAlgorithm != s3_cipher.SignatureAlgorithmAnonymous && (serverData.CipherDef.Spec.KeyExchange != s3_cipher.KeyExchangeMethodDH && serverData.CipherDef.Spec.KeyExchange != s3_cipher.KeyExchangeMethodDHE) {
		return nil
	}

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
		return fmt.Errorf("Unsupported Algorithm: %v", serverData.CipherDef.Spec.SignatureAlgorithm)
	}

	signedParams := serverData.CipherDef.SignParams(hash)
	keyExchangeData := []byte{}
	keyExchangeData = append(keyExchangeData, keyExchangeParams...)
	keyExchangeData = append(keyExchangeData, signedParams...)

	// Send key exchange message
	// TODO: write better logic for it
	// maybe lets put ino another function for now
	if len(keyExchangeData) < 1 {
		return nil
	}

	handshakeLengthh := len(keyExchangeData)
	handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(handshakeLengthh)
	if err != nil {
		fmt.Print("err while converting to big endina")
	}
	recordLengthByte := helpers.Int32ToBigEndian(handshakeLengthh + 4)

	serverKeyExchange = append(serverKeyExchange, byte(TLSContentTypeHandshake))

	serverKeyExchange = append(serverKeyExchange, serverData.SSLVersion...)
	serverKeyExchange = append(serverKeyExchange, recordLengthByte...)
	serverKeyExchange = append(serverKeyExchange, byte(TLSHandshakeMessageServerKeyExchange))
	serverKeyExchange = append(serverKeyExchange, handshakeLengthByte...)
	serverKeyExchange = append(serverKeyExchange, keyExchangeData...)

	for _, v := range keyExchangeData {
		fmt.Printf("%d, ", v)
	}

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

	// pass actually list of cipher suite and compressionMethods and write like basic function to choose algorithm

	cipherSuite := helpers.Int32ToBigEndian(int(serverData.CipherDef.CipherSuite))
	compressionMethod := serverData.CipherDef.SelectCompressionMethod()
	protocolVersion := serverData.SSLVersion
	// TODO make session work, we can focus on it later, first implement another alogrithm
	sessionId := byte(0)
	//                  time				random bytes	 session id cypher suit	  compression methodd
	handshakeLength := len(unitTimeBytes) + len(randomBytes) + 1 + len(cipherSuite) + len(compressionMethod) + len(protocolVersion)
	handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(handshakeLength)

	if err != nil {
		return fmt.Errorf("Error converting int to big endian: %v", err)
	}

	recordLengthByte := helpers.Int32ToBigEndian(handshakeLength + 4)

	serverHello := []byte{byte(TLSContentTypeHandshake)}
	serverHello = append(serverHello, serverData.SSLVersion...)
	serverHello = append(serverHello, recordLengthByte...)
	serverHello = append(serverHello, byte(TLSHandshakeMessageServerHello))
	serverHello = append(serverHello, handshakeLengthByte...) // 3 bytes
	serverHello = append(serverHello, protocolVersion...)
	// serverHello = append(serverHello, unitTimeBytes...)
	// serverHello = append(serverHello, randomBytes...)
	// TODO: lets leave it for now as it easier to debug, remove later
	serverHello = append(serverHello, []byte{102, 221, 107, 191, 80, 40, 191, 66, 96, 85, 167, 65, 108, 253, 149, 220, 154, 111, 218, 246, 151, 219, 148, 153, 252, 180, 122, 211, 0, 0, 0, 0}...)
	serverHello = append(serverHello, sessionId)
	serverHello = append(serverHello, cipherSuite...)
	serverHello = append(serverHello, compressionMethod...)

	serverData.ServerRandom = []byte{102, 221, 107, 191, 80, 40, 191, 66, 96, 85, 167, 65, 108, 253, 149, 220, 154, 111, 218, 246, 151, 219, 148, 153, 252, 180, 122, 211, 0, 0, 0, 0}

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

	// TODO
	// change cipher spec is zeroing sequence number
	// TODO implement for working with rsa,

	preMasterSecret := serverData.CipherDef.ComputerMasterSecret(contentData[4:])

	masterKeySeed := []byte{}
	masterKeySeed = append(masterKeySeed, serverData.ClientRandom...)
	masterKeySeed = append(masterKeySeed, serverData.ServerRandom...)

	keyBlockSeed := []byte{}
	keyBlockSeed = append(keyBlockSeed, serverData.ServerRandom...)
	keyBlockSeed = append(keyBlockSeed, serverData.ClientRandom...)

	masterKey := ssl_prf(preMasterSecret, masterKeySeed, MASTER_SECRET_LENGTH)
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
	serverData.MasterKey = masterKey
	serverData.PreMasterSecret = preMasterSecret

}

func (serverData *ServerData) changeCipher() {
	serverData.wBuff = append(serverData.wBuff, []byte{byte(TLSContentTypeChangeCipherSpec), 3, 0, 0, 1, 1}...)
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

	for i := 7; i >= 0; i-- {
		serverData.ServerSeqNum[i] += 1
		if serverData.ServerSeqNum[i] != 0 {
			break
		}
	}

	combinedBytes := []byte{}
	combinedBytes = append(combinedBytes, verifyMacWithHeaders...)
	combinedBytes = append(combinedBytes, mac...)

	encryptedMsg := serverData.CipherDef.EncryptMessage(combinedBytes)

	if err != nil {
		return fmt.Errorf("problem encrypting data")
	}
	serverFinished := []byte{byte(TLSContentTypeHandshake), 3, 0, 0, byte(len(encryptedMsg))}
	serverFinished = append(serverFinished, encryptedMsg...)

	// let's think about sending messages
	// TODO: lets maybe return just bytes, and have another function to send it and there get iv, update  seq number etc...
	serverData.CipherDef.Keys.IVServer = serverFinished[61:69]

	serverData.wBuff = append(serverData.wBuff, serverFinished...)

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
		// TODO Need to throw some error/alert\
		fmt.Println("message are different")
		fmt.Println(contentData[:hashLen])
		os.Exit(1)

	}

	return [][]byte{}

}

func (serverData *ServerData) handleHandshakeChangeCipherSpec(contentData []byte) {

	message := TLSCipherSpec(contentData[0])
	if message == TLSCipherSpecDefault {
		fmt.Print("Sender is switching to new cipher :)")
	}
	serverData.IsEncrypted = true
}
