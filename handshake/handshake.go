package handshake

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"handshakeServer/cipher"
	"handshakeServer/helpers"
	"hash"
	"net"
	"os"
	"reflect"
	"sync"
	"time"
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

type ContentType byte

const (
	ContentTypeApplicationData  ContentType = 23
	ContentTypeHandshake        ContentType = 22
	ContentTypeAlert            ContentType = 21
	ContentTypeChangeCipherSpec ContentType = 20
	// to help avoid pipeline stalls, changeciperspec is independet ssl protocol type
	// The CCS message being independent allows it to be processed out of sync with the strict sequence of handshake messages. While the rest of the handshake is being processed, the system can already signal readiness to switch to the new cipher suite, avoiding unnecessary wait times.
)

type Version uint16

const (
	SSL30Version Version = 0x0300
	TLS10Version Version = 0x0301
)

type AlertDescription byte

const (
	AlertDescriptionCloseNotify            AlertDescription = 0
	AlertDescriptionUnexpectedMessage      AlertDescription = 10
	AlertDescriptionBadRecordMac           AlertDescription = 20
	AlertDescriptionDecompressionFailure   AlertDescription = 30
	AlertDescriptionHandshakeFailure       AlertDescription = 40
	AlertDescriptionNoCertificate          AlertDescription = 41
	AlertDescriptionBadCertificate         AlertDescription = 42
	AlertDescriptionUnsupportedCertificate AlertDescription = 43
	AlertDescriptionCertificateRevoked     AlertDescription = 44
	AlertDescriptionCertificateExpired     AlertDescription = 45
	AlertDescriptionCertificateUnknown     AlertDescription = 46
	AlertDescriptionIllegalParameter       AlertDescription = 47
)

const MASTER_SECRET_LENGTH = 48
const RANDOM_BYTES_LENGTH = 32

type AlertLevel byte

const (
	AlertLevelwarning AlertLevel = 1
	AlertLevelfatal   AlertLevel = 2
)

type HandshakeMessageType byte

const (
	HandshakeMessageHelloRequest HandshakeMessageType = 0
	// server send a request to start new handshake process, allowing session renewals and paramters update
	HandshakeMessageClientHello       HandshakeMessageType = 1
	HandshakeMessageServerHello       HandshakeMessageType = 2
	HandshakeMessageCertificate       HandshakeMessageType = 11
	HandshakeMessageServerKeyExchange HandshakeMessageType = 12
	HandshakeMessageCerificateRequest HandshakeMessageType = 13
	HandshakeMessageServerHelloDone   HandshakeMessageType = 14
	HandshakeMessageCertificateVerify HandshakeMessageType = 15
	HandshakeMessageClientKeyExchange HandshakeMessageType = 16
	HandshakeMessageFinished          HandshakeMessageType = 20
)

type CipherSpec byte

const (
	CipherSpecDefault CipherSpec = 1
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

type Session struct {
	mu   sync.Mutex
	data map[string]*ServerData
}

var sessions = Session{
	data: make(map[string]*ServerData),
}

func (serverData *ServerData) sendAlertMsg(level AlertLevel, description AlertDescription) {

	alertMsg := []byte{byte(level)}
	alertMsg = append(alertMsg, byte(description))

	serverData.wBuff = append(serverData.wBuff, alertMsg...)

	_, err := serverData.sendData(serverData.wBuff)

	if err != nil {
		fmt.Printf("\n problem sending alert: %v", err)
	}

	serverData.handleAlert(alertMsg)

}

func handleMessage(clientData []byte, conn net.Conn, serverData *ServerData) error {
	contentType := clientData[0]
	dataContent := clientData[5:]
	var err error
	if serverData.IsClientEncrypted {
		decryptedClientData, err := serverData.CipherDef.DecryptMessage(clientData[5:], serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient)

		if err != nil {
			serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionBadRecordMac)
			return fmt.Errorf("\n Decryption failed: %v", err)
		}

		dataWithoutMac, err := serverData.verifyMac(contentType, decryptedClientData)

		if err != nil {
			serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionBadRecordMac)
			return fmt.Errorf("\n eror with verify mac, err: %v", err)
		}

		dataContent = dataWithoutMac

	}

	if contentType == byte(ContentTypeHandshake) {

		handshakeLength := int32(dataContent[1])<<16 | int32(dataContent[2])<<8 | int32(dataContent[3])
		serverData.HandshakeMessages = append(serverData.HandshakeMessages, dataContent[:handshakeLength+4])
		err = serverData.handleHandshake(dataContent)

	} else if contentType == byte(ContentTypeAlert) {
		serverData.handleAlert(dataContent)
	} else if contentType == byte(ContentTypeChangeCipherSpec) {
		serverData.handleHandshakeChangeCipherSpec(dataContent)

	} else if contentType == byte(ContentTypeApplicationData) {
		HttpHandler(dataContent)
	} else {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("\n Unknown record layer type:" + string(contentType))
	}
	return err

}
func (serverData *ServerData) generateStreamCipher(dataCompressedType, sslCompressData, seqNum, mac []byte) []byte {
	switch binary.BigEndian.Uint16(serverData.Version) {
	case 0x0300:
		return serverData.S3generateStreamCipher(dataCompressedType, sslCompressData, seqNum, mac)
	case 0x0301:
		return serverData.T1GenerateStreamCipher(dataCompressedType, sslCompressData, seqNum, mac)
	default:
		fmt.Println("should never enter this state")
		os.Exit(1)
	}
	return []byte{}
}

func (serverData *ServerData) verifyMac(contentType byte, contentData []byte) ([]byte, error) {
	var macSize int
	switch serverData.CipherDef.Spec.HashAlgorithm {
	case cipher.HashAlgorithmMD5:
		macSize = md5.New().Size()
	case cipher.HashAlgorithmSHA:
		macSize = sha1.New().Size()
	default:
		panic("wrong algorithm used can't use: " + serverData.CipherDef.Spec.HashAlgorithm)
	}

	macSent := contentData[len(contentData)-macSize:]

	dataSent := contentData[:len(contentData)-macSize]

	streamCipher := serverData.generateStreamCipher([]byte{byte(contentType)}, dataSent, serverData.ClientSeqNum, serverData.CipherDef.Keys.MacClient)

	if !reflect.DeepEqual(streamCipher, macSent) {
		return nil, fmt.Errorf("\n macs are diffrent, expected: %v, got: %v", streamCipher, macSent)
	}

	for i := 7; i >= 0; i-- {
		serverData.ClientSeqNum[i] += 1
		if serverData.ClientSeqNum[i] != 0 {
			break
		}
	}

	return dataSent, nil
}

func (serverData *ServerData) handleAlert(contentData []byte) {
	// majorVersion := clientHello[1]
	// minorVersion := clientHello[2]
	// length := clientHello[3:4]
	alertLevel := AlertLevel(contentData[0])
	closeConn := false

	if alertLevel == AlertLevelfatal {
		closeConn = true
	}

	alertDescription := AlertDescription(contentData[1])

	switch alertDescription {
	case AlertDescriptionCloseNotify:
		// The connection is closing or has been closed gracefully, no action needed
		fmt.Println("Closing connection")
		closeConn = true
	case AlertDescriptionUnexpectedMessage:
		// Do Retry, bad message recive, long term problem can indicate protocol mismatch(client expecting e.g tls 1.2 and server sending 1.3), incorrect squence or error in
		fmt.Print("Unexpected message, Retry connectin again, if problem persist, check configuration")

	case AlertDescriptionBadRecordMac:
		// A message auhentication code (MAC) check failed, check your connection, can indicate server problem or an attack
		// Always fatal
		fmt.Print("MAC failed, check your connection")
	case AlertDescriptionDecompressionFailure:
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
	case AlertDescriptionHandshakeFailure:
		// Handshake process failed, ensure that server and browser supports required protocol and ciphers, may indicate problem with server configuration
		// Always fatal
		fmt.Print("Handshake failure, make sure choose procol and ciphers are supported by both parties")
	case AlertDescriptionNoCertificate:
		// No certificate was provided by the peer
		// Optional field
		fmt.Print("No certificate provided")
	case AlertDescriptionBadCertificate:
		// Bad certificate
		fmt.Print("Make sure that provided cerificate is valid")
	case AlertDescriptionUnsupportedCertificate:
		// The certificate is unsported:
		// 1. Invalid certificate type, e.g server can only accept x5.09 certificated
		// 2. Unrecgonized cerificate authority
		// 3. Certificate algorithm issue, its not supported by peers
		// 4. Certificate version its not supported
		fmt.Print("Unsported certificated, make sure both parties support the type, issuer, version and both known authority")
	case AlertDescriptionCertificateRevoked:
		// Cerificate was revoke
		fmt.Print("Certificate revoked")
	case AlertDescriptionCertificateExpired:
		// Cerificated expired
		fmt.Print("Certificate expiered")
	case AlertDescriptionCertificateUnknown:
		// 1. Unknown certificate
		// 2. Untrusted CA
		// 3. Incomplete Certificate chain, presented certifiacted does not include a complate chain to trsuted root CA
		// 4. Revoked or expired
		// 5. Malformed or corrupted
		// 6. Mimstached purpose, doesnt have appropriate extention
		// 7. Expired trust store
		fmt.Print("Unknown certificate, check CA authority, trust store, extenstion compability or maybe its coruppted data")
	case AlertDescriptionIllegalParameter:
		// Paramters not allowed or recognized:
		// 1. Invalid cipher suite, not implmented by one of the parties
		// 2. Not supported tls version
		// 3. Incorrected exntesion
		// 4. Invalid message structure
		fmt.Print("Illegal paramters, check tls version, supported protcol, extenstion or message structure")

	default:
		fmt.Printf("Unregonized alert occured: %v", alertDescription)
	}

	if closeConn {
		serverData.conn.Close()
		return
	}
}

func (serverData *ServerData) loadCertificate() error {

	handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(len(serverData.cert) + 3 + 3)
	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return errors.New("problem converting record layer length to big endina")
	}

	certLengthByte, err := helpers.IntTo3BytesBigEndian(len(serverData.cert) + 3)
	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return errors.New("problem converting certs length to big endian")
	}

	certLengthByteSingle, err := helpers.IntTo3BytesBigEndian(len(serverData.cert))
	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return errors.New("problem converting cert length to big endian")
	}

	serverCertificate := []byte{byte(HandshakeMessageCertificate)}
	serverCertificate = append(serverCertificate, handshakeLengthByte...)
	serverCertificate = append(serverCertificate, certLengthByte...)
	serverCertificate = append(serverCertificate, certLengthByteSingle...)
	serverCertificate = append(serverCertificate, serverData.cert...)

	err = serverData.BuffSendData(ContentTypeHandshake, serverCertificate)

	return err

}

func (serverData *ServerData) sendData(data []byte) (n int, err error) {

	n, err = serverData.conn.Write(data)
	if err != nil {
		return 0, fmt.Errorf("error sending data: %v", err)
	}
	serverData.wBuff = []byte{}

	return n, err
}

func (serverData *ServerData) BuffSendData(contentData ContentType, data []byte) error {

	if contentData == ContentTypeHandshake {
		serverData.HandshakeMessages = append(serverData.HandshakeMessages, data)
	}

	msg := []byte{byte(contentData)}
	msg = append(msg, serverData.Version...)

	if serverData.IsServerEncrypted {

		mac := serverData.generateStreamCipher([]byte{byte(contentData)}, data, serverData.ServerSeqNum, serverData.CipherDef.Keys.MacServer)

		dataWithMac := []byte{}
		dataWithMac = append(dataWithMac, data...)
		dataWithMac = append(dataWithMac, mac...)

		encryptedMsg, err := serverData.CipherDef.EncryptMessage(dataWithMac, serverData.CipherDef.Keys.WriteKeyServer, serverData.CipherDef.Keys.IVServer)

		if err != nil {
			serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionBadRecordMac)
			return err
		}

		msg = append(msg, helpers.Int32ToBigEndian(len(encryptedMsg))...)
		msg = append(msg, encryptedMsg...)

		data = msg

		for i := 7; i >= 0; i-- {
			serverData.ServerSeqNum[i] += 1
			if serverData.ServerSeqNum[i] != 0 {
				break
			}
		}
	} else {

		msg = append(msg, helpers.Int32ToBigEndian(len(data))...)
		msg = append(msg, data...)

	}

	serverData.wBuff = append(serverData.wBuff, msg...)

	return nil
}

func (serverData *ServerData) handleHandshake(contentData []byte) error {

	handshakeMessageType := HandshakeMessageType(contentData[0])
	var err error
	if handshakeMessageType == HandshakeMessageClientHello {
		if err = serverData.handleHandshakeClientHello(contentData); err != nil {
			return fmt.Errorf("\n Problem handling client hello: %v", err)
		}

		if err = serverData.serverHello(); err != nil {
			return fmt.Errorf("\n problem with serverHello msg : %v", err)

		}

		if serverData.reuseSession {
			if err = serverData.changeCipher(); err != nil {
				return fmt.Errorf("problem with change cipher in resuse sesstion, err: %v", err)
			}

			serverData.calculateKeyBlock(serverData.MasterKey)
			if err = serverData.serverFinished(); err != nil {
				return fmt.Errorf("\n problem with serverFinish msg, err: %v", err)
			}

			_, err = serverData.sendData(serverData.wBuff)
			return err
		}

		if serverData.CipherDef.Spec.SignatureAlgorithm != cipher.SignatureAlgorithmAnonymous {
			if err = serverData.loadCertificate(); err != nil {
				return fmt.Errorf("\n problem loading certificate: %V", err)
			}
		}

		// The server key exchange message is sent by the server if it has no cetificate, has a certificate used for siging (e.g. dss certificate, signing-only rsa)
		// if serverData.CipherDef.Spec.SignatureAlgorithm == cipher.SignatureAlgorithmAnonymous || // No certificate
		// 	serverData.CipherDef.Spec.SignatureAlgorithm == cipher.SignatureAlgorithmDSA || // das certificate
		// 	(serverData.CipherDef.Spec.SignatureAlgorithm == cipher.SignatureAlgorithmRSA && // signin only
		// 		(serverData.CipherDef.Spec.KeyExchange == cipher.KeyExchangeMethodDH))
		// I think can simply if to just if the key exchange method is DH
		if serverData.CipherDef.Spec.KeyExchange == cipher.KeyExchangeMethodDH {
			if err = serverData.serverKeyExchange(); err != nil {
				return fmt.Errorf("\n problem with serverkeyexchange message: %v", err)

			}
		}

		if err = serverData.serverHelloDone(); err != nil {
			return fmt.Errorf("\n  problem with serverHelloDone message, err: %v", err)
		}

		// lets do one write with collected few messages, don't send extra network round trips
		_, err = serverData.sendData(serverData.wBuff)
		if err != nil {
			serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
			return fmt.Errorf("\n problem sending server hello data, err: %v", err)
		}

	} else if handshakeMessageType == HandshakeMessageClientKeyExchange {
		// computes ivs, writekeys, macs, don't need to send any message after this
		if err := serverData.handleHandshakeClientKeyExchange(contentData); err != nil {
			serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
			return fmt.Errorf("\n handshake client key exchange err: %v", err)
		}
	} else if handshakeMessageType == HandshakeMessageFinished {
		if serverData.reuseSession {
			return nil
		}

		if err := serverData.handleHandshakeClientFinished(contentData); err != nil {
			return err
		}

		if err = serverData.changeCipher(); err != nil {
			return fmt.Errorf("problem with changing cipher, err: %v", err)
		}

		// We don't combine message here to single route trip as change cipher msg is separate content type, in order to not be stalling
		_, err = serverData.sendData(serverData.wBuff)
		if err != nil {
			serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
			return fmt.Errorf("\n problem sending change cipher msg: %v", err)
		}

		err = serverData.serverFinished()
		if err != nil {
			return fmt.Errorf("\n problem with serverFinish msg, err: %v", err)
		}
		_, err = serverData.sendData(serverData.wBuff)

		if err != nil {
			serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
			return fmt.Errorf("\n problem sending server finished msgs: %v", err)
		}
		sessions.mu.Lock()
		sessions.data[string(serverData.session)] = serverData
		sessions.mu.Unlock()

	}
	return nil
}

func (serverData *ServerData) loadSession(sessionId string) {
	sessions.mu.Lock()
	session := sessions.data[sessionId]
	sessions.mu.Unlock()
	if session != nil {
		session := session
		serverData.IsClientEncrypted = false
		serverData.reuseSession = true

		serverData.PreMasterSecret = session.PreMasterSecret
		serverData.MasterKey = session.MasterKey
		serverData.cert = session.cert
		serverData.session = session.session
	}
}

func (serverData *ServerData) handleHandshakeClientHello(contentData []byte) error {
	contentLength := int(contentData[1])<<16 | int(contentData[2])<<8 | int(contentData[3])
	dataContentExpectedLen := contentLength + 4 // 4: 1 bytefor content type, 3 bytes for length
	if dataContentExpectedLen != len(contentData) {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("conent length does not fit data passed, expected to have length of: %v, got: %v", dataContentExpectedLen, len(contentData))
	}

	clientVersion := contentData[4:6] // backward compability, used to dicated which version to use, now we have version in protocol header.

	if !reflect.DeepEqual(clientVersion, serverData.Version) {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("ssl version not matches, expected: %v, got: %v", serverData.Version, clientVersion)
	}
	radnomBytesTime := int64(binary.BigEndian.Uint32(contentData[6:10]))
	currentTime := time.Now().UnixMilli()

	if currentTime < radnomBytesTime {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("time: %v should be less than is currently: %v", radnomBytesTime, currentTime)
	}

	sessionLength := int(contentData[38])
	if sessionLength > 32 {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("session length should be between 0-32")
	}
	sessionIndexEnd := uint16(39 + sessionLength)
	session := contentData[39:sessionIndexEnd]

	cipherSuitesLength := binary.BigEndian.Uint16(contentData[sessionIndexEnd : sessionIndexEnd+2])

	cipherSuites := contentData[sessionIndexEnd+2 : sessionIndexEnd+2+cipherSuitesLength]
	compressionsLength := contentData[sessionIndexEnd+2+cipherSuitesLength]
	compressionMethodList := contentData[sessionIndexEnd+2+cipherSuitesLength+1:]

	if len(compressionMethodList) != int(compressionsLength) {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("\n got length:%v, expected :%v", len(compressionMethodList), int(compressionsLength))
	}

	serverData.loadSession(string(session))

	serverData.ClientRandom = contentData[6:38]
	err := serverData.CipherDef.SelectCipherSuite(cipherSuites)
	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("problem selecting cipher suite, err: %v", err)
	}
	serverData.CipherDef.GetCipherSpecInfo()

	if serverData.CipherDef.Spec.SignatureAlgorithm != cipher.SignatureAlgorithmAnonymous && serverData.cert == nil {
		return fmt.Errorf("please provider certificate for: %v", serverData.CipherDef.Spec.SignatureAlgorithm)
	}
	err = serverData.CipherDef.SelectCompressionMethod(compressionMethodList)

	serverData.SelectBlockCipherPadding()

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

	keyExchangeParams, err := serverData.CipherDef.GenerateServerKeyExchange()
	if err != nil {
		return err
	}
	hash := []byte{}

	switch serverData.CipherDef.Spec.SignatureAlgorithm {
	case cipher.SignatureAlgorithmAnonymous:
	case cipher.SignatureAlgorithmRSA:
		md5Hash := signatureHash(md5.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		shaHash := signatureHash(sha1.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		hash = append(hash, md5Hash...)
		hash = append(hash, shaHash...)

	case cipher.SignatureAlgorithmDSA:

		shaHash := signatureHash(sha1.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		hash = append(hash, shaHash...)
	default:
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("unsupported Algorithm: %v", serverData.CipherDef.Spec.SignatureAlgorithm)
	}

	signedParams, err := serverData.CipherDef.SignData(hash)
	signatureLength := helpers.Int32ToBigEndian(len(signedParams))

	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("problem with singin data, err: %v", err)
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
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("err while converting to big endian, err: %v", err)
	}

	serverKeyExchange := []byte{byte(HandshakeMessageServerKeyExchange)}
	serverKeyExchange = append(serverKeyExchange, handshakeLengthByte...)
	serverKeyExchange = append(serverKeyExchange, keyExchangeData...)

	err = serverData.BuffSendData(ContentTypeHandshake, serverKeyExchange)

	return err
}

func (serverData *ServerData) serverHello() error {

	currentTime := time.Now()
	unixTime := currentTime.Unix()

	unitTimeBytes := helpers.Int64ToBIgEndian(unixTime)
	randomBytes := make([]byte, RANDOM_BYTES_LENGTH-len(unitTimeBytes))

	_, err := rand.Read(randomBytes)

	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("problem generating random bytes, err:%v", err)
	}

	cipherSuite := helpers.Int32ToBigEndian(int(serverData.CipherDef.CipherSuite))
	compressionMethod := []byte{byte(serverData.CipherDef.Spec.CompressionMethod)}
	protocolVersion := serverData.Version

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

	serverHello := []byte{byte(HandshakeMessageServerHello)}
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

	err = serverData.BuffSendData(ContentTypeHandshake, serverHello)

	return err
}

func (serverData *ServerData) serverHelloDone() error {
	serverHelloDone := []byte{byte(HandshakeMessageServerHelloDone)}
	serverHelloDone = append(serverHelloDone, []byte{0, 0, 0}...) // Always 0 length

	err := serverData.BuffSendData(ContentTypeHandshake, serverHelloDone)

	return err
}

var masterKeyGenLabel = map[uint16][]byte{
	0x0300: []byte{},
	0x0301: []byte("master secret"),
}

func (serverData *ServerData) handleHandshakeClientKeyExchange(contentData []byte) error {

	preMasterSecret, err := serverData.CipherDef.ComputerMasterSecret(contentData[4:])

	if err != nil {
		return err
	}

	masterKeySeed := []byte{}
	masterKeySeed = append(masterKeySeed, serverData.ClientRandom...)
	masterKeySeed = append(masterKeySeed, serverData.ServerRandom...)

	label := masterKeyGenLabel[binary.BigEndian.Uint16(serverData.Version)]
	masterKey := serverData.prf(preMasterSecret, masterKeySeed, label, MASTER_SECRET_LENGTH)

	serverData.calculateKeyBlock(masterKey)

	serverData.MasterKey = masterKey
	serverData.PreMasterSecret = preMasterSecret

	return nil
}

func (serverData *ServerData) calculateExportableFinalWriteKey(key, seed []byte) []byte {
	hash := md5.New()

	hash.Write(key)
	hash.Write(seed)

	return hash.Sum(nil)

}

func (serverData *ServerData) calculateExportableFinalIv(seed []byte) []byte {
	hash := md5.New()

	hash.Write(seed)

	return hash.Sum(nil)

}

var keyBlockLabel = map[uint16][]byte{
	0x0300: []byte{},
	0x0301: []byte("key expansion"),
}

func (serverData *ServerData) prf(key, seed, label []byte, length int) []byte {
	seedExtended := label
	seedExtended = append(seedExtended, seed...)
	switch binary.BigEndian.Uint16(serverData.Version) {
	case 0x0300:
		return s3_prf(key, seedExtended, length)
	case 0x0301:
		return T1Prf(key, seedExtended, length)
	default:
		fmt.Println("should never enter this state")
		os.Exit(1)
	}
	return []byte{}
}

func (serverData *ServerData) SelectBlockCipherPadding() error {
	switch binary.BigEndian.Uint16(serverData.Version) {
	case 0x0300:
		serverData.CipherDef.Spec.PaddingType = cipher.ZerosPaddingType
	case 0x0301:
		serverData.CipherDef.Spec.PaddingType = cipher.LengthPaddingType
	default:
		return fmt.Errorf("unsporrted version")
	}
	return nil

}

func (serverData *ServerData) calculateKeyBlock(masterKey []byte) {
	keyBlockSeed := []byte{}
	keyBlockSeed = append(keyBlockSeed, serverData.ServerRandom...)
	keyBlockSeed = append(keyBlockSeed, serverData.ClientRandom...)

	keyBlockLen := serverData.CipherDef.Spec.HashSize*2 + serverData.CipherDef.Spec.KeyMaterial*2 + serverData.CipherDef.Spec.IvSize*2
	label := keyBlockLabel[binary.BigEndian.Uint16(serverData.Version)]
	keyBlock := serverData.prf(masterKey, keyBlockSeed, label, keyBlockLen)

	macEndIndex := serverData.CipherDef.Spec.HashSize * 2
	writeKeyEndIndex := macEndIndex + serverData.CipherDef.Spec.KeyMaterial*2

	cipherDefKeys := cipher.CipherKeys{
		MacClient:      keyBlock[:serverData.CipherDef.Spec.HashSize],
		MacServer:      keyBlock[serverData.CipherDef.Spec.HashSize:macEndIndex],
		WriteKeyClient: keyBlock[macEndIndex : macEndIndex+serverData.CipherDef.Spec.KeyMaterial],
		WriteKeyServer: keyBlock[serverData.CipherDef.Spec.HashSize*2+serverData.CipherDef.Spec.KeyMaterial : writeKeyEndIndex],
		IVClient:       keyBlock[writeKeyEndIndex : writeKeyEndIndex+serverData.CipherDef.Spec.IvSize],
		IVServer:       keyBlock[writeKeyEndIndex+serverData.CipherDef.Spec.IvSize : writeKeyEndIndex+serverData.CipherDef.Spec.IvSize*2],
	}

	if serverData.CipherDef.Spec.IsExportable {
		clientSeed := []byte{}
		clientSeed = append(clientSeed, serverData.ClientRandom...)
		clientSeed = append(clientSeed, serverData.ServerRandom...)
		clientWriteKey := serverData.calculateExportableFinalWriteKey(cipherDefKeys.WriteKeyClient, clientSeed)

		serverSeed := []byte{}
		serverSeed = append(serverSeed, serverData.ServerRandom...)
		serverSeed = append(serverSeed, serverData.ClientRandom...)
		serverWriteKey := serverData.calculateExportableFinalWriteKey(cipherDefKeys.WriteKeyServer, serverSeed)

		cipherDefKeys.WriteKeyClient = clientWriteKey[:serverData.CipherDef.Spec.ExportKeyMaterial]
		cipherDefKeys.WriteKeyServer = serverWriteKey[:serverData.CipherDef.Spec.ExportKeyMaterial]

		IVClient := serverData.calculateExportableFinalIv(clientSeed)
		IVServer := serverData.calculateExportableFinalIv(serverSeed)

		cipherDefKeys.IVClient = IVClient[:serverData.CipherDef.Spec.IvSize]
		cipherDefKeys.IVServer = IVServer[:serverData.CipherDef.Spec.IvSize]

	}
	serverData.CipherDef.Keys = cipherDefKeys
}

func (serverData *ServerData) changeCipher() error {
	serverData.ServerSeqNum = []byte{0, 0, 0, 0, 0, 0, 0, 0}

	changeCipherSpecContent := []byte{byte(CipherSpecDefault)}

	err := serverData.BuffSendData(ContentTypeChangeCipherSpec, changeCipherSpecContent)

	return err
}

func (serverData *ServerData) serverFinished() error {
	serverData.IsServerEncrypted = true
	label := finishedLabel[uint16(binary.BigEndian.Uint16(serverData.Version))]["server"]

	verifyHashMac := serverData.generate_finished_handshake_mac(label, serverData.HandshakeMessages)

	hashLen := len(verifyHashMac)
	msgLenEndian, err := helpers.IntTo3BytesBigEndian(hashLen)

	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("problem converting hash len into endian format")
	}

	verifyMacWithHeaders := []byte{byte(HandshakeMessageFinished)}
	verifyMacWithHeaders = append(verifyMacWithHeaders, msgLenEndian...)
	verifyMacWithHeaders = append(verifyMacWithHeaders, verifyHashMac...)

	err = serverData.BuffSendData(ContentTypeHandshake, verifyMacWithHeaders)

	return err

}

func (serverData *ServerData) generate_finished_handshake_mac(label []byte, handshakeMessages [][]byte) []byte {
	switch binary.BigEndian.Uint16(serverData.Version) {
	case 0x0300:
		md5Hash := serverData.S3GenerateFinishedHandshakeMac(md5.New(), label, handshakeMessages) // -1 without last message witch is client verify
		shaHash := serverData.S3GenerateFinishedHandshakeMac(sha1.New(), label, handshakeMessages)
		return append(md5Hash, shaHash...)
	case 0x0301:
		return serverData.T1GenerateFinishedHandshakeMac(label, handshakeMessages)
	default:
		fmt.Println("should never enter this state")
		os.Exit(1)
	}
	return []byte{}
}

var finishedLabel = map[uint16]map[string][]byte{
	0x0300: {
		"client": helpers.Int64ToBIgEndian(int64(ClientSender)),
		"server": helpers.Int64ToBIgEndian(int64(serverSender)),
	},
	0x0301: {
		"client": []byte("client finished"),
		"server": []byte("server finished"),
	},
}

func (serverData *ServerData) handleHandshakeClientFinished(contentData []byte) error {

	label := finishedLabel[uint16(binary.BigEndian.Uint16(serverData.Version))]["client"]

	clientHash := serverData.generate_finished_handshake_mac(label, serverData.HandshakeMessages[:len(serverData.HandshakeMessages)-1])

	hashLen := len(clientHash)

	// 4 bytes, 1 handshake type, 3 byes length
	inputHash := contentData[4:]

	if !reflect.DeepEqual(clientHash, inputHash[:hashLen]) {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionBadRecordMac)
		return fmt.Errorf("message are different, expected: %v, got: %v", inputHash[:hashLen], clientHash)
	}
	return nil
}

func (serverData *ServerData) handleHandshakeChangeCipherSpec(contentData []byte) {
	serverData.ClientSeqNum = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	message := CipherSpec(contentData[0])
	if message == CipherSpecDefault {
		fmt.Print("Sender is switching to new cipher")
	}
	serverData.IsClientEncrypted = true
}
