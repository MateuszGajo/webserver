package handshake

//
import (
	"crypto"
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"os"
	"reflect"
	"sync"
	"time"

	cipher1 "crypto/cipher"
	"handshakeServer/cipher"
	"handshakeServer/helpers"

	"github.com/keys-pub/keys"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Client                                           Server

// Key  ^ ClientHello
// Exch | + key_share*
//
//	| + signature_algorithms*
//	| + psk_key_exchange_modes*
//	v + pre_shared_key*       -------->
//	                                             ServerHello  ^ Key
//	                                            + key_share*  | Exch
//	                                       + pre_shared_key*  v
//	                                   {EncryptedExtensions}  ^  Server
//	                                   {CertificateRequest*}  v  Params
//	                                          {Certificate*}  ^
//	                                    {CertificateVerify*}  | Auth
//	                                              {Finished}  v
//	                          <--------  [Application Data*]
//	^ {Certificate*}
//
// Auth | {CertificateVerify*}
//
//	v {Finished}              -------->
//	  [Application Data]      <------->  [Application Data]
type ContentType byte

const (
	ContentTypeHeartBeat        ContentType = 24
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
	TLS11Version Version = 0x0302
	TLS12Version Version = 0x0303
	TLS13Version Version = 0x0304
)

type AlertDescription byte

const (
	AlertDescriptionCloseNotify            AlertDescription = 0
	AlertDescriptionUnexpectedMessage      AlertDescription = 10
	AlertDescriptionBadRecordMac           AlertDescription = 20
	AlertDescriptionDecryptionFailed       AlertDescription = 21
	AlertDescriptionRecordOverflow         AlertDescription = 22
	AlertDescriptionDecompressionFailure   AlertDescription = 30
	AlertDescriptionHandshakeFailure       AlertDescription = 40
	AlertDescriptionBadCertificate         AlertDescription = 42
	AlertDescriptionUnsupportedCertificate AlertDescription = 43
	AlertDescriptionCertificateRevoked     AlertDescription = 44
	AlertDescriptionCertificateExpired     AlertDescription = 45
	AlertDescriptionCertificateUnknown     AlertDescription = 46
	AlertDescriptionIllegalParameter       AlertDescription = 47
	AlertDescriptionUnknownCA              AlertDescription = 48
	AlertDescriptionAccessDenided          AlertDescription = 49
	AlertDescriptionDecodeError            AlertDescription = 50
	AlertDescriptionDecryptError           AlertDescription = 51
	AlertDescriptionExportRestriction      AlertDescription = 60
	AlertDescriptionProtocolVersion        AlertDescription = 70
	AlertDescriptionInsufficientSecuirty   AlertDescription = 71
	AlertDescriptionInternalError          AlertDescription = 80
	AlertDescriptionUserCancceled          AlertDescription = 90
	AlertDescriptionNoRenegotation         AlertDescription = 100
	AlertDescriptionUnsportedExtension     AlertDescription = 110
)

const MasterSecretLength = 48
const RandomBytesLength = 32
const ConnectionTimeoutSec = 10

type AlertLevel byte

const (
	AlertLevelwarning AlertLevel = 1
	AlertLevelfatal   AlertLevel = 2
)

type HandshakeMessageType byte

const (
	HandshakeMessageHelloRequest HandshakeMessageType = 0
	// server send a request to start new handshake process, allowing session renewals and paramters update
	HandshakeMessageClientHello        HandshakeMessageType = 1
	HandshakeMessageServerHello        HandshakeMessageType = 2
	HandshakeMessageNewSessionTicket   HandshakeMessageType = 4
	HandshakeMessageEndOfEarlyData     HandshakeMessageType = 5
	HandshakeMessageEncryptedExtension HandshakeMessageType = 8
	HandshakeMessageCertificate        HandshakeMessageType = 11
	HandshakeMessageCertificateVerify  HandshakeMessageType = 15
	HandshakeMessageFinished           HandshakeMessageType = 20
	HandshakeMessageKeyUpdate          HandshakeMessageType = 24
	HandshakeMessageMessageHash        HandshakeMessageType = 254
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

type HeartBeatMode byte

const (
	HeartBeatPeerAllowedToSendMode    HeartBeatMode = 1
	HeartBeatPeerNotAllowedToSendMode HeartBeatMode = 2
)

type HeartBeatMessageType byte

const (
	HeartBeatMessageTypeRequest  HeartBeatMessageType = 1
	HeartBeatMessageTypeResponse HeartBeatMessageType = 2
)

// enum {

// 	/* Elliptic Curve Groups (ECDHE) */
// 	secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
// 	x25519(0x001D), x448(0x001E),

// 	/* Finite Field Groups (DHE) */
// 	ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
// 	ffdhe6144(0x0103), ffdhe8192(0x0104),

// 	/* Reserved Code Points */
// 	ffdhe_private_use(0x01FC..0x01FF),
// 	ecdhe_private_use(0xFE00..0xFEFF),
// 	(0xFFFF)
// } NamedGroup;

// DES -Data encryption standard, block encryption, symmetric key, not secure anymore, succedor is 3des, and then aes replaced them

// AES advanced encryption standard, block cipher, symmetric key, aes is faster

type Session struct {
	mu   sync.Mutex
	data map[string]*ServerData
}

var sessions = Session{
	data: make(map[string]*ServerData),
}

func (serverData *ServerData) closeHandshakeConn() {
	serverData.conn.Close()
	if serverData.extHeartBeat != nil && serverData.extHeartBeat.quit != nil {
		serverData.extHeartBeat.once.Do(func() {
			close(serverData.extHeartBeat.quit)
		})
	}
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

func handleMessage(clientData []byte, serverData *ServerData) error {

	contentType := clientData[0]
	dataContent := clientData[5:]
	var err error
	if serverData.IsClientEncrypted && false {
		decryptedClientData, err := serverData.CipherDef.DecryptMessage(clientData[5:], serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient)

		if err != nil {
			serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionDecryptionFailed)
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
	} else if contentType == byte(ContentTypeHeartBeat) {

		if err := serverData.handleHeartBeat(dataContent); err != nil {
			serverData.sendAlertMsg(AlertLevelwarning, AlertDescriptionCloseNotify)
			return fmt.Errorf("problem while reading hear beat response: %v", err)
		}
	} else {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("\n Unknown record layer type:" + string(contentType))
	}
	return err
}

func (serverData *ServerData) handleHeartBeat(dataContent []byte) error {
	if len(dataContent) < 3 {
		return fmt.Errorf("data content should have at least 3 bytes, 1 for type, 2 for length")
	}
	MinPaddingLength := 16

	dataType := dataContent[0]

	if dataType != byte(HeartBeatMessageTypeResponse) {
		return fmt.Errorf("expecting heart beat to be of type response")
	}
	dataLength := binary.BigEndian.Uint16(dataContent[1:3])

	if len(dataContent) < int(dataLength)+3+MinPaddingLength {
		return fmt.Errorf("data should be at of length :%v, insted we got: %v", int(dataLength)+3+MinPaddingLength, len(dataContent))
	}

	msg := dataContent[3 : 3+dataLength]

	if !reflect.DeepEqual(msg, serverData.extHeartBeat.lastPayload) {
		return fmt.Errorf("heart beat msg content should be the same as in request: %v, insted we got: %v", serverData.extHeartBeat.lastPayload, msg)
	}
	fmt.Println("thump-thump ~~ Heart beat ~~ thump-thump")

	currentTime := time.Now()
	serverData.extHeartBeat.lastAct = &currentTime

	return nil
}

func (serverData *ServerData) generateStreamCipher(dataCompressedType, sslCompressData, seqNum, mac []byte) []byte {
	switch binary.BigEndian.Uint16(serverData.Version) {
	case 0x0300:
		return serverData.S3generateStreamCipher(dataCompressedType, sslCompressData, seqNum, mac)
	case 0x0301, 0x0302:
		return serverData.T1GenerateStreamCipher(dataCompressedType, sslCompressData, seqNum, mac)
	case 0x0303:
		return serverData.T12GenerateStreamCipher(dataCompressedType, sslCompressData, seqNum, mac)
	default:
		fmt.Println("should never enter this state in generateStreamCipher")
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
	case cipher.HashAlgorithmSHA256:
		macSize = sha256.New().Size()
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
	alertLevel := AlertLevel(contentData[0])
	closeConn := false

	if alertLevel == AlertLevelfatal {
		closeConn = true
	}

	alertDescription := AlertDescription(contentData[1])

	switch alertDescription {
	case AlertDescriptionCloseNotify:
		// The connection is closing or has been closed gracefully
		fmt.Println("Closing connection")
		closeConn = true
	case AlertDescriptionUnexpectedMessage:
		// Do Retry, bad message recive, long term problem can indicate protocol mismatch(client expecting e.g tls 1.2 and server sending 1.3), incorrect squence or error in
		fmt.Println("Unexpected message, Retry connectin again, if problem persist, check configuration")

	case AlertDescriptionBadRecordMac:
		// A message auhentication code (MAC) check failed, check your connection, can indicate server problem or an attack
		// Always fatal
		fmt.Println("MAC failed, check your connection")
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
		fmt.Println("Can't decompress data, check for input corupteness")
	case AlertDescriptionHandshakeFailure:
		// Handshake process failed, ensure that server and browser supports required protocol and ciphers, may indicate problem with server configuration
		// Always fatal
		fmt.Println("Handshake failure, make sure choose procol and ciphers are supported by both parties")

	case AlertDescriptionBadCertificate:
		// Bad certificate
		fmt.Println("Make sure that provided cerificate is valid")
	case AlertDescriptionUnsupportedCertificate:
		// The certificate is unsported:
		// 1. Invalid certificate type, e.g server can only accept x5.09 certificated
		// 2. Unrecgonized cerificate authority
		// 3. Certificate algorithm issue, its not supported by peers
		// 4. Certificate version its not supported
		fmt.Println("Unsported certificated, make sure both parties support the type, issuer, version and both known authority")
	case AlertDescriptionCertificateRevoked:
		// Cerificate was revoke
		fmt.Println("Certificate revoked")
	case AlertDescriptionCertificateExpired:
		// Cerificated expired
		fmt.Println("Certificate expiered")
	case AlertDescriptionCertificateUnknown:
		// 1. Unknown certificate
		// 2. Untrusted CA
		// 3. Incomplete Certificate chain, presented certifiacted does not include a complate chain to trsuted root CA
		// 4. Revoked or expired
		// 5. Malformed or corrupted
		// 6. Mimstached purpose, doesnt have appropriate extention
		// 7. Expired trust store
		fmt.Println("Unknown certificate, check CA authority, trust store, extenstion compability or maybe its coruppted data")
	case AlertDescriptionIllegalParameter:
		// Paramters not allowed or recognized:
		// 1. Invalid cipher suite, not implmented by one of the parties
		// 2. Not supported tls version
		// 3. Incorrected exntesion
		// 4. Invalid message structure
		fmt.Println("Illegal paramters, check tls version, supported protcol, extenstion or message structure")
	case AlertDescriptionDecryptionFailed:
		// Corrupted data
		// Invalid padding
		// Invalid key
		// Mac compromised
		fmt.Println("Decryptio failed")
	case AlertDescriptionRecordOverflow:
		// Overflowed limit of 16.384 bytes
		fmt.Println("Record overflowed")
	case AlertDescriptionUnknownCA:
		// UnknownCA
		fmt.Println("Unknown cert CA")
	case AlertDescriptionAccessDenided:
		// Access denied, no permission
		// Rejected client cert
		fmt.Println("Access Denied")
	case AlertDescriptionDecodeError:
		// Message incorrectly formatted
		// Corupted data
		fmt.Println("Decode error")
	case AlertDescriptionDecryptError:
		// 	Decryption of a message failed, often due to a key mismatch or improper encryption mechanism.
		// The MAC (Message Authentication Code) was incorrect, meaning the integrity check failed.
		fmt.Println("Decrypt error")
	case AlertDescriptionExportRestriction:
		// Can't use exported cipher
		fmt.Println("Export restirction")
	case AlertDescriptionProtocolVersion:
		// Client and server do not support common veersion
		// Reject older version by newer clients
		fmt.Println("Protocol version")
	case AlertDescriptionInsufficientSecuirty:
		// Weak cipher suite
		fmt.Println("Infufficient security")
	case AlertDescriptionInternalError:
		// Just internal error
		fmt.Println("Internal error")
	case AlertDescriptionNoRenegotation:
		// 	One of the parties requested to renegotiate the TLS session, but the other party refused.
		// Some servers or clients may disable renegotiation for security reasons
		fmt.Println("No renegotation")
	case AlertDescriptionUnsportedExtension:
		// Extenstion not supported
		fmt.Println("Unsported extension")
	default:
		fmt.Printf("Unregonized alert occured: %v", alertDescription)
	}

	if closeConn {
		fmt.Println("close connection by alert")
		serverData.closeHandshakeConn()
		return
	}
}

func (serverData *ServerData) loadCertificate() (error, []byte) {

	// handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(len(serverData.cert) + 3 + 3)
	// if err != nil {
	// 	serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionInternalError)
	// 	return errors.New("problem converting record layer length to big endina"), nil
	// }

	// certLengthByte, err := helpers.IntTo3BytesBigEndian(len(serverData.cert) + 3)
	// if err != nil {
	// 	serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionInternalError)
	// 	return errors.New("problem converting certs length to big endian"), nil
	// }

	// serverCertificate := []byte{byte(HandshakeMessageCertificate)}
	// // serverCertificate = append(serverCertificate, byte(0))
	// serverCertificate = append(serverCertificate, handshakeLengthByte...)
	// serverCertificate = append(serverCertificate, certLengthByte...)
	// serverCertificate = append(serverCertificate, certLengthByteSingle...)
	// serverCertificate = append(serverCertificate, serverData.cert...)
	// serverCertificate = append(serverCertificate, []byte{0, 0}...)

	// enum {
	// 	X509(0),
	// 	RawPublicKey(2),
	// 	(255)
	// } CertificateType;

	// struct {
	// 	select (certificate_type) {
	// 		case RawPublicKey:
	// 		  /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
	// 		  opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

	// 		case X509:
	// 		  opaque cert_data<1..2^24-1>;
	// 	};
	// 	Extension extensions<0..2^16-1>;
	// } CertificateEntry;

	// struct {
	// 	opaque certificate_request_context<0..2^8-1>;
	// 	CertificateEntry certificate_list<0..2^24-1>;
	// } Certificate;

	//certificate_request_context:  If this message is in response to a CertificateRequest, the value of certificate_request_context inthat message.  Otherwise (in the case of server authentication), this field SHALL be zero length.

	cerificateEntryExtenstionData := []byte{}
	cerificateEntryExtenstionLength := helpers.Int32ToBigEndian(len(cerificateEntryExtenstionData))
	cerificateEntryExtenstion := cerificateEntryExtenstionLength
	cerificateEntryExtenstion = append(cerificateEntryExtenstion, cerificateEntryExtenstionData...)

	certLength, err := helpers.IntTo3BytesBigEndian(len(serverData.cert))
	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionInternalError)
		return errors.New("problem converting cert length to big endian"), nil
	}

	certificateEntryCertData := certLength
	certificateEntryCertData = append(certificateEntryCertData, serverData.cert...)

	cerificateEntry := certificateEntryCertData
	cerificateEntry = append(cerificateEntry, cerificateEntryExtenstion...)
	certificateEntryLength, err := helpers.IntTo3BytesBigEndian(len(cerificateEntry))

	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionInternalError)
		return errors.New("problem converting certificate entry length length to big endian"), nil
	}

	certificateRequestContentData := []byte{}
	certificateRequestContentLength := len(certificateRequestContentData)
	certificateRequestContent := []byte{byte(certificateRequestContentLength)}
	certificateRequestContent = append(certificateRequestContent, certificateRequestContentData...)

	certMsg := certificateRequestContent
	certMsg = append(certMsg, certificateEntryLength...)
	certMsg = append(certMsg, cerificateEntry...)
	certMsgLength, err := helpers.IntTo3BytesBigEndian(len(certMsg))

	handshakeCertificateMsg := []byte{byte(HandshakeMessageCertificate)}
	handshakeCertificateMsg = append(handshakeCertificateMsg, certMsgLength...)
	handshakeCertificateMsg = append(handshakeCertificateMsg, certMsg...)

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, handshakeCertificateMsg)

	return err, handshakeCertificateMsg

}

func (serverData *ServerData) sendData(data []byte) (n int, err error) {

	fmt.Println("Send data")
	fmt.Println(data)
	fmt.Println("Send data")

	n, err = serverData.conn.Write(data)
	if err != nil {
		return 0, fmt.Errorf("error sending data: %v", err)
	}
	serverData.wBuff = []byte{}

	return n, err
}

func (serverData *ServerData) BuffSendData(contentData ContentType, data []byte) error {

	if contentData == ContentTypeHandshake || (contentData == ContentTypeApplicationData && data[len(data)-1] == byte(ContentTypeHandshake)) {
		serverData.HandshakeMessages = append(serverData.HandshakeMessages, data)
		// There is this problem that we send some data as apllication data, but it is indeed handshake data
		fmt.Println("hash handshake")
		sha := sha512.New384()
		handshakeMsg := []byte{}

		for _, v := range serverData.HandshakeMessages {
			handshakeMsg = append(handshakeMsg, v...)
		}
		sha.Write(handshakeMsg)

		fmt.Println(sha.Sum(nil))
	}

	msg := []byte{byte(contentData)}
	msg = append(msg, []byte{3, 3}...)

	// if serverData.IsServerEncrypted {

	// 	mac := serverData.generateStreamCipher([]byte{byte(contentData)}, data, serverData.ServerSeqNum, serverData.CipherDef.Keys.MacServer)
	// 	// Iv is a pseudo-random function used along with key to add randomness to encryption proces. The IV ensure if the same plaintext is encrypted multiple time with the same key, the result is different
	// 	// Why iv is inside message?
	// 	// Iv used to be taken from last msg, attacker that has access to plaintext of message can send request and with a use of reverse engineering deduce content of the message.
	// 	// For example, Alice's ciphertext-block-1 (aC1) is result of Alice's PlainText-block-1 (aP1) being XORed with the iv generate for the encryptioin
	// 	// ac1=e(ao1 xor aiv)
	// 	// If the eavesdropper (Eve) can predict the IV to be used for her encryption (eIV) then she can choose plaintext such the Eve's Plaintext-Block-1(eP1)
	// 	// eP1=aIv xor eIV xor PG1
	// 	// Wher PG1 is Plaintext-guess-Block-1 which is what Eve is guessing for the value of aP1. This allows a dirt trick to be played in the calculation of Eve's ciphertext-block01(ec1)
	// 	// ec1 = e(ep1 xor eiv)
	// 	// ec1 = e(aiv xor eiv xor pg1 xor eiv)
	// 	// ec1 - e(aiv xor pg1)
	// 	// Therefore if Eve's plainText-Guess block-1 is a match for Alice plaintext-block1 then ec1=Ac1
	// 	// Now you might be thinking that for AES which has a 128-bit block size that Eve will still have her work cut out for herself as there is a huge range of possibilities for plaintext values. You would be right as a guess has a 1 in 2^128 (3.40282366921e38) chance of being right; however, that can be wittled down further as language is not random, not all bytes map to printable characters, context matters, and the protocol might have additional features that can be leveraged.
	// 	// source: https://derekwill.com/2021/01/01/aes-cbc-mode-chosen-plaintext-attack/
	// 	dataWithMac := []byte{}
	// 	if binary.BigEndian.Uint16(serverData.Version) >= uint16(TLS11Version) {
	// 		Iv := make([]byte, serverData.CipherDef.Spec.IvSize)
	// 		_, err := rand.Read(Iv)
	// 		if err != nil {
	// 			return fmt.Errorf("can't generate iv, err: %v", err)
	// 		}
	// 		dataWithMac = Iv
	// 	}
	// 	dataWithMac = append(dataWithMac, data...)
	// 	dataWithMac = append(dataWithMac, mac...)

	// 	encryptedMsg, err := serverData.CipherDef.EncryptMessage(dataWithMac, serverData.CipherDef.Keys.WriteKeyServer, serverData.CipherDef.Keys.IVServer)

	// 	if err != nil {
	// 		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionBadRecordMac)
	// 		return err
	// 	}

	// 	msg = append(msg, helpers.Int32ToBigEndian(len(encryptedMsg))...)
	// 	msg = append(msg, encryptedMsg...)

	// 	data = msg

	// 	for i := 7; i >= 0; i-- {
	// 		serverData.ServerSeqNum[i] += 1
	// 		if serverData.ServerSeqNum[i] != 0 {
	// 			break
	// 		}
	// 	}
	// }
	// else {

	msg = append(msg, helpers.Int32ToBigEndian(len(data))...)
	// msg = append(msg, []byte{0, 122}...)
	msg = append(msg, data...)

	// }

	serverData.wBuff = append(serverData.wBuff, msg...)
	fmt.Println("prepared data to send")
	fmt.Println(serverData.wBuff)

	return nil
}

func (serverData *ServerData) handleLiveConnection() {
	if serverData.extHeartBeat == nil {
		return
	}
	ticker := time.NewTicker(3 * time.Second)

	quit := make(chan struct{})
	serverData.extHeartBeat.quit = quit
	for {
		select {
		case <-ticker.C:
			if serverData.extHeartBeat.lastAct != nil {
				differenceSec := (time.Now().UnixMilli() - serverData.extHeartBeat.lastAct.UnixMilli()) / 1000

				if differenceSec > ConnectionTimeoutSec {
					serverData.closeHandshakeConn()
				}
			}
			heartBeatType := HeartBeatMessageTypeRequest
			heartBeatContentLength := helpers.Int32ToBigEndian(16)
			heartBeatContent, err := helpers.GenerateRandomBytes(16)
			heartBeatPadding := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			if err != nil {
				fmt.Printf("problem creating random bytes, :%v", heartBeatContent)
				return
			}
			data := []byte{byte(heartBeatType)}
			data = append(data, heartBeatContentLength...)
			data = append(data, heartBeatContent...)
			data = append(data, heartBeatPadding...)

			serverData.extHeartBeat.lastPayload = heartBeatContent

			serverData.BuffSendData(ContentTypeHeartBeat, data)

			_, err = serverData.sendData(serverData.wBuff)

			if err != nil {
				serverData.closeHandshakeConn()
			}
		case <-quit:
			ticker.Stop()
			return
		}
	}

}

func encryptRecord(clientWriteKey, clientWriteIV, plaintext []byte, sequenceNumber uint64) ([]byte, error) {
	ivLength := len(clientWriteIV)

	fmt.Println("write key")
	fmt.Println(clientWriteKey)
	fmt.Println(len(clientWriteKey))
	// if sequenceNumber > maxSeqNum {
	// 	return nil, fmt.Errorf("sequence number exceeded limit")
	// }

	// Derive per-record nonce
	perRecordNonce := make([]byte, 12)
	seqNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNumBytes, sequenceNumber)
	copy(perRecordNonce[ivLength-8:], seqNumBytes) // Pad to ivLength
	for i := 0; i < len(clientWriteIV); i++ {
		perRecordNonce[i] ^= clientWriteIV[i]
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(clientWriteKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}
	aesGCM, err := cipher1.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}
	fmt.Println("plaintext")
	fmt.Println(plaintext)

	// Construct additional data
	// TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
	additionalData := make([]byte, 5)
	additionalData[0] = byte(ContentTypeApplicationData)    // opaque_type
	binary.BigEndian.PutUint16(additionalData[1:3], 0x0303) // legacy_record_version
	binary.BigEndian.PutUint16(additionalData[3:], uint16(len(plaintext)+aesGCM.Overhead()))

	fmt.Println("aesgm overhread")
	fmt.Println(aesGCM.Overhead())
	fmt.Println("data length")
	fmt.Println(len(plaintext))
	fmt.Println(plaintext)

	// dst := make([]byte, 1)

	fmt.Println("additional data")
	fmt.Println(additionalData)

	fmt.Println("nonce ")
	fmt.Println(perRecordNonce)

	// Encrypt the plaintext
	ciphertext := aesGCM.Seal(nil, perRecordNonce, plaintext, additionalData)

	return ciphertext, nil
}

func (serverData *ServerData) encryptedExtensions() {
	msgType := byte(HandshakeMessageEncryptedExtension)
	ext := []byte{}
	extLength := helpers.Int32ToBigEndian(len(ext))
	msgLength, err := helpers.IntTo3BytesBigEndian(len(ext) + len(extLength))

	if err != nil {
		panic(err)
	}

	// iv 103 25 169 184 104 164 48 109 122 209 83 235
	// key  249 251 242 231 224 206 34 229 213 178 125 62 18 89 213 169 76 235 184 171 176 14 5 174 2 220 8 46 150 72 50 186
	// in  rec input
	//8 0 0 2 0 0 22
	// data  out
	//195 69 174 252 186 101 46 169 6 180 70 206 142 53 21

	encryptesExtMsg := []byte{msgType}
	encryptesExtMsg = append(encryptesExtMsg, msgLength...)
	encryptesExtMsg = append(encryptesExtMsg, extLength...)
	encryptesExtMsg = append(encryptesExtMsg, ext...)
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, encryptesExtMsg)
	// There is this problem that we send some data as apllication data, but it is indeed handshake data

	sha := sha512.New384()
	handshakeMsg := []byte{}
	fmt.Println("handshake msgs")
	for _, v := range serverData.HandshakeMessages {
		fmt.Println(v)
		handshakeMsg = append(handshakeMsg, v...)
	}
	sha.Write(handshakeMsg)
	fmt.Println("hash handshake")
	fmt.Println(sha.Sum(nil))

	encryptesExtMsg = append(encryptesExtMsg, byte(22))

	// we're missing mac
	// cipherMsg := ExampleNewGCMEncrypter(writeSecret, encryptesExtMsg)
	cipherMsg, err := encryptRecord(writeSecret, ivKey, encryptesExtMsg, 0)

	fmt.Println("encrypted ext msg")
	fmt.Println(encryptesExtMsg)
	// serverData.conn.Write(encryptesExtMsg)
	// //   opaque_type:  The outer opaque_type field of a TLSCiphertext record
	// is always set to the value 23 (application_data) for outward
	// compatibility with middleboxes accustomed to parsing previous
	// versions of TLS.  The actual content type of the record is found
	// in TLSInnerPlaintext.type after decryption.

	// TODO: tls1.3 encrypt the data
	serverData.BuffSendData(ContentTypeApplicationData, cipherMsg)
	serverData.sendData(serverData.wBuff)
}

var writeSecret []byte
var handshakesecret []byte
var ivKey []byte

func SignData(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	// Hash the data using SHA-256
	hasher := sha256.New()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to hash data: %v", err)
	}
	hashed := hasher.Sum(nil)

	// Set salt length to the hash size (32 bytes for SHA-256)
	saltLength := hasher.Size()

	// Sign the hash using RSA-PSS with MGF1 using SHA-256
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed, &rsa.PSSOptions{
		SaltLength: saltLength,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	// Return the base64-encoded signature
	return signature, nil
}

func (serverData *ServerData) CertVerify() {
	// enum {
	// 	/* RSASSA-PKCS1-v1_5 algorithms */
	// 	rsa_pkcs1_sha256(0x0401),
	// 	rsa_pkcs1_sha384(0x0501),
	// 	rsa_pkcs1_sha512(0x0601),

	// 	/* ECDSA algorithms */
	// 	ecdsa_secp256r1_sha256(0x0403),
	// 	ecdsa_secp384r1_sha384(0x0503),
	// 	ecdsa_secp521r1_sha512(0x0603),

	// 	/* RSASSA-PSS algorithms with public key OID rsaEncryption */
	// 	rsa_pss_rsae_sha256(0x0804),
	// 	rsa_pss_rsae_sha384(0x0805),
	// 	rsa_pss_rsae_sha512(0x0806),

	// 	/* EdDSA algorithms */
	// 	ed25519(0x0807),
	// 	ed448(0x0808),

	// 	/* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
	// 	rsa_pss_pss_sha256(0x0809),
	// 	rsa_pss_pss_sha384(0x080a),
	// 	rsa_pss_pss_sha512(0x080b),

	// 	/* Legacy algorithms */
	// 	rsa_pkcs1_sha1(0x0201),
	// 	ecdsa_sha1(0x0203),

	// 	/* Reserved Code Points */
	// 	private_use(0xFE00..0xFFFF),
	// 	(0xFFFF)
	// } SignatureScheme;
	// certVerify := []byte{
	// 	15, 0, 1, 4, 8, 4, 1, 0, 48, 232, 108, 214, 141, 113, 42, 212, 172, 23, 109, 4, 109, 84, 31, 54, 28, 78, 204, 123, 79, 254, 134, 216, 162, 120, 62, 202, 40, 15, 182, 211, 142, 48, 119, 58, 7, 130, 181, 25, 112, 241, 185, 103, 218, 172, 114, 69, 133, 109, 179, 105, 181, 197, 40, 216, 230, 249, 106, 0, 31, 192, 89, 200, 133, 214, 125, 218, 50, 210, 170, 167, 115, 30, 16, 203, 81, 95, 103, 47, 99, 151, 211, 11, 111, 9, 29, 55, 28, 15, 165, 52, 12, 188, 3, 57, 60, 179, 64, 221, 187, 251, 75, 225, 8, 97, 78, 153, 242, 23, 39, 90, 84, 35, 221, 138, 45, 247, 116, 182, 60, 190, 189, 99, 110, 58, 171, 179, 1, 229, 23, 25, 204, 130, 19, 174, 215, 79, 15, 145, 116, 37, 176, 10, 118, 204, 34, 38, 100, 249, 45, 143, 154, 27, 149, 136, 104, 4, 185, 110, 138, 206, 13, 254, 141, 70, 58, 214, 84, 49, 195, 180, 165, 68, 81, 90, 134, 67, 152, 182, 89, 99, 54, 92, 52, 90, 0, 213, 84, 238, 184, 28, 197, 194, 89, 121, 243, 57, 17, 9, 158, 23, 111, 157, 26, 51, 218, 50, 155, 173, 48, 47, 45, 69, 216, 24, 237, 80, 132, 85, 196, 189, 150, 143, 69, 253, 160, 64, 49, 177, 229, 112, 39, 1, 17, 140, 61, 72, 79, 5, 91, 106, 219, 165, 25, 109, 11, 160, 25, 24, 129, 214, 145, 151, 168, 15,
	// }
	// certVerify = append(certVerify, byte(22))

	certVerify := []byte{15, 0, 1, 4, 8, 4, 1, 0}

	signatureData := []byte{}

	for i := 0; i < 64; i++ {
		signatureData = append(signatureData, 32)
	}

	serverContext := "TLS 1.3, server CertificateVerify"

	signatureData = append(signatureData, []byte(serverContext)...)
	signatureData = append(signatureData, 0)

	sha := sha512.New384()
	handshakeMsg := []byte{}
	fmt.Println("handshake msgs")
	for _, v := range serverData.HandshakeMessages {
		fmt.Println(v)
		handshakeMsg = append(handshakeMsg, v...)
	}
	sha.Write(handshakeMsg)
	fmt.Println("hash handshake")
	hash := sha.Sum(nil)
	fmt.Println(hash)
	signatureData = append(signatureData, hash...)

	fmt.Println("signature data")
	fmt.Println(signatureData)

	sha.Reset()
	sha.Write(signatureData)
	// signatureHashed := sha.Sum(nil)

	if serverData.CipherDef.Rsa.PrivateKey == nil {
		panic("private key empty")
	}

	signature, err := SignData(serverData.CipherDef.Rsa.PrivateKey, signatureData)

	if err != nil {
		panic(err)
	}

	fmt.Println("signature")
	fmt.Println(signature)
	fmt.Println(len(signature))
	certVerify = append(certVerify, signature...)
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, certVerify)
	certVerify = append(certVerify, 22)

	cipherMsg, _ := encryptRecord(writeSecret, ivKey, certVerify, 2)

	// serverData.conn.Write(encryptesExtMsg)
	// //   opaque_type:  The outer opaque_type field of a TLSCiphertext record
	// is always set to the value 23 (application_data) for outward
	// compatibility with middleboxes accustomed to parsing previous
	// versions of TLS.  The actual content type of the record is found
	// in TLSInnerPlaintext.type after decryption.

	// TODO: tls1.3 encrypt the data
	fmt.Println("Cert verify")
	serverData.BuffSendData(ContentTypeApplicationData, cipherMsg)
	serverData.sendData(serverData.wBuff)
	// }
}

func HMAC(key, message []byte) []byte {
	// Create a new HMAC object using the provided key and SHA-256.
	h := hmac.New(sha512.New384, key)
	// Write the message to the HMAC object.
	h.Write(message)
	// Compute the final HMAC digest and return it.
	return h.Sum(nil)
}

func (serverData *ServerData) finishMsg() {
	handshakeSecret := handshakesecret

	fmt.Println("handshake secret in finsih")
	fmt.Println(handshakeSecret)

	finish_key, err := serverData.HKDFExpandLabel(handshakeSecret, []byte("finished"), []byte(""), 48)

	if err != nil {
		panic(err)
	}

	fmt.Println("hello finish key is:")
	fmt.Println(finish_key)

	sha := sha512.New384()
	handshakeMsg := []byte{}
	fmt.Println("handshake msgs")
	for _, v := range serverData.HandshakeMessages {
		fmt.Println(v)
		handshakeMsg = append(handshakeMsg, v...)
	}
	sha.Write(handshakeMsg)
	fmt.Println("hash handshake")
	transcriptHash := sha.Sum(nil)
	fmt.Println(transcriptHash)

	verifyData := HMAC(finish_key, transcriptHash)[:serverData.CipherDef.Spec.HashSize]

	fmt.Println("verify Data")
	fmt.Println(verifyData)
	fmt.Println("verify Data")

	verifyDataMsg := []byte{byte(HandshakeMessageFinished)}
	verifyDataLength, _ := helpers.IntTo3BytesBigEndian(len(verifyData))
	verifyDataMsg = append(verifyDataMsg, verifyDataLength...)
	verifyDataMsg = append(verifyDataMsg, verifyData...)
	verifyDataMsg = append(verifyDataMsg, 22)

	// fmt.Println("verify Data msg")
	// fmt.Println(verifyDataMsg)

	cipherMsg, _ := encryptRecord(writeSecret, ivKey, verifyDataMsg, 3)

	// serverData.conn.Write(encryptesExtMsg)
	// //   opaque_type:  The outer opaque_type field of a TLSCiphertext record
	// is always set to the value 23 (application_data) for outward
	// compatibility with middleboxes accustomed to parsing previous
	// versions of TLS.  The actual content type of the record is found
	// in TLSInnerPlaintext.type after decryption.

	// TODO: tls1.3 encrypt the data
	fmt.Println("verify Data")
	serverData.BuffSendData(ContentTypeApplicationData, cipherMsg)
	serverData.sendData(serverData.wBuff)

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

		// if err = serverData.changeCipher(); err != nil {
		// 	return fmt.Errorf("problem with change cipher in resuse sesstion, err: %v", err)
		// }

		if _, err = serverData.sendData(serverData.wBuff); err != nil {
			return err
		}
		if err = serverData.changeCipher(); err != nil {
			return fmt.Errorf("problem with changing cipher, err: %v", err)
		}
		if _, err = serverData.sendData(serverData.wBuff); err != nil {
			return err
		}
		// serverData.conn.Write([]byte{20, 3, 3, 0, 1, 1})
		serverData.encryptedExtensions()

		// if serverData.CipherDef.Spec.SignatureAlgorithm != cipher.SignatureAlgorithmAnonymous {
		err, cert := serverData.loadCertificate()
		if err != nil {
			return fmt.Errorf("\n problem loading certificate: %V", err)
		}
		cert = append(cert, byte(22))
		cipherMsg, err := encryptRecord(writeSecret, ivKey, cert, 1)

		// serverData.conn.Write(encryptesExtMsg)
		// //   opaque_type:  The outer opaque_type field of a TLSCiphertext record
		// is always set to the value 23 (application_data) for outward
		// compatibility with middleboxes accustomed to parsing previous
		// versions of TLS.  The actual content type of the record is found
		// in TLSInnerPlaintext.type after decryption.

		// TODO: tls1.3 encrypt the data
		fmt.Println("Cert")
		fmt.Println(cert)
		serverData.BuffSendData(ContentTypeApplicationData, cipherMsg)
		serverData.sendData(serverData.wBuff)

		serverData.CertVerify()

		serverData.finishMsg()
		// }
		// fmt.Println("Cert")
		// fmt.Println(cipherMsg)
		// serverData.conn.Write(cert)
		// serverData.conn.Write([]byte{23, 3, 3, 0, 23, 31, 116, 98, 167, 200, 71, 1, 101, 157, 208, 244, 116, 202, 90, 229, 171, 63, 161, 79, 3, 160, 248, 124})
		return err

		// if serverData.reuseSession {

		// 	if err = serverData.calculateKeyBlock(serverData.MasterKey); err != nil {
		// 		return fmt.Errorf("\n problem calculating key block, err: %v", err)
		// 	}
		// 	if err = serverData.serverFinished(); err != nil {
		// 		return fmt.Errorf("\n problem with serverFinish msg, err: %v", err)
		// 	}

		// }

		// if (serverData.CipherDef.Spec.KeyExchange == cipher.KeyExchangeMethodDH && serverData.CipherDef.Spec.KeyExchangeRotation) ||
		// 	(serverData.CipherDef.Spec.KeyExchange == cipher.KeyExchangeMethodDH && serverData.CipherDef.Spec.SignatureAlgorithm == cipher.SignatureAlgorithmAnonymous) {
		// 	if err = serverData.serverKeyExchange(); err != nil {
		// 		return fmt.Errorf("\n problem with serverkeyexchange message: %v", err)
		// 	}
		// }

		// if err = serverData.serverHelloDone(); err != nil {
		// 	return fmt.Errorf("\n  problem with serverHelloDone message, err: %v", err)
		// }

		// // lets do one write with collected few messages, don't send extra network round trips
		// _, err = serverData.sendData(serverData.wBuff)
		// if err != nil {
		// 	serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		// 	return fmt.Errorf("\n problem sending server hello data, err: %v", err)
		// }
	}
	// else if handshakeMessageType == HandshakeMessageClientKeyExchange {
	// 	// computes ivs, writekeys, macs, don't need to send any message after this
	// 	if err := serverData.handleHandshakeClientKeyExchange(contentData); err != nil {
	// 		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
	// 		return fmt.Errorf("\n handshake client key exchange err: %v", err)
	// 	}
	// } else if handshakeMessageType == HandshakeMessageFinished {
	// 	if serverData.reuseSession {
	// 		go serverData.handleLiveConnection()
	// 		return nil
	// 	}

	// 	if err := serverData.handleHandshakeClientFinished(contentData); err != nil {
	// 		return err
	// 	}

	// 	if err = serverData.changeCipher(); err != nil {
	// 		return fmt.Errorf("problem with changing cipher, err: %v", err)
	// 	}

	// 	// We don't combine message here to single route trip as change cipher msg is separate content type, in order to not be stalling
	// 	_, err = serverData.sendData(serverData.wBuff)
	// 	if err != nil {
	// 		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
	// 		return fmt.Errorf("\n problem sending change cipher msg: %v", err)
	// 	}

	// 	err = serverData.serverFinished()
	// 	if err != nil {
	// 		return fmt.Errorf("\n problem with serverFinish msg, err: %v", err)
	// 	}
	// 	_, err = serverData.sendData(serverData.wBuff)

	// 	if err != nil {
	// 		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
	// 		return fmt.Errorf("\n problem sending server finished msgs: %v", err)
	// 	}
	// 	sessions.mu.Lock()
	// 	sessions.data[string(serverData.session)] = serverData
	// 	sessions.mu.Unlock()
	// 	go serverData.handleLiveConnection()
	// }
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

var sessiontmp []byte
var keyShare []byte

func (serverData *ServerData) handleHandshakeClientHello(contentData []byte) error {
	contentLength := int(contentData[1])<<16 | int(contentData[2])<<8 | int(contentData[3])
	dataContentExpectedLen := contentLength + 4 // 4: 1 bytefor content type, 3 bytes for length
	if dataContentExpectedLen != len(contentData) {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("conent length does not fit data passed, expected to have length of: %v, got: %v", dataContentExpectedLen, len(contentData))
	}

	// FROM TLS 1.2 spec
	// Earlier versions of the TLS specification were not fully clear on
	// what the record layer version number (TLSPlaintext.version) should
	// contain when sending ClientHello (i.e., before it is known which
	// version of the protocol will be employed).  Thus, TLS servers
	// compliant with this specification MUST accept any value {03,XX} as
	// the record layer version number for ClientHello.
	clientVersion := binary.BigEndian.Uint16(contentData[4:6])
	// TODO TLS 1.1 maybe write better algo to chose version
	if clientVersion < 0x0300 || clientVersion > binary.BigEndian.Uint16(serverData.Version) {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("ssl version not matches, expected to be: %v or lower, got: %v", binary.BigEndian.Uint16(serverData.Version), clientVersion)
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

	fmt.Println("wha we have in session")
	fmt.Println(session)

	cipherSuitesLength := binary.BigEndian.Uint16(contentData[sessionIndexEnd : sessionIndexEnd+2])

	cipherSuites := contentData[sessionIndexEnd+2 : sessionIndexEnd+2+cipherSuitesLength]
	compressionsLength := contentData[sessionIndexEnd+2+cipherSuitesLength]
	compressionMethodListEndIndex := sessionIndexEnd + 2 + cipherSuitesLength + 1 + uint16(compressionsLength)
	compressionMethodList := contentData[sessionIndexEnd+2+cipherSuitesLength+1 : compressionMethodListEndIndex]

	if len(compressionMethodList) != int(compressionsLength) {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return fmt.Errorf("\n compression method list wrong length got:%v, expected :%v", len(compressionMethodList), int(compressionsLength))
	}

	serverData.loadSession(string(session))

	sessiontmp = session

	serverData.ClientRandom = contentData[6:38]
	err := serverData.CipherDef.SelectCipherSuite(cipherSuites)
	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionInsufficientSecuirty)
		return fmt.Errorf("problem selecting cipher suite, err: %v", err)
	}
	serverData.CipherDef.GetCipherSpecInfo()
	if binary.BigEndian.Uint16(serverData.Version) >= uint16(TLS11Version) {
		serverData.CipherDef.Spec.IvAsPayload = true
	}
	if binary.BigEndian.Uint16(serverData.Version) >= uint16(TLS12Version) {
		serverData.CipherDef.Spec.HashBasedSigning = true
	}

	if serverData.CipherDef.Spec.SignatureAlgorithm != cipher.SignatureAlgorithmAnonymous && serverData.cert == nil {
		return fmt.Errorf("please provider certificate for: %v", serverData.CipherDef.Spec.SignatureAlgorithm)
	}
	if err = serverData.CipherDef.SelectCompressionMethod(compressionMethodList); err != nil {
		return err
	}

	err = serverData.SelectBlockCipherPadding()

	if compressionMethodListEndIndex == uint16(len(contentData)) {
		return err
	}
	extension := contentData[compressionMethodListEndIndex:]

	// TODO implement this
	if compressionMethodListEndIndex+4 > uint16(len(contentData)) {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionUnsportedExtension)
		return fmt.Errorf("invalid extenstion length, expect to get at least four bytes of extension length, extenstion we got: %v", contentData[compressionMethodListEndIndex:])
	}

	// extension := contentData[compressionMethodListEndIndex:]

	// extensionLength := binary.BigEndian.Uint16(extension[:2])
	// That is length for all extenstion, we need to do loop here
	extenstionData := extension[2:]

	type sslExtension struct {
		extType uint16
		extData []byte
	}

	extenstions := []sslExtension{}

	for len(extenstionData) > 0 {
		if len(extenstionData) < 4 {
			return fmt.Errorf("extenstion data should have at least four bytes, 2 for type, 2 for data length, insted we got: %v, with data:%v", len(extenstionData), extenstionData)
		}
		extenionType := binary.BigEndian.Uint16(extenstionData[0:2])
		dataLength := binary.BigEndian.Uint16(extenstionData[2:4])
		if len(extenstionData) < int(4+dataLength) {
			return fmt.Errorf("expected to data have length of %v, insted we got:%v, data: %v", dataLength, len(extenstionData)-4, extenstionData[4:])
		}
		data := extenstionData[4 : 4+dataLength]

		extData := sslExtension{
			extType: extenionType,
			extData: data,
		}
		extenstions = append(extenstions, extData)
		extenstionData = extenstionData[4+dataLength:]
	}

	fmt.Println("extensions")
	fmt.Println(extenstions)

	for _, v := range extenstions {
		dataType := v.extType
		data := v.extData
		switch dataType {
		case 10:
			// supported groups
			if len(data) < 2 {
				return fmt.Errorf("data should be at least of length: 2, we got data: %v", data)
			}
			supportedGroup := cipher.DhGroupX25519
			groupsLength := binary.BigEndian.Uint16(data[:2])

			if len(data)-2 != int(groupsLength) {
				return fmt.Errorf("data should be of lenth: %v, insted we got: %v, data: %v", int(groupsLength), len(data)-2, data[2:])
			}
			clientGroups := data[2:]
			if len(clientGroups)%2 != 0 {
				return fmt.Errorf("client groups data length should be odd, data we got: %v", data[2:])
			}
			serverData.CipherDef.DhParams.Group = &supportedGroup

			clientGroupsMap := make(map[uint16]bool)

			for i := 0; i < len(clientGroups); i += 2 {
				clientGroupsMap[binary.BigEndian.Uint16(clientGroups[i:i+2])] = true
			}

			fmt.Println("client groups")
			fmt.Println(clientGroupsMap)

			if !clientGroupsMap[uint16(supportedGroup)] {
				return fmt.Errorf("Don't support any of the group")
			}

			fmt.Printf("we can use group: %v", supportedGroup)
		case 11:
			// ec points formats
		case 13:
			if len(data) < 2 {
				return fmt.Errorf("signature algorithm should have at least two bytes for length, we got: %v", data)
			}
			length := binary.BigEndian.Uint16(data[:2])
			if len(data) < 2+int(length) {
				return fmt.Errorf("expected data to be of length: %v, insted we got:%v, with data: %v", length, len(data)-2, data)
			}

			serverData.CipherDef.ExtSetSignatureAlgorithms(data[2:])
		case 15:
			if len(data) < 1 {
				return fmt.Errorf("heart beat should have a length of 1 byte we got: %v", data)
			}

			if HeartBeatMode(data[0]) != HeartBeatPeerAllowedToSendMode && HeartBeatMode(data[0]) != HeartBeatPeerNotAllowedToSendMode {
				serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionIllegalParameter)
				return fmt.Errorf("heart beat should have value of: %v, %v", HeartBeatPeerAllowedToSendMode, HeartBeatPeerNotAllowedToSendMode)
			}
			if HeartBeatMode(data[0]) == HeartBeatPeerAllowedToSendMode {
				serverData.extHeartBeat = &ExtHeartBeat{}
			}
		case 22:
			// encrypt_then_mac
		case 23:
			// extended_master_secret
		case 27:
			// compress_certificate
		case 35:
			// TODO: implement
			// Sessioc ticket
			// https://www.rfc-editor.org/rfc/rfc5077.html
			// https://www.rfc-editor.org/rfc/rfc8447.html
		case 43:
			// supported_versions
			if len(data) < 1 {
				return fmt.Errorf("data should be at least of length: 1, we got data: %v", data)
			}

			if len(data)-1 != int(data[0]) {
				return fmt.Errorf("expected the to be of length: %v, got: %v, data: %v", data[0], len(data)-1, data)
			}
			supportedVersionData := binary.BigEndian.Uint16(data[1 : 1+data[0]])

			if supportedVersionData != binary.BigEndian.Uint16(serverData.Version) {
				return fmt.Errorf("expected version to be: %v, got: %v", serverData.Version, data[1:1+data[0]])
			}

			fmt.Println("supported version")
			fmt.Println(supportedVersionData)
		case 45:
			//psk_key_exchange_modes
		case 51:
			//key_share

			// Clients MAY send an empty client_shares vector in order to request
			//group selection from the server, at the cost of an additional round
			//trip
			// This vector MAY be empty if the client is requesting a
			// HelloRetryRequest.

			if len(data) < 2 {
				return fmt.Errorf("data should be at least of length: 1, we got data: %v", data)
			}

			keyShareDataLength := binary.BigEndian.Uint16(data[:2])
			if len(data)-2 != int(keyShareDataLength) {
				return fmt.Errorf("data should be of lenth: %v, insted we got: %v, data: %v", int(keyShareDataLength), len(data)-2, data[2:])
			}

			keyShareData := data[2 : 2+keyShareDataLength]

			if len(keyShareData) < 4 {
				return fmt.Errorf("key share data  ext should have length of at least 4, 2 for group name, 2 for key exchange length, we got data: %v", keyShareData)
			}

			groupName := keyShareData[:2]
			//x25519(0x001D) - 19
			keyExchangeLength := binary.BigEndian.Uint16(keyShareData[2:4])

			if len(keyShareData)-4 != int(keyExchangeLength) {
				return fmt.Errorf("key exchange should be of lenth: %v, insted we got: %v, data: %v", int(keyExchangeLength), len(keyShareData)-4, keyShareData[4:])
			}

			keyExchange := keyShareData[4 : 4+keyExchangeLength]

			fmt.Println("alright, we got groupname")
			fmt.Println(groupName)
			fmt.Println("and key exchange")
			fmt.Println(keyExchange)
			keyShare = keyExchange

		default:
			return fmt.Errorf("unknown extenstion type: %v", dataType)
		}
	}

	return err
}

func signatureHash(algorithm hash.Hash, clientRandom, serverRandom, serverParams []byte) []byte {
	algorithm.Reset()
	algorithm.Write(clientRandom)
	algorithm.Write(serverRandom)
	algorithm.Write(serverParams)

	return algorithm.Sum(nil)

}

func (serverData *ServerData) getServerKeyExchange() ([]byte, error) {
	switch binary.BigEndian.Uint16(serverData.Version) {
	case 0x0300, 0x0301, 0x0302:
		return serverData.S3GetServerKeyExchangeMessage()
	case 0x0303:
		return serverData.T12GetServerKeyExchangeMessage()
	default:
		panic("should never enter this state, in getServerKeyExchange")
	}
}

// func (serverData *ServerData) serverKeyExchange() error {

// 	keyExchangeData, err := serverData.getServerKeyExchange()

// 	if err != nil {
// 		return fmt.Errorf("Problem while generating key exchange msg: %v", err)
// 	}
// 	handshakeLengthh := len(keyExchangeData)
// 	handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(handshakeLengthh)
// 	if err != nil {
// 		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
// 		return fmt.Errorf("err while converting to big endian, err: %v", err)
// 	}

// 	serverKeyExchange := []byte{byte(HandshakeMessageServerKeyExchange)}
// 	serverKeyExchange = append(serverKeyExchange, handshakeLengthByte...)
// 	serverKeyExchange = append(serverKeyExchange, keyExchangeData...)

// 	err = serverData.BuffSendData(ContentTypeHandshake, serverKeyExchange)

// 	return err
// }

// HKDF-Expand-Label(Secret, Label, Context, Length) =
//             HKDF-Expand(Secret, HkdfLabel, Length)

//        Where HkdfLabel is specified as:

//        struct {
//            uint16 length = Length;
//            opaque label<7..255> = "tls13 " + Label;
//            opaque context<0..255> = Context;
//        } HkdfLabel;

//        Derive-Secret(Secret, Label, Messages) =
//             HKDF-Expand-Label(Secret, Label,
//                               Transcript-Hash(Messages), Hash.length)

func (serverData *ServerData) HKDFExpandLabel(secret, label, context []byte, length int) ([]byte, error) {
	// TLS 1.3 uses SHA256 for the HMAC function
	hash := sha1.New

	switch serverData.CipherDef.Spec.HashAlgorithm {
	case cipher.HashAlgorithmSHA384:
		hash = sha512.New384
	default:
		panic("hash function not implemneted")
	}

	// Create the HKDF instance
	combinedLabel := []byte("tls13 ")
	combinedLabel = append(combinedLabel, label...)
	lengthByte := helpers.Int32ToBigEndian(length)
	info := []byte{}
	info = append(info, lengthByte...)
	info = append(info, byte(len(combinedLabel)))
	info = append(info, combinedLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)

	hkdf1 := hkdf.Expand(hash, secret, info)

	output := make([]byte, length)

	_, err := hkdf1.Read(output)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func (serverData *ServerData) DeriveSecret(Secret, Label, Messages []byte) ([]byte, error) {

	hashFunc := sha1.New()

	switch serverData.CipherDef.Spec.HashAlgorithm {
	case cipher.HashAlgorithmSHA384:
		hashFunc = sha512.New384()
	default:
		panic("hash function not implemneted")
	}

	hashFunc.Write(Messages)
	res := hashFunc.Sum(nil)

	return serverData.HKDFExpandLabel(Secret, Label, res, serverData.CipherDef.Spec.HashSize)
}

var serverHelloSecret []byte

func (serverData *ServerData) derive() {
	hash := sha1.New

	switch serverData.CipherDef.Spec.HashAlgorithm {
	case cipher.HashAlgorithmSHA384:
		hash = sha512.New384
	default:
		panic("hash function not implemneted")
	}

	arr := make([]byte, serverData.CipherDef.Spec.HashSize)
	earlySecret := hkdf.Extract(hash, arr, []byte{})

	//     Derive-Secret(., "derived", "")
	aa, err := serverData.DeriveSecret(earlySecret, []byte("derived"), []byte(""))

	derivedSecret := hkdf.Extract(hash, serverHelloSecret, aa)

	fmt.Println("lets see dervied keys, secret")
	fmt.Println(aa)
	fmt.Println("and key")
	fmt.Println(derivedSecret)
	//

	//             +-----> Derive-Secret(., "s hs traffic",
	// |                     ClientHello...ServerHello)
	// |                     = server_handshake_traffic_secret

	handshakeMsgs := []byte{}

	for _, v := range serverData.HandshakeMessages {
		handshakeMsgs = append(handshakeMsgs, v...)
	}

	handshakeSecretKey, err := serverData.DeriveSecret(derivedSecret, []byte("s hs traffic"), handshakeMsgs)

	// handshakeSecret := hkdf.Extract(hash, serverHelloSecret, bb)
	//

	fmt.Println("lets see HAndshake~~!!!!!!!!!!!!!!!111, secret")
	fmt.Println(handshakeSecretKey)
	handshakesecret = handshakeSecretKey
	// fmt.Println("and key")
	// fmt.Println(handshakeSecret)

	if err != nil {
		panic(err)
	}

	write_key, err := serverData.HKDFExpandLabel(handshakeSecretKey, []byte("key"), []byte(""), 32)
	iv_key, err := serverData.HKDFExpandLabel(handshakeSecretKey, []byte("iv"), []byte(""), 12)

	fmt.Println("hello write key is:")
	fmt.Println(write_key)
	fmt.Println("hello iv is")
	fmt.Println(iv_key)

	writeSecret = write_key
	ivKey = iv_key

}

func (serverData *ServerData) serverHello() error {

	currentTime := time.Now()
	unixTime := currentTime.Unix()

	unitTimeBytes := helpers.Int64ToBIgEndian(unixTime)
	randomBytes := make([]byte, RandomBytesLength-len(unitTimeBytes))

	_, err := rand.Read(randomBytes)

	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionInternalError)
		return fmt.Errorf("problem generating random bytes, err:%v", err)
	}

	// cipherSuite := helpers.Int32ToBigEndian(int(serverData.CipherDef.CipherSuite))
	cipherSuite := []byte{19, 2}
	// compressionMethod := []byte{byte(serverData.CipherDef.Spec.CompressionMethod)}
	compressionMethod := []byte{0}
	protocolVersion := serverData.Version

	session := []byte{}
	sessionLength := []byte{0}

	if binary.BigEndian.Uint16(serverData.Version) == 0x0304 {
		session = sessiontmp
		sessionLength = []byte{byte(len(session))}
		fmt.Println("tls 1.3 session")
	} else {
		if len(serverData.session) != 0 {
			session = serverData.session
			sessionLength = []byte{byte(len(session))}
		} else {
			session = helpers.GenerateSession()

			sessionLength = []byte{byte(len(session))}
			serverData.session = session
		}

	}
	ext := []byte{}

	if binary.BigEndian.Uint16(serverData.Version) == 0x0304 {
		keyShareExt := []byte{0, 51, 0, 36, 0, 29, 0, 32}
		if *serverData.CipherDef.DhParams.Group == cipher.DhGroupX25519 {
			key := keys.GenerateX25519Key()
			privateKey := key.Private()
			pubKey := key.Public()

			fmt.Println("we are using for sharedSecret1 ")
			fmt.Println("priv key")
			fmt.Println(privateKey)
			fmt.Println("and pub key")
			fmt.Println(keyShare)
			sharedSecret1, _ := curve25519.X25519(privateKey, keyShare)
			fmt.Println("Shared secret:", sharedSecret1)
			serverHelloSecret = sharedSecret1
			fmt.Println("this should be right")

			keyShareExt = append(keyShareExt, pubKey...)

		}

		versionExt := []byte{0, 46, 0, 43, 0, 2, 3, 4}
		extLength := helpers.Int32ToBigEndian(len(keyShareExt) + len(versionExt))

		fmt.Println(extLength)
		ext = append(ext, versionExt...)
		ext = append(ext, keyShareExt...)

		// Encrypted Extensions

		// In all handshakes, the server MUST send the EncryptedExtensions
		// message immediately after the ServerHello message.  This is the first
		// message that is encrypted under keys derived from the
		// server_handshake_traffic_secret.

		// The EncryptedExtensions message contains extensions that can be
		// protected, i.e., any which are not needed to establish the
		// cryptographic context but which are not associated with individual
		// certificates.  The client MUST check EncryptedExtensions for the
		// presence of any forbidden extensions and if any are found MUST abort
		// the handshake with an "illegal_parameter" alert.

		// Structure of this message:

		//    struct {
		// 	   Extension extensions<0..2^16-1>;
		//    } EncryptedExtensions;

		// extensions:  A list of extensions.  For more information, see the
		//    table in Section 4.2.

	}

	handshakeLength := len(unitTimeBytes) + len(randomBytes) + len(sessionLength) + len(session) + len(cipherSuite) + len(compressionMethod) + len(protocolVersion) + len(ext)
	// handshakeLength := len(unitTimeBytes) + len(randomBytes) + len(sessionLength) + len(session) + len(protocolVersion) + len(ext)
	handshakeLengthByte, err := helpers.IntTo3BytesBigEndian(handshakeLength)

	if err != nil {
		return fmt.Errorf("error converting int to big endian: %v", err)
	}
	// serverHello := []byte{22, 3, 3, 0, 122}

	serverHello := []byte{byte(HandshakeMessageServerHello)}
	// 22, 3, 3, 0, 122,
	// serverHello = append(serverHello, []byte{0, 0, 118}...)
	// serverHello = append(serverHello, []byte{0, 0, 118}...)
	serverHello = append(serverHello, handshakeLengthByte...)
	serverHello = append(serverHello, []byte{3, 3}...)
	// serverHello = append(serverHello, protocolVersion...)
	serverHello = append(serverHello, unitTimeBytes...)
	serverHello = append(serverHello, randomBytes...)
	serverHello = append(serverHello, sessionLength...)
	serverHello = append(serverHello, session...)
	serverHello = append(serverHello, cipherSuite...)
	serverHello = append(serverHello, compressionMethod...)
	serverHello = append(serverHello, ext...)
	fmt.Println("Server hello, cipher suite")
	fmt.Println(cipherSuite)
	fmt.Println(serverData.CipherDef.Spec.HashAlgorithm)
	fmt.Println(serverHello)

	serverData.ServerRandom = unitTimeBytes
	serverData.ServerRandom = append(serverData.ServerRandom, randomBytes...)

	err = serverData.BuffSendData(ContentTypeHandshake, serverHello)

	if binary.BigEndian.Uint16(serverData.Version) == 0x0304 {
		serverData.derive()
	}

	return err
}

// func (serverData *ServerData) serverHelloDone() error {
// 	serverHelloDone := []byte{byte(HandshakeMessageServerHelloDone)}
// 	serverHelloDone = append(serverHelloDone, []byte{0, 0, 0}...) // Always 0 length

// 	err := serverData.BuffSendData(ContentTypeHandshake, serverHelloDone)

// 	return err
// }

var masterKeyGenLabel = map[uint16][]byte{
	0x0300: nil,
	0x0301: []byte("master secret"),
	0x0302: []byte("master secret"),
	0x0303: []byte("master secret"),
}

func (serverData *ServerData) handleHandshakeClientKeyExchange(contentData []byte) error {
	conentLength := uint32(contentData[1])<<16 | uint32(contentData[2])<<8 | uint32(contentData[3])
	if len(contentData)-4 != int(conentLength) {
		return fmt.Errorf("invalid content length, expected: %v, got: %v", conentLength, len(contentData)-4)
	}

	preMasterSecret, err := serverData.CipherDef.ComputeMasterSecret(contentData[4:])

	if err != nil {
		return err
	}

	masterKeySeed := []byte{}
	masterKeySeed = append(masterKeySeed, serverData.ClientRandom...)
	masterKeySeed = append(masterKeySeed, serverData.ServerRandom...)

	label := masterKeyGenLabel[binary.BigEndian.Uint16(serverData.Version)]
	if label == nil && binary.BigEndian.Uint16(serverData.Version) >= 0x301 {
		return fmt.Errorf("every version from tls1.0 should use label for calculate master key")
	}
	masterKey := serverData.prf(preMasterSecret, masterKeySeed, label, MasterSecretLength)

	err = serverData.calculateKeyBlock(masterKey)

	if err != nil {
		return fmt.Errorf("problem while calculating key block: %v", err)
	}

	serverData.MasterKey = masterKey
	serverData.PreMasterSecret = preMasterSecret

	return nil
}

var keyBlockLabel = map[uint16][]byte{
	0x0300: nil,
	0x0301: []byte("key expansion"),
	0x0302: []byte("key expansion"),
	0x0303: []byte("key expansion"),
}

func (serverData *ServerData) prf(key, seed, label []byte, length int) []byte {
	seedExtended := label
	seedExtended = append(seedExtended, seed...)
	switch binary.BigEndian.Uint16(serverData.Version) {
	case 0x0300:
		return s3_prf(key, seedExtended, length)
	case 0x0301, 0x0302:
		return T1Prf(key, seedExtended, length)
	case 0x0303:
		return T12Prf(key, seedExtended, length)
	default:
		fmt.Println("should never enter this state in prf")
		os.Exit(1)
	}
	return []byte{}
}

func (serverData *ServerData) SelectBlockCipherPadding() error {
	switch binary.BigEndian.Uint16(serverData.Version) {
	case 0x0300:
		serverData.CipherDef.Spec.PaddingType = cipher.ZerosPaddingType
	case 0x0301, 0x0302, 0x0303, 0x0304:
		serverData.CipherDef.Spec.PaddingType = cipher.LengthPaddingType
	default:
		return fmt.Errorf("unsporrted version  in selct cipher padding")
	}
	return nil

}

func (serverData *ServerData) calculateKeyBlock(masterKey []byte) error {
	keyBlockSeed := []byte{}
	keyBlockSeed = append(keyBlockSeed, serverData.ServerRandom...)
	keyBlockSeed = append(keyBlockSeed, serverData.ClientRandom...)

	keyBlockLen := serverData.CipherDef.Spec.HashSize*2 + serverData.CipherDef.Spec.KeyMaterial*2 + serverData.CipherDef.Spec.IvSize*2
	label := keyBlockLabel[binary.BigEndian.Uint16(serverData.Version)]
	if label == nil && binary.BigEndian.Uint16(serverData.Version) >= 0x301 {
		return fmt.Errorf("every version from tls1.0 should use label for calculate key block")
	}
	keyBlock := serverData.prf(masterKey, keyBlockSeed, label, keyBlockLen)

	macEndIndex := serverData.CipherDef.Spec.HashSize * 2
	writeKeyEndIndex := macEndIndex + serverData.CipherDef.Spec.KeyMaterial*2

	if len(keyBlock) < writeKeyEndIndex+serverData.CipherDef.Spec.IvSize*2 {
		return fmt.Errorf("key block should be of at lest length: %v, instead we got: %v", writeKeyEndIndex+serverData.CipherDef.Spec.IvSize*2, len(keyBlock))
	}

	cipherDefKeys := cipher.CipherKeys{
		MacClient:      keyBlock[:serverData.CipherDef.Spec.HashSize],
		MacServer:      keyBlock[serverData.CipherDef.Spec.HashSize:macEndIndex],
		WriteKeyClient: keyBlock[macEndIndex : macEndIndex+serverData.CipherDef.Spec.KeyMaterial],
		WriteKeyServer: keyBlock[serverData.CipherDef.Spec.HashSize*2+serverData.CipherDef.Spec.KeyMaterial : writeKeyEndIndex],
		IVClient:       keyBlock[writeKeyEndIndex : writeKeyEndIndex+serverData.CipherDef.Spec.IvSize],
		IVServer:       keyBlock[writeKeyEndIndex+serverData.CipherDef.Spec.IvSize : writeKeyEndIndex+serverData.CipherDef.Spec.IvSize*2],
	}

	serverData.CipherDef.Keys = cipherDefKeys

	return nil
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

	verifyHashMac := serverData.generateFinishedHandshakeMac(label, serverData.HandshakeMessages)

	hashLen := len(verifyHashMac)
	msgLenEndian, err := helpers.IntTo3BytesBigEndian(hashLen)

	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionInternalError)
		return fmt.Errorf("problem converting hash len into endian format")
	}

	verifyMacWithHeaders := []byte{byte(HandshakeMessageFinished)}
	verifyMacWithHeaders = append(verifyMacWithHeaders, msgLenEndian...)
	verifyMacWithHeaders = append(verifyMacWithHeaders, verifyHashMac...)

	err = serverData.BuffSendData(ContentTypeHandshake, verifyMacWithHeaders)

	return err

}

func (serverData *ServerData) generateFinishedHandshakeMac(label []byte, handshakeMessages [][]byte) []byte {
	switch binary.BigEndian.Uint16(serverData.Version) {
	case 0x0300:
		md5Hash := serverData.S3GenerateFinishedHandshakeMac(md5.New(), label, handshakeMessages) // -1 without last message witch is client verify
		shaHash := serverData.S3GenerateFinishedHandshakeMac(sha1.New(), label, handshakeMessages)
		return append(md5Hash, shaHash...)
	case 0x0301, 0x0302:
		return serverData.T1GenerateFinishedHandshakeMac(label, handshakeMessages)
	case 0x0303:
		return serverData.T12GenerateFinishedHandshakeMac(label, handshakeMessages)
	default:
		fmt.Println("should never enter this state in generateFinishedHandshakeMac")
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
	0x0302: {
		"client": []byte("client finished"),
		"server": []byte("server finished"),
	},
	0x0303: {
		"client": []byte("client finished"),
		"server": []byte("server finished"),
	},
}

func (serverData *ServerData) handleHandshakeClientFinished(contentData []byte) error {

	label := finishedLabel[uint16(binary.BigEndian.Uint16(serverData.Version))]["client"]

	if label == nil {
		return fmt.Errorf("there is no label for client finished msg")
	}

	clientHash := serverData.generateFinishedHandshakeMac(label, serverData.HandshakeMessages[:len(serverData.HandshakeMessages)-1])

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

	serverData.IsClientEncrypted = true
}
