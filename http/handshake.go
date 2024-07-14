package http

import (
	"fmt"
	"net"
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

type TLSCipherSuite byte

const (
	TLS_CIPER_SUITE_SSL_NULL_WITH_NULL_NULL            TLSCipherSuite = 0
	TLS_CIPER_SUITE_SSL_RSA_WITH_NULL_MD5              TLSCipherSuite = 1
	TLS_CIPER_SUITE_SSL_RSA_WITH_NULL_SHA              TLSCipherSuite = 2
	TLS_CIPER_SUITE_SSL_RSA_EXPORT_WITH_RC4_40_MD5     TLSCipherSuite = 3
	TLS_CIPER_SUITE_SSL_RSA_WITH_RC4_128_MD5           TLSCipherSuite = 4
	TLS_CIPER_SUITE_SSL_RSA_WITH_RC4_128_SHA           TLSCipherSuite = 5
	TLS_CIPER_SUITE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5 TLSCipherSuite = 6
	TLS_CIPER_SUITE_SSL_RSA_WITH_IDEA_CBC_SHA          TLSCipherSuite = 7
	TLS_CIPER_SUITE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA  TLSCipherSuite = 8
	TLS_CIPER_SUITE_SSL_RSA_WITH_DES_CBC_SHA           TLSCipherSuite = 9
	TLS_CIPER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA      TLSCipherSuite = 10
	//Following cipher suite definition requires that server provide an rsa certificat ethat can be used for key exchange.
	TLS_CIPER_SUITE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  TLSCipherSuite = 11
	TLS_CIPER_SUITE_SSL_DH_DSS_WITH_DES_CBC_SHA           TLSCipherSuite = 12
	TLS_CIPER_SUITE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA      TLSCipherSuite = 13
	TLS_CIPER_SUITE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  TLSCipherSuite = 14
	TLS_CIPER_SUITE_SSL_DH_RSA_WITH_DES_CBC_SHA           TLSCipherSuite = 15
	TLS_CIPER_SUITE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA      TLSCipherSuite = 16
	TLS_CIPER_SUITE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA TLSCipherSuite = 17
	TLS_CIPER_SUITE_SSL_DHE_DSS_WITH_DES_CBC_SHA          TLSCipherSuite = 18
	TLS_CIPER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA     TLSCipherSuite = 19
	TLS_CIPER_SUITE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA TLSCipherSuite = 20
	TLS_CIPER_SUITE_SSL_DHE_RSA_WITH_DES_CBC_SH           TLSCipherSuite = 21
	TLS_CIPER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA     TLSCipherSuite = 22
	// Folowing cipher suited are used for server-authenticated (optianlly client) diffie-hellman. Dh denotes cipher suited in which the server-s certificate contains dh paramters signed by the  certificate authority.
	// dhe denothes ephemral diffie-hellman where dh paramters are signed by dss or rsa cerificate, which has been signed by ca. The sigin algorithm used in specified after the dh or dhepparamter.
	// In all case  the clie must have the same type of cerificate, and must use the dh paramters chosen by the server

	TLS_CIPER_SUITE_SSL_DH_anon_EXPORT_WITH_RC4_40_MD5    TLSCipherSuite = 23
	TLS_CIPER_SUITE_SSL_DH_anon_WITH_RC4_128_MD5          TLSCipherSuite = 24
	TLS_CIPER_SUITE_SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA TLSCipherSuite = 25
	TLS_CIPER_SUITE_SSL_DH_anon_WITH_DES_CBC_SHA          TLSCipherSuite = 26
	TLS_CIPER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA     TLSCipherSuite = 27
	// The following cipher suited are used for completely anonymous diffie hellman in which neither party is authenticated. Note thi is extremly vuluberable to man in the middle attackers, so its strongly discouraged to use it.
	TLS_CIPER_SUITE_SSL_FORTEZZA_KEA_WITH_NULL_SHA         TLSCipherSuite = 28
	TLS_CIPER_SUITE_SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA TLSCipherSuite = 29
	TLS_CIPER_SUITE_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA      TLSCipherSuite = 30
	// fortezza tokens used in the highly secure env such as goverment
	//
)

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Step 3: Receive Client Hello
	clientHello := make([]byte, 1024)
	n, err := conn.Read(clientHello)
	if err != nil {
		fmt.Println("Error reading Client Hello:", err)
		return
	}

	contentType := clientHello[0]
	if contentType == byte(TLSContentTypeHandshake) {
		majorVersion := clientHello[1]
		minorVersion := clientHello[2]
		recordLength := clientHello[3:5]
		// record length is only 2 bytes while handshake can be 3 bytes, when that happend two request are transmited and reasmbled into one
		handshakeMessageType := TLSHandshakeMessageType(clientHello[5])

		if handshakeMessageType == TLSHandshakeMessageClinetHello {
			// client hello
			handshakeLength := clientHello[6:8]
			clientVersion := clientHello[8:9] // backward compability, used to dicated which version to use, now there is set in protocol version and newest one is chosen.

			//client random
			radnomBytesTime := clientHello[9:13]
			radnomBytesData := clientHello[13:45]
			//session id
			session := clientHello[45]
			//cipher suites
			cipherSuite := clientHello[45:47]
			if cipherSuite[0] == 255 {
				//
				//    Note: All cipher suites whose first byte is 0xFF are considered
				//    private and can be used for defining local/experimental algorithms.
				//    Interoperability of such types is a local matter.
			} else {
				// other encryptions
			}
			// compression mehod
			compressionMethod := clientVersion[47:48]
			//estinsl ength
			//extentsion server name
			// extenstion status request
			//extenstion supported grops
			//extenstion ec points format
			//extension singing algorithm
			//extension renogotation info
			//extension sct
		}

	} else if contentType == byte(TLSContentTypeAlert) {
		majorVersion := clientHello[1]
		minorVersion := clientHello[2]
		length := clientHello[3:4]
		alertLevel := TlSAlertLevel(clientHello[5])
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
			// Match an literal: if match is found it is encoded a tuple (distnace, length)
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

		if alertLevel == TLSAlertLevelfatal {
			conn.Close()
			return
		}

	} else if contentType == byte(TLSContentTypeChangeCipherSpec) {
		// The change cipher spec message is sent by both the client and the server to notify the reciing part that subsequent record will be protected under the just-negotiated cipherspec and keys. Copy pending state into currnet.
		// *When resuming a previous sessin, the change cipher spec message is sent after the hello
		majorVersion := clientHello[1]
		minorVersion := clientHello[2]
		length := clientHello[3:4]
		message := TLSCipherSpec(clientHello[5])
		if message == TLSCipherSpecDefault {
			fmt.Print("Sender is switching to new cipher :)")
		}
	}
	fmt.Print(clientHello)
}
