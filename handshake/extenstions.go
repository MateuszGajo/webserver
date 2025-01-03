package handshake

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"handshakeServer/cipher"
	"handshakeServer/helpers"

	"golang.org/x/crypto/curve25519"
)

// struct {
// 	ExtensionType extension_type;
// 	opaque extension_data<0..2^16-1>;
// } Extension;

type ExtenstionType int32

const (
	ExtenstionTypeSupportedGroups   ExtenstionType = 10
	ExtenstionTypeSupportedVersions ExtenstionType = 43
	ExtenstionTypeKeyShare          ExtenstionType = 51
	ExtenstionTypeRenegotiationInfo ExtenstionType = 65281
)

func (serverData *ServerData) ConstructExtenstion(extType ExtenstionType) ([]byte, error) {

	var extData []byte
	var err error

	switch extType {
	case ExtenstionTypeKeyShare:
		extData, err = serverData.extenstionKeyShare()
	case ExtenstionTypeSupportedVersions:
		extData, err = serverData.extenstionSupportedVersions()
	case ExtenstionTypeRenegotiationInfo:
		extData, err = serverData.extenstionRenegotiationInfo()
	default:
		return nil, fmt.Errorf("extenstion %v not implement", extType)
	}

	if err != nil {
		return nil, fmt.Errorf("problem constructing extenstion %v, err: %v", extType, err)
	}

	extDataLength := helpers.Int32ToBigEndian(len(extData))
	extTypeBinary := helpers.Int32ToBigEndian(int(extType))

	extenstion := extTypeBinary
	extenstion = append(extenstion, extDataLength...)
	extenstion = append(extenstion, extData...)

	return extenstion, nil
}

func (serverData *ServerData) extenstionSupportedVersions() ([]byte, error) {
	// struct {
	// 	select (Handshake.msg_type) {
	// 		case client_hello:
	// 			 ProtocolVersion versions<2..254>;

	// 		case server_hello: /* and HelloRetryRequest */
	// 			 ProtocolVersion selected_version;
	// 	};
	// } SupportedVersions;

	//   uint16 ProtocolVersion;

	//versionExt := []byte{ 0, 2, 3, 4}

	// 	If this extension is not present, servers which are compliant with
	//    this specification and which also support TLS 1.2 MUST negotiate
	//    TLS 1.2 or prior as specified in [RFC5246], even if
	//    ClientHello.legacy_version is 0x0304 or later.  Servers MAY abort the
	//    handshake upon receiving a ClientHello with legacy_version 0x0304 or
	//    later.

	// If this extension is present in the ClientHello, servers MUST NOT use
	// the ClientHello.legacy_version value for version negotiation and MUST
	// use only the "supported_versions" extension to determine client
	// preferences.  Servers MUST only select a version of TLS present in
	// that extension and MUST ignore any unknown versions that are present
	// in that extension.  Note that this mechanism makes it possible to
	// negotiate a version prior to TLS 1.2 if one side supports a sparse
	// range.  Implementations of TLS 1.3 which choose to support prior
	// versions of TLS SHOULD support TLS 1.2.  Servers MUST be prepared to
	// receive ClientHellos that include this extension but do not include
	// 0x0304 in the list of versions.

	// A server which negotiates a version of TLS prior to TLS 1.3 MUST set
	// ServerHello.version and MUST NOT send the "supported_versions"
	// extension.  A server which negotiates TLS 1.3 MUST respond by sending
	// a "supported_versions" extension containing the selected version
	// value (0x0304).  It MUST set the ServerHello.legacy_version field to
	// 0x0303 (TLS 1.2).  Clients MUST check for this extension prior to
	// processing the rest of the ServerHello (although they will have to  parse the ServerHello in order to read the extension).  If this
	// extension is present, clients MUST ignore the
	// ServerHello.legacy_version value and MUST use only the
	// "supported_versions" extension to determine the selected version.  If
	// the "supported_versions" extension in the ServerHello contains a
	// version not offered by the client or contains a version prior to
	// TLS 1.3, the client MUST abort the handshake with an
	// "illegal_parameter" alert.

	// TODO: write logic to support older versions, aborting etc

	version := serverData.Version

	// Let's assume that client supports tls 1.3 0x0304, set legacy version to 0x0303 tls 1.2 as rfc specified

	serverData.tls13.legacyRecordVersion = []byte{3, 3}

	return version, nil

}

func (serverData *ServerData) extenstionKeyShare() ([]byte, error) {

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

	// struct {
	// 	NamedGroup group;
	// 	opaque key_exchange<1..2^16-1>;
	// } KeyShareEntry;
	// struct {
	// 	KeyShareEntry server_share;
	// } KeyShareServerHello;
	if *serverData.CipherDef.DhParams.Group == cipher.DhGroupX25519 {
	}

	// THIS key generation should be in cipher
	_, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 private key: %v", err)
	}

	// Derive the x25519 private key
	var privateKey [32]byte
	copy(privateKey[:], edPrivateKey.Seed())

	// Derive the x25519 public key
	x25519PublicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 public key: %v ", err)
	}

	// THIS key generation should be in cipher

	// THIS secret generation should be in ciper too
	sharedSecret, _ := curve25519.X25519(privateKey[:], serverData.extenstions.keyShare.clientKey)
	serverData.CipherDef.ECDH.SharedSecret = sharedSecret
	// THIS secret generation should be in ciper too

	keyShareEntryGroupName := helpers.Int32ToBigEndian(int(cipher.DhGroupX25519))
	keyShareEntryKeyExchange := x25519PublicKey[:]
	keyShareEntryKeyExchangeLength := helpers.Int32ToBigEndian(len(keyShareEntryKeyExchange))

	keyShareEntry := keyShareEntryGroupName
	keyShareEntry = append(keyShareEntry, keyShareEntryKeyExchangeLength...)
	keyShareEntry = append(keyShareEntry, keyShareEntryKeyExchange...)

	return keyShareEntry, nil
}

func (serverData *ServerData) extenstionRenegotiationInfo() ([]byte, error) {

	data := []byte{byte(0)}

	return data, nil
}

func (serverData *ServerData) extenstionHandleSupportedGroups(data []byte) error {
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

	for i := 0; i < len(clientGroups); i += 2 {
		group := binary.BigEndian.Uint16(clientGroups[i : i+2])
		fmt.Println("test group")
		fmt.Println(group)
		if _, ok := cipher.SupportedGroups[cipher.DHGroups(group)]; ok {
			// supportedGroup = cipher.DHGroups(group)
			serverData.CipherDef.DhParams.Group = &supportedGroup
			return nil
		}
	}
	return fmt.Errorf("don't support any of the groups passed: %v", clientGroups)
}

func (serverData *ServerData) extenstionHandleSupportedVersion(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("data should be at least of length: 1, we got data: %v", data)
	}
	dataLen := int(data[0])

	if len(data)-1 != int(dataLen) {
		return fmt.Errorf("expected the to be of length: %v, got: %v, data: %v", dataLen, len(data)-1, data)
	}

	content := data[1:]

	if len(content)%2 != 0 {
		return fmt.Errorf("data length should be odd number, data: %v", data)
	}

	for i := 0; i < len(content); i += 2 {
		version := binary.BigEndian.Uint16(content[i : i+2])
		if _, ok := SupportedVersion[Version(version)]; ok {
			return nil
		}
	}

	return fmt.Errorf("expected supports versions %v, got: %v", SupportedVersion, content)
}

func (serverData *ServerData) extenstionHandleKeyShare(data []byte) error {
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

	groupName := binary.BigEndian.Uint16(keyShareData[:2])

	if _, ok := cipher.SupportedGroups[cipher.DHGroups(groupName)]; !ok {
		serverData.sendAlertMsg(AlertLevelwarning, AlertDescriptionIllegalParameter)
		return fmt.Errorf("server doesn't supports: %v group, supported groups: %v", groupName, cipher.SupportedGroups)
	}
	//x25519(0x001D) - 19
	keyExchangeLength := binary.BigEndian.Uint16(keyShareData[2:4])

	if len(keyShareData)-4 != int(keyExchangeLength) {
		return fmt.Errorf("key exchange should be of lenth: %v, insted we got: %v, data: %v", int(keyExchangeLength), len(keyShareData)-4, keyShareData[4:])
	}

	keyExchange := keyShareData[4 : 4+keyExchangeLength]

	serverData.extenstions.keyShare.clientKey = keyExchange

	return nil
}
