package handshake

import (
	"fmt"
	"handshakeServer/helpers"
)

func (serverData *ServerData) T13RecordLayerMacEncryption(data []byte, contentData ContentType) (ContentType, []byte, error) {
	// //   opaque_type:  The outer opaque_type field of a TLSCiphertext record
	// is always set to the value 23 (application_data) for outward
	// compatibility with middleboxes accustomed to parsing previous
	// versions of TLS.  The actual content type of the record is found
	// in TLSInnerPlaintext.type after decryption.

	if contentData == ContentTypeHandshake {
		data = append(data, byte(22))
		contentData = ContentTypeApplicationData
	} else if contentData == ContentTypeApplicationData {
		data = append(data, byte(23))
	}

	AdditionalDataOverHead := 16 // Probably should not be hardcoded

	additionalData := []byte{byte(ContentTypeApplicationData)}
	additionalData = append(additionalData, serverData.tls13.legacyRecordVersion...)
	additionalDataLength := helpers.Int32ToBigEndian(len(data) + AdditionalDataOverHead)
	additionalData = append(additionalData, additionalDataLength...)

	encryptedMsg, err := serverData.CipherDef.EncryptMessage(data, serverData.CipherDef.Keys.WriteKeyServer, serverData.CipherDef.Keys.IVServer, serverData.ServerSeqNum, additionalData)

	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionDecryptError)
		return 0, nil, err
	}

	// serverData.conn.Write(encryptesExtMsg)
	// //   opaque_type:  The outer opaque_type field of a TLSCiphertext record
	// is always set to the value 23 (application_data) for outward
	// compatibility with middleboxes accustomed to parsing previous
	// versions of TLS.  The actual content type of the record is found
	// in TLSInnerPlaintext.type after decryption.

	return contentData, encryptedMsg, nil
}

func (serverData *ServerData) T13DecryptData(dataContent []byte, contentType byte) (byte, []byte, error) {
	additionalData := []byte{byte(ContentTypeApplicationData)}
	additionalData = append(additionalData, serverData.tls13.legacyRecordVersion...)
	additionalDataLength := helpers.Int32ToBigEndian(len(dataContent)) // gcm tag size)
	additionalData = append(additionalData, additionalDataLength...)

	decryptedClientData, err := serverData.CipherDef.DecryptMessage(dataContent, serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient, serverData.ClientSeqNum, additionalData)

	if err != nil {
		return 0, nil, err
	}

	// TODO: this should be only for tls 1.3
	for i := 7; i >= 0; i-- {
		serverData.ClientSeqNum[i] += 1
		if serverData.ClientSeqNum[i] != 0 {
			break
		}
	}

	// Transforming hidden handshake message under application data into handshake message format
	if true {
		contentType = decryptedClientData[len(decryptedClientData)-1]
		if contentType < byte(ContentTypeChangeCipherSpec) || contentType > byte(ContentTypeHeartBeat) {
			serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionUnexpectedMessage)
			return 0, nil, fmt.Errorf("invalid content type, got: %v", contentType)
		}
		decryptedClientData = decryptedClientData[:len(decryptedClientData)-1]
	}

	return contentType, decryptedClientData, nil
}
