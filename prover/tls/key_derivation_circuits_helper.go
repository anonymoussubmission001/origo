package tls

import (
	"golang.org/x/crypto/cryptobyte"
)

type layerHashProofData struct {
	hkdfSHTSFirstBlockHash  []byte
	hkdfKFSFirstBlockHash   []byte
	hkdfSFFirstBlockHash    []byte
	hkdfDHSFirstBlockHash   []byte
	hkdfMSFirstBlockHash    []byte
	hkdfSATSFirstBlockHash  []byte
	hkdfCATSFirstBlockHash  []byte
	hkdfKSAPPFirstBlockHash []byte
	hkdfKCAPPFirstBlockHash []byte
}

type savedData struct {
	earlySecret                  []byte
	derivedEarlySecret           []byte
	handshakeSecret              []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
	serverHandshakeTrafficKey    []byte
	serverHandshakeTrafficIV     []byte
	hkdfSHTSFirstBlock           []byte
	hkdfDHSFirstBlock            []byte
	derivedHandshakeSecret       []byte
	masterSecret                 []byte
	hkdfMSFirstBlock             []byte
	hkdfKFSFirstBlock            []byte
	hkdfKFS                      []byte
	hkdfSFFirstBlock             []byte
	hkdfSF                       []byte
	hkdfSATSFirstBlock           []byte
	clientAppTrafficSecret       []byte
	serverAppTrafficSecret       []byte
	serverApplicationTrafficKey  []byte
	serverApplicationTrafficIV   []byte
	hkdfKSAPPFirstBlock          []byte
	clientApplicationTrafficKey  []byte
	clientApplicationTrafficIV   []byte
	hkdfKCAPPFirstBlock          []byte
	galoisKeyCipher              []byte
	taskMaskCipher               []byte
	plaintextToProof             []byte

	HkdfSHTSInnerHash     []byte
	HkdfKFSInnerHash      []byte
	HkdfSFInnerHash       []byte
	HkdfDHSInnerHash      []byte
	HkdfMSInnerHash       []byte
	HkdfSATSInnerHash     []byte
	HkdfCATSInnerHash     []byte
	HkdfKSAPPKeyInnerHash []byte
	HkdfKSAPPIVInnerHash  []byte
	HkdfKCAPPKeyInnerHash []byte
	HkdfKCAPPIVInnerHash  []byte
	CiphertextToProof     []byte

	record []byte
}

func HKDFExpandInnerHashInputBuilder(label string, context []byte, length int) (expandInput []byte, err error) {
	var hkdfLabel cryptobyte.Builder
	//length := sha256.Size
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	hkdfLabel.AddUint8(uint8(0x01))
	expandInput, err = hkdfLabel.Bytes()
	return expandInput, err
}

func computeHKDFExpandInnerHash(msg []byte, prevInnerBlockHash []byte) []byte {
	md := new(HmacMD)
	md.CompInnerHash(msg, prevInnerBlockHash)
	return md.inner
}
