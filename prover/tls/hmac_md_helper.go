package tls

import (
	"encoding/hex"
	"errors"
)

type HmacMD struct {
	inner, outer    []byte
	prevBlockDigest []byte
}

func HmacPadConstructHelper(key []byte, pad byte) []byte {
	result := make([]byte, 64)
	for i := 0; i < 32; i++ {
		result[i] = key[i] ^ pad
	}
	for i := 32; i < 64; i++ {
		result[i] = pad
	}
	return result
}

func compute(msg []byte, iv []byte) ([]byte, error) {
	prevHashLen := 64
	digest, err := SHA256Gadget(msg, iv, true, prevHashLen)
	if err != nil {
		return nil, errors.New("md sha256 computation failed")
	}
	return digest, err
}

func (h *HmacMD) CompInnerHash(remainInner []byte, prevInnerBlockDigest []byte) error {
	var err error
	h.inner, err = compute(remainInner, prevInnerBlockDigest)
	return err
}

func (h *HmacMD) CompOuterHashMD(remainOuter []byte, prevOuterBlockDigest []byte) error {
	var err error
	h.outer, err = compute(remainOuter, prevOuterBlockDigest)
	return err
}

func (h *HmacMD) CompOuterHash(key []byte) error {
	var err error
	oh1, _ := h.ComputeOuterFirstBlockDigest(key)
	h.CompOuterHashMD(h.inner, oh1)
	return err
}

func (h *HmacMD) ComputeInnerFirstBlockDigest(key []byte) (ih1 []byte, err error) {
	iv, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	ipad := HmacPadConstructHelper(key, 0x36)
	ih1, err = SHA256Gadget(ipad, iv, false, 0)
	if err != nil {
		return nil, err
	}
	return ih1, nil
}

func (h *HmacMD) ComputeOuterFirstBlockDigest(key []byte) (oh1 []byte, err error) {
	iv, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	opad := HmacPadConstructHelper(key, 0x5c)
	oh1, _ = SHA256Gadget(opad, iv, false, 0)
	if err != nil {
		return nil, err
	}
	return oh1, nil
}

func (h *HmacMD) ComputeRemainHmac(msg []byte, prevBlockHash []byte, key []byte) []byte {
	h.CompInnerHash(msg, prevBlockHash)
	oh1, _ := h.ComputeOuterFirstBlockDigest(key)
	h.CompOuterHashMD(h.inner, oh1)
	return h.outer
}

func (h *HmacMD) GetHMACOut() []byte {
	return h.outer
}
func (h *HmacMD) GetHMACInner() []byte {
	return h.inner
}
